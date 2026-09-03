Param(
    [string] $AzureUserName,
    [string] $AzurePassword,
    [string] $AzureTenantID,
    [string] $AzureSubscriptionID,
    [string] $ODLID,
    [string] $InstallCloudLabsShadow,
    [string] $DeploymentID,
    [string] $vmAdminUsername,
    [string] $vmAdminPassword,
    [string] $trainerUserName,
    [string] $trainerUserPassword
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

New-Item -ItemType Directory -Path 'C:\WindowsAzure\Logs' -Force | Out-Null
Start-Transcript -Path 'C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt' -Append

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $global:LabRoot = 'C:\LabFiles'
    $global:ToolRoot = Join-Path $global:LabRoot 'Tools'
    $global:ScriptRoot = Join-Path $global:LabRoot 'Scripts'
    $global:SeedRoot = Join-Path $global:LabRoot 'Seed'
    New-Item -ItemType Directory -Path $global:LabRoot,$global:ToolRoot,$global:ScriptRoot,$global:SeedRoot -Force | Out-Null

    function Write-Log {
        param([string]$Message)
        Write-Host "[$((Get-Date).ToUniversalTime().ToString('s'))Z] $Message"
    }

    function Invoke-WithRetry {
        param(
            [scriptblock]$ScriptBlock,
            [int]$MaxAttempts = 6,
            [int]$DelaySeconds = 20,
            [string]$OperationName = 'operation'
        )
        $lastError = $null
        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            try { return & $ScriptBlock }
            catch {
                $lastError = $_
                Write-Log "$OperationName attempt $attempt of $MaxAttempts failed: $($_.Exception.Message)"
                if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
            }
        }
        throw $lastError
    }

    function CreateCredFile {
        Write-Log 'Downloading CloudLabs credential helper files.'
        $commonUri = 'https://experienceazure.blob.core.windows.net/templates/cloudlabs-common'
        $downloadDir = Join-Path $env:TEMP 'cloudlabs-common'
        New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
        foreach ($file in @('AzureCreds.txt','AzureCreds.ps1')) {
            $source = "$commonUri/$file"
            $target = Join-Path $downloadDir $file
            Invoke-WebRequest -Uri $source -OutFile $target -UseBasicParsing
            $content = Get-Content -Path $target -Raw
            $replacements = @{
                'GET-AZUSER-UPN' = $AzureUserName
                'GET-AZUSER-PASSWORD' = $AzurePassword
                'GET-TENANT-ID' = $AzureTenantID
                'GET-SUBSCRIPTION-ID' = $AzureSubscriptionID
                'GET-ODL-ID' = $ODLID
                'GET-DEPLOYMENT-ID' = $DeploymentID
                'AzureUserName' = $AzureUserName
                'AzurePassword' = $AzurePassword
                'AzureTenantID' = $AzureTenantID
                'AzureSubscriptionID' = $AzureSubscriptionID
                'ODLID' = $ODLID
                'DeploymentID' = $DeploymentID
            }
            foreach ($key in $replacements.Keys) { $content = $content.Replace($key, [string]$replacements[$key]) }
            Set-Content -Path $target -Value $content -Encoding UTF8
            Copy-Item -Path $target -Destination (Join-Path $global:LabRoot $file) -Force
            Copy-Item -Path $target -Destination (Join-Path 'C:\Users\Public\Desktop' $file) -Force
        }
    }

    function Ensure-TrainerLocalAccount {
        if ([string]::IsNullOrWhiteSpace($InstallCloudLabsShadow) -or $InstallCloudLabsShadow.ToLowerInvariant() -ne 'false') {
            if (-not [string]::IsNullOrWhiteSpace($trainerUserName) -and -not [string]::IsNullOrWhiteSpace($trainerUserPassword)) {
                Write-Log "Ensuring local trainer account '$trainerUserName' for VM Shadow."
                $secureTrainerPassword = ConvertTo-SecureString $trainerUserPassword -AsPlainText -Force
                $existing = Get-LocalUser -Name $trainerUserName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-LocalUser -Name $trainerUserName -Password $secureTrainerPassword -PasswordNeverExpires -AccountNeverExpires | Out-Null
                }
                else {
                    Set-LocalUser -Name $trainerUserName -Password $secureTrainerPassword -PasswordNeverExpires $true
                    Enable-LocalUser -Name $trainerUserName
                }
                foreach ($group in @('Remote Desktop Users','Administrators')) {
                    try { Add-LocalGroupMember -Group $group -Member $trainerUserName -ErrorAction Stop }
                    catch { Write-Log "Trainer account is already in or cannot be added to '$group': $($_.Exception.Message)" }
                }
            }
        }
        else { Write-Log 'InstallCloudLabsShadow is explicitly false. Skipping trainer local account creation.' }
    }

    function Ensure-AzureCli {
        if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
            Write-Log 'Azure CLI not found. Installing Azure CLI for Windows.'
            $msi = Join-Path $env:TEMP 'AzureCLI.msi'
            Invoke-WebRequest -Uri 'https://aka.ms/installazurecliwindows' -OutFile $msi -UseBasicParsing
            Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$msi`" /quiet /norestart" -Wait
            $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
            if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI installation completed but az.exe is not available on PATH.' }
        }
        Write-Log "Using Azure CLI at $((Get-Command az).Source)."
    }

    function Invoke-AzCli {
        param([string[]]$Arguments, [switch]$AllowFailure)
        $output = & az @Arguments 2>&1
        $exit = $LASTEXITCODE
        if ($exit -ne 0 -and -not $AllowFailure) { throw "az $($Arguments -join ' ') failed with exit code $exit. Output: $output" }
        return ($output -join "`n")
    }

    function Test-AzResourceId {
        param([string]$ResourceId)
        if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $false }
        & az resource show --ids $ResourceId --only-show-errors -o none 2>$null
        return ($LASTEXITCODE -eq 0)
    }

    function Invoke-AzRestJson {
        param(
            [string]$Method,
            [string]$Uri,
            [object]$Body = $null,
            [switch]$AllowFailure
        )
        $args = @('rest','--method',$Method,'--uri',$Uri,'--only-show-errors')
        $tempFile = $null
        if ($null -ne $Body) {
            $tempFile = Join-Path $env:TEMP ("azbody-{0}.json" -f ([guid]::NewGuid().Guid))
            # Set-Content -Encoding UTF8 emits a byte order mark on Windows PowerShell 5.1, and ARM
            # rejects a request body that starts with one as malformed JSON. Write it without.
            $bodyJson = $Body | ConvertTo-Json -Depth 30
            [System.IO.File]::WriteAllText($tempFile, $bodyJson, (New-Object System.Text.UTF8Encoding $false))
            $args += @('--body', "@$tempFile")
        }
        try {
            $raw = Invoke-AzCli -Arguments $args -AllowFailure:$AllowFailure
            if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
            return $raw | ConvertFrom-Json
        }
        finally {
            if ($tempFile -and (Test-Path $tempFile)) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
        }
    }

    function Connect-CloudLabsAzure {
        # Azure enforces MFA on public cloud, so a username/password sign-in is refused with
        # AADSTS50076 and takes the whole bootstrap down. The VM carries a system-assigned managed
        # identity with Owner on this resource group, granted by the ARM template, so sign in as
        # that instead. It needs no secret and is unaffected by MFA.
        Write-Log 'Signing in to Azure CLI with the VM managed identity.'
        $signedIn = $false
        try {
            Invoke-WithRetry -OperationName 'az login --identity' -MaxAttempts 5 -DelaySeconds 30 -ScriptBlock {
                Invoke-AzCli -Arguments @('login','--identity','--output','none') | Out-Null
                Invoke-AzCli -Arguments @('account','set','--subscription',$AzureSubscriptionID) | Out-Null
            } | Out-Null
            $signedIn = $true
            Write-Log 'Signed in with the VM managed identity.'
        }
        catch {
            Write-Log "WARNING: Managed identity sign-in failed: $($_.Exception.Message)"
        }

        if (-not $signedIn) {
            # Kept only for tenants where MFA is not enforced. Expected to fail where it is.
            Write-Log 'Falling back to the lab user credentials.'
            Invoke-WithRetry -OperationName 'az login (user)' -MaxAttempts 3 -DelaySeconds 30 -ScriptBlock {
                Invoke-AzCli -Arguments @('login','--username',$AzureUserName,'--password',$AzurePassword,'--tenant',$AzureTenantID,'--output','none') | Out-Null
                Invoke-AzCli -Arguments @('account','set','--subscription',$AzureSubscriptionID) | Out-Null
            } | Out-Null
            Write-Log 'Signed in with the lab user credentials.'
        }
    }

    function Get-InstanceMetadata {
        try { return Invoke-RestMethod -Headers @{ Metadata = 'true' } -Method GET -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -TimeoutSec 10 }
        catch {
            Write-Log "Unable to query instance metadata: $($_.Exception.Message)"
            return $null
        }
    }

    function Get-DeterministicGuid {
        param([string]$InputString)
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        $hash = $md5.ComputeHash($bytes)
        return ([guid]::new($hash)).Guid
    }

    function Get-AzResourceByPrefix {
        param([string]$ResourceGroupName, [string]$ResourceType, [string]$Prefix)
        $query = "sort_by([?starts_with(name, '$Prefix')], &name)[0].{name:name,id:id,location:location,type:type}"
        $raw = Invoke-AzCli -Arguments @('resource','list','--resource-group',$ResourceGroupName,'--resource-type',$ResourceType,'--query',$query,'-o','json') -AllowFailure
        if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq 'null') { return $null }
        return $raw | ConvertFrom-Json
    }

    function Get-UserAssignedIdentityByPrefix {
        param([string]$ResourceGroupName, [string]$Prefix)
        $query = "sort_by([?starts_with(name, '$Prefix')], &name)[0]"
        $raw = Invoke-AzCli -Arguments @('identity','list','--resource-group',$ResourceGroupName,'--query',$query,'-o','json') -AllowFailure
        if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq 'null') { return $null }
        return $raw | ConvertFrom-Json
    }

    function Get-SentinelAutomationRuleContext {
        param([string]$ResourceGroupName, [string]$WorkspaceName)
        $uri = "https://management.azure.com/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules?api-version=2024-03-01"
        $response = Invoke-AzRestJson -Method GET -Uri $uri -AllowFailure
        if (-not $response -or -not $response.value) { return $null }
        $match = @($response.value) | Where-Object { $_.properties.displayName -eq 'AR-ZAVA-Auto-Isolate-VM' -or $_.name -eq 'AR-ZAVA-Auto-Isolate-VM' } | Select-Object -First 1
        if (-not $match) { return $null }
        return [pscustomobject]@{ name = $match.name; id = $match.id; displayName = $match.properties.displayName }
    }

    function Resolve-ZavaResourceContext {
        param(
            [string]$ResourceGroupName,
            [string]$Location,
            [string]$VmName,
            [string]$VmResourceId,
            [string]$WorkspaceName,
            [string]$WorkspaceResourceId
        )
        Write-Log 'Discovering deployed Zava resource names and IDs for local configuration files. Learner-created resource names are recorded as hints only when resources are absent.'
        $nsgResource = Get-AzResourceByPrefix -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Network/networkSecurityGroups' -Prefix 'nsg-zava-workload-'
        $dcrResource = Get-AzResourceByPrefix -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Insights/dataCollectionRules' -Prefix 'dcr-zava-securityevents-'
        $dceResource = Get-AzResourceByPrefix -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Insights/dataCollectionEndpoints' -Prefix 'dce-zava-securityevents-'
        $logicAppResource = Get-AzResourceByPrefix -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Logic/workflows' -Prefix 'la-zava-isolate-notify-'
        $workbookResource = Get-AzResourceByPrefix -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Insights/workbooks' -Prefix 'wb-zava-triage-report-'
        $publicIpResource = Get-AzResourceByPrefix -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.Network/publicIPAddresses' -Prefix 'pip-zava-soc-'
        $identityResource = Get-UserAssignedIdentityByPrefix -ResourceGroupName $ResourceGroupName -Prefix 'id-zava-playbook-'
        $automationRule = Get-SentinelAutomationRuleContext -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName

        $fallbackDcrName = "dcr-zava-securityevents-$DeploymentID"
        $fallbackDcrId = "/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionRules/$fallbackDcrName"
        $fallbackLogicAppName = "la-zava-isolate-notify-$DeploymentID"
        $fallbackWorkbookName = "wb-zava-triage-report-$DeploymentID"

        Write-Log "Windows Security Events DCR end-state name hint: $fallbackDcrName. The CSE does not create DCRs or DCR associations."
        Write-Log "Learner-created Logic App and workbook name hints: $fallbackLogicAppName, $fallbackWorkbookName. The CSE does not create Logic Apps or workbooks."
        if ($identityResource) { Write-Log "Discovered precreated playbook user-assigned identity: $($identityResource.name)." }
        else { Write-Log 'No precreated user-assigned identity with prefix id-zava-playbook- was discovered. Learner playbook can use system-assigned identity if directed by the guide.' }

        return [ordered]@{
            AzureSubscriptionID = $AzureSubscriptionID
            AzureTenantID = $AzureTenantID
            ODLID = $ODLID
            DeploymentID = $DeploymentID
            ResourceGroupName = $ResourceGroupName
            Location = $Location
            VmName = $VmName
            VmResourceId = $VmResourceId
            WorkspaceName = $WorkspaceName
            WorkspaceResourceId = $WorkspaceResourceId
            SentinelOnboardingStateResourceId = "$WorkspaceResourceId/providers/Microsoft.SecurityInsights/onboardingStates/default"
            NsgName = if ($nsgResource) { $nsgResource.name } else { '' }
            NsgResourceId = if ($nsgResource) { $nsgResource.id } else { '' }
            SecurityEventsDcrName = if ($dcrResource) { $dcrResource.name } else { $fallbackDcrName }
            SecurityEventsDcrId = if ($dcrResource) { $dcrResource.id } else { $fallbackDcrId }
            SecurityEventsDcrNameHint = $fallbackDcrName
            SecurityEventsDcrIdHint = $fallbackDcrId
            SecurityEventsDcrExists = if ($dcrResource) { 'true' } else { 'false' }
            DataCollectionEndpointName = if ($dceResource) { $dceResource.name } else { '' }
            DataCollectionEndpointResourceId = if ($dceResource) { $dceResource.id } else { '' }
            LogicAppName = if ($logicAppResource) { $logicAppResource.name } else { '' }
            LogicAppResourceId = if ($logicAppResource) { $logicAppResource.id } else { '' }
            LearnerLogicAppNameHint = $fallbackLogicAppName
            AutomationRuleName = if ($automationRule) { $automationRule.name } else { '' }
            AutomationRuleDisplayName = if ($automationRule) { $automationRule.displayName } else { 'AR-ZAVA-Auto-Isolate-VM' }
            AutomationRuleResourceId = if ($automationRule) { $automationRule.id } else { '' }
            WorkbookName = if ($workbookResource) { $workbookResource.name } else { '' }
            WorkbookResourceId = if ($workbookResource) { $workbookResource.id } else { '' }
            LearnerWorkbookNameHint = $fallbackWorkbookName
            PlaybookUserAssignedIdentityName = if ($identityResource) { $identityResource.name } else { '' }
            PlaybookUserAssignedIdentityResourceId = if ($identityResource) { $identityResource.id } else { '' }
            PlaybookUserAssignedIdentityClientId = if ($identityResource) { $identityResource.clientId } else { '' }
            PlaybookUserAssignedIdentityPrincipalId = if ($identityResource) { $identityResource.principalId } else { '' }
            PublicIpName = if ($publicIpResource) { $publicIpResource.name } else { '' }
            PublicIpResourceId = if ($publicIpResource) { $publicIpResource.id } else { '' }
            BenignFalsePositiveAccount = 'svc-zava-audit@zavacorp.example'
            BenignFalsePositiveSourceIp = '198.51.100.23'
            ExpectedLogicAppPrefix = 'la-zava-isolate-notify-'
            ExpectedWorkbookPrefix = 'wb-zava-triage-report-'
            ExpectedUserAssignedIdentityPrefix = 'id-zava-playbook-'
            ExpectedAutomationRuleDisplayName = 'AR-ZAVA-Auto-Isolate-VM'
        }
    }

    function Get-WorkspaceSharedKey {
        param([string]$ResourceGroupName, [string]$WorkspaceName)
        $raw = Invoke-AzCli -Arguments @('monitor','log-analytics','workspace','get-shared-keys','--resource-group',$ResourceGroupName,'--workspace-name',$WorkspaceName,'-o','json')
        $keys = $raw | ConvertFrom-Json
        if ($keys.primarySharedKey) { return $keys.primarySharedKey }
        $uri = "https://management.azure.com/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/sharedKeys?api-version=2020-08-01"
        $restKeys = Invoke-AzRestJson -Method POST -Uri $uri
        return $restKeys.primarySharedKey
    }

    function Send-LogAnalyticsDataCollectorRecords {
        param(
            [string]$WorkspaceId,
            [string]$WorkspaceKey,
            [string]$LogType,
            [object[]]$Records
        )
        if (-not $Records -or $Records.Count -eq 0) { return }
        $legacyApiRetirementUtc = [DateTimeOffset]::Parse('2026-09-14T00:00:00Z').UtcDateTime
        $legacyApiHardStopUtc = [DateTimeOffset]::Parse('2026-09-13T00:00:00Z').UtcDateTime
        # LEGACY INGESTION RETIREMENT MARKER: Microsoft Learn states the Azure Monitor Logs HTTP Data Collector API support ends on September 14, 2026.
        # This short-lived lab seed path intentionally remains on the existing API in this minimal CSE revision to avoid an incomplete Logs Ingestion API migration.
        # HARD TIME-BOX: this path is blocked starting 2026-09-13T00:00:00Z, before the documented support-retirement date. Migration must be completed before republishing after that date.
        # MIGRATION BLOCKER: replace this function with a coherent DCR-based Logs Ingestion API path, including the ZavaSOCSeed_CL table schema/transform, a direct-ingestion DCR or DCE endpoint, and a least-privilege authenticated ingestion identity with DCR access.
        if ([DateTime]::UtcNow -ge $legacyApiHardStopUtc) {
            throw "Legacy HTTP Data Collector API seed ingestion is blocked for this lab after $($legacyApiHardStopUtc.ToString('o')). Microsoft Learn documents support retirement on $($legacyApiRetirementUtc.ToString('yyyy-MM-dd')). Migrate ZavaSOCSeed_CL ingestion to the DCR-based Logs Ingestion API before publishing or running this lab."
        }
        $json = $Records | ConvertTo-Json -Depth 15
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $rfc1123Date = [DateTime]::UtcNow.ToString('r')
        $stringToHash = "POST`n$($bodyBytes.Length)`napplication/json`nx-ms-date:$rfc1123Date`n/api/logs"
        $decodedKey = [Convert]::FromBase64String($WorkspaceKey)
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $decodedKey
        $encodedHash = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToHash)))
        $signature = "SharedKey ${WorkspaceId}:$encodedHash"
        $headers = @{
            'Authorization' = $signature
            'Log-Type' = $LogType
            'x-ms-date' = $rfc1123Date
            'time-generated-field' = 'TimeGenerated'
        }
        $uri = "https://$WorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        Invoke-WithRetry -OperationName "Log Analytics custom table ingestion $LogType" -MaxAttempts 5 -DelaySeconds 20 -ScriptBlock {
            Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -ContentType 'application/json' -Body $bodyBytes | Out-Null
        } | Out-Null
    }

    function Invoke-LogAnalyticsQuery {
        param(
            [string]$WorkspaceCustomerId,
            [string]$Query,
            [string]$Timespan = 'P30D'
        )
        $uri = "https://api.loganalytics.io/v1/workspaces/$WorkspaceCustomerId/query"
        $body = @{ query = $Query; timespan = $Timespan }
        return Invoke-AzRestJson -Method POST -Uri $uri -Body $body
    }

    function Convert-LogAnalyticsTableToObjects {
        param([object]$QueryResponse)
        $objects = New-Object System.Collections.Generic.List[object]
        if (-not $QueryResponse -or -not $QueryResponse.tables -or @($QueryResponse.tables).Count -eq 0) { return $objects.ToArray() }
        $table = @($QueryResponse.tables)[0]
        if (-not $table.rows) { return $objects.ToArray() }
        $columnNames = @($table.columns | ForEach-Object { $_.name })
        foreach ($row in @($table.rows)) {
            $item = [ordered]@{}
            for ($i = 0; $i -lt $columnNames.Count; $i++) { $item[$columnNames[$i]] = $row[$i] }
            $objects.Add([pscustomobject]$item) | Out-Null
        }
        return $objects.ToArray()
    }

    function Ensure-SentinelEnabled {
        param([string]$ResourceGroupName, [string]$WorkspaceName, [string]$Location)
        Write-Log "Ensuring Microsoft Sentinel is enabled on workspace $WorkspaceName."
        $solutionUri = "https://management.azure.com/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationsManagement/solutions/SecurityInsights($WorkspaceName)?api-version=2015-11-01-preview"
        $solutionBody = @{
            location = $Location
            plan = @{ name = "SecurityInsights($WorkspaceName)"; publisher = 'Microsoft'; product = 'OMSGallery/SecurityInsights'; promotionCode = '' }
            properties = @{ workspaceResourceId = "/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" }
        }
        Invoke-AzRestJson -Method PUT -Uri $solutionUri -Body $solutionBody -AllowFailure | Out-Null
        $onboardingUri = "https://management.azure.com/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01-preview"
        Invoke-AzRestJson -Method PUT -Uri $onboardingUri -Body @{ properties = @{} } -AllowFailure | Out-Null
    }

    function Get-ArmDeploymentOutputValue {
        param([string]$ResourceGroupName, [string]$OutputName)
        try {
            $raw = Invoke-AzCli -Arguments @('deployment','group','list','--resource-group',$ResourceGroupName,'-o','json','--only-show-errors') -AllowFailure
            if ([string]::IsNullOrWhiteSpace($raw)) { return '' }
            $deployments = @($raw | ConvertFrom-Json)
            $ordered = @($deployments | Sort-Object -Property @{ Expression = { [DateTime]$_.properties.timestamp }; Descending = $true })
            foreach ($deployment in $ordered) {
                if ($deployment.properties -and $deployment.properties.outputs) {
                    $prop = $deployment.properties.outputs.PSObject.Properties[$OutputName]
                    if ($prop -and $prop.Value -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value.value)) {
                        return [string]$prop.Value.value
                    }
                }
            }
        }
        catch { Write-Log "WARNING: Unable to read ARM deployment output '$OutputName': $($_.Exception.Message)" }
        return ''
    }

    function Test-SentinelPlaybookAutomationContributorAssignment {
        param([string]$ResourceGroupName)

        $sentinelAutomationContributorRoleGuid = 'f4c81013-99ee-4d62-a7ee-b3f1f648599a'
        $scope = "/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName"
        $statusPath = Join-Path $global:SeedRoot 'sentinel-playbook-permission-verification.json'
        $expectedSpObjectId = Get-ArmDeploymentOutputValue -ResourceGroupName $ResourceGroupName -OutputName 'azureSecurityInsightsServicePrincipalObjectId'

        # The Azure Security Insights object id is tenant-specific, so it cannot be supplied as a fixed
        # ARM parameter when CloudLabs draws a fresh tenant per deployment. Resolve it here from the
        # well-known application id instead, and grant the role if it is missing.
        $azureSecurityInsightsAppId = '98785600-1bb7-4fb9-b9fa-19afe2c8a360'
        if ([string]::IsNullOrWhiteSpace($expectedSpObjectId) -or $expectedSpObjectId -eq '00000000-0000-0000-0000-000000000000') {
            Write-Log "ARM did not supply a usable Azure Security Insights object id. Resolving it from well-known appId $azureSecurityInsightsAppId."
            try {
                $spRaw = Invoke-AzCli -Arguments @('ad','sp','show','--id',$azureSecurityInsightsAppId,'-o','json','--only-show-errors') -AllowFailure
                if (-not [string]::IsNullOrWhiteSpace($spRaw)) {
                    $spObj = $spRaw | ConvertFrom-Json
                    if ($spObj -and $spObj.id) {
                        $expectedSpObjectId = [string]$spObj.id
                        Write-Log "Resolved Azure Security Insights service principal objectId $expectedSpObjectId."
                    }
                }
            }
            catch { Write-Log "WARNING: Could not resolve the Azure Security Insights service principal: $($_.Exception.Message)" }
        }

        if (-not [string]::IsNullOrWhiteSpace($expectedSpObjectId) -and $expectedSpObjectId -ne '00000000-0000-0000-0000-000000000000') {
            try {
                $existing = Invoke-AzCli -Arguments @('role','assignment','list','--scope',$scope,'--assignee',$expectedSpObjectId,'--role',$sentinelAutomationContributorRoleGuid,'-o','json','--only-show-errors') -AllowFailure
                $existingCount = 0
                if (-not [string]::IsNullOrWhiteSpace($existing)) { $existingCount = @($existing | ConvertFrom-Json).Count }
                if ($existingCount -lt 1) {
                    Write-Log "Granting Microsoft Sentinel Automation Contributor to objectId $expectedSpObjectId at $scope."
                    Invoke-AzCli -Arguments @('role','assignment','create','--assignee-object-id',$expectedSpObjectId,'--assignee-principal-type','ServicePrincipal','--role',$sentinelAutomationContributorRoleGuid,'--scope',$scope,'-o','json','--only-show-errors') -AllowFailure | Out-Null
                }
            }
            catch { Write-Log "WARNING: Could not grant Microsoft Sentinel Automation Contributor: $($_.Exception.Message)" }
        }

        Write-Log 'Verifying Microsoft Sentinel playbook execution permissions without creating service principals or role assignments from CSE.'
        Write-Log 'Microsoft Learn documents that Sentinel automation rules use a special Microsoft Sentinel service account and require Microsoft Sentinel Automation Contributor on the playbook resource group; granting that permission requires Owner or User Access Administrator and must be handled by platform/ARM, not learners or CSE.'

        if ([string]::IsNullOrWhiteSpace($expectedSpObjectId)) {
            $status = [ordered]@{
                VerificationStatus = 'WarningArmObjectIdNotSupplied'
                VerifiedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                Scope = $scope
                ExpectedRoleDefinitionId = $sentinelAutomationContributorRoleGuid
                ExpectedServicePrincipalObjectId = ''
                Note = 'ARM deployment output azureSecurityInsightsServicePrincipalObjectId is empty. The ARM role assignment is conditional on that value, so CSE cannot deterministically verify the Sentinel service account permission. CSE intentionally does not create the Azure Security Insights service principal and does not create role assignments. Learners must not be asked to grant playbook permissions.'
            }
            $status | ConvertTo-Json -Depth 6 | Set-Content -Path $statusPath -Encoding UTF8
            Copy-Item -Path $statusPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'sentinel-playbook-permission-verification.json') -Force
            Write-Log "WARNING: ARM did not supply azureSecurityInsightsServicePrincipalObjectId. Sentinel playbook automation permission was not verified. If playbooks appear unavailable or show Grant permission/Missing permissions, fix the ARM/platform parameter before learner delivery rather than asking learners for role assignment rights. Status file: $statusPath"
            return $false
        }

        $assignments = @()
        try {
            $rawAssignments = Invoke-AzCli -Arguments @('role','assignment','list','--scope',$scope,'--include-inherited','false','-o','json','--only-show-errors')
            if (-not [string]::IsNullOrWhiteSpace($rawAssignments)) { $assignments = @($rawAssignments | ConvertFrom-Json) }
        }
        catch {
            $status = [ordered]@{
                VerificationStatus = 'FailedRoleAssignmentRead'
                VerifiedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                Scope = $scope
                ExpectedRoleDefinitionId = $sentinelAutomationContributorRoleGuid
                ExpectedServicePrincipalObjectId = $expectedSpObjectId
                Error = $_.Exception.Message
                Note = 'ARM supplied a tenant-specific Sentinel service principal object ID, so the CSE treats verification failure as a platform readiness failure. CSE does not create role assignments.'
            }
            $status | ConvertTo-Json -Depth 6 | Set-Content -Path $statusPath -Encoding UTF8
            Copy-Item -Path $statusPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'sentinel-playbook-permission-verification.json') -Force
            Write-Log "WARNING: Unable to verify the Microsoft Sentinel Automation Contributor assignment at $scope for objectId ${expectedSpObjectId}: $($_.Exception.Message). Grant it via Manage playbook permissions on the automation rule if playbooks show missing permissions."
            return $false
        }

        $matchingAssignments = @($assignments | Where-Object {
            ([string]$_.principalId).ToLowerInvariant() -eq $expectedSpObjectId.ToLowerInvariant() -and
            ([string]$_.roleDefinitionId).ToLowerInvariant().EndsWith("/$sentinelAutomationContributorRoleGuid")
        })

        if ($matchingAssignments.Count -lt 1) {
            $status = [ordered]@{
                VerificationStatus = 'FailedExpectedAssignmentMissing'
                VerifiedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                Scope = $scope
                ExpectedRoleDefinitionId = $sentinelAutomationContributorRoleGuid
                ExpectedServicePrincipalObjectId = $expectedSpObjectId
                MatchingAssignmentCount = 0
                Note = 'ARM supplied azureSecurityInsightsServicePrincipalObjectId, so the conditional ARM role assignment should exist before CSE. Learners must not be asked to grant this permission; fix the ARM/platform deployment input or role assignment.'
            }
            $status | ConvertTo-Json -Depth 6 | Set-Content -Path $statusPath -Encoding UTF8
            Copy-Item -Path $statusPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'sentinel-playbook-permission-verification.json') -Force
            Write-Log "WARNING: Microsoft Sentinel Automation Contributor is not present at $scope for objectId $expectedSpObjectId. Grant it via Manage playbook permissions on the automation rule if playbooks show missing permissions."
            return $false
        }

        $statusOk = [ordered]@{
            VerificationStatus = 'Succeeded'
            VerifiedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            Scope = $scope
            ExpectedRoleDefinitionId = $sentinelAutomationContributorRoleGuid
            ExpectedServicePrincipalObjectId = $expectedSpObjectId
            MatchingAssignmentCount = $matchingAssignments.Count
            AssignmentIds = @($matchingAssignments | ForEach-Object { $_.id })
            Note = 'Verified pre-existing ARM/platform-supplied Microsoft Sentinel Automation Contributor assignment. CSE made no service principal or role assignment changes.'
        }
        $statusOk | ConvertTo-Json -Depth 6 | Set-Content -Path $statusPath -Encoding UTF8
        Copy-Item -Path $statusPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'sentinel-playbook-permission-verification.json') -Force
        Write-Log "Verified ARM-created Microsoft Sentinel Automation Contributor assignment for Sentinel service principal objectId $expectedSpObjectId at $scope."
        return $true
    }

    function PreStage-AmaWithoutLearnerDcrCreation {
        param(
            [string]$ResourceGroupName,
            [string]$VmName,
            [string]$DcrName,
            [string]$DcrResourceId
        )
        Write-Log "Pre-staging Azure Monitor Agent extension on $VmName only. This CSE does not create DCRs, DCR associations, Logic Apps, or workbooks."
        Invoke-AzCli -Arguments @('vm','extension','set','--resource-group',$ResourceGroupName,'--vm-name',$VmName,'--publisher','Microsoft.Azure.Monitor','--name','AzureMonitorWindowsAgent','--enable-auto-upgrade','true','--only-show-errors') -AllowFailure | Out-Null

        if (Test-AzResourceId -ResourceId $DcrResourceId) {
            Write-Log "Discovered Windows Security Events DCR '$DcrName'. The CSE did not create it and did not associate it to the VM. Learners complete or verify the association in Challenge 1."
        }
        else {
            Write-Log "No DCR named '$DcrName' was discovered. This value is only the learner end-state name hint dcr-zava-securityevents-$DeploymentID; no fallback DCR or DCR association was created by CSE."
        }
    }

    function Write-ZavaLabConfiguration {
        param([System.Collections.IDictionary]$Context)

        $jsonPath = Join-Path $global:LabRoot 'zava-lab-config.json'
        $envPath = Join-Path $global:LabRoot '.env'
        $psPath = Join-Path $global:LabRoot 'Zava-LabConfig.ps1'

        $Context | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

        $envLines = @(
            "AZURE_SUBSCRIPTION_ID=$($Context.AzureSubscriptionID)",
            "AZURE_TENANT_ID=$($Context.AzureTenantID)",
            "ODLID=$($Context.ODLID)",
            "DEPLOYMENT_ID=$($Context.DeploymentID)",
            "RESOURCE_GROUP_NAME=$($Context.ResourceGroupName)",
            "LOCATION=$($Context.Location)",
            "LOG_ANALYTICS_WORKSPACE=$($Context.WorkspaceName)",
            "LOG_ANALYTICS_WORKSPACE_RESOURCE_ID=$($Context.WorkspaceResourceId)",
            "SENTINEL_ONBOARDING_STATE_RESOURCE_ID=$($Context.SentinelOnboardingStateResourceId)",
            "ZAVA_VM_NAME=$($Context.VmName)",
            "ZAVA_VM_RESOURCE_ID=$($Context.VmResourceId)",
            "ZAVA_NSG_NAME=$($Context.NsgName)",
            "ZAVA_NSG_RESOURCE_ID=$($Context.NsgResourceId)",
            "ZAVA_SECURITY_EVENTS_DCR=$($Context.SecurityEventsDcrName)",
            "ZAVA_SECURITY_EVENTS_DCR_ID=$($Context.SecurityEventsDcrId)",
            "ZAVA_SECURITY_EVENTS_DCR_NAME_HINT=$($Context.SecurityEventsDcrNameHint)",
            "ZAVA_SECURITY_EVENTS_DCR_ID_HINT=$($Context.SecurityEventsDcrIdHint)",
            "ZAVA_SECURITY_EVENTS_DCR_EXISTS=$($Context.SecurityEventsDcrExists)",
            "ZAVA_DATA_COLLECTION_ENDPOINT=$($Context.DataCollectionEndpointName)",
            "ZAVA_DATA_COLLECTION_ENDPOINT_ID=$($Context.DataCollectionEndpointResourceId)",
            "ZAVA_LOGIC_APP_NAME=$($Context.LogicAppName)",
            "ZAVA_LOGIC_APP_RESOURCE_ID=$($Context.LogicAppResourceId)",
            "ZAVA_LEARNER_LOGIC_APP_NAME_HINT=$($Context.LearnerLogicAppNameHint)",
            "ZAVA_AUTOMATION_RULE_NAME=$($Context.AutomationRuleName)",
            "ZAVA_AUTOMATION_RULE_DISPLAY_NAME=$($Context.AutomationRuleDisplayName)",
            "ZAVA_AUTOMATION_RULE_RESOURCE_ID=$($Context.AutomationRuleResourceId)",
            "ZAVA_WORKBOOK_NAME=$($Context.WorkbookName)",
            "ZAVA_WORKBOOK_RESOURCE_ID=$($Context.WorkbookResourceId)",
            "ZAVA_LEARNER_WORKBOOK_NAME_HINT=$($Context.LearnerWorkbookNameHint)",
            "ZAVA_PLAYBOOK_UAMI_NAME=$($Context.PlaybookUserAssignedIdentityName)",
            "ZAVA_PLAYBOOK_UAMI_RESOURCE_ID=$($Context.PlaybookUserAssignedIdentityResourceId)",
            "ZAVA_PLAYBOOK_UAMI_CLIENT_ID=$($Context.PlaybookUserAssignedIdentityClientId)",
            "ZAVA_PLAYBOOK_UAMI_PRINCIPAL_ID=$($Context.PlaybookUserAssignedIdentityPrincipalId)",
            "ZAVA_BENIGN_ACCOUNT=$($Context.BenignFalsePositiveAccount)",
            "ZAVA_BENIGN_SOURCE_IP=$($Context.BenignFalsePositiveSourceIp)"
        )
        $envLines | Set-Content -Path $envPath -Encoding ASCII

        $psLines = @()
        foreach ($key in $Context.Keys) {
            $safeValue = ([string]$Context[$key]).Replace("'", "''")
            $psLines += "`$$key = '$safeValue'"
        }
        $psLines | Set-Content -Path $psPath -Encoding UTF8

        Copy-Item -Path $jsonPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'zava-lab-config.json') -Force
        Copy-Item -Path $envPath -Destination (Join-Path 'C:\Users\Public\Desktop' '.env') -Force
        Copy-Item -Path $psPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'Zava-LabConfig.ps1') -Force
    }

    function Ensure-SentinelAnalyticsRule {
        param(
            [string]$ResourceGroupName,
            [string]$WorkspaceName,
            [string]$DisplayName,
            [string]$Severity,
            [string]$Query,
            [string[]]$Tactics,
            [string[]]$Techniques = @(),
            [hashtable]$CustomDetails = @{}
        )
        $ruleId = Get-DeterministicGuid -InputString "zava-sentinel-rule-$DeploymentID-$DisplayName"
        $uri = "https://management.azure.com/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules/$ruleId?api-version=2023-02-01-preview"
        $body = @{
            kind = 'Scheduled'
            properties = @{
                displayName = $DisplayName
                description = "Zava SOC lab seeded detection: $DisplayName"
                severity = $Severity
                enabled = $true
                query = $Query
                queryFrequency = 'PT5M'
                queryPeriod = 'PT12H'
                triggerOperator = 'GreaterThan'
                triggerThreshold = 0
                suppressionDuration = 'PT12H'
                suppressionEnabled = $true
                tactics = $Tactics
                techniques = $Techniques
                eventGroupingSettings = @{ aggregationKind = 'SingleAlert' }
                incidentConfiguration = @{ createIncident = $true; groupingConfiguration = @{ enabled = $true; reopenClosedIncident = $false; lookbackDuration = 'P1D'; matchingMethod = 'AnyAlert' } }
                customDetails = $CustomDetails
                entityMappings = @(
                    @{ entityType = 'Account'; fieldMappings = @(@{ identifier = 'FullName'; columnName = 'Account' }) },
                    @{ entityType = 'IP'; fieldMappings = @(@{ identifier = 'Address'; columnName = 'SourceIp' }) },
                    @{ entityType = 'Host'; fieldMappings = @(@{ identifier = 'HostName'; columnName = 'VmName' }) },
                    @{ entityType = 'AzureResource'; fieldMappings = @(@{ identifier = 'ResourceId'; columnName = 'ResourceId' }) }
                )
            }
        }
        # Sentinel validates the rule's KQL when the rule is created. These queries read
        # ZavaSOCSeed_CL, and a custom table stays unresolvable for several minutes after its first
        # ingestion, so a rule created too early fails validation. Retry rather than give up.
        Invoke-WithRetry -OperationName "create Sentinel analytics rule '$DisplayName'" -MaxAttempts 10 -DelaySeconds 60 -ScriptBlock {
            Invoke-AzRestJson -Method PUT -Uri $uri -Body $body | Out-Null
        } | Out-Null
    }

    function Wait-ForSeedTableQueryable {
        param([string]$WorkspaceCustomerId, [int]$MaxAttempts = 20, [int]$DelaySeconds = 45)
        # A _CL table does not exist until its first ingestion is committed, which commonly takes
        # five to fifteen minutes. Analytics rules that read it cannot be created before then.
        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            try {
                $probe = Invoke-AzRestJson -Method POST -Uri "https://api.loganalytics.io/v1/workspaces/$WorkspaceCustomerId/query" -Body @{ query = 'ZavaSOCSeed_CL | limit 1'; timespan = 'P1D' } -AllowFailure
                if ($probe -and $probe.tables) {
                    Write-Log "ZavaSOCSeed_CL is queryable after $attempt attempt(s)."
                    return $true
                }
            }
            catch { }
            Write-Log "Waiting for ZavaSOCSeed_CL to become queryable (attempt $attempt of $MaxAttempts)."
            Start-Sleep -Seconds $DelaySeconds
        }
        Write-Log 'WARNING: ZavaSOCSeed_CL did not become queryable within the bounded wait. Baseline analytics rule creation may fail validation.'
        return $false
    }

    function New-ZavaSeedRecords {
        param([string]$VmName, [string]$VmResourceId, [string]$NsgName)
        $benignAccount = 'svc-zava-audit@zavacorp.example'
        $benignSourceIp = '198.51.100.23'
        $truePositiveIp = '203.0.113.77'
        $seedStart = [DateTime]::UtcNow.AddHours(-10)
        $records = New-Object System.Collections.Generic.List[object]

        for ($i = 1; $i -le 12; $i++) {
            $records.Add([pscustomobject]@{
                TimeGenerated = $seedStart.AddMinutes($i * 11).ToString('o')
                SeedRunId = $DeploymentID
                ZavaCaseId = ('ZAVA-NOISE-POLICY-{0:000}' -f $i)
                RuleName = 'ZAVA-Noise-Repeated-Policy-Change'
                ScenarioType = 'RepeatedPolicyChange'
                IsTruePositive = $false
                ExpectedEntity = 'Azure Policy'
                NoiseGroup = 'PolicyChangeMaintenance'
                Account = "policy-admin-$($i % 3)@zavacorp.example"
                SourceIp = "198.51.100.$(40 + $i)"
                VmName = $VmName
                ResourceId = $VmResourceId
                NsgName = $NsgName
                OperationName = 'Microsoft.Authorization/policyAssignments/write'
                ResultType = 'Success'
                AlertSummary = 'Expected policy maintenance created repeated low-severity control-plane alerts.'
                BenignAccount = $benignAccount
                BenignSourceIp = $benignSourceIp
                MitreTactic = 'DefenseEvasion'
                SeverityHint = 'Low'
            })
        }
        for ($i = 1; $i -le 16; $i++) {
            $records.Add([pscustomobject]@{
                TimeGenerated = $seedStart.AddHours(1).AddMinutes($i * 7).ToString('o')
                SeedRunId = $DeploymentID
                ZavaCaseId = ('ZAVA-NOISE-ENUM-{0:000}' -f $i)
                RuleName = 'ZAVA-Noise-Administrative-Enumeration'
                ScenarioType = 'AdministrativeEnumeration'
                IsTruePositive = $false
                ExpectedEntity = $benignAccount
                NoiseGroup = 'BenignAuditEnumeration'
                Account = $benignAccount
                SourceIp = $benignSourceIp
                VmName = $VmName
                ResourceId = $VmResourceId
                NsgName = $NsgName
                OperationName = 'Microsoft.Resources/subscriptions/resourceGroups/read'
                ResultType = 'Success'
                AlertSummary = 'Known audit service account performed benign inventory enumeration.'
                BenignAccount = $benignAccount
                BenignSourceIp = $benignSourceIp
                MitreTactic = 'Discovery'
                SeverityHint = 'Medium'
            })
        }
        for ($i = 1; $i -le 10; $i++) {
            $records.Add([pscustomobject]@{
                TimeGenerated = $seedStart.AddHours(3).AddMinutes($i * 9).ToString('o')
                SeedRunId = $DeploymentID
                ZavaCaseId = ('ZAVA-NOISE-STORAGE-{0:000}' -f $i)
                RuleName = 'ZAVA-Noise-Failed-Storage-Access'
                ScenarioType = 'FailedStorageAccess'
                IsTruePositive = $false
                ExpectedEntity = 'build-agent@zavacorp.example'
                NoiseGroup = 'ExpiredBuildAgentToken'
                Account = 'build-agent@zavacorp.example'
                SourceIp = "198.51.100.$(80 + $i)"
                VmName = $VmName
                ResourceId = $VmResourceId
                NsgName = $NsgName
                OperationName = 'Microsoft.Storage/storageAccounts/listKeys/action'
                ResultType = 'Failure'
                AlertSummary = 'Expired build agent token caused expected failed storage access noise.'
                BenignAccount = $benignAccount
                BenignSourceIp = $benignSourceIp
                MitreTactic = 'CredentialAccess'
                SeverityHint = 'Low'
            })
        }
        $trueEvents = @(
            @{ Offset = 360; Case = 'ZAVA-TRUE-001'; Operation = 'Repeated failed VM logon attempts'; Summary = 'External source attempted repeated access to the lab VM.'; Tactic = 'InitialAccess' },
            @{ Offset = 372; Case = 'ZAVA-TRUE-002'; Operation = 'Microsoft.Network/networkSecurityGroups/securityRules/write'; Summary = 'Suspicious NSG rule change attempted after VM access failures.'; Tactic = 'DefenseEvasion' },
            @{ Offset = 384; Case = 'ZAVA-TRUE-003'; Operation = 'Microsoft.Compute/virtualMachines/runCommand/action'; Summary = 'Potential command execution activity observed on target VM.'; Tactic = 'Execution' }
        )
        foreach ($event in $trueEvents) {
            $records.Add([pscustomobject]@{
                TimeGenerated = $seedStart.AddMinutes([int]$event.Offset).ToString('o')
                SeedRunId = $DeploymentID
                ZavaCaseId = $event.Case
                RuleName = 'ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change'
                ScenarioType = 'SuspiciousVmAccessAndNsgChange'
                IsTruePositive = $true
                ExpectedEntity = $VmName
                NoiseGroup = 'HiddenTruePositive'
                Account = 'alex.mercer@zavacorp.example'
                SourceIp = $truePositiveIp
                VmName = $VmName
                ResourceId = $VmResourceId
                NsgName = $NsgName
                OperationName = $event.Operation
                ResultType = 'Success'
                AlertSummary = $event.Summary
                BenignAccount = $benignAccount
                BenignSourceIp = $benignSourceIp
                MitreTactic = $event.Tactic
                SeverityHint = 'High'
            })
        }
        return $records.ToArray()
    }

    function Ensure-SeededIncidents {
        param([string]$ResourceGroupName, [string]$WorkspaceName, [object[]]$Records, [string]$VmName, [string]$NsgName)
        Write-Log 'Creating deterministic Microsoft Sentinel seed incidents for immediate triage queue readiness. These direct incidents supplement, but do not replace, SecurityAlert evidence from scheduled analytics rules.'
        $caseGroups = $Records | Group-Object -Property RuleName
        foreach ($group in $caseGroups) {
            $ruleName = $group.Name
            $items = @($group.Group)
            $maxIncidents = switch ($ruleName) {
                'ZAVA-Noise-Repeated-Policy-Change' { 6 }
                'ZAVA-Noise-Administrative-Enumeration' { 8 }
                'ZAVA-Noise-Failed-Storage-Access' { 5 }
                'ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change' { 1 }
                default { 1 }
            }
            for ($i = 0; $i -lt [Math]::Min($items.Count, $maxIncidents); $i++) {
                $row = $items[$i]
                $incidentId = Get-DeterministicGuid -InputString "zava-seeded-incident-$DeploymentID-$ruleName-$i"
                $isTp = [bool]$row.IsTruePositive
                $severity = if ($isTp) { 'High' } elseif ($row.SeverityHint -eq 'Medium') { 'Medium' } else { 'Low' }
                $title = if ($isTp) { "$ruleName - hidden true positive affecting $VmName" } else { "$ruleName - seeded noise $($i + 1)" }
                $description = @"
Zava SOC seeded incident.
RuleName: $ruleName
ZavaCaseId: $($row.ZavaCaseId)
ScenarioType: $($row.ScenarioType)
IsTruePositive: $($row.IsTruePositive)
Account: $($row.Account)
SourceIp: $($row.SourceIp)
VM: $VmName
NSG: $NsgName
BenignAccount: $($row.BenignAccount)
BenignSourceIp: $($row.BenignSourceIp)
EvidenceHint: Query ZavaSOCSeed_CL, AzureActivity, SecurityIncident, SecurityAlert, and SecurityEvent.
"@
                $uri = "https://management.azure.com/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/incidents/$incidentId?api-version=2024-03-01"
                $body = @{
                    properties = @{
                        title = $title
                        description = $description
                        severity = $severity
                        status = 'New'
                        firstActivityTimeUtc = ([DateTime]$row.TimeGenerated).ToUniversalTime().ToString('o')
                        lastActivityTimeUtc = ([DateTime]$row.TimeGenerated).ToUniversalTime().AddMinutes(20).ToString('o')
                        labels = @(
                            @{ labelName = 'ZAVA-Seeded'; labelType = 'User' },
                            @{ labelName = $ruleName; labelType = 'User' },
                            @{ labelName = if ($isTp) { 'ZAVA-HiddenTruePositive' } else { 'ZAVA-Noise' }; labelType = 'User' }
                        )
                    }
                }
                Invoke-AzRestJson -Method PUT -Uri $uri -Body $body -AllowFailure | Out-Null
                $commentId = Get-DeterministicGuid -InputString "zava-seeded-comment-$DeploymentID-$ruleName-$i"
                $commentUri = "https://management.azure.com/subscriptions/$AzureSubscriptionID/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/incidents/$incidentId/comments/$commentId?api-version=2024-03-01"
                $commentText = if ($isTp) { 'Seed context: this incident is the hidden true positive. Correlate source IP 203.0.113.77, VM access failures, and NSG change evidence before containment.' } else { 'Seed context: likely noisy scenario. Administrative enumeration tuning must preserve detections except benign account svc-zava-audit@zavacorp.example and source IP 198.51.100.23.' }
                Invoke-AzRestJson -Method PUT -Uri $commentUri -Body @{ properties = @{ message = $commentText } } -AllowFailure | Out-Null
            }
        }
    }

    function Ensure-BaselineAnalyticsRules {
        param([string]$ResourceGroupName, [string]$WorkspaceName)
        Write-Log 'Ensuring baseline Microsoft Sentinel analytics rules exist and are enabled with a bounded recent seed window, SingleAlert event grouping, incident grouping, and rule suppression to avoid repeated seeded alerts.'
        $baseProjection = @'
| extend Account=tostring(Account_s), SourceIp=tostring(SourceIp_s), VmName=tostring(VmName_s), ResourceId=tostring(ResourceId_s), ZavaCaseId=tostring(ZavaCaseId_s), ScenarioType=tostring(ScenarioType_s), OperationName=tostring(OperationName_s), ResultType=tostring(ResultType_s), AlertSummary=tostring(AlertSummary_s), MitreTactic=tostring(MitreTactic_s), NoiseGroup=tostring(NoiseGroup_s), IsTruePositive=tobool(IsTruePositive_b)
| project TimeGenerated, Account, SourceIp, VmName, ResourceId, ZavaCaseId, ScenarioType, OperationName, ResultType, AlertSummary, MitreTactic, NoiseGroup, IsTruePositive
'@
        Ensure-SentinelAnalyticsRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -DisplayName 'ZAVA-Noise-Repeated-Policy-Change' -Severity 'Low' -Tactics @('DefenseEvasion') -Techniques @('T1484') -CustomDetails @{ ZavaCaseId='ZavaCaseId'; ScenarioType='ScenarioType'; NoiseGroup='NoiseGroup' } -Query @"
let ZavaSeedWindowStart = ago(12h);
let ZavaSeedWindowEnd = now();
ZavaSOCSeed_CL
| where TimeGenerated between (ZavaSeedWindowStart .. ZavaSeedWindowEnd)
| where tostring(SeedRunId_s) == '$DeploymentID'
| where RuleName_s == 'ZAVA-Noise-Repeated-Policy-Change'
$baseProjection
"@
        Ensure-SentinelAnalyticsRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -DisplayName 'ZAVA-Noise-Administrative-Enumeration' -Severity 'Medium' -Tactics @('Discovery') -Techniques @('T1087','T1082') -CustomDetails @{ ZavaCaseId='ZavaCaseId'; ScenarioType='ScenarioType'; BenignSource='SourceIp' } -Query @"
let ZavaSeedWindowStart = ago(12h);
let ZavaSeedWindowEnd = now();
ZavaSOCSeed_CL
| where TimeGenerated between (ZavaSeedWindowStart .. ZavaSeedWindowEnd)
| where tostring(SeedRunId_s) == '$DeploymentID'
| where RuleName_s == 'ZAVA-Noise-Administrative-Enumeration'
$baseProjection
"@
        Ensure-SentinelAnalyticsRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -DisplayName 'ZAVA-Noise-Failed-Storage-Access' -Severity 'Low' -Tactics @('CredentialAccess') -Techniques @('T1552') -CustomDetails @{ ZavaCaseId='ZavaCaseId'; ScenarioType='ScenarioType'; ResultType='ResultType' } -Query @"
let ZavaSeedWindowStart = ago(12h);
let ZavaSeedWindowEnd = now();
ZavaSOCSeed_CL
| where TimeGenerated between (ZavaSeedWindowStart .. ZavaSeedWindowEnd)
| where tostring(SeedRunId_s) == '$DeploymentID'
| where RuleName_s == 'ZAVA-Noise-Failed-Storage-Access'
$baseProjection
"@
        Ensure-SentinelAnalyticsRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -DisplayName 'ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change' -Severity 'High' -Tactics @('InitialAccess','Execution','DefenseEvasion') -Techniques @('T1110','T1059','T1562') -CustomDetails @{ ZavaCaseId='ZavaCaseId'; ScenarioType='ScenarioType'; OperationName='OperationName'; IsTruePositive='IsTruePositive' } -Query @"
let ZavaSeedWindowStart = ago(12h);
let ZavaSeedWindowEnd = now();
ZavaSOCSeed_CL
| where TimeGenerated between (ZavaSeedWindowStart .. ZavaSeedWindowEnd)
| where tostring(SeedRunId_s) == '$DeploymentID'
| where RuleName_s == 'ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change'
$baseProjection
"@
    }

    function Wait-ForBaselineSecurityAlertEvidence {
        param(
            [string]$WorkspaceCustomerId,
            [int]$MaxAttempts = 18,
            [int]$DelaySeconds = 60
        )
        $expectedRules = @(
            'ZAVA-Noise-Repeated-Policy-Change',
            'ZAVA-Noise-Administrative-Enumeration',
            'ZAVA-Noise-Failed-Storage-Access',
            'ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change'
        )
        $statusPath = Join-Path $global:SeedRoot 'baseline-securityalert-verification.json'
        $lastError = $null
        $lastRows = @()
        Write-Log 'Starting bounded post-seed verification for SecurityAlert evidence from baseline ZAVA scheduled analytics rules. Microsoft Learn documents that scheduled Sentinel analytics rules create SecurityAlert records and incidents when incident creation is enabled.'
        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            try {
                $query = @"
let expected = dynamic(['ZAVA-Noise-Repeated-Policy-Change','ZAVA-Noise-Administrative-Enumeration','ZAVA-Noise-Failed-Storage-Access','ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change']);
SecurityAlert
| where TimeGenerated > ago(30d)
| extend CandidateName = tostring(AlertName)
| where CandidateName in (expected)
| summarize AlertCount=count(), Latest=max(TimeGenerated) by BaselineRule=CandidateName
| order by BaselineRule asc
"@
                $response = Invoke-LogAnalyticsQuery -WorkspaceCustomerId $WorkspaceCustomerId -Query $query -Timespan 'P30D'
                $rows = @(Convert-LogAnalyticsTableToObjects -QueryResponse $response)
                $lastRows = $rows
                $seen = @{}
                foreach ($row in $rows) {
                    if ($row.BaselineRule) { $seen[[string]$row.BaselineRule] = [int]$row.AlertCount }
                }
                $missing = @($expectedRules | Where-Object { -not $seen.ContainsKey($_) -or $seen[$_] -lt 1 })
                $summary = if ($rows.Count -gt 0) { ($rows | ForEach-Object { "$($_.BaselineRule)=$($_.AlertCount)" }) -join '; ' } else { 'no matching SecurityAlert rows yet' }
                Write-Log "SecurityAlert verification attempt $attempt of ${MaxAttempts}: $summary. Missing: $($missing -join ', ')"
                if ($missing.Count -eq 0) {
                    $status = [ordered]@{
                        VerificationStatus = 'Succeeded'
                        VerifiedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
                        Attempts = $attempt
                        ExpectedRules = $expectedRules
                        MissingRules = @()
                        AlertCounts = $rows
                        Note = 'SecurityAlert evidence exists for every baseline ZAVA scheduled analytics rule.'
                    }
                    $status | ConvertTo-Json -Depth 10 | Set-Content -Path $statusPath -Encoding UTF8
                    Copy-Item -Path $statusPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'baseline-securityalert-verification.json') -Force
                    Write-Log 'Baseline SecurityAlert verification succeeded.'
                    return $true
                }
            }
            catch {
                $lastError = $_.Exception.Message
                Write-Log "SecurityAlert verification attempt $attempt of $MaxAttempts could not query Log Analytics yet: $lastError"
            }
            if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
        }
        $missingFinal = $expectedRules
        if ($lastRows.Count -gt 0) {
            $seenFinal = @{}
            foreach ($row in $lastRows) { if ($row.BaselineRule) { $seenFinal[[string]$row.BaselineRule] = [int]$row.AlertCount } }
            $missingFinal = @($expectedRules | Where-Object { -not $seenFinal.ContainsKey($_) -or $seenFinal[$_] -lt 1 })
        }
        $status = [ordered]@{
            VerificationStatus = 'PendingOrUnavailable'
            VerifiedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            Attempts = $MaxAttempts
            ExpectedRules = $expectedRules
            MissingRules = $missingFinal
            AlertCounts = $lastRows
            LastError = $lastError
            Note = 'Direct seeded incidents may still exist for queue readiness, but SecurityAlert evidence was not confirmed for every baseline scheduled analytics rule within the bounded CSE wait. Review analytics rule health, custom table ingestion latency, and SecurityAlert after scheduled rules run.'
        }
        $status | ConvertTo-Json -Depth 10 | Set-Content -Path $statusPath -Encoding UTF8
        Copy-Item -Path $statusPath -Destination (Join-Path 'C:\Users\Public\Desktop' 'baseline-securityalert-verification.json') -Force
        Write-Log "Baseline SecurityAlert verification did not complete within bounded wait. Missing: $($missingFinal -join ', '). Direct incidents will still be seeded for readiness, but validators and guides should rely on SecurityAlert only after this evidence appears. Status file: $statusPath"
        return $false
    }

    function Stage-HelperScripts {
        Write-Log 'Staging Zava SOC helper scripts under C:\LabFiles\Scripts and Public Desktop.'

        @'
Param(
    [int]$Attempts = 8,
    [string]$TargetUser = 'zava.failed.lab',
    [string]$BadPassword = 'NotTheRightPassword!234',
    [int]$DelaySeconds = 2
)
$ErrorActionPreference = 'Continue'
$signature = @"
using System;
using System.Runtime.InteropServices;
public class ZavaLogon {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
try { Add-Type -TypeDefinition $signature -ErrorAction SilentlyContinue } catch {}
Write-Host "Generating $Attempts benign failed Windows logon attempts for Sentinel SecurityEvent validation."
for ($i = 1; $i -le $Attempts; $i++) {
    $token = [IntPtr]::Zero
    $ok = [ZavaLogon]::LogonUser($TargetUser, $env:COMPUTERNAME, $BadPassword, 2, 0, [ref]$token)
    if ($ok -and $token -ne [IntPtr]::Zero) { [ZavaLogon]::CloseHandle($token) | Out-Null }
    Write-Host "Attempt $i complete. Expected local audit event: Security 4625."
    Start-Sleep -Seconds $DelaySeconds
}
Write-EventLog -LogName Application -Source 'Windows PowerShell' -EventId 4100 -EntryType Information -Message 'ZAVA endpoint signal helper generated benign failed logon attempts for Challenge 1.' -ErrorAction SilentlyContinue
Write-Host 'Done. Allow normal Azure Monitor Agent ingestion latency before querying SecurityEvent.'
'@ | Set-Content -Path (Join-Path $global:ScriptRoot 'Generate-ZavaEndpointSignals.ps1') -Encoding UTF8

        @'
Param([string]$Scenario = 'ManualContainmentBaseline')
$path = 'C:\LabFiles\zava-containment-timer.json'
$state = [ordered]@{
    Scenario = $Scenario
    StartTimeUtc = (Get-Date).ToUniversalTime().ToString('o')
    StopTimeUtc = $null
    ElapsedSeconds = $null
}
$state | ConvertTo-Json | Set-Content -Path $path -Encoding UTF8
Write-Host "Started Zava containment timer at $($state.StartTimeUtc). State: $path"
'@ | Set-Content -Path (Join-Path $global:ScriptRoot 'Start-ZavaManualContainmentTimer.ps1') -Encoding UTF8

        @'
$path = 'C:\LabFiles\zava-containment-timer.json'
if (-not (Test-Path $path)) { throw "Timer state file not found: $path. Run Start-ZavaManualContainmentTimer.ps1 first." }
$state = Get-Content -Path $path -Raw | ConvertFrom-Json
$stop = (Get-Date).ToUniversalTime()
$start = [DateTime]::Parse($state.StartTimeUtc).ToUniversalTime()
$state.StopTimeUtc = $stop.ToString('o')
$state.ElapsedSeconds = [int]($stop - $start).TotalSeconds
$state | ConvertTo-Json | Set-Content -Path $path -Encoding UTF8
Write-Host "Stopped Zava containment timer at $($state.StopTimeUtc). Elapsed seconds: $($state.ElapsedSeconds)."
'@ | Set-Content -Path (Join-Path $global:ScriptRoot 'Stop-ZavaManualContainmentTimer.ps1') -Encoding UTF8

        @'
Param(
    [string]$ResourceGroupName,
    [string]$NsgName,
    [string]$RuleName = 'Deny-Inbound-Zava-Quarantine'
)
$ErrorActionPreference = 'Stop'
$configPath = 'C:\LabFiles\zava-lab-config.json'
if ((-not $ResourceGroupName -or -not $NsgName) -and (Test-Path $configPath)) {
    $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    if (-not $ResourceGroupName) { $ResourceGroupName = $config.ResourceGroupName }
    if (-not $NsgName) { $NsgName = $config.NsgName }
}
if (-not $ResourceGroupName -or -not $NsgName) { throw 'ResourceGroupName and NsgName are required or must be available in C:\LabFiles\zava-lab-config.json.' }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI is required for reset. Open a new PowerShell session if Azure CLI was just installed.' }
$acct = az account show -o json 2>$null | ConvertFrom-Json
if (-not $acct) { throw 'Azure CLI is not signed in. Run az login with your lab credentials, then retry.' }
Write-Host "Removing NSG containment rule '$RuleName' from NSG '$NsgName' in resource group '$ResourceGroupName' if present."
az network nsg rule delete --resource-group $ResourceGroupName --nsg-name $NsgName --name $RuleName --only-show-errors 2>$null
Write-Host 'Containment reset completed. If the rule did not exist, no change was made.'
'@ | Set-Content -Path (Join-Path $global:ScriptRoot 'Reset-ZavaNSGContainment.ps1') -Encoding UTF8

        $desktop = 'C:\Users\Public\Desktop'
        foreach ($scriptName in @('Generate-ZavaEndpointSignals.ps1','Start-ZavaManualContainmentTimer.ps1','Stop-ZavaManualContainmentTimer.ps1','Reset-ZavaNSGContainment.ps1')) {
            Copy-Item -Path (Join-Path $global:ScriptRoot $scriptName) -Destination (Join-Path $desktop $scriptName) -Force
        }
    }

    function Generate-ControlPlaneActivity {
        param([string]$ResourceGroupName, [string]$NsgName)
        Write-Log 'Generating benign Azure control-plane activity for baseline AzureActivity evidence.'
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddHHmmss')
        Invoke-AzCli -Arguments @('group','update','--name',$ResourceGroupName,'--set',"tags.zavaSeedLastRun=$stamp",'--only-show-errors','-o','none') -AllowFailure | Out-Null
        if ($NsgName) {
            Invoke-AzCli -Arguments @('network','nsg','rule','create','--resource-group',$ResourceGroupName,'--nsg-name',$NsgName,'--name','Allow-Zava-Seed-Heartbeat','--priority','4090','--direction','Inbound','--access','Allow','--protocol','Tcp','--source-address-prefixes','AzureCloud','--source-port-ranges','*','--destination-address-prefixes','*','--destination-port-ranges','65000','--description','Temporary benign seed heartbeat rule for AzureActivity evidence.','--only-show-errors','-o','none') -AllowFailure | Out-Null
            Invoke-AzCli -Arguments @('network','nsg','rule','delete','--resource-group',$ResourceGroupName,'--nsg-name',$NsgName,'--name','Allow-Zava-Seed-Heartbeat','--only-show-errors','-o','none') -AllowFailure | Out-Null
        }
    }

    CreateCredFile
    Ensure-TrainerLocalAccount
    Ensure-AzureCli
    Connect-CloudLabsAzure

    $metadata = Get-InstanceMetadata
    $resourceGroupName = if ($metadata -and $metadata.resourceGroupName) { $metadata.resourceGroupName } else { Invoke-AzCli -Arguments @('group','list','--query',"[?contains(name, '$DeploymentID')].name | [0]",'-o','tsv') }
    if ([string]::IsNullOrWhiteSpace($resourceGroupName)) { throw 'Unable to determine lab resource group name.' }
    $location = if ($metadata -and $metadata.location) { $metadata.location } else { Invoke-AzCli -Arguments @('group','show','--name',$resourceGroupName,'--query','location','-o','tsv') }
    $vmName = if ($metadata -and $metadata.name) { $metadata.name } else { (Get-AzResourceByPrefix -ResourceGroupName $resourceGroupName -ResourceType 'Microsoft.Compute/virtualMachines' -Prefix 'vm-zava-soc-').name }
    $vmResourceId = "/subscriptions/$AzureSubscriptionID/resourceGroups/$resourceGroupName/providers/Microsoft.Compute/virtualMachines/$vmName"

    $workspaceResource = Invoke-WithRetry -OperationName 'discover Log Analytics workspace' -MaxAttempts 10 -DelaySeconds 30 -ScriptBlock { Get-AzResourceByPrefix -ResourceGroupName $resourceGroupName -ResourceType 'Microsoft.OperationalInsights/workspaces' -Prefix 'law-zava-soc-' }
    if (-not $workspaceResource) { throw "Unable to find Log Analytics workspace with prefix law-zava-soc in $resourceGroupName." }
    $workspaceName = $workspaceResource.name
    $workspaceId = Invoke-AzCli -Arguments @('monitor','log-analytics','workspace','show','--resource-group',$resourceGroupName,'--workspace-name',$workspaceName,'--query','customerId','-o','tsv')
    $workspaceResourceId = $workspaceResource.id

    $context = Resolve-ZavaResourceContext -ResourceGroupName $resourceGroupName -Location $location -VmName $vmName -VmResourceId $vmResourceId -WorkspaceName $workspaceName -WorkspaceResourceId $workspaceResourceId

    Ensure-SentinelEnabled -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -Location $location
    Test-SentinelPlaybookAutomationContributorAssignment -ResourceGroupName $resourceGroupName | Out-Null
    PreStage-AmaWithoutLearnerDcrCreation -ResourceGroupName $resourceGroupName -VmName $vmName -DcrName $context.SecurityEventsDcrName -DcrResourceId $context.SecurityEventsDcrId

    $context = Resolve-ZavaResourceContext -ResourceGroupName $resourceGroupName -Location $location -VmName $vmName -VmResourceId $vmResourceId -WorkspaceName $workspaceName -WorkspaceResourceId $workspaceResourceId
    Write-ZavaLabConfiguration -Context $context
    Stage-HelperScripts
    Generate-ControlPlaneActivity -ResourceGroupName $resourceGroupName -NsgName $context.NsgName

    $markerPath = Join-Path $global:SeedRoot 'zava-seed-state.json'
    $shouldSeed = $true
    if (Test-Path $markerPath) {
        try {
            $marker = Get-Content -Path $markerPath -Raw | ConvertFrom-Json
            $lastSeedUtc = [DateTime]::Parse($marker.SeededAtUtc).ToUniversalTime()
            if (((Get-Date).ToUniversalTime() - $lastSeedUtc).TotalHours -lt 36) { $shouldSeed = $false }
        }
        catch { $shouldSeed = $true }
    }

    $records = New-ZavaSeedRecords -VmName $vmName -VmResourceId $vmResourceId -NsgName $context.NsgName
    if ($shouldSeed) {
        # Seeding is what fills the incident queue, but it must never destroy the environment.
        # A learner can be given a thin queue and a clear status file; they cannot be given a VM
        # that failed to provision. Note the ingestion API this uses is retired from 2026-09-14.
        try {
            Write-Log "Seeding $($records.Count) records into ZavaSOCSeed_CL."
            $workspaceKey = Get-WorkspaceSharedKey -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName
            Send-LogAnalyticsDataCollectorRecords -WorkspaceId $workspaceId -WorkspaceKey $workspaceKey -LogType 'ZavaSOCSeed' -Records $records
            @{ SeededAtUtc = (Get-Date).ToUniversalTime().ToString('o'); DeploymentID = $DeploymentID; RecordCount = $records.Count; BenignAccount = 'svc-zava-audit@zavacorp.example'; BenignSourceIp = '198.51.100.23' } | ConvertTo-Json | Set-Content -Path $markerPath -Encoding UTF8
        }
        catch {
            Write-Log "WARNING: Seed ingestion did not complete: $($_.Exception.Message)"
            @{ Status = 'SeedIngestionFailed'; Error = $_.Exception.Message; AtUtc = (Get-Date).ToUniversalTime().ToString('o') } |
                ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $global:SeedRoot 'seed-ingestion-status.json') -Encoding UTF8
        }
    }
    else { Write-Log 'Recent seed marker found. Skipping duplicate custom log ingestion while still ensuring baseline analytics rules and readiness incidents.' }

    Wait-ForSeedTableQueryable -WorkspaceCustomerId $workspaceId | Out-Null
    try {
        Ensure-BaselineAnalyticsRules -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName
    }
    catch {
        # Incidents are also seeded directly below, so a rule that will not create is a degraded
        # lab rather than a dead environment. Record it loudly instead of failing the deployment.
        Write-Log "WARNING: Baseline analytics rule creation did not complete: $($_.Exception.Message)"
        @{ Status = 'BaselineRulesIncomplete'; Error = $_.Exception.Message; AtUtc = (Get-Date).ToUniversalTime().ToString('o') } |
            ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $global:SeedRoot 'baseline-rules-status.json') -Encoding UTF8
    }
    $securityAlertVerified = Wait-ForBaselineSecurityAlertEvidence -WorkspaceCustomerId $workspaceId -MaxAttempts 18 -DelaySeconds 60
    Ensure-SeededIncidents -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -Records $records -VmName $vmName -NsgName $context.NsgName

    if ($securityAlertVerified) {
        Write-Log 'Zava SOC Stage 1 bootstrap completed with confirmed SecurityAlert evidence for all baseline ZAVA scheduled analytics rules.'
    }
    else {
        Write-Log 'Zava SOC Stage 1 bootstrap completed with direct incident readiness, but SecurityAlert evidence was pending or unavailable within the bounded wait. See C:\LabFiles\Seed\baseline-securityalert-verification.json.'
    }
}
catch {
    Write-Error "CloudLabs Custom Script Extension failed: $($_.Exception.Message)"
    throw
}
finally {
    Stop-Transcript | Out-Null
}
