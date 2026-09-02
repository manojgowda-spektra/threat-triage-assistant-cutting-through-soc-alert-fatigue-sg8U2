using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
$rg = "rg-zava-soc-$DID"
$count = 0
$found = $false
$lastFailure = "Challenge 4 tuning and reporting validation has not run."

# CloudLabs coherence metadata:
# - DeployedPrerequisite: the deployment provides the Log Analytics workspace (resource type Microsoft.OperationalInsights/workspaces, name pattern law-zava-soc-*) and the lab NSG foundation (resource type Microsoft.Network/networkSecurityGroups, name pattern nsg-zava-workload-*). These are baseline infrastructure, not learner-created reporting artifacts.
# - LearnerRuntimeEndState: the learner creates the reporting workbook during Challenge 4. The workbook is an Azure Monitor workbook resource (resource type Microsoft.Insights/workbooks) with visible displayName pattern wb-zava-triage-report-* and must reference the Sentinel workspace through sourceId or serializedData.
# - RuntimeEvidence: Microsoft Sentinel analytics rules are workspace-scoped SecurityInsights alertRules checked through the SecurityInsights extension API. The tuned rule, true-positive rule, and learner failed-logon rule are runtime validation evidence, not deployed workbook prerequisites.
# - OperationEvidence: AzureActivity is queried for the operation name Microsoft.Network/networkSecurityGroups/securityRules/write associated with Deny-Inbound-Zava-Quarantine. This is observed as control-plane activity in logs, not treated as a resource type.

function Get-ArmCollection {
    param([Parameter(Mandatory = $true)][string]$Path)

    $items = @()
    $next = $Path
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        if ($next -match '^https://') {
            $response = Invoke-AzRestMethod -Method GET -Uri $next -ErrorAction Stop
        }
        else {
            $response = Invoke-AzRestMethod -Method GET -Path $next -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($response.Content)) { break }
        $payload = $response.Content | ConvertFrom-Json -Depth 100
        if ($null -ne $payload.value) { $items += @($payload.value) } elseif ($null -ne $payload) { $items += @($payload) }
        $next = $payload.nextLink
    }
    return @($items)
}

function Get-ArmResourceById {
    param(
        [Parameter(Mandatory = $true)][string]$ResourceId,
        [Parameter(Mandatory = $true)][string]$ApiVersion
    )

    $response = Invoke-AzRestMethod -Method GET -Path "$ResourceId?api-version=$ApiVersion" -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($response.Content)) { return $null }
    return ($response.Content | ConvertFrom-Json -Depth 100)
}

function Get-QueryRows {
    param($QueryResult)

    if ($null -eq $QueryResult -or $null -eq $QueryResult.Results) { return @() }
    if ($QueryResult.Results -is [System.Data.DataTable]) {
        $rows = @()
        foreach ($row in $QueryResult.Results.Rows) {
            $obj = [ordered]@{}
            foreach ($col in $QueryResult.Results.Columns) { $obj[$col.ColumnName] = $row[$col.ColumnName] }
            $rows += [pscustomobject]$obj
        }
        return @($rows)
    }
    return @($QueryResult.Results)
}

function Test-ExactExclusion {
    param(
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][string]$Literal
    )

    $escapedLiteral = [regex]::Escape($Literal)
    $queryWithoutFullLineComments = (($Query -split "`r?`n") | Where-Object { $_ -notmatch '^\s*//' }) -join "`n"
    if ($queryWithoutFullLineComments -notmatch $escapedLiteral) { return $false }

    $linesWithLiteral = @($queryWithoutFullLineComments -split "`r?`n" | Where-Object { $_ -match $escapedLiteral })
    foreach ($line in $linesWithLiteral) {
        if ($line -match "(?i)(!=|!~|!in\b|\bnot\s+in\b)[^`r`n|;]{0,250}['\"]$escapedLiteral['\"]") { return $true }
        if ($line -match "(?i)['\"]$escapedLiteral['\"][^`r`n|;]{0,250}(\bnot\s+in\b|!in\b)") { return $true }
    }

    $compactQuery = ($queryWithoutFullLineComments -replace '\s+', ' ')
    if ($compactQuery -match "(?i)\bnot\s*\([^\)]{0,500}(==|=~|\bin\s*\()[^\)]{0,250}['\"]$escapedLiteral['\"][^\)]{0,500}\)") { return $true }
    return $false
}

function Get-RuleByDisplayName {
    param(
        [Parameter(Mandatory = $true)]$Rules,
        [Parameter(Mandatory = $true)][string]$DisplayName
    )

    $matches = @($Rules | Where-Object { $_.properties.displayName -ceq $DisplayName })
    if ($matches.Count -ne 1) { return $null }
    return $matches[0]
}

function Test-RuleEnabled {
    param($Rule)
    if ($null -eq $Rule -or $null -eq $Rule.properties) { return $false }
    return ([bool]$Rule.properties.enabled -eq $true)
}

function Invoke-WorkspaceQueryRows {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspaceCustomerId,
        [Parameter(Mandatory = $true)][string]$Query
    )

    $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceCustomerId -Query $Query -ErrorAction Stop
    return @(Get-QueryRows -QueryResult $result)
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        # Deployed infrastructure: locate the lab Log Analytics workspace that hosts Microsoft Sentinel and all observable KQL evidence.
        $workspaceResources = @(Get-AzResource -ResourceType "Microsoft.OperationalInsights/workspaces" -ErrorAction Stop | Where-Object { $_.Name -like "law-zava-soc-*" })
        if ($workspaceResources.Count -eq 0) { throw "No Log Analytics workspace matching 'law-zava-soc-*' was found in subscription '$sub'." }

        $preferredWorkspace = @($workspaceResources | Where-Object { $_.ResourceGroupName -like "*$DID*" } | Select-Object -First 1)
        if ($preferredWorkspace.Count -gt 0) { $workspaceResource = $preferredWorkspace[0] } else { $workspaceResource = @($workspaceResources | Sort-Object ResourceGroupName, Name | Select-Object -First 1)[0] }
        $rg = $workspaceResource.ResourceGroupName
        $workspaceName = $workspaceResource.Name
        $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $workspaceName -ErrorAction Stop
        $workspaceCustomerId = [string]$workspace.CustomerId
        $workspaceResourceId = $workspace.ResourceId
        if ([string]::IsNullOrWhiteSpace($workspaceCustomerId) -or [string]::IsNullOrWhiteSpace($workspaceResourceId)) { throw "Workspace '$workspaceName' in RG '$rg' was found, but its customer ID or resource ID was empty." }

        # Deployed infrastructure: confirm the lab NSG foundation exists. The quarantine write is validated later from AzureActivity as an operation, not as a prerequisite resource type.
        $nsgResources = @(Get-AzResource -ResourceGroupName $rg -ResourceType "Microsoft.Network/networkSecurityGroups" -ErrorAction Stop | Where-Object { $_.Name -like "nsg-zava-workload-*" })
        if ($nsgResources.Count -eq 0) { throw "No lab NSG foundation resource matching 'nsg-zava-workload-*' was found in RG '$rg'." }

        $sentinelBasePath = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights"
        # Control-plane evidence: Microsoft.SecurityInsights/alertRules@2023-02-01 exposes displayName, enabled, and query for scheduled Sentinel analytics rules.
        $alertRules = @(Get-ArmCollection -Path "$sentinelBasePath/alertRules?api-version=2023-02-01")
        if ($alertRules.Count -eq 0) { throw "No Microsoft Sentinel analytics rules were returned for workspace '$workspaceName'." }

        $noiseRuleName = "ZAVA-Noise-Administrative-Enumeration"
        $truePositiveRuleName = "ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change"
        $failedLogonRuleName = "ZAVA-Learner-Failed-VM-Logons"
        $benignAccount = "svc-zava-audit@zavacorp.example"
        $benignIp = "198.51.100.23"

        $noiseRule = Get-RuleByDisplayName -Rules $alertRules -DisplayName $noiseRuleName
        $truePositiveRule = Get-RuleByDisplayName -Rules $alertRules -DisplayName $truePositiveRuleName
        $failedLogonRule = Get-RuleByDisplayName -Rules $alertRules -DisplayName $failedLogonRuleName

        if ($null -eq $noiseRule) { throw "Exact Sentinel analytics rule displayName '$noiseRuleName' was not found exactly once; equivalent names are not accepted." }
        if (-not (Test-RuleEnabled -Rule $noiseRule)) { throw "Analytics rule '$noiseRuleName' is disabled. The noisy rule must be tuned, not disabled." }
        if (-not (Test-RuleEnabled -Rule $truePositiveRule)) { throw "Required true-positive analytics rule '$truePositiveRuleName' is missing or disabled." }
        if (-not (Test-RuleEnabled -Rule $failedLogonRule)) { throw "Required learner failed-logon analytics rule '$failedLogonRuleName' is missing or disabled." }

        $noiseQuery = [string]$noiseRule.properties.query
        if ([string]::IsNullOrWhiteSpace($noiseQuery)) { throw "Analytics rule '$noiseRuleName' has an empty active query." }
        if (-not (Test-ExactExclusion -Query $noiseQuery -Literal $benignAccount) -or -not (Test-ExactExclusion -Query $noiseQuery -Literal $benignIp)) {
            throw "Analytics rule '$noiseRuleName' is enabled, but its active query does not contain exact negative exclusions for both '$benignAccount' and '$benignIp'."
        }

        $modifiedAt = $noiseRule.systemData.lastModifiedAt
        if ([string]::IsNullOrWhiteSpace([string]$modifiedAt)) { $modifiedAt = $noiseRule.properties.lastModifiedUtc }
        if ([string]::IsNullOrWhiteSpace([string]$modifiedAt)) { $modifiedAt = (Get-Date).ToUniversalTime().AddHours(-1).ToString("o") }
        $tuneTimeIso = ([datetime]$modifiedAt).ToUniversalTime().ToString("o")

        $falsePositiveReductionQuery = @"
let TuneTime = datetime($tuneTimeIso);
let BenignAccount = '$benignAccount';
let BenignIp = '$benignIp';
let AlertIncidentEvidence = union isfuzzy=true
(
    SecurityAlert
    | where TimeGenerated > ago(21d)
    | extend RuleName = tostring(column_ifexists('AlertName', column_ifexists('DisplayName', '')))
    | where RuleName == '$noiseRuleName'
    | extend EvidenceText = strcat(tostring(column_ifexists('Entities', '')), ' ', tostring(column_ifexists('ExtendedProperties', '')), ' ', tostring(column_ifexists('Description', '')), ' ', tostring(column_ifexists('AlertLink', '')))
    | where EvidenceText has BenignAccount and EvidenceText has BenignIp
    | project TimeGenerated, Source='AlertOrIncident'
),
(
    SecurityIncident
    | where TimeGenerated > ago(21d)
    | extend IncidentText = strcat(tostring(column_ifexists('Title', '')), ' ', tostring(column_ifexists('AdditionalData', '')), ' ', tostring(column_ifexists('Labels', '')), ' ', tostring(column_ifexists('AlertIds', '')))
    | where IncidentText has '$noiseRuleName' and IncidentText has BenignAccount and IncidentText has BenignIp
    | project TimeGenerated, Source='AlertOrIncident'
);
let SeedEvidence = union isfuzzy=true
(
    ZavaSOCSeed_CL
    | where TimeGenerated > ago(21d)
    | extend SeedText = strcat(tostring(column_ifexists('BenignAccount_s', '')), ' ', tostring(column_ifexists('BenignSourceIp_s', '')), ' ', tostring(column_ifexists('Account_s', '')), ' ', tostring(column_ifexists('SourceIp_s', '')), ' ', tostring(column_ifexists('AlertRuleName_s', '')), ' ', tostring(column_ifexists('ScenarioType_s', '')), ' ', tostring(column_ifexists('NoiseGroup_s', '')))
    | where SeedText has BenignAccount and SeedText has BenignIp
    | project TimeGenerated, Source='Seed'
);
AlertIncidentEvidence
| summarize BeforeAlertsOrIncidents=countif(TimeGenerated < TuneTime), AfterAlertsOrIncidents=countif(TimeGenerated >= TuneTime)
| extend SeedBefore = toscalar(SeedEvidence | summarize countif(TimeGenerated < TuneTime)), SeedTotal = toscalar(SeedEvidence | summarize count())
"@
        $fpRows = @(Invoke-WorkspaceQueryRows -WorkspaceCustomerId $workspaceCustomerId -Query $falsePositiveReductionQuery)
        if ($fpRows.Count -eq 0) { throw "False-positive measurement query returned no summary row for '$noiseRuleName'." }
        $beforeCount = [int]$fpRows[0].BeforeAlertsOrIncidents
        $afterCount = [int]$fpRows[0].AfterAlertsOrIncidents
        $seedBeforeCount = [int]$fpRows[0].SeedBefore
        $seedTotalCount = [int]$fpRows[0].SeedTotal
        if (($beforeCount + $seedBeforeCount + $seedTotalCount) -le 0) {
            throw "No before-side false-positive seed, alert, or incident evidence was found for '$noiseRuleName' tied to '$benignAccount' and '$benignIp'. BeforeAlertsOrIncidents=$beforeCount; SeedBefore=$seedBeforeCount; SeedTotal=$seedTotalCount; TuneTime=$tuneTimeIso."
        }

        $reductionEvidence = if ($beforeCount -gt 0 -and $afterCount -lt $beforeCount) { "observed alert/incident reduction" } elseif ($afterCount -eq 0) { "no post-tune benign alerts/incidents observed" } else { "supporting counts captured; no hard failure because active exclusions are correct" }

        $truePositiveEvidenceQuery = @"
union isfuzzy=true
(
    SecurityAlert
    | where TimeGenerated > ago(21d)
    | extend RuleName = tostring(column_ifexists('AlertName', column_ifexists('DisplayName', '')))
    | where RuleName == '$truePositiveRuleName'
    | project Evidence = 'SecurityAlert', TimeGenerated
),
(
    ZavaSOCSeed_CL
    | where TimeGenerated > ago(21d)
    | extend SeedText = strcat(tostring(column_ifexists('IsTruePositive_s', '')), ' ', tostring(column_ifexists('IsTruePositive', '')), ' ', tostring(column_ifexists('AlertRuleName_s', '')), ' ', tostring(column_ifexists('ZavaCaseId_s', '')), ' ', tostring(column_ifexists('ScenarioType_s', '')))
    | where SeedText has 'true' or SeedText has '$truePositiveRuleName'
    | project Evidence = 'ZavaSOCSeed_CL', TimeGenerated
)
| summarize EvidenceRows=count(), Latest=max(TimeGenerated)
"@
        $tpRows = @(Invoke-WorkspaceQueryRows -WorkspaceCustomerId $workspaceCustomerId -Query $truePositiveEvidenceQuery)
        if ($tpRows.Count -eq 0 -or [int]$tpRows[0].EvidenceRows -le 0) { throw "True-positive detection '$truePositiveRuleName' is enabled but produced no observable true-positive evidence in SecurityAlert or ZavaSOCSeed_CL." }
        $truePositiveEvidenceRows = [int]$tpRows[0].EvidenceRows

        $failedLogonEvidenceQuery = @"
union isfuzzy=true
(
    SecurityAlert
    | where TimeGenerated > ago(7d)
    | extend RuleName = tostring(column_ifexists('AlertName', column_ifexists('DisplayName', '')))
    | where RuleName == '$failedLogonRuleName'
    | project Evidence = 'SecurityAlert', TimeGenerated
),
(
    SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4625 and Computer has 'vm-zava-soc'
    | project Evidence = 'SecurityEvent', TimeGenerated
)
| summarize EvidenceRows=count(), Latest=max(TimeGenerated)
"@
        $failedRows = @(Invoke-WorkspaceQueryRows -WorkspaceCustomerId $workspaceCustomerId -Query $failedLogonEvidenceQuery)
        if ($failedRows.Count -eq 0 -or [int]$failedRows[0].EvidenceRows -le 0) { throw "Failed-logon detection '$failedLogonRuleName' is enabled but no SecurityAlert or SecurityEvent 4625 evidence was found." }
        $failedLogonEvidenceRows = [int]$failedRows[0].EvidenceRows

        $incidents = @(Get-ArmCollection -Path "$sentinelBasePath/incidents?api-version=2023-02-01")
        if ($incidents.Count -eq 0) { throw "No Microsoft Sentinel incidents were returned from workspace '$workspaceName'." }

        $commentMarker = "Challenge4-TunedFalsePositive"
        $commentFound = $false
        $commentIncidentTitle = $null
        $candidateIncidents = @($incidents | Where-Object { ([string]$_.properties.title -like "*$noiseRuleName*") -or ([string]$_.properties.additionalData -like "*$noiseRuleName*") })
        if ($candidateIncidents.Count -eq 0) { $candidateIncidents = @($incidents) }
        foreach ($incident in $candidateIncidents) {
            $incidentName = [string]$incident.name
            if ([string]::IsNullOrWhiteSpace($incidentName)) { continue }
            $comments = @(Get-ArmCollection -Path "$sentinelBasePath/incidents/$incidentName/comments?api-version=2023-02-01")
            foreach ($comment in $comments) {
                if ([string]$comment.properties.message -cmatch [regex]::Escape($commentMarker)) {
                    $commentFound = $true
                    $commentIncidentTitle = [string]$incident.properties.title
                    break
                }
            }
            if ($commentFound) { break }
        }
        if (-not $commentFound) { throw "No Microsoft Sentinel incident comment containing exact marker '$commentMarker' was found on the tuned-noise representative incident set." }

        # Learner-created reporting end-state: Microsoft.Insights/workbooks@2023-06-01 exposes displayName, serializedData, and sourceId. The visible workbook display name must start with wb-zava-triage-report-; the ARM resource name can be a generated GUID/name.
        $workbookResources = @(Get-AzResource -ResourceGroupName $rg -ResourceType "Microsoft.Insights/workbooks" -ErrorAction Stop)
        if ($workbookResources.Count -eq 0) { throw "No Microsoft.Insights/workbooks resources were found in RG '$rg'." }
        $matchingWorkbook = $null
        foreach ($workbookResource in $workbookResources) {
            $workbookDetails = Get-ArmResourceById -ResourceId $workbookResource.ResourceId -ApiVersion "2023-06-01"
            if ($null -eq $workbookDetails -or $null -eq $workbookDetails.properties) { continue }
            $wbDisplayName = [string]$workbookDetails.properties.displayName
            if ($wbDisplayName -like "wb-zava-triage-report-*") {
                $serializedData = [string]$workbookDetails.properties.serializedData
                $sourceId = [string]$workbookDetails.properties.sourceId
                $workspaceRefFound = $false
                if (-not [string]::IsNullOrWhiteSpace($sourceId) -and ($sourceId -ieq $workspaceResourceId)) { $workspaceRefFound = $true }
                if (-not $workspaceRefFound -and -not [string]::IsNullOrWhiteSpace($serializedData)) {
                    $workspaceRefFound = ($serializedData.IndexOf($workspaceResourceId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or ($serializedData.IndexOf($workspaceCustomerId, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or ($serializedData.IndexOf($workspaceName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
                }
                if ($workspaceRefFound) { $matchingWorkbook = $workbookDetails; break }
            }
        }
        if ($null -eq $matchingWorkbook) { throw "No Microsoft.Insights/workbooks resource in RG '$rg' has visible displayName starting with 'wb-zava-triage-report-' and a sourceId or serializedData reference to workspace '$workspaceName'. The ARM resource name may be generated, but the visible workbook display name must use the required prefix." }

        # Learner-created containment timing evidence: AzureActivity records the Microsoft.Network/networkSecurityGroups/securityRules/write control-plane operation for the quarantine rule.
        $timingEvidenceQuery = @"
let LatestIncidentCreated = toscalar(
    SecurityIncident
    | where TimeGenerated > ago(14d)
    | extend IncidentText = strcat(tostring(column_ifexists('Title', '')), ' ', tostring(column_ifexists('AdditionalData', '')), ' ', tostring(column_ifexists('AlertIds', '')))
    | where IncidentText has '$failedLogonRuleName'
    | summarize max(todatetime(column_ifexists('CreatedTime', TimeGenerated)))
);
let LatestNsgChange = toscalar(
    AzureActivity
    | where TimeGenerated > ago(14d)
    | extend OperationValue = tostring(column_ifexists('OperationNameValue', column_ifexists('OperationName', '')))
    | extend StatusValue = tostring(column_ifexists('ActivityStatusValue', column_ifexists('ActivityStatus', '')))
    | extend ResourceText = strcat(tostring(column_ifexists('_ResourceId', '')), ' ', tostring(column_ifexists('Resource', '')), ' ', tostring(column_ifexists('Properties_d', '')), ' ', tostring(column_ifexists('Properties', '')))
    | where tolower(OperationValue) has 'microsoft.network/networksecuritygroups/securityrules/write' or tolower(OperationValue) has 'securityrules/write' or OperationValue has 'security rule'
    | where isempty(StatusValue) or StatusValue in~ ('Success', 'Succeeded')
    | where ResourceText has 'Deny-Inbound-Zava-Quarantine'
    | summarize max(TimeGenerated)
);
print LatestIncidentCreated = LatestIncidentCreated, LatestNsgChange = LatestNsgChange, SecondsToContainment = datetime_diff('second', LatestNsgChange, LatestIncidentCreated)
| where isnotempty(LatestIncidentCreated) and isnotempty(LatestNsgChange) and LatestNsgChange >= LatestIncidentCreated
"@
        $timingRows = @(Invoke-WorkspaceQueryRows -WorkspaceCustomerId $workspaceCustomerId -Query $timingEvidenceQuery)
        if ($timingRows.Count -eq 0) { throw "Automation timing evidence query returned no correlated failed-logon incident creation and quarantine-rule change evidence." }
        $secondsToContainment = [int]$timingRows[0].SecondsToContainment

        $found = $true
        if ($found) {
            $message = @{
                Status  = "Succeeded"
                Message = "Challenge 4 validated in RG '$rg': '$noiseRuleName' is enabled and its active query excludes exact account '$benignAccount' plus source IP '$benignIp'; false-positive supporting evidence shows BeforeAlertsOrIncidents=$beforeCount, AfterAlertsOrIncidents=$afterCount, SeedBefore=$seedBeforeCount, SeedTotal=$seedTotalCount ($reductionEvidence); '$truePositiveRuleName' and '$failedLogonRuleName' remain enabled with evidence rows $truePositiveEvidenceRows and $failedLogonEvidenceRows; comment marker '$commentMarker' found on incident '$commentIncidentTitle'; workbook visible displayName '$($matchingWorkbook.properties.displayName)' (ARM resource name '$($matchingWorkbook.name)') starts with 'wb-zava-triage-report-' and references workspace '$workspaceName'; lab NSG foundation '$($nsgResources[0].Name)' exists; automation timing evidence shows $secondsToContainment seconds from incident creation to quarantine-rule change."
            } | ConvertTo-Json
        }
        else {
            $message = @{
                Status  = "Failed"
                Message = "Challenge 4 tuning and reporting evidence was not found in RG '$rg'."
            } | ConvertTo-Json
        }
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        $lastFailure = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        $message = @{
            Status  = "Failed"
            Message = $lastFailure
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
        Start-Sleep -Seconds 10
    }
} while ($count -lt 3 -and -not $found)

# Post-loop: if every attempt failed, emit a final failure JSON so CloudLabs always sees a structured result.
if (-not $found) {
    $message = @{
        Status  = "Failed"
        Message = "Validate-Challenge-04-TuneAndReport.ps1 did not pass in RG '$rg' after 3 attempts. Last failure: $lastFailure"
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
