using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
#
# CloudLabs-Coherence: validationIndex=2; challenge="Challenge 2 - Correlate and Investigate with KQL".
# CloudLabs-Coherence: deployedPrerequisiteResourceTypes=Microsoft.OperationalInsights/workspaces.
# CloudLabs-Coherence: armPrerequisiteResourceTypes=Microsoft.OperationalInsights/workspaces.
# CloudLabs-Coherence: runtimeResourceTypes=Microsoft.SecurityInsights/incidents.
# CloudLabs-Coherence: learnerCreatedResourceTypes=Microsoft.SecurityInsights/incidents/comments,Microsoft.SecurityInsights/bookmarks,Microsoft.OperationalInsights/workspaces/savedSearches.
# CloudLabs-Coherence: notDeploymentPrerequisiteResourceTypes=Microsoft.SecurityInsights/incidents,Microsoft.SecurityInsights/incidents/comments,Microsoft.SecurityInsights/bookmarks,Microsoft.OperationalInsights/workspaces/savedSearches.
# CloudLabs-Coherence: legacyFilenameBinding=Preserved current filename because validation tags already bind to Validations/Validate-Challenge-02-Investigation.ps1.
#
# CloudLabs validation coherence notes (Challenge 2):
# - This script validates the Challenge 2 learner/runtime end-state, not only a static ARM manifest.
# - Deployed prerequisite scope: DeploymentPackage/deploy-01.json creates the Log Analytics workspace
#   Microsoft.OperationalInsights/workspaces named 'law-zava-soc-*'. The workspace is the only deployed
#   prerequisite resource type asserted by this validator and is the parent/scope used for Log Analytics
#   queries and Microsoft.SecurityInsights extension resources.
# - Deployment/runtime-seeded end-state: baseline Microsoft Sentinel analytics and seed bootstrap activity generate
#   the true-positive SecurityIncident and SecurityAlert table rows for 'ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change',
#   plus supporting evidence such as ZavaSOCSeed_CL and Azure control-plane telemetry.
# - Runtime service-generated artifacts: Microsoft.SecurityInsights/incidents are Microsoft Sentinel incident
#   resources under the workspace. The validator expects the seeded true-positive incident to exist by validation
#   time; it is a runtime investigation artifact, not a deployed ARM prerequisite.
# - Learner-updated runtime artifacts: the learner updates the selected Microsoft.SecurityInsights/incidents record
#   with exact label 'Challenge2-Investigated' and creates a Microsoft.SecurityInsights/incidents/comments child
#   resource containing exact marker 'Challenge2-Investigated'.
# - Learner-created hunting evidence: the learner creates either a Microsoft.SecurityInsights/bookmarks resource or
#   a Log Analytics Microsoft.OperationalInsights/workspaces/savedSearches resource whose displayName starts with
#   'ZAVA-Hunt-TruePositive'. These are Challenge 2 end-state artifacts and are not ARM template prerequisites.
# - The validator intentionally fails closed if the incident, exact tag, exact comment marker, three-table evidence,
#   or the learner-created hunting artifact is missing after bounded retries.
$rg = "rg-zava-soc-$DID"
$count = 0
$found = $false
$lastFailure = "Validation has not run."

$ruleName = "ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change"
$requiredTag = "Challenge2-Investigated"
$requiredCommentMarker = "Challenge2-Investigated"
$huntPrefix = "ZAVA-Hunt-TruePositive"
$workspaceNamePrefix = "law-zava-soc-"
$workspaceProviderNamespace = "Microsoft.OperationalInsights"
$workspaceTypeName = "workspaces"
$sentinelProviderNamespace = "Microsoft.SecurityInsights"
# Microsoft Learn REST/ARM grounding:
# - Microsoft.SecurityInsights/incidents and Microsoft.SecurityInsights/incidents/comments are workspace-scoped
#   Microsoft Sentinel resource types. The comments child resource has properties.message.
# - Microsoft.SecurityInsights/bookmarks is a workspace-scoped Sentinel resource type with properties.displayName
#   and properties.query; Microsoft.OperationalInsights/workspaces/savedSearches has properties.displayName and
#   properties.query under a Log Analytics workspace.
# - The workspace-scoped extension-resource paths below use the same provider/type names documented for these
#   Sentinel and Log Analytics resource types.
$sentinelApiVersion = "2024-09-01"
$savedSearchApiVersion = "2020-08-01"
$bookmarkApiVersion = "2024-09-01"

function Get-ObjectPropertyValue {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $exact = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $exact) {
        return $exact.Value
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.Name -ieq $Name) {
            return $property.Value
        }
    }

    return $null
}

function ConvertTo-Array {
    param([object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        return @($Value)
    }

    return @($Value)
}

function Get-ZavaDeploymentOutputValue {
    param(
        [object]$Deployment,
        [string]$OutputName
    )

    if ($null -eq $Deployment -or $null -eq $Deployment.Outputs) {
        return $null
    }

    try {
        if ($Deployment.Outputs.ContainsKey($OutputName)) {
            $outputObject = $Deployment.Outputs[$OutputName]
            $outputValue = Get-ObjectPropertyValue -InputObject $outputObject -Name "Value"
            if ($null -ne $outputValue) {
                return [string]$outputValue
            }
        }
    }
    catch {
        return $null
    }

    return $null
}

function Get-WorkspaceResourceGroupName {
    param([object]$Workspace)

    $workspaceRg = [string](Get-ObjectPropertyValue -InputObject $Workspace -Name "ResourceGroupName")
    if (-not [string]::IsNullOrWhiteSpace($workspaceRg)) {
        return $workspaceRg
    }

    $workspaceResourceId = [string](Get-ObjectPropertyValue -InputObject $Workspace -Name "ResourceId")
    if ([string]::IsNullOrWhiteSpace($workspaceResourceId)) {
        $workspaceResourceId = [string](Get-ObjectPropertyValue -InputObject $Workspace -Name "Id")
    }

    if ($workspaceResourceId -match "/resourceGroups/([^/]+)/") {
        return $Matches[1]
    }

    return $null
}

function Get-ZavaWorkspace {
    param(
        [string]$ExpectedResourceGroupName,
        [string]$DeploymentId,
        [string]$NamePrefix
    )

    $outputWorkspaceNames = @()
    $outputResourceGroupNames = @()
    $deploymentSearchGroups = @()

    try {
        $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
        $deploymentSearchGroups = @($resourceGroups | Where-Object {
            $_.ResourceGroupName -eq $ExpectedResourceGroupName -or
            $_.ResourceGroupName -like "*$DeploymentId*" -or
            ($null -ne $_.Tags -and $_.Tags.ContainsKey("cloudlabs-lab") -and $_.Tags["cloudlabs-lab"] -eq "Threat Triage Assistant")
        })
    }
    catch {
        $deploymentSearchGroups = @()
    }

    foreach ($resourceGroup in $deploymentSearchGroups) {
        try {
            $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $resourceGroup.ResourceGroupName -ErrorAction Stop
            foreach ($deployment in $deployments) {
                $outputWorkspaceName = Get-ZavaDeploymentOutputValue -Deployment $deployment -OutputName "logAnalyticsWorkspaceName"
                if (-not [string]::IsNullOrWhiteSpace($outputWorkspaceName)) {
                    $outputWorkspaceNames += $outputWorkspaceName
                }

                $outputResourceGroupName = Get-ZavaDeploymentOutputValue -Deployment $deployment -OutputName "resourceGroupName"
                if (-not [string]::IsNullOrWhiteSpace($outputResourceGroupName)) {
                    $outputResourceGroupNames += $outputResourceGroupName
                }
            }
        }
        catch {
            # Deployment-output discovery is best effort. Workspace prefix discovery below is authoritative for validation.
        }
    }

    $workspaceCandidates = @()
    try {
        $workspaceCandidates += @(Get-AzOperationalInsightsWorkspace -ResourceGroupName $ExpectedResourceGroupName -ErrorAction Stop | Where-Object { $_.Name -like "$NamePrefix*" })
    }
    catch {
        # The lab resource group name is deployment-defined, so continue with subscription-level discovery if this prefix guess is absent.
    }

    try {
        $workspaceCandidates += @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop | Where-Object { $_.Name -like "$NamePrefix*" })
    }
    catch {
        return $null
    }

    $uniqueCandidates = @{}
    foreach ($candidate in $workspaceCandidates) {
        if ($null -eq $candidate) {
            continue
        }

        $candidateName = [string](Get-ObjectPropertyValue -InputObject $candidate -Name "Name")
        $candidateRg = Get-WorkspaceResourceGroupName -Workspace $candidate
        $candidateKey = "$candidateRg/$candidateName"
        if (-not [string]::IsNullOrWhiteSpace($candidateName) -and -not $uniqueCandidates.ContainsKey($candidateKey)) {
            $uniqueCandidates[$candidateKey] = $candidate
        }
    }

    $rankedCandidates = @()
    foreach ($candidate in $uniqueCandidates.Values) {
        $candidateName = [string](Get-ObjectPropertyValue -InputObject $candidate -Name "Name")
        $candidateRg = Get-WorkspaceResourceGroupName -Workspace $candidate
        $candidateTags = Get-ObjectPropertyValue -InputObject $candidate -Name "Tags"
        $score = 0

        if ($candidateName -like "$NamePrefix*") { $score += 100 }
        if (@($outputWorkspaceNames | Where-Object { $_ -eq $candidateName }).Count -gt 0) { $score += 70 }
        if ($candidateRg -eq $ExpectedResourceGroupName) { $score += 40 }
        if (@($outputResourceGroupNames | Where-Object { $_ -eq $candidateRg }).Count -gt 0) { $score += 30 }
        if ($candidateRg -like "*$DeploymentId*") { $score += 20 }
        if ($candidateName -like "*$DeploymentId*") { $score += 10 }

        try {
            if ($null -ne $candidateTags -and $candidateTags.ContainsKey("zava-purpose") -and $candidateTags["zava-purpose"] -eq "soc-sentinel-lab") {
                $score += 25
            }
        }
        catch {
            # Tags are optional for discovery scoring.
        }

        $rankedCandidates += [pscustomobject]@{
            Score     = $score
            Workspace = $candidate
        }
    }

    return ($rankedCandidates | Sort-Object -Property Score -Descending | Select-Object -First 1).Workspace
}

function Get-ArmListValue {
    param([string]$Path)

    $response = Invoke-AzRestMethod -Method GET -Path $Path -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($response.Content)) {
        return @()
    }

    $payload = $response.Content | ConvertFrom-Json
    if ($payload -is [System.Array]) {
        return @($payload)
    }

    $values = Get-ObjectPropertyValue -InputObject $payload -Name "value"
    return (ConvertTo-Array -Value $values)
}

function Invoke-ZavaWorkspaceQuery {
    param(
        [string]$WorkspaceId,
        [string]$Query,
        [int]$Days = 30
    )

    $queryResult = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -Timespan (New-TimeSpan -Days $Days) -Wait 60 -ErrorAction Stop
    return (ConvertTo-Array -Value $queryResult.Results)
}

function Get-EvidenceCount {
    param(
        [string]$WorkspaceId,
        [string]$Query
    )

    try {
        $rows = Invoke-ZavaWorkspaceQuery -WorkspaceId $WorkspaceId -Query $Query -Days 30
        if ($rows.Count -eq 0) {
            return 0
        }

        $countValue = Get-ObjectPropertyValue -InputObject $rows[0] -Name "EvidenceCount"
        if ($null -eq $countValue) {
            return $rows.Count
        }

        return [int]$countValue
    }
    catch {
        # Some optional evidence tables might not exist in all workspaces. Treat that table as empty and fail closed later if fewer than three tables have evidence.
        return 0
    }
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $workspace = Get-ZavaWorkspace -ExpectedResourceGroupName $rg -DeploymentId $DID -NamePrefix $workspaceNamePrefix

        if ($null -eq $workspace) {
            $lastFailure = "Log Analytics workspace of resource type '$workspaceProviderNamespace/$workspaceTypeName' with name prefix '$workspaceNamePrefix' was not found."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $rg = Get-WorkspaceResourceGroupName -Workspace $workspace
        $workspaceName = [string](Get-ObjectPropertyValue -InputObject $workspace -Name "Name")
        $workspaceId = $workspace.CustomerId.Guid
        if ([string]::IsNullOrWhiteSpace($workspaceId)) {
            $workspaceId = [string]$workspace.CustomerId
        }

        $workspaceScopePath = "/subscriptions/$sub/resourceGroups/$rg/providers/$workspaceProviderNamespace/$workspaceTypeName/$workspaceName"
        $sentinelScopePath = "$workspaceScopePath/providers/$sentinelProviderNamespace"

        $trueIncidentQuery = @"
SecurityIncident
| where TimeGenerated > ago(30d)
| extend Rule=tostring(column_ifexists("AlertRuleName", "")), IncidentResourceName=tostring(column_ifexists("IncidentName", "")), IncidentNumberValue=tostring(column_ifexists("IncidentNumber", "")), IncidentTitle=tostring(column_ifexists("Title", "")), RelatedAlerts=tostring(column_ifexists("AlertIds", "")), Additional=tostring(column_ifexists("AdditionalData", ""))
| where Rule =~ '$ruleName' or IncidentTitle has '$ruleName' or RelatedAlerts has '$ruleName' or Additional has '$ruleName'
| summarize arg_max(TimeGenerated, *) by IncidentResourceName
| top 1 by TimeGenerated desc
| project TimeGenerated, CreatedTime, IncidentResourceName, IncidentNumberValue, IncidentTitle, Rule
"@
        $trueIncidentRows = Invoke-ZavaWorkspaceQuery -WorkspaceId $workspaceId -Query $trueIncidentQuery -Days 30
        if ($trueIncidentRows.Count -eq 0) {
            $lastFailure = "No SecurityIncident row was found for seeded true-positive rule '$ruleName' in workspace '$workspaceName'."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $trueAlertQuery = @"
SecurityAlert
| where TimeGenerated > ago(30d)
| extend AlertDisplayName=tostring(column_ifexists("DisplayName", "")), AlertNameValue=tostring(column_ifexists("AlertName", "")), AlertRuleValue=tostring(column_ifexists("AlertRuleName", "")), Extended=tostring(column_ifexists("ExtendedProperties", "")), EntitiesValue=tostring(column_ifexists("Entities", ""))
| where AlertDisplayName =~ '$ruleName' or AlertNameValue =~ '$ruleName' or AlertRuleValue =~ '$ruleName' or Extended has '$ruleName' or EntitiesValue has '$ruleName'
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| top 5 by TimeGenerated desc
| project TimeGenerated, SystemAlertId, AlertDisplayName, AlertNameValue, AlertRuleValue
"@
        $trueAlertRows = Invoke-ZavaWorkspaceQuery -WorkspaceId $workspaceId -Query $trueAlertQuery -Days 30
        if ($trueAlertRows.Count -eq 0) {
            $lastFailure = "No SecurityAlert row was found for seeded true-positive rule '$ruleName' in workspace '$workspaceName'."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $securityIncidentResourceName = [string](Get-ObjectPropertyValue -InputObject $trueIncidentRows[0] -Name "IncidentResourceName")
        $securityIncidentNumber = [string](Get-ObjectPropertyValue -InputObject $trueIncidentRows[0] -Name "IncidentNumberValue")

        $incidentListPath = "$sentinelScopePath/incidents?api-version=$sentinelApiVersion"
        $incidents = Get-ArmListValue -Path $incidentListPath
        if ($incidents.Count -eq 0) {
            $lastFailure = "Microsoft Sentinel incident API returned no incidents for workspace '$workspaceName'."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $matchingIncidents = @($incidents | Where-Object {
            $name = [string](Get-ObjectPropertyValue -InputObject $_ -Name "name")
            $properties = Get-ObjectPropertyValue -InputObject $_ -Name "properties"
            $title = [string](Get-ObjectPropertyValue -InputObject $properties -Name "title")
            $incidentNumber = [string](Get-ObjectPropertyValue -InputObject $properties -Name "incidentNumber")
            $description = [string](Get-ObjectPropertyValue -InputObject $properties -Name "description")
            $additionalData = [string](Get-ObjectPropertyValue -InputObject $properties -Name "additionalData")

            ((-not [string]::IsNullOrWhiteSpace($securityIncidentResourceName)) -and ($name -eq $securityIncidentResourceName)) -or
            ((-not [string]::IsNullOrWhiteSpace($securityIncidentNumber)) -and ($incidentNumber -eq $securityIncidentNumber)) -or
            ($title -like "*$ruleName*") -or
            ($description -like "*$ruleName*") -or
            ($additionalData -like "*$ruleName*")
        })

        if ($matchingIncidents.Count -eq 0) {
            $lastFailure = "Seeded true-positive incident '$ruleName' was present in logs but not found through the Microsoft Sentinel incident API."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $sentinelIncident = $matchingIncidents | Select-Object -First 1
        $sentinelIncidentName = [string](Get-ObjectPropertyValue -InputObject $sentinelIncident -Name "name")
        $sentinelIncidentProperties = Get-ObjectPropertyValue -InputObject $sentinelIncident -Name "properties"
        $sentinelIncidentTitle = [string](Get-ObjectPropertyValue -InputObject $sentinelIncidentProperties -Name "title")

        $labels = ConvertTo-Array -Value (Get-ObjectPropertyValue -InputObject $sentinelIncidentProperties -Name "labels")
        $labelNames = @()
        foreach ($label in $labels) {
            if ($label -is [string]) {
                $labelNames += $label
            }
            else {
                $labelName = [string](Get-ObjectPropertyValue -InputObject $label -Name "labelName")
                if (-not [string]::IsNullOrWhiteSpace($labelName)) {
                    $labelNames += $labelName
                }
            }
        }

        $hasExactTag = @($labelNames | Where-Object { $_ -ceq $requiredTag }).Count -gt 0
        if (-not $hasExactTag) {
            $lastFailure = "Incident '$sentinelIncidentName' for '$ruleName' does not have exact tag '$requiredTag'. Current tags: '$($labelNames -join ', ')'."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $incidentCommentsPath = "$sentinelScopePath/incidents/$sentinelIncidentName/comments?api-version=$sentinelApiVersion"
        $comments = Get-ArmListValue -Path $incidentCommentsPath
        if ($comments.Count -eq 0) {
            $lastFailure = "Incident '$sentinelIncidentName' has no Microsoft Sentinel incident comments."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $commentMessages = @()
        foreach ($comment in $comments) {
            $commentProperties = Get-ObjectPropertyValue -InputObject $comment -Name "properties"
            $messageValue = [string](Get-ObjectPropertyValue -InputObject $commentProperties -Name "message")
            if (-not [string]::IsNullOrWhiteSpace($messageValue)) {
                $commentMessages += $messageValue
            }
        }

        $hasExactCommentMarker = @($commentMessages | Where-Object { $_.Contains($requiredCommentMarker) }).Count -gt 0
        if (-not $hasExactCommentMarker) {
            $lastFailure = "Incident '$sentinelIncidentName' does not contain the exact comment marker '$requiredCommentMarker'."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $evidenceCounts = [ordered]@{}
        $evidenceCounts["SecurityIncident"] = $trueIncidentRows.Count
        $evidenceCounts["SecurityAlert"] = $trueAlertRows.Count
        $evidenceCounts["ZavaSOCSeed_CL"] = Get-EvidenceCount -WorkspaceId $workspaceId -Query @"
ZavaSOCSeed_CL
| where TimeGenerated > ago(30d)
| extend Packed=tostring(pack_all())
| where Packed has '$ruleName' or (Packed has 'TruePositive' and Packed has 'vm-zava-soc') or (Packed has 'IsTruePositive' and Packed has 'true')
| summarize EvidenceCount=count()
"@
        $evidenceCounts["AzureActivity"] = Get-EvidenceCount -WorkspaceId $workspaceId -Query @"
AzureActivity
| where TimeGenerated > ago(30d)
| extend Packed=tostring(pack_all()), ResourceText=strcat(tostring(column_ifexists("ResourceProviderValue", "")), " ", tostring(column_ifexists("ResourceGroup", "")), " ", tostring(column_ifexists("Resource", "")), " ", tostring(column_ifexists("OperationNameValue", "")), " ", tostring(column_ifexists("Properties", "")))
| where ResourceText has 'vm-zava-soc' or ResourceText has 'nsg-zava-workload' or Packed has '$ruleName'
| summarize EvidenceCount=count()
"@
        $evidenceCounts["SecurityEvent"] = Get-EvidenceCount -WorkspaceId $workspaceId -Query @"
SecurityEvent
| where TimeGenerated > ago(30d)
| extend Packed=tostring(pack_all()), ComputerValue=tostring(column_ifexists("Computer", "")), EventIdValue=tostring(column_ifexists("EventID", ""))
| where ComputerValue has 'vm-zava-soc' or Packed has '$ruleName' or (EventIdValue in ('4624','4625') and Packed has 'zava')
| summarize EvidenceCount=count()
"@
        $evidenceCounts["AzureDiagnostics"] = Get-EvidenceCount -WorkspaceId $workspaceId -Query @"
AzureDiagnostics
| where TimeGenerated > ago(30d)
| extend Packed=tostring(pack_all())
| where Packed has 'vm-zava-soc' or Packed has 'nsg-zava-workload' or Packed has '$ruleName'
| summarize EvidenceCount=count()
"@

        $tablesWithEvidence = @($evidenceCounts.Keys | Where-Object { [int]$evidenceCounts[$_] -gt 0 })
        if ($tablesWithEvidence.Count -lt 3) {
            $lastFailure = "Evidence for '$ruleName' was found in only $($tablesWithEvidence.Count) table(s): '$($tablesWithEvidence -join ', ')'. At least three relevant tables are required."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $savedSearchListPath = "$workspaceScopePath/savedSearches?api-version=$savedSearchApiVersion"
        $savedSearches = Get-ArmListValue -Path $savedSearchListPath
        $matchingSavedSearches = @($savedSearches | Where-Object {
            $properties = Get-ObjectPropertyValue -InputObject $_ -Name "properties"
            $displayName = [string](Get-ObjectPropertyValue -InputObject $properties -Name "displayName")
            (-not [string]::IsNullOrWhiteSpace($displayName)) -and $displayName.StartsWith($huntPrefix, [System.StringComparison]::Ordinal)
        })

        $bookmarkListPath = "$sentinelScopePath/bookmarks?api-version=$bookmarkApiVersion"
        $bookmarks = Get-ArmListValue -Path $bookmarkListPath
        $matchingBookmarks = @($bookmarks | Where-Object {
            $properties = Get-ObjectPropertyValue -InputObject $_ -Name "properties"
            $displayName = [string](Get-ObjectPropertyValue -InputObject $properties -Name "displayName")
            (-not [string]::IsNullOrWhiteSpace($displayName)) -and $displayName.StartsWith($huntPrefix, [System.StringComparison]::Ordinal)
        })

        if (($matchingSavedSearches.Count + $matchingBookmarks.Count) -eq 0) {
            $lastFailure = "No learner-created saved hunting query or Microsoft Sentinel bookmark with display name prefix '$huntPrefix' was found in workspace '$workspaceName'."
            $message = @{
                Status  = "Failed"
                Message = $lastFailure
            } | ConvertTo-Json
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $message
            })
            Start-Sleep -Seconds 10
            continue
        }

        $found = $true
        $huntArtifactSummary = "saved hunting queries=$($matchingSavedSearches.Count), bookmarks=$($matchingBookmarks.Count)"
        $message = @{
            Status  = "Succeeded"
            Message = "Challenge 2 investigation validated. Seeded true-positive incident '$sentinelIncidentName' ('$sentinelIncidentTitle') from rule '$ruleName' has exact tag '$requiredTag', a comment containing marker '$requiredCommentMarker', evidence in tables '$($tablesWithEvidence -join ', ')', and learner-created hunting artifact count ($huntArtifactSummary) with prefix '$huntPrefix' in workspace '$workspaceName' (RG '$rg')."
        } | ConvertTo-Json
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
        Message = "Validate-Challenge-02-Investigation.ps1 failed in RG '$rg' after 3 attempts. Last failure: $lastFailure"
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
