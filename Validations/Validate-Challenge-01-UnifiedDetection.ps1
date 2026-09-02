using namespace System.Net

# CloudLabs coherence metadata:
# cloudlabs.coherence.version: 3
# cloudlabs.coherence.validationIndex: 1
# cloudlabs.coherence.validationMode: runtimeEndState
# cloudlabs.coherence.legacyFilenamePreserved: true
# cloudlabs.coherence.filenameBinding: keep Validations/Validate-Challenge-01-UnifiedDetection.ps1 because existing validation tags reference this exact file.
# cloudlabs.coherence.staticDeploymentScope: discover the pre-provisioned Zava lab foundation workspace and VM only.
# cloudlabs.coherence.runtimeEvidenceScope: observe Challenge 1 learner/runtime end state created after lab start.
# cloudlabs.coherence.runtimeObservedTypes: Microsoft.Insights/dataCollectionRules; Microsoft.SecurityInsights/alertRules; Microsoft.SecurityInsights/incidents; Microsoft.SecurityInsights/incidents/comments
# cloudlabs.coherence.runtimeObservedTypesClassification: learnerCreatedOrServiceGeneratedRuntimeEvidence, not ARM-deployed prerequisites.
# cloudlabs.coherence.evidenceSource: Challenge 1 guide tasks have the learner configure the DCR, create analytics rules, generate alerts/incidents, tag an incident, and add the required incident comment.
#
# CloudLabs validation coherence notes:
# - This script validates Challenge 1 observable runtime state, not a static ARM deployment manifest.
# - The DCR association is expected only after the learner connects Windows Security Events via AMA.
# - Sentinel analytics rules named below are learner-authored Challenge 1 rules checked through the workspace extension API.
# - Sentinel incidents and incident comments named below are service-generated or learner-authored investigation records checked at validation time.
# - The validator fails closed when the DCR association, Log Analytics evidence, learner rules, incident tag, or incident comment is absent after bounded retries.

# Note: $sub (subscription id) and $DID (deployment id) are injected by the platform.
# The lab resource group can be supplied by the CloudLabs deployment engine; if the
# conventional name is not present, the validator discovers the Zava lab resources by
# the deployed ARM output-backed prefixes used by the template.
$rg = "rg-zava-soc-$DID"
$count = 0
$found = $false
$lastFailure = "Unified detection validation has not run."

function Get-CollectionFromAzRest {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    $items = @()
    $nextPath = $Path

    while (-not [string]::IsNullOrWhiteSpace($nextPath)) {
        $response = Invoke-AzRestMethod -Method GET -Path $nextPath -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            return @()
        }

        $payload = $response.Content | ConvertFrom-Json
        if ($null -ne $payload.value) {
            $items += @($payload.value)
        }
        elseif ($null -ne $payload) {
            $items += $payload
        }

        $nextLink = $payload.nextLink
        if ([string]::IsNullOrWhiteSpace($nextLink)) {
            $nextPath = $null
        }
        elseif ($nextLink -like "https://management.azure.com/*") {
            $nextPath = $nextLink.Substring("https://management.azure.com".Length)
        }
        else {
            $nextPath = $nextLink
        }
    }

    return @($items)
}

function Get-ResultRows {
    param($QueryResponse)

    if ($null -eq $QueryResponse -or $null -eq $QueryResponse.Results) {
        return @()
    }

    return @($QueryResponse.Results)
}

function Test-IncidentHasExactTag {
    param(
        [Parameter(Mandatory = $true)]$Incident,
        [Parameter(Mandatory = $true)][string]$Tag
    )

    $labels = @($Incident.properties.labels)
    foreach ($label in $labels) {
        if ($label -is [string] -and $label -eq $Tag) {
            return $true
        }

        if ($null -ne $label.labelName -and [string]$label.labelName -eq $Tag) {
            return $true
        }

        if ($null -ne $label.name -and [string]$label.name -eq $Tag) {
            return $true
        }
    }

    return $false
}

function Test-IncidentMatchesLearnerEvidence {
    param(
        [Parameter(Mandatory = $true)]$Incident,
        [Parameter(Mandatory = $true)][string[]]$IncidentNamesFromLogs,
        [Parameter(Mandatory = $true)][string[]]$AlertIdsFromLogs,
        [Parameter(Mandatory = $true)][string[]]$RequiredRuleNames,
        [Parameter(Mandatory = $true)][string[]]$RequiredRuleResourceIds
    )

    if ($IncidentNamesFromLogs -contains [string]$Incident.name) {
        return $true
    }

    $title = [string]$Incident.properties.title
    foreach ($ruleName in $RequiredRuleNames) {
        if ($title -like "*$ruleName*") {
            return $true
        }
    }

    $incidentAlertIds = @($Incident.properties.alertIds | ForEach-Object { [string]$_ })
    if ($incidentAlertIds.Count -gt 0 -and ($incidentAlertIds | Where-Object { $AlertIdsFromLogs -contains $_ } | Select-Object -First 1)) {
        return $true
    }

    $relatedRules = @($Incident.properties.relatedAnalyticRuleIds | ForEach-Object { [string]$_ })
    foreach ($requiredRuleId in $RequiredRuleResourceIds) {
        if ($relatedRules -contains $requiredRuleId) {
            return $true
        }
    }

    return $false
}

function Get-ZavaLabResourceSet {
    param(
        [Parameter(Mandatory = $true)][string]$PreferredResourceGroupName
    )

    $candidateResourceGroups = @()
    $preferredResourceGroup = Get-AzResourceGroup -Name $PreferredResourceGroupName -ErrorAction SilentlyContinue
    if ($null -ne $preferredResourceGroup) {
        $candidateResourceGroups += $preferredResourceGroup.ResourceGroupName
    }

    $zavaResources = @(Get-AzResource -ErrorAction Stop | Where-Object {
        $_.Name -like "vm-zava-soc-*" -or
        $_.Name -like "law-zava-soc-*" -or
        $_.Name -like "dcr-zava-securityevents-*" -or
        ($_.Tags -and $_.Tags["zava-purpose"] -eq "soc-sentinel-lab")
    })

    $candidateResourceGroups += @($zavaResources | ForEach-Object { $_.ResourceGroupName })
    $candidateResourceGroups = @($candidateResourceGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    foreach ($candidateRg in $candidateResourceGroups) {
        $candidateVm = Get-AzResource -ResourceGroupName $candidateRg -ResourceType "Microsoft.Compute/virtualMachines" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "vm-zava-soc-*" } |
            Sort-Object Name |
            Select-Object -First 1

        $candidateWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $candidateRg -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "law-zava-soc-*" } |
            Sort-Object Name |
            Select-Object -First 1

        $candidateDcr = Get-AzResource -ResourceGroupName $candidateRg -ResourceType "Microsoft.Insights/dataCollectionRules" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "dcr-zava-securityevents-*" } |
            Sort-Object Name |
            Select-Object -First 1

        if ($null -ne $candidateVm -and $null -ne $candidateWorkspace -and $null -ne $candidateDcr) {
            return [PSCustomObject]@{
                ResourceGroupName = $candidateRg
                Vm                = $candidateVm
                Workspace         = $candidateWorkspace
                Dcr               = $candidateDcr
            }
        }
    }

    return $null
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        $resourceSet = Get-ZavaLabResourceSet -PreferredResourceGroupName $rg
        if ($null -eq $resourceSet) {
            $lastFailure = "Could not discover a complete Zava SOC lab resource set with VM 'vm-zava-soc-*', workspace 'law-zava-soc-*', and DCR 'dcr-zava-securityevents-*'."
            throw $lastFailure
        }

        $rg = $resourceSet.ResourceGroupName
        $vm = $resourceSet.Vm
        $workspace = $resourceSet.Workspace
        $dcr = $resourceSet.Dcr

        $workspaceResource = Get-AzResource -ResourceGroupName $rg -ResourceType "Microsoft.OperationalInsights/workspaces" -Name $workspace.Name -ErrorAction Stop
        $workspaceResourceId = $workspaceResource.ResourceId
        $workspaceCustomerId = [string]$workspace.CustomerId
        if ([string]::IsNullOrWhiteSpace($workspaceCustomerId)) {
            $lastFailure = "Workspace '$($workspace.Name)' does not expose a customer ID required for Log Analytics queries."
            throw $lastFailure
        }

        $vmAssociations = @(Get-AzDataCollectionRuleAssociation -ResourceUri $vm.ResourceId -ErrorAction SilentlyContinue)
        $dcrAssociations = @(Get-AzDataCollectionRuleAssociation -DataCollectionRuleName $dcr.Name -ResourceGroupName $rg -ErrorAction SilentlyContinue)
        $allAssociations = @($vmAssociations + $dcrAssociations) | Where-Object { $null -ne $_ } | Sort-Object Id -Unique
        $dcrId = [string]$dcr.ResourceId
        $vmId = [string]$vm.ResourceId

        $matchingAssociation = $allAssociations | Where-Object {
            $_.DataCollectionRuleId -and
            ([string]$_.DataCollectionRuleId).TrimEnd("/") -ieq $dcrId.TrimEnd("/") -and
            (
                ([string]$_.Id -like "$vmId/*") -or
                ([string]$_.Id -match "/resourceGroups/$([regex]::Escape($rg))/providers/Microsoft\.Insights/dataCollectionRuleAssociations/") -or
                ([string]$_.Id -like "*/$($vm.Name)/*")
            )
        } | Select-Object -First 1

        if ($null -eq $matchingAssociation) {
            $lastFailure = "DCR '$($dcr.Name)' exists, but no association to VM '$($vm.Name)' or the lab resource scope was found."
            throw $lastFailure
        }

        $vmNameEscaped = $vm.Name.Replace("'", "''")
        $vmIdEscaped = $vmId.Replace("'", "''")
        $securityEventQuery = @"
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where Computer has '$vmNameEscaped' or _ResourceId =~ '$vmIdEscaped'
| summarize FailedLogonCount = count(), Latest = max(TimeGenerated) by Computer
| where FailedLogonCount > 0
"@
        $securityEventResponse = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceCustomerId -Query $securityEventQuery -Timespan (New-TimeSpan -Hours 24) -Wait 60 -ErrorAction Stop
        $securityEventRows = Get-ResultRows -QueryResponse $securityEventResponse
        if ($securityEventRows.Count -eq 0) {
            $lastFailure = "No recent SecurityEvent 4625 failed-logon rows were found for VM '$($vm.Name)' in workspace '$($workspace.Name)'."
            throw $lastFailure
        }

        $apiVersion = "2023-02-01"
        $requiredRuleNames = @("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation")

        # Sentinel alertRules are queried as workspace extension resources. These two display names are
        # learner-created Challenge 1 analytics rules observed as runtime end state, not template prerequisites.
        $alertRulesPath = "$workspaceResourceId/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"
        $alertRules = Get-CollectionFromAzRest -Path $alertRulesPath
        if ($alertRules.Count -eq 0) {
            $lastFailure = "The Sentinel analytics-rules API returned no rules for workspace '$($workspace.Name)'. This validator is observing Challenge 1 learner-created runtime state."
            throw $lastFailure
        }

        $enabledLearnerRules = @()
        foreach ($requiredRuleName in $requiredRuleNames) {
            $rule = $alertRules | Where-Object {
                ([string]$_.properties.displayName -eq $requiredRuleName -or [string]$_.name -eq $requiredRuleName) -and
                ($_.properties.enabled -eq $true)
            } | Select-Object -First 1

            if ($null -ne $rule) {
                $enabledLearnerRules += $rule
            }
        }

        if ($enabledLearnerRules.Count -ne $requiredRuleNames.Count) {
            $presentEnabledNames = @($enabledLearnerRules | ForEach-Object { [string]$_.properties.displayName }) -join ", "
            $lastFailure = "Both learner analytics rules must exist and be enabled. Enabled learner rules found: [$presentEnabledNames]. Expected Challenge 1 runtime state for learner-authored Sentinel alert rules."
            throw $lastFailure
        }

        $requiredRuleResourceIds = @($enabledLearnerRules | ForEach-Object { [string]$_.id })
        $alertQuery = @'
SecurityAlert
| where TimeGenerated > ago(48h)
| where AlertName in~ ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation") or DisplayName in~ ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation")
| summarize AlertCount = count(), LatestAlert = max(TimeGenerated), AlertIds = make_set(SystemAlertId, 50), AlertNames = make_set(AlertName, 10)
| where AlertCount > 0
'@
        $alertResponse = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceCustomerId -Query $alertQuery -Timespan (New-TimeSpan -Hours 48) -Wait 60 -ErrorAction Stop
        $alertRows = Get-ResultRows -QueryResponse $alertResponse
        if ($alertRows.Count -eq 0 -or [int]$alertRows[0].AlertCount -le 0) {
            $lastFailure = "No SecurityAlert evidence was found in the last 48 hours for learner analytics rules '$($requiredRuleNames -join "' or '")'."
            throw $lastFailure
        }

        $alertIdsFromLogs = @()
        if ($null -ne $alertRows[0].AlertIds) {
            $alertIdsFromLogs = @($alertRows[0].AlertIds | ForEach-Object { [string]$_ }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }

        $incidentQuery = @'
SecurityIncident
| where TimeGenerated > ago(48h)
| where Title has_any ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation") or tostring(AlertIds) has_any ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation") or tostring(Labels) has "Challenge1-UnifiedDetection"
| summarize arg_max(TimeGenerated, *) by IncidentName
| project IncidentName, IncidentNumber, Title, Labels, AlertIds, CreatedTime, TimeGenerated
| take 20
'@
        $incidentResponse = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceCustomerId -Query $incidentQuery -Timespan (New-TimeSpan -Hours 48) -Wait 60 -ErrorAction Stop
        $incidentRows = Get-ResultRows -QueryResponse $incidentResponse
        if ($incidentRows.Count -eq 0) {
            $lastFailure = "No SecurityIncident log rows were found in the last 48 hours for learner rules or tag 'Challenge1-UnifiedDetection'."
            throw $lastFailure
        }

        $incidentNamesFromLogs = @($incidentRows | ForEach-Object { [string]$_.IncidentName }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        # Sentinel incidents are queried as the workspace runtime incident queue. Challenge 1 expects an
        # incident produced by learner rules plus a learner-applied tag and comment; these are not template prerequisites.
        $incidentsPath = "$workspaceResourceId/providers/Microsoft.SecurityInsights/incidents?api-version=$apiVersion"
        $incidents = Get-CollectionFromAzRest -Path $incidentsPath
        if ($incidents.Count -eq 0) {
            $lastFailure = "The Sentinel incidents API returned no incident records for workspace '$($workspace.Name)'. This validator is observing Challenge 1 runtime incident state."
            throw $lastFailure
        }

        $taggedIncidents = @($incidents | Where-Object { Test-IncidentHasExactTag -Incident $_ -Tag "Challenge1-UnifiedDetection" })
        if ($taggedIncidents.Count -eq 0) {
            $lastFailure = "No Sentinel incident record has the exact learner tag 'Challenge1-UnifiedDetection'. Expected Challenge 1 runtime state after learner tagging."
            throw $lastFailure
        }

        $validatedIncident = $null
        $validatedComment = $null
        foreach ($incident in $taggedIncidents) {
            $matchesLearnerEvidence = Test-IncidentMatchesLearnerEvidence -Incident $incident -IncidentNamesFromLogs $incidentNamesFromLogs -AlertIdsFromLogs $alertIdsFromLogs -RequiredRuleNames $requiredRuleNames -RequiredRuleResourceIds $requiredRuleResourceIds
            if (-not $matchesLearnerEvidence) {
                continue
            }

            # Sentinel incident comments are runtime documentation evidence added by the learner during Challenge 1.
            $commentsPath = "$($incident.id)/comments?api-version=$apiVersion"
            $comments = Get-CollectionFromAzRest -Path $commentsPath
            if ($comments.Count -eq 0) {
                continue
            }

            $comment = $comments | Where-Object { [string]$_.properties.message -like "*Challenge1-UnifiedDetection confirmed*" } | Select-Object -First 1
            if ($null -ne $comment) {
                $validatedIncident = $incident
                $validatedComment = $comment
                break
            }
        }

        if ($null -eq $validatedIncident) {
            $lastFailure = "A tagged learner incident was found, but no matching learner-rule incident has a comment containing 'Challenge1-UnifiedDetection confirmed'. Expected Challenge 1 runtime incident-comment evidence."
            throw $lastFailure
        }

        $found = $true
        $message = @{
            Status  = "Succeeded"
            Message = "Validated Challenge 1 unified detection in RG '$rg': DCR '$($dcr.Name)' is associated through '$($matchingAssociation.Name)', workspace '$($workspace.Name)' has SecurityEvent 4625 evidence for VM '$($vm.Name)', learner-created Sentinel alert rules are enabled, learner alert count is $($alertRows[0].AlertCount), and runtime Sentinel incident '$($validatedIncident.name)' has tag 'Challenge1-UnifiedDetection' plus comment '$($validatedComment.name)'."
        } | ConvertTo-Json -Depth 8
        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        if ([string]::IsNullOrWhiteSpace($lastFailure) -or $lastFailure -eq "Unified detection validation has not run.") {
            $lastFailure = $_.Exception.Message
        }

        $message = @{
            Status  = "Failed"
            Message = "Error during check. Attempt $count of 3. $lastFailure Error: $($_.Exception.Message)"
        } | ConvertTo-Json -Depth 8
        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
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
        Message = "Validate-Challenge-01-UnifiedDetection.ps1 did not find complete Challenge 1 learner runtime evidence in RG '$rg' after 3 attempts. Last failure: $lastFailure"
    } | ConvertTo-Json -Depth 8
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
