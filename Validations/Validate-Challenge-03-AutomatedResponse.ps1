using namespace System.Net

# Note: $sub (subscription id) and $DID (deployment id) are injected by the CloudLabs platform.
# CloudLabs coherence metadata:
# cloudlabs.coherence.version: 2
# cloudlabs.coherence.validationIndex: 3
# cloudlabs.coherence.legacyFilenamePreserved: true
# cloudlabs.coherence.resourceProvenance:
#   armPrerequisites:
#     - Microsoft.OperationalInsights/workspaces
#     - Microsoft.Compute/virtualMachines
#     - Microsoft.Network/networkSecurityGroups
#     - Microsoft.ManagedIdentity/userAssignedIdentities (precreated id-zava-playbook-* identity used by the Challenge 3 playbook)
#   learnerCreatedRuntimeEndState:
#     - Microsoft.Logic/workflows (la-zava-isolate-notify-* playbook created by the learner; not an ARM prerequisite)
#     - Microsoft.SecurityInsights/automationRules
#     - Microsoft.Network/networkSecurityGroups/securityRules
#     - Microsoft.SecurityInsights/incidents/comments
#   evidenceSource: Challenge 3 lab-guide tasks create the Logic App playbook, attach the precreated user-assigned identity id-zava-playbook-*, create the Sentinel automation rule, create or update the quarantine NSG security rule, and add the required Sentinel incident comment.
#
# CloudLabs validation coherence notes:
# - This script validates Challenge 3 learner-created runtime end state, not additional static ARM deployment prerequisites.
# - Microsoft.Logic/workflows named la-zava-isolate-notify-* is created by the learner during Challenge 3 and must exist by validation time; it is intentionally not listed as an ARM prerequisite.
# - The precreated Microsoft.ManagedIdentity/userAssignedIdentities resource named id-zava-playbook-* is an ARM prerequisite. The learner-created Logic App must attach and use that user-assigned identity, not a system-assigned identity.
# - Microsoft.Network/networkSecurityGroups/securityRules named Deny-Inbound-Zava-Quarantine is created or updated by the learner playbook during Challenge 3; only the parent lab NSG is an ARM prerequisite.
# - The workspace, VM, lab NSG foundation, and playbook UAMI are deployed before the lab; the playbook and quarantine rule are validated only as Challenge 3 end state.
# - PermissionFact: Microsoft Sentinel Automation Contributor for the Sentinel service account is a separate platform/facilitator authorization path required for automation rules to run playbooks.
# - PermissionFact: the Logic App user-assigned managed identity separately needs scoped permissions for Sentinel incident comment write and lab NSG rule update.
$rg = "rg-zava-soc-$DID"
$count = 0
$found = $false
$lastFailure = "Challenge 3 automated response validation did not run."

$logicAppNamePattern = "la-zava-isolate-notify-*"
$userAssignedIdentityNamePattern = "id-zava-playbook-*"
$workspaceNamePattern = "law-zava-soc-*"
$vmNamePattern = "vm-zava-soc-*"
$nsgNamePattern = "nsg-zava-workload-*"
$automationRuleDisplayName = "AR-ZAVA-Auto-Isolate-VM"
$learnerRuleName = "ZAVA-Learner-Failed-VM-Logons"
$quarantineRuleName = "Deny-Inbound-Zava-Quarantine"
$commentMarker = "Challenge3-AutomatedContainment"

function Invoke-ZavaPagedArmGet {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PathOrUri
    )

    $items = @()
    $next = $PathOrUri
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        if ($next -match '^https://') {
            $response = Invoke-AzRestMethod -Method GET -Uri $next -ErrorAction Stop
        }
        else {
            $response = Invoke-AzRestMethod -Method GET -Path $next -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            break
        }

        $payload = $response.Content | ConvertFrom-Json
        if ($null -ne $payload.value) {
            $items += @($payload.value)
            $next = $payload.nextLink
        }
        else {
            $items += $payload
            $next = $null
        }
    }

    return @($items)
}

function Get-ZavaResourceByPattern {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResourceType,
        [Parameter(Mandatory = $true)]
        [string] $NamePattern,
        [string] $PreferredResourceGroup
    )

    $resources = @(Get-AzResource -ResourceType $ResourceType -ErrorAction Stop | Where-Object { $_.Name -like $NamePattern })
    if (-not $resources -or $resources.Count -eq 0) {
        return $null
    }

    $preferred = @($resources | Where-Object { $_.ResourceGroupName -eq $PreferredResourceGroup })
    if ($preferred.Count -gt 0) {
        return ($preferred | Sort-Object Name | Select-Object -First 1)
    }

    $didScoped = @($resources | Where-Object { $_.ResourceGroupName -like "*$DID*" -or $_.Name -like "*$DID*" })
    if ($didScoped.Count -gt 0) {
        return ($didScoped | Sort-Object ResourceGroupName, Name | Select-Object -First 1)
    }

    return ($resources | Sort-Object ResourceGroupName, Name | Select-Object -First 1)
}

function Get-ZavaRuleValues {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Rule,
        [Parameter(Mandatory = $true)]
        [string] $SingleProperty,
        [Parameter(Mandatory = $true)]
        [string] $PluralProperty
    )

    $values = @()
    $single = $Rule.$SingleProperty
    $plural = $Rule.$PluralProperty

    if ($null -ne $single -and -not [string]::IsNullOrWhiteSpace([string]$single)) {
        $values += [string]$single
    }
    if ($null -ne $plural) {
        $values += @($plural | ForEach-Object { [string]$_ })
    }

    return @($values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Test-ZavaPortSetIncludesManagementPort {
    param([string[]] $Ports)

    if (-not $Ports -or $Ports.Count -eq 0) {
        return $false
    }

    foreach ($port in $Ports) {
        if ($port -eq "*") {
            return $true
        }
        if ($port -in @("22", "443", "3389", "5985", "5986")) {
            return $true
        }
        if ($port -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            foreach ($managementPort in @(22, 443, 3389, 5985, 5986)) {
                if ($managementPort -ge $start -and $managementPort -le $end) {
                    return $true
                }
            }
        }
    }

    return $false
}

function Test-ZavaRestrictedSource {
    param([string[]] $Sources)

    if (-not $Sources -or $Sources.Count -eq 0) {
        return $false
    }

    foreach ($source in $Sources) {
        if ($source -in @("*", "Internet", "0.0.0.0/0", "::/0")) {
            return $false
        }
    }

    return $true
}

function Test-ZavaAnySource {
    param([string[]] $Sources)

    if (-not $Sources -or $Sources.Count -eq 0) {
        return $true
    }

    foreach ($source in $Sources) {
        if ($source -in @("*", "Internet", "0.0.0.0/0", "::/0")) {
            return $true
        }
    }

    return $false
}

function Test-ZavaDestinationTargetsVm {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Rule,
        [string[]] $VmPrivateIps
    )

    $destinationPrefixes = @(Get-ZavaRuleValues -Rule $Rule -SingleProperty "DestinationAddressPrefix" -PluralProperty "DestinationAddressPrefixes")
    if (-not $destinationPrefixes -or $destinationPrefixes.Count -eq 0) {
        return $true
    }
    if ($destinationPrefixes | Where-Object { $_ -in @("*", "VirtualNetwork") -or $_ -in $VmPrivateIps }) {
        return $true
    }
    if ($Rule.DestinationApplicationSecurityGroups -and $Rule.DestinationApplicationSecurityGroups.Count -gt 0) {
        return $true
    }

    return $false
}

function Get-ZavaAutomationPropertyConditions {
    param([object] $Node)

    $results = @()
    if ($null -eq $Node) {
        return $results
    }

    foreach ($item in @($Node)) {
        if ($null -eq $item) {
            continue
        }

        $propertyNames = @($item.PSObject.Properties.Name)
        if (($propertyNames -contains "conditionType") -and ($propertyNames -contains "conditionProperties")) {
            $conditionProperties = $item.conditionProperties
            if ($null -ne $conditionProperties) {
                $conditionPropertyNames = @($conditionProperties.PSObject.Properties.Name)
                if ($conditionPropertyNames -contains "propertyName") {
                    $propertyValues = @()
                    if ($conditionPropertyNames -contains "propertyValues") {
                        $propertyValues = @($conditionProperties.propertyValues | ForEach-Object { [string]$_ })
                    }
                    $results += [pscustomobject]@{
                        PropertyName   = [string]$conditionProperties.propertyName
                        Operator       = [string]$conditionProperties.operator
                        PropertyValues = $propertyValues
                    }
                }
            }
        }

        foreach ($property in $item.PSObject.Properties) {
            if ($null -ne $property.Value -and ($property.Value -is [System.Management.Automation.PSCustomObject] -or $property.Value -is [System.Array])) {
                $results += Get-ZavaAutomationPropertyConditions -Node $property.Value
            }
        }
    }

    return @($results)
}

function Test-ZavaTextContainsAny {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Text,
        [string[]] $Needles
    )

    foreach ($needle in @($Needles)) {
        if (-not [string]::IsNullOrWhiteSpace($needle) -and $Text -match [regex]::Escape($needle)) {
            return $true
        }
    }

    return $false
}

function Get-ZavaLogicAppUserAssignedIdentityAssociations {
    param([object] $LogicAppIdentity)

    $associations = @()
    if ($null -eq $LogicAppIdentity -or $null -eq $LogicAppIdentity.UserAssignedIdentities) {
        return $associations
    }

    foreach ($property in @($LogicAppIdentity.UserAssignedIdentities.PSObject.Properties)) {
        if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Name)) {
            continue
        }

        $value = $property.Value
        $associations += [pscustomobject]@{
            ResourceId  = [string]$property.Name
            PrincipalId = if ($null -ne $value -and $null -ne $value.principalId) { [string]$value.principalId } else { "" }
            ClientId    = if ($null -ne $value -and $null -ne $value.clientId) { [string]$value.clientId } else { "" }
        }
    }

    return @($associations)
}

function Test-ZavaWorkflowHasLearnerConfiguration {
    param([object] $LogicApp)

    $definition = $LogicApp.Properties.definition
    if ($null -eq $definition) {
        return $false
    }

    $definitionJson = $definition | ConvertTo-Json -Depth 80 -Compress
    $triggerNames = @()
    $actionNames = @()
    if ($null -ne $definition.triggers) {
        $triggerNames = @($definition.triggers.PSObject.Properties.Name)
    }
    if ($null -ne $definition.actions) {
        $actionNames = @($definition.actions.PSObject.Properties.Name)
    }

    $hasTrigger = $triggerNames.Count -gt 0
    $hasActions = $actionNames.Count -gt 0
    $looksLikeSentinelIncidentPlaybook = ($definitionJson -match '(?i)incident') -and ($definitionJson -match '(?i)azuresentinel|securityinsights|microsoft sentinel|sentinel')

    return ($hasTrigger -and $hasActions -and $looksLikeSentinelIncidentPlaybook)
}

do {
    $count = $count + 1
    try {
        Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null

        # Learner-created Challenge 3 playbook resource: Microsoft Sentinel playbooks are Azure Logic Apps workflows.
        $logicAppResource = Get-ZavaResourceByPattern -ResourceType "Microsoft.Logic/workflows" -NamePattern $logicAppNamePattern -PreferredResourceGroup $rg
        if ($null -eq $logicAppResource) {
            $lastFailure = "Learner-created Logic App matching '$logicAppNamePattern' was not found in subscription '$sub'. This workflow is a Challenge 3 runtime end state and is not expected to be deployed by ARM."
            throw $lastFailure
        }

        $rg = $logicAppResource.ResourceGroupName
        $logicApp = Get-AzResource -ResourceId $logicAppResource.ResourceId -ExpandProperties -ErrorAction Stop

        $uamiResource = Get-ZavaResourceByPattern -ResourceType "Microsoft.ManagedIdentity/userAssignedIdentities" -NamePattern $userAssignedIdentityNamePattern -PreferredResourceGroup $rg
        if ($null -eq $uamiResource) {
            $lastFailure = "Precreated user-assigned managed identity matching '$userAssignedIdentityNamePattern' was not found for RG '$rg'. The Challenge 3 Logic App must use the precreated playbook identity instead of a system-assigned identity."
            throw $lastFailure
        }
        $uami = Get-AzResource -ResourceId $uamiResource.ResourceId -ExpandProperties -ErrorAction Stop
        $uamiPrincipalId = if ($uami.Properties -and $uami.Properties.principalId) { [string]$uami.Properties.principalId } else { "" }
        $uamiClientId = if ($uami.Properties -and $uami.Properties.clientId) { [string]$uami.Properties.clientId } else { "" }
        if ([string]::IsNullOrWhiteSpace($uamiPrincipalId) -or [string]::IsNullOrWhiteSpace($uamiClientId)) {
            $lastFailure = "Precreated user-assigned identity '$($uami.Name)' exists at '$($uami.ResourceId)' but its principalId/clientId were not observable from ARM. PrincipalId='$uamiPrincipalId', ClientId='$uamiClientId'."
            throw $lastFailure
        }

        $identityType = if ($logicApp.Identity -and $logicApp.Identity.Type) { [string]$logicApp.Identity.Type } else { "None" }
        $hasSystemAssignedIdentity = ($identityType -match '(^|,)\s*SystemAssigned\s*(,|$)') -and (-not [string]::IsNullOrWhiteSpace([string]$logicApp.Identity.PrincipalId))
        $hasUserAssignedIdentity = ($identityType -match '(^|,)\s*UserAssigned\s*(,|$)')
        if (-not $hasUserAssignedIdentity) {
            $lastFailure = "Learner-created Logic App '$($logicApp.Name)' exists in RG '$rg' but does not have a user-assigned managed identity enabled. Identity type: '$identityType'. Attach precreated identity '$($uami.Name)' ('$($uami.ResourceId)') instead of enabling only a system-assigned identity."
            throw $lastFailure
        }
        if ($hasSystemAssignedIdentity) {
            $lastFailure = "Learner-created Logic App '$($logicApp.Name)' has a system-assigned managed identity principal '$($logicApp.Identity.PrincipalId)'. Challenge 3 requires using only the precreated user-assigned identity '$($uami.Name)' ('$($uami.ResourceId)') for playbook runtime authorization."
            throw $lastFailure
        }

        $logicAppUamiAssociations = @(Get-ZavaLogicAppUserAssignedIdentityAssociations -LogicAppIdentity $logicApp.Identity)
        if (-not $logicAppUamiAssociations -or $logicAppUamiAssociations.Count -eq 0) {
            $lastFailure = "Logic App '$($logicApp.Name)' identity type is '$identityType' but no userAssignedIdentities association entries were returned. Attach precreated identity '$($uami.Name)' ('$($uami.ResourceId)')."
            throw $lastFailure
        }

        $matchedAssociation = @($logicAppUamiAssociations | Where-Object { ([string]$_.ResourceId).ToLowerInvariant() -eq ([string]$uami.ResourceId).ToLowerInvariant() } | Select-Object -First 1)
        if (-not $matchedAssociation -or $matchedAssociation.Count -eq 0) {
            $lastFailure = "Logic App '$($logicApp.Name)' is not associated with the required precreated user-assigned identity '$($uami.Name)'. Expected resourceId '$($uami.ResourceId)'. Actual userAssignedIdentities: $((@($logicAppUamiAssociations | ForEach-Object { $_.ResourceId })) -join ', ')."
            throw $lastFailure
        }
        $matchedAssociation = $matchedAssociation[0]

        if (-not [string]::IsNullOrWhiteSpace($matchedAssociation.PrincipalId) -and $matchedAssociation.PrincipalId -ne $uamiPrincipalId) {
            $lastFailure = "Logic App '$($logicApp.Name)' user-assigned identity association principalId '$($matchedAssociation.PrincipalId)' does not match deployed identity '$($uami.Name)' principalId '$uamiPrincipalId'."
            throw $lastFailure
        }
        if (-not [string]::IsNullOrWhiteSpace($matchedAssociation.ClientId) -and $matchedAssociation.ClientId -ne $uamiClientId) {
            $lastFailure = "Logic App '$($logicApp.Name)' user-assigned identity association clientId '$($matchedAssociation.ClientId)' does not match deployed identity '$($uami.Name)' clientId '$uamiClientId'."
            throw $lastFailure
        }

        if (-not (Test-ZavaWorkflowHasLearnerConfiguration -LogicApp $logicApp)) {
            $lastFailure = "Learner-created Logic App '$($logicApp.Name)' is only a starter or incomplete workflow. It must have a Microsoft Sentinel incident trigger and response actions configured by the learner, using the precreated user-assigned identity '$($uami.Name)' where supported. Platform/facilitator authorization must also allow Sentinel to invoke the playbook and the UAMI to update Sentinel comments and the lab NSG."
            throw $lastFailure
        }

        $workspaceResource = Get-ZavaResourceByPattern -ResourceType "Microsoft.OperationalInsights/workspaces" -NamePattern $workspaceNamePattern -PreferredResourceGroup $rg
        if ($null -eq $workspaceResource) {
            $lastFailure = "Log Analytics workspace matching '$workspaceNamePattern' was not found for RG '$rg'."
            throw $lastFailure
        }

        $workspace = Get-AzResource -ResourceId $workspaceResource.ResourceId -ExpandProperties -ErrorAction Stop
        $workspaceSecurityInsightsPath = "$($workspace.ResourceId)/providers/Microsoft.SecurityInsights"

        $alertRules = @(Invoke-ZavaPagedArmGet -PathOrUri "$workspaceSecurityInsightsPath/alertRules?api-version=2023-11-01")
        if (-not $alertRules -or $alertRules.Count -eq 0) {
            $lastFailure = "No Microsoft Sentinel analytics rules were returned for workspace '$($workspace.Name)'."
            throw $lastFailure
        }

        $learnerAlertRules = @($alertRules | Where-Object { $_.name -eq $learnerRuleName -or $_.properties.displayName -eq $learnerRuleName })
        if (-not $learnerAlertRules -or $learnerAlertRules.Count -eq 0) {
            $lastFailure = "Analytics rule '$learnerRuleName' was not found in workspace '$($workspace.Name)'."
            throw $lastFailure
        }

        $learnerRuleIdentifiers = @($learnerRuleName)
        foreach ($rule in $learnerAlertRules) {
            $learnerRuleIdentifiers += [string]$rule.name
            $learnerRuleIdentifiers += [string]$rule.id
            $learnerRuleIdentifiers += [string]$rule.properties.displayName
        }
        $learnerRuleIdentifiers = @($learnerRuleIdentifiers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

        $automationRules = @(Invoke-ZavaPagedArmGet -PathOrUri "$workspaceSecurityInsightsPath/automationRules?api-version=2023-11-01")
        if (-not $automationRules -or $automationRules.Count -eq 0) {
            $lastFailure = "No Microsoft Sentinel automation rules were returned for workspace '$($workspace.Name)'."
            throw $lastFailure
        }

        $automationRule = @($automationRules | Where-Object { $_.name -eq $automationRuleDisplayName -or $_.properties.displayName -eq $automationRuleDisplayName } | Select-Object -First 1)
        if (-not $automationRule -or $automationRule.Count -eq 0) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' was not found in workspace '$($workspace.Name)'."
            throw $lastFailure
        }
        $automationRule = $automationRule[0]

        $triggeringLogic = $automationRule.properties.triggeringLogic
        $isEnabled = $false
        if ($null -ne $triggeringLogic -and $null -ne $triggeringLogic.isEnabled) {
            $isEnabled = [System.Convert]::ToBoolean($triggeringLogic.isEnabled)
        }
        if (-not $isEnabled) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' exists but is not enabled for the learner-configured response."
            throw $lastFailure
        }

        $triggerTypeOk = ([string]$triggeringLogic.triggersOn -eq "Incidents") -and ([string]$triggeringLogic.triggersWhen -eq "Created")
        if (-not $triggerTypeOk) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' must trigger when incidents are created. Actual triggersOn='$($triggeringLogic.triggersOn)', triggersWhen='$($triggeringLogic.triggersWhen)'."
            throw $lastFailure
        }

        $runPlaybookActions = @($automationRule.properties.actions | Where-Object { [string]$_.actionType -eq "RunPlaybook" })
        if (-not $runPlaybookActions -or $runPlaybookActions.Count -eq 0) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' has no RunPlaybook action. Microsoft Sentinel must also have platform/facilitator-granted Microsoft Sentinel Automation Contributor on the playbook resource group so automation rules can invoke playbooks."
            throw $lastFailure
        }

        $playbookResourceIds = @($runPlaybookActions | ForEach-Object { [string]$_.actionConfiguration.logicAppResourceId } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $referencesPlaybook = $false
        foreach ($playbookResourceId in $playbookResourceIds) {
            if ($playbookResourceId -eq $logicApp.ResourceId -or $playbookResourceId -like "*/$($logicApp.Name)" -or $playbookResourceId -match [regex]::Escape($logicApp.Name)) {
                $referencesPlaybook = $true
                break
            }
        }
        if (-not $referencesPlaybook) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' RunPlaybook action does not reference learner-created Logic App '$($logicApp.Name)'. Referenced playbooks: $($playbookResourceIds -join ', ')."
            throw $lastFailure
        }

        $propertyConditions = @(Get-ZavaAutomationPropertyConditions -Node $triggeringLogic.conditions)
        $analyticsConditions = @($propertyConditions | Where-Object { $_.PropertyName -match "(?i)Analytic|AlertRule|IncidentRelatedAnalyticRuleIds|IncidentTitle|Title" })
        if (-not $analyticsConditions -or $analyticsConditions.Count -eq 0) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' has no condition limiting it to incidents from '$learnerRuleName'."
            throw $lastFailure
        }

        $automationConditionValues = @($analyticsConditions | ForEach-Object { $_.PropertyValues } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        if (-not $automationConditionValues -or $automationConditionValues.Count -eq 0) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' condition has no property values; it must target only '$learnerRuleName'."
            throw $lastFailure
        }

        $conditionTargetsLearnerRule = $false
        foreach ($value in $automationConditionValues) {
            if ($learnerRuleIdentifiers | Where-Object { $value -eq $_ -or $value -like "*$_*" -or $_ -like "*$value*" }) {
                $conditionTargetsLearnerRule = $true
                break
            }
        }
        if (-not $conditionTargetsLearnerRule) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' condition values do not reference '$learnerRuleName'. Values: $($automationConditionValues -join ', ')."
            throw $lastFailure
        }

        $nonLearnerConditionValues = @()
        foreach ($value in $automationConditionValues) {
            $matchesLearner = $false
            foreach ($identifier in $learnerRuleIdentifiers) {
                if ($value -eq $identifier -or $value -like "*$identifier*" -or $identifier -like "*$value*") {
                    $matchesLearner = $true
                    break
                }
            }
            if (-not $matchesLearner) {
                $nonLearnerConditionValues += $value
            }
        }
        if ($nonLearnerConditionValues.Count -gt 0) {
            $lastFailure = "Automation rule '$automationRuleDisplayName' is not scoped only to '$learnerRuleName'. Non-matching condition values: $($nonLearnerConditionValues -join ', ')."
            throw $lastFailure
        }

        $incidents = @(Invoke-ZavaPagedArmGet -PathOrUri "$workspaceSecurityInsightsPath/incidents?api-version=2023-11-01")
        if (-not $incidents -or $incidents.Count -eq 0) {
            $lastFailure = "No Sentinel incidents were returned for workspace '$($workspace.Name)'."
            throw $lastFailure
        }

        $matchingIncidents = @($incidents | Where-Object {
                $incidentJson = $_ | ConvertTo-Json -Depth 60 -Compress
                Test-ZavaTextContainsAny -Text $incidentJson -Needles $learnerRuleIdentifiers
            })
        if (-not $matchingIncidents -or $matchingIncidents.Count -eq 0) {
            $lastFailure = "No Sentinel incidents referencing '$learnerRuleName' were found in workspace '$($workspace.Name)'. Generate fresh failed-logon activity so the learner rule creates an incident before validating."
            throw $lastFailure
        }

        $latestIncident = @($matchingIncidents | Sort-Object { [datetime]$_.properties.createdTimeUtc } -Descending | Select-Object -First 1)[0]
        $latestIncidentCreatedTime = [datetime]$latestIncident.properties.createdTimeUtc
        if ($null -eq $latestIncidentCreatedTime) {
            $lastFailure = "Latest '$learnerRuleName' incident has no createdTimeUtc value. Incident resource name: '$($latestIncident.name)'."
            throw $lastFailure
        }

        $runHistory = @(Get-AzLogicAppRunHistory -ResourceGroupName $rg -Name $logicApp.Name -FollowNextPageLink -MaximumFollowNextPageLink 2 -ErrorAction Stop)
        if (-not $runHistory -or $runHistory.Count -eq 0) {
            $lastFailure = "Learner-created Logic App '$($logicApp.Name)' has no run history. The playbook must run after the latest '$learnerRuleName' incident is created. If the automation rule cannot invoke it, platform/facilitator authorization must include Microsoft Sentinel Automation Contributor for the Sentinel service account on RG '$rg'. The workflow itself must use UAMI '$($uami.Name)' principal '$uamiPrincipalId' for scoped actions."
            throw $lastFailure
        }

        $successfulRuns = @($runHistory | Where-Object {
                $_.Status -eq "Succeeded" -and (
                    ($_.StartTime -and ([datetime]$_.StartTime).ToUniversalTime() -ge $latestIncidentCreatedTime.ToUniversalTime()) -or
                    ($_.EndTime -and ([datetime]$_.EndTime).ToUniversalTime() -ge $latestIncidentCreatedTime.ToUniversalTime())
                )
            } | Sort-Object { if ($_.EndTime) { [datetime]$_.EndTime } else { [datetime]$_.StartTime } } -Descending)
        if (-not $successfulRuns -or $successfulRuns.Count -eq 0) {
            $lastFailure = "No successful Logic App run for '$($logicApp.Name)' occurred after latest '$learnerRuleName' incident creation time '$($latestIncidentCreatedTime.ToUniversalTime().ToString("o"))'. Verify both separate authorization paths: Sentinel Automation Contributor for the Sentinel service account on RG '$rg', and scoped permissions for the Logic App user-assigned identity '$($uami.Name)' principal '$uamiPrincipalId' to add Sentinel incident comments and update the lab NSG."
            throw $lastFailure
        }
        $successfulRun = $successfulRuns[0]
        $successfulRunTime = if ($successfulRun.EndTime) { [datetime]$successfulRun.EndTime } else { [datetime]$successfulRun.StartTime }

        $vmResource = Get-ZavaResourceByPattern -ResourceType "Microsoft.Compute/virtualMachines" -NamePattern $vmNamePattern -PreferredResourceGroup $rg
        if ($null -eq $vmResource) {
            $lastFailure = "VM matching '$vmNamePattern' was not found in RG '$rg'."
            throw $lastFailure
        }
        $vm = Get-AzVM -ResourceGroupName $vmResource.ResourceGroupName -Name $vmResource.Name -ErrorAction Stop
        $vmPrivateIps = @()
        foreach ($nicRef in @($vm.NetworkProfile.NetworkInterfaces)) {
            $nic = Get-AzNetworkInterface -ResourceId $nicRef.Id -ErrorAction Stop
            foreach ($ipConfig in @($nic.IpConfigurations)) {
                if (-not [string]::IsNullOrWhiteSpace($ipConfig.PrivateIpAddress)) {
                    $vmPrivateIps += $ipConfig.PrivateIpAddress
                }
            }
        }
        $vmPrivateIps = @($vmPrivateIps | Select-Object -Unique)

        $nsgResource = Get-ZavaResourceByPattern -ResourceType "Microsoft.Network/networkSecurityGroups" -NamePattern $nsgNamePattern -PreferredResourceGroup $rg
        if ($null -eq $nsgResource) {
            $lastFailure = "NSG matching '$nsgNamePattern' was not found in RG '$rg'."
            throw $lastFailure
        }
        $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $nsgResource.ResourceGroupName -Name $nsgResource.Name -ErrorAction Stop

        # Learner-created Challenge 3 containment end state: the playbook must create/update this custom NSG rule.
        $quarantineRule = @($nsg.SecurityRules | Where-Object { $_.Name -eq $quarantineRuleName } | Select-Object -First 1)
        if (-not $quarantineRule -or $quarantineRule.Count -eq 0) {
            $lastFailure = "NSG '$($nsg.Name)' does not contain learner-created security rule '$quarantineRuleName'. This rule is a runtime containment end state created or updated by the playbook, not an ARM prerequisite."
            throw $lastFailure
        }
        $quarantineRule = $quarantineRule[0]

        $denyInboundOk = ([string]$quarantineRule.Access -eq "Deny") -and ([string]$quarantineRule.Direction -eq "Inbound")
        if (-not $denyInboundOk) {
            $lastFailure = "Learner-created NSG rule '$quarantineRuleName' must be Deny/Inbound. Actual Access='$($quarantineRule.Access)', Direction='$($quarantineRule.Direction)'."
            throw $lastFailure
        }

        if (-not (Test-ZavaDestinationTargetsVm -Rule $quarantineRule -VmPrivateIps $vmPrivateIps)) {
            $destinationPrefixes = @(Get-ZavaRuleValues -Rule $quarantineRule -SingleProperty "DestinationAddressPrefix" -PluralProperty "DestinationAddressPrefixes")
            $lastFailure = "Learner-created NSG rule '$quarantineRuleName' denies inbound traffic but does not target all destinations, VirtualNetwork, an ASG, or VM private IP(s) '$($vmPrivateIps -join ', ')'. Destinations: $($destinationPrefixes -join ', ')."
            throw $lastFailure
        }

        $managementAllowRules = @($nsg.SecurityRules | Where-Object {
                $_.Access -eq "Allow" -and $_.Direction -eq "Inbound" -and [int]$_.Priority -lt [int]$quarantineRule.Priority
            } | Where-Object {
                $ports = @(Get-ZavaRuleValues -Rule $_ -SingleProperty "DestinationPortRange" -PluralProperty "DestinationPortRanges")
                $sources = @(Get-ZavaRuleValues -Rule $_ -SingleProperty "SourceAddressPrefix" -PluralProperty "SourceAddressPrefixes")
                $ruleText = "$($_.Name) $($_.Description) $($sources -join ' ') $($ports -join ' ')"
                $hasManagementPort = Test-ZavaPortSetIncludesManagementPort -Ports $ports
                $hasRestrictedSource = Test-ZavaRestrictedSource -Sources $sources
                $hasExplicitManagementText = $ruleText -match '(?i)cloudlabs|management|manager|bastion|guacamole|odl|shadow|lab access'
                ($hasExplicitManagementText -or ($hasManagementPort -and $hasRestrictedSource))
            })
        if (-not $managementAllowRules -or $managementAllowRules.Count -eq 0) {
            $lastFailure = "NSG '$($nsg.Name)' has learner-created quarantine deny rule '$quarantineRuleName' at priority '$($quarantineRule.Priority)', but no higher-precedence inbound Allow rule preserves CloudLabs or restricted management access."
            throw $lastFailure
        }

        $blockingBroadAllows = @($nsg.SecurityRules | Where-Object {
                $_.Access -eq "Allow" -and $_.Direction -eq "Inbound" -and [int]$_.Priority -lt [int]$quarantineRule.Priority
            } | Where-Object {
                $rule = $_
                $isManagementRule = $false
                foreach ($mgmtRule in $managementAllowRules) {
                    if ($mgmtRule.Name -eq $rule.Name) {
                        $isManagementRule = $true
                        break
                    }
                }
                if ($isManagementRule) {
                    return $false
                }
                $sources = @(Get-ZavaRuleValues -Rule $rule -SingleProperty "SourceAddressPrefix" -PluralProperty "SourceAddressPrefixes")
                (Test-ZavaAnySource -Sources $sources) -and (Test-ZavaDestinationTargetsVm -Rule $rule -VmPrivateIps $vmPrivateIps)
            })
        if ($blockingBroadAllows.Count -gt 0) {
            $lastFailure = "NSG '$($nsg.Name)' has broad inbound Allow rule(s) with higher precedence than learner-created '$quarantineRuleName': $((@($blockingBroadAllows | ForEach-Object { $_.Name })) -join ', '). The quarantine rule must isolate the VM while preserving only management access."
            throw $lastFailure
        }

        $incidentComments = @(Invoke-ZavaPagedArmGet -PathOrUri "$($latestIncident.id)/comments?api-version=2023-11-01")
        if (-not $incidentComments -or $incidentComments.Count -eq 0) {
            $lastFailure = "Latest '$learnerRuleName' incident '$($latestIncident.name)' has no incident comments."
            throw $lastFailure
        }

        $runTimeNeedles = @(
            $successfulRun.Name,
            $successfulRunTime.ToUniversalTime().ToString("o"),
            $successfulRunTime.ToUniversalTime().ToString("yyyy-MM-dd"),
            $successfulRunTime.ToUniversalTime().ToString("yyyy-MM-ddTHH")
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        $matchingComments = @($incidentComments | Where-Object {
                $message = [string]$_.properties.message
                (-not [string]::IsNullOrWhiteSpace($message)) -and
                ($message -match [regex]::Escape($commentMarker)) -and
                ($message -match [regex]::Escape($vm.Name)) -and
                ($message -match [regex]::Escape($quarantineRuleName)) -and
                ((Test-ZavaTextContainsAny -Text $message -Needles $runTimeNeedles) -or ($message -match '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}'))
            })
        if (-not $matchingComments -or $matchingComments.Count -eq 0) {
            $lastFailure = "Latest '$learnerRuleName' incident '$($latestIncident.name)' does not contain a comment with marker '$commentMarker', VM '$($vm.Name)', NSG rule '$quarantineRuleName', and the playbook run ID or UTC run timestamp."
            throw $lastFailure
        }

        $found = $true
        $message = @{
            Status  = "Succeeded"
            Message = "Challenge 3 automated response learner-created end state is valid: Logic App '$($logicApp.Name)' is associated with precreated user-assigned identity '$($uami.Name)' resourceId '$($uami.ResourceId)' principalId '$uamiPrincipalId' clientId '$uamiClientId' and has no system-assigned identity; automation rule '$automationRuleDisplayName' is enabled for '$learnerRuleName' incidents only and references the playbook, confirming the required platform/facilitator Sentinel Automation Contributor authorization path is usable; successful run '$($successfulRun.Name)' occurred at '$($successfulRunTime.ToUniversalTime().ToString("o"))' after incident '$($latestIncident.name)'; NSG '$($nsg.Name)' has learner-created '$quarantineRuleName' with management access preserved by '$($managementAllowRules[0].Name)'; incident comment marker '$commentMarker' was found."
        } | ConvertTo-Json
        Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $message
        })
    }
    catch {
        if ($_.Exception.Message -ne $lastFailure -and -not [string]::IsNullOrWhiteSpace($_.Exception.Message)) {
            $lastFailure = "Error during check. Attempt $count of 3. Error: $($_.Exception.Message)"
        }
        $message = @{
            Status  = "Failed"
            Message = $lastFailure
        } | ConvertTo-Json
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
        Message = "Challenge 3 automated response validation failed in RG '$rg' after 3 attempts. Last failure: $lastFailure"
    } | ConvertTo-Json
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $message
    })
}
