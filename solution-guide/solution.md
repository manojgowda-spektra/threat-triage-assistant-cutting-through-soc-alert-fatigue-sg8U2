# Facilitator Solution Guide

## Threat Triage Assistant: Cutting Through SOC Alert Fatigue

Assess observable outcomes rather than a particular portal sequence. The deployment supplies the infrastructure, Sentinel-enabled Log Analytics workspace, AMA readiness, baseline rules and incidents, seed data, helper scripts, and the precreated user-assigned managed identity (UAMI). The learner creates the DCR and association, two analytics rules, Logic App workflow, automation rule, and workbook.

## Microsoft Sentinel playbook and identity model

The following implementation facts are aligned with Microsoft Learn guidance for [automating threat response with playbooks](https://learn.microsoft.com/azure/sentinel/automation/automate-responses-with-playbooks), [authenticating playbooks to Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/automation/authenticate-playbooks-to-sentinel), and [assigning playbook permissions](https://learn.microsoft.com/azure/sentinel/automation/run-playbooks):

- A Microsoft Sentinel playbook is an Azure Logic Apps workflow. Automatic incident execution requires the Microsoft Sentinel **incident** trigger, an enabled automation rule, and permission for Microsoft Sentinel to run the playbook.
- Microsoft Sentinel's service account needs **Microsoft Sentinel Automation Contributor** on the resource group containing the playbook. This invocation permission is separate from permissions used by the workflow's actions.
- The learner creates or updates the Consumption Logic App `la-zava-isolate-notify-*` and attaches the precreated UAMI `id-zava-playbook-*`.
- The UAMI is the workflow's downstream execution identity. Deployment preassigns **Microsoft Sentinel Responder** for Sentinel incident operations and **Network Contributor** at the lab NSG scope for containment. The learner does not create or repair role assignments.
- Normal success does not depend on creating a system-assigned identity or on facilitator repair after Logic App creation. A system-assigned-only workflow does not satisfy the selected identity model.
- Managed connector connections and workflow actions must explicitly use the UAMI where supported. The existence of a managed identity does not prove that a connection or action is using it.
- If the playbook is absent from the automation-rule picker, first verify the Sentinel service account's Automation Contributor assignment. Do not grant Automation Contributor to the playbook UAMI as a substitute.
- NSG rules evaluate in ascending numeric priority. `Allow-RDP-CloudLabs` at priority `1000` must remain ahead of `Deny-Inbound-Zava-Quarantine`.
- Windows Security Events via AMA uses a DCR with a `windowsEventLogs` source, `Microsoft-SecurityEvent` stream, Log Analytics destination, data flow, and VM association. The DCR must be region-compatible with the VM.
- Azure workbooks are `Microsoft.Insights/workbooks`. Grade the visible `properties.displayName`, not the often-generated ARM resource name.

### Package exceptions and runtime boundaries

- **Daily cap:** The current ARM template remains authoritative and currently sets `workspaceCapping.dailyQuotaGb` to **2 GB/day**. Therefore this guide does not claim 3 GB/day. If the ARM value is subsequently changed to `3`, all cap references in this guide must be interpreted as 3 GB/day. Keep Windows Security Events at **Minimal** in either case.
- **Intentional no-auto-shutdown exception:** This package intentionally does not configure DevTestLab auto-shutdown or an equivalent schedule. The VM must remain available during pre-provisioning and the timed lab. Do not report this absence as deployment drift.
- **Legacy validator filename waiver:** Physical validators retain their existing `Validate-Challenge-0X-*` filenames while candidate pages use established validation tags without `.ps1`. Related filename/tag warnings are waived and are not learner failures.
- **Runtime boundary:** The DCR, DCR association, learner analytics rules, Logic App, automation rule, NSG quarantine rule, comments, tags, and workbook are learner-created runtime state. Their absence immediately after ARM deployment is expected. The UAMI and its role assignments are predeployed.

## Environment discovery

```bash
RG="the CloudLabs-assigned resource group name"
SUB=$(az account show --query id -o tsv)
LOCATION=$(az group show -n "$RG" --query location -o tsv)
LAW=$(az monitor log-analytics workspace list -g "$RG" --query "[?starts_with(name,'law-zava-soc-')].name | [0]" -o tsv)
VM=$(az vm list -g "$RG" --query "[?starts_with(name,'vm-zava-soc-')].name | [0]" -o tsv)
NSG=$(az network nsg list -g "$RG" --query "[?starts_with(name,'nsg-zava-workload-')].name | [0]" -o tsv)
UAMI=$(az identity list -g "$RG" --query "[?starts_with(name,'id-zava-playbook-')].name | [0]" -o tsv)
LAW_ID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query id -o tsv)
WS_GUID=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query customerId -o tsv)
VM_ID=$(az vm show -g "$RG" -n "$VM" --query id -o tsv)
NSG_ID=$(az network nsg show -g "$RG" -n "$NSG" --query id -o tsv)
UAMI_ID=$(az identity show -g "$RG" -n "$UAMI" --query id -o tsv)
UAMI_PRINCIPAL=$(az identity show -g "$RG" -n "$UAMI" --query principalId -o tsv)
```

```powershell
$rg = 'the CloudLabs-assigned resource group name'
$law = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg | Where-Object Name -Like 'law-zava-soc-*' | Select-Object -First 1
$vm = Get-AzVM -ResourceGroupName $rg | Where-Object Name -Like 'vm-zava-soc-*' | Select-Object -First 1
$nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $rg | Where-Object Name -Like 'nsg-zava-workload-*' | Select-Object -First 1
$uami = Get-AzUserAssignedIdentity -ResourceGroupName $rg | Where-Object Name -Like 'id-zava-playbook-*' | Select-Object -First 1
```

Expected resources include workspace `law-zava-soc-*`, VM `vm-zava-soc-*`, NSG `nsg-zava-workload-*`, UAMI `id-zava-playbook-*`, seed table `ZavaSOCSeed_CL`, and management rule `Allow-RDP-CloudLabs` at priority `1000`.

Verify cap, diagnostics, and predeployed UAMI access:

```bash
az monitor log-analytics workspace show -g "$RG" -n "$LAW" --query "{dailyQuotaGb:workspaceCapping.dailyQuotaGb,retention:retentionInDays}" -o json
az monitor diagnostic-settings list --resource "$NSG_ID" --query "value[].{name:name,workspaceId:workspaceId,logs:logs}" -o json
az role assignment list --assignee-object-id "$UAMI_PRINCIPAL" --include-inherited --all --query "[].{role:roleDefinitionName,scope:scope}" -o table
```

Expected current cap: `2`. Expected UAMI roles include Microsoft Sentinel Responder at the deployed Sentinel/workspace scope and Network Contributor at the exact lab NSG scope. Expected NSG diagnostic categories are `NetworkSecurityGroupEvent` and `NetworkSecurityGroupRuleCounter`.

## Getting Started — Confirm the sandbox and record triage start

**Expected end state:** The correct subscription, resource group, workspace, VM, NSG, and UAMI are identified; Sentinel is already onboarded; seeded incidents are visible; the baseline is unchanged; and a UTC triage-start timestamp is recorded.

**Rubric**

- **Full credit:** Correct environment, existing incident queue, no duplicate onboarding, and UTC start recorded.
- **Partial credit:** Correct environment but missing/local timestamp or a harmless baseline edit was restored.
- **No credit:** Wrong workspace/subscription, duplicate onboarding, or deleted baseline state.

```bash
az rest --method get --url "https://management.azure.com${LAW_ID}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01"
az monitor log-analytics query -w "$WS_GUID" --analytics-query "SecurityIncident | where TimeGenerated > ago(7d) | summarize Incidents=count(), Latest=max(TimeGenerated)" -o table
```

**Common pitfalls:** Wrong Defender workspace context, query range shorter than the seed window, or attempting first-time Sentinel enablement.

## Challenge 1 — Establish Unified Detection

### Task 1: Confirm assets and preserve the baseline

**Expected end state:** Work is limited to the assigned workspace. The four baseline rules remain intact: `ZAVA-Noise-Repeated-Policy-Change`, `ZAVA-Noise-Administrative-Enumeration`, `ZAVA-Noise-Failed-Storage-Access`, and `ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change`.

**Rubric:** Full credit for correct scope and preserved rules; partial for a restored reversible edit; no credit for deleting baseline rules or using another workspace.

**Common pitfalls:** Assuming the learner DCR is precreated or confusing seeded rules with learner rules.

### Task 2: Create and associate the Windows Security Events DCR

**Expected end state:** Learner-created `dcr-zava-securityevents-*` is region-compatible, sends `Microsoft-SecurityEvent` to the lab workspace, collects the Minimal set including 4625, and is associated with the VM.

```bash
DCR=$(az resource list -g "$RG" --resource-type Microsoft.Insights/dataCollectionRules --query "[?starts_with(name,'dcr-zava-securityevents-')].name | [0]" -o tsv)
DCR_ID=$(az resource show -g "$RG" -n "$DCR" --resource-type Microsoft.Insights/dataCollectionRules --query id -o tsv)
az resource show --ids "$DCR_ID" --query "{location:location,sources:properties.dataSources.windowsEventLogs,destinations:properties.destinations.logAnalytics,flows:properties.dataFlows}" -o json
az rest --method get --url "https://management.azure.com${VM_ID}/providers/Microsoft.Insights/dataCollectionRuleAssociations?api-version=2023-03-11" --query "value[].properties.dataCollectionRuleId" -o tsv
```

**Rubric:** Full credit for correct name, region, source, stream, destination, Minimal selection, and association; partial for an incomplete destination/association; no credit for legacy-agent-only collection or broad collection left enabled.

**Common pitfalls:** Wrong region, malformed XPath, no association, associating only a DCE, or selecting Common/All and reaching the workspace cap.

### Task 3: Generate and verify endpoint signals

**Expected end state:** The staged helper creates fresh benign failed logons and bounded KQL returns current VM-specific 4625 rows.

```powershell
& 'C:\LabFiles\Scripts\Generate-ZavaEndpointSignals.ps1'
```

```kusto
SecurityEvent
| where TimeGenerated between (ago(2h) .. now())
| where EventID == 4625
| where Computer startswith "vm-zava-soc-" or _ResourceId has "/virtualMachines/vm-zava-soc-"
| summarize Events=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Computer, _ResourceId
```

**Rubric:** Full credit for fresh VM-specific rows; partial for stale or weakly attributed rows; no credit for unrelated data.

**Common pitfalls:** AMA latency, querying before association convergence, daily-cap suspension, or recreating resources while telemetry is in flight.

### Task 4: Create the failed-logon analytics rule

**Expected end state:** Enabled scheduled rule `ZAVA-Learner-Failed-VM-Logons` detects multiple recent 4625 events, maps useful entities, and creates incidents.

**Rubric:** Full credit for exact name, enabled rule, valid threshold/schedule, entity mapping, and incident creation; partial for weak mappings; no credit for disabled/invalid/misnamed rule.

**Common pitfalls:** Threshold above helper output, omitted `TimeGenerated`, or incident creation disabled.

### Task 5: Create endpoint-and-Azure correlation

**Expected end state:** Enabled `ZAVA-Learner-Endpoint-And-Azure-Correlation` correlates fresh endpoint data with `AzureActivity` or seeded evidence through normalized VM/resource/IP keys and bounded windows. A `union` alone is insufficient.

**Rubric:** Full credit for exact name, meaningful join, bounded windows, and incident evidence; partial for weak normalization; no credit for unrelated tables merely displayed together.

**Common pitfalls:** Joining a full resource ID directly to a computer name, dynamic/null keys, or seed data satisfying both sides.

### Task 6: Prove unified incidents and document evidence

**Expected end state:** Both learner rules generate alert/incident evidence. One learner-created incident has tag `Challenge1-UnifiedDetection` and a comment containing `Challenge1-UnifiedDetection confirmed` plus source, rule, and incident number.

```bash
az rest --method get --url "https://management.azure.com${LAW_ID}/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" --query "value[?properties.displayName=='ZAVA-Learner-Failed-VM-Logons' || properties.displayName=='ZAVA-Learner-Endpoint-And-Azure-Correlation'].{name:properties.displayName,enabled:properties.enabled}" -o table
```

**Rubric:** Full credit for both enabled rules, incidents, exact tag, and comment marker; partial for one missing artifact; no credit when evidence is attached only to a seeded incident.

**Common pitfalls:** Confusing custom details with incident tags or waiting on `SecurityIncident` projection when the incident API already shows the update.

## Challenge 2 — Correlate and Investigate with KQL

### Task 1: Identify the hidden true positive

**Expected end state:** Learner selects the incident from `ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change` and supports the decision using overlapping VM, identity, source IP, NSG activity, and time.

```kusto
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Title has "ZAVA-TruePositive-Suspicious-VM-Access-And-NSG-Change"
| project IncidentNumber, Title, CreatedTime, Severity, Status, Labels
```

**Rubric:** Full credit for the correct incident and evidence-based rationale; partial for title/severity-only reasoning; no credit for a noise incident.

**Common pitfalls:** Selecting only the newest/highest-severity item or overlooking incident snapshots.

### Task 2: Hunt across at least three tables

**Expected end state:** Reproducible, bounded KQL uses at least three relevant tables, normalizes entities, and constructs or ranks a defensible timeline. Valid sources include `SecurityIncident`, `SecurityAlert`, `SecurityEvent`, `AzureActivity`, `AzureDiagnostics`, and `ZavaSOCSeed_CL`.

**Rubric:** Full credit for three correlated sources and time/entity reasoning; partial when three tables are queried but not correlated; no credit for portal narrative alone.

**Common pitfalls:** Omitting `arg_max()` for snapshots, treating dynamic entities as scalar text, or assuming alert IDs equal incident IDs.

### Task 3: Document scope and conclusion

**Expected end state:** Notes identify affected VM, identity, source IP, UTC timeline, evidence tables, root cause, severity/status decision, and containment recommendation.

**Rubric:** Full credit for complete evidence-backed scope; partial for one or two missing fields; no credit for unsupported disposition.

**Common pitfalls:** Substituting the later benign account/IP pair, omitting UTC, or tuning the true-positive rule.

### Task 4: Preserve traceable artifacts

**Expected end state:** A saved hunting query or bookmark begins `ZAVA-Hunt-TruePositive`. The correct incident has tag `Challenge2-Investigated` and a comment containing the marker, root cause, scope, evidence tables, and recommendation.

**Rubric:** Full credit for all artifacts on the correct incident; partial for one missing/misnamed artifact; no credit when markers are on another incident.

**Common pitfalls:** Leaving an unsaved query or writing a portal note instead of an incident comment.

## Challenge 3 — Build the Automated Response Playbook

### Task 1: Confirm design, identity, and platform prerequisites

**Expected end state:** Learner identifies the NSG, preserved RDP rule, triggering analytics rule, and precreated `id-zava-playbook-*` UAMI. The learner distinguishes Sentinel-to-playbook invocation from playbook-to-Sentinel/NSG authorization.

```bash
az network nsg rule list -g "$RG" --nsg-name "$NSG" --query "sort_by([?direction=='Inbound'].{name:name,priority:priority,access:access},&priority)" -o table
az identity show -g "$RG" -n "$UAMI" --query "{id:id,principalId:principalId,clientId:clientId}" -o json
az role assignment list --assignee-object-id "$UAMI_PRINCIPAL" --include-inherited --all --query "[].{role:roleDefinitionName,scope:scope}" -o table
az role assignment list --resource-group "$RG" --role "Microsoft Sentinel Automation Contributor" --include-inherited --query "[].{principal:principalName,principalType:principalType,scope:scope}" -o table
```

**Rubric:** Full credit for correct targets, preserved management path, precreated-UAMI selection, and accurate separation of the two permission paths; partial for incomplete design; no credit for all-incidents/wrong-NSG design or learner-created RBAC.

**Common pitfalls:** Selecting another managed identity, confusing Automation Contributor with downstream permissions, or trying to create role assignments.

### Task 2: Create or update the incident-triggered Logic App

**Expected end state:** Enabled Consumption Logic App `la-zava-isolate-notify-*` uses the Microsoft Sentinel incident trigger, parses incident/entities, performs a guarded NSG update, and adds an incident comment. The workflow has the precreated UAMI attached.

```bash
LA=$(az logic workflow list -g "$RG" --query "[?starts_with(name,'la-zava-isolate-notify-')].name | [0]" -o tsv)
az logic workflow show -g "$RG" -n "$LA" --query "{name:name,state:state,identity:identity,definition:definition}" -o json
```

A satisfactory identity object contains `UserAssigned` and a `userAssignedIdentities` key equal to `$UAMI_ID`.

**Rubric:** Full credit for learner-created/updated enabled Consumption workflow, incident trigger, attached designated UAMI, and guarded action sequence; partial for incomplete actions; no credit for Standard, recurrence/manual-only, alert trigger, system-assigned-only identity, or a different UAMI.

**Common pitfalls:** Enabling system-assigned identity instead of attaching the supplied UAMI, wrong hosting model, alert fields used as incident fields, or duplicate workflows after portal delay.

### Task 3: Verify UAMI authentication and predeployed access

**Expected end state:** The Logic App identity references `id-zava-playbook-*`; Sentinel and Azure Resource Manager actions use that identity where supported; no secrets or personal-user fallback are embedded; and the predeployed role assignments remain intact.

```bash
LA_ID=$(az logic workflow show -g "$RG" -n "$LA" --query id -o tsv)
az logic workflow show -g "$RG" -n "$LA" --query "{identityType:identity.type,userAssigned:identity.userAssignedIdentities,parameters:parameters}" -o json
az resource list -g "$RG" --resource-type Microsoft.Web/connections --query "[].{name:name,status:properties.statuses[0].status,api:properties.api.id,parameterValues:properties.parameterValueSet}" -o json
az role assignment list --assignee-object-id "$UAMI_PRINCIPAL" --include-inherited --all --query "[].{role:roleDefinitionName,scope:scope}" -o table
```

```powershell
$logicApp = Get-AzLogicApp -ResourceGroupName $rg | Where-Object Name -Like 'la-zava-isolate-notify-*' | Select-Object -First 1
Get-AzResource -ResourceId $logicApp.Id -ExpandProperties | Select-Object Name,Identity,Properties
Get-AzRoleAssignment -ObjectId $uami.PrincipalId | Select-Object RoleDefinitionName,Scope
```

**Rubric**

- **Full credit:** Correct UAMI attached and used, predeployed Responder and NSG-scoped Network Contributor visible, authenticated actions valid, and no embedded credentials.
- **Partial credit:** Correct UAMI is attached but a connector binding is incomplete or RBAC propagation is still converging.
- **No credit:** Missing/wrong UAMI, system-assigned-only model, personal-user fallback, embedded secrets, or learner-created broad role assignments.

**Common pitfalls:** Assuming attachment automatically changes an existing connection's authentication, using a stale cross-tenant connection, testing before RBAC propagation, or granting Automation Contributor to the UAMI.

### Task 4: Implement safe NSG containment and incident comment

**Expected end state:** Workflow idempotently creates or updates `Deny-Inbound-Zava-Quarantine` on the lab NSG. It is an inbound deny with a unique priority greater than `1000` but ahead of workload allows it must supersede. The workflow reads back the rule and reports success only after the NSG action succeeds.

```bash
az network nsg rule show -g "$RG" --nsg-name "$NSG" -n Deny-Inbound-Zava-Quarantine --query "{priority:priority,access:access,direction:direction,source:sourceAddressPrefix,destination:destinationAddressPrefix,ports:destinationPortRange}" -o json
az network nsg rule list -g "$RG" --nsg-name "$NSG" --query "sort_by([?direction=='Inbound'].{name:name,priority:priority,access:access},&priority)" -o table
```

Required comment shape:

```text
Challenge3-AutomatedContainment | Incident=actual incident title | VM=actual vm-zava-soc name | NSGRule=Deny-Inbound-Zava-Quarantine | UTC=actual ISO-8601 UTC time | RunId=actual Logic App run identifier
```

**Rubric:** Full credit for exact rule, idempotence, safe priority, preserved RDP allow, read-back/failure handling, and runtime-valued comment; partial for safe containment with weak audit handling; no credit if management is blocked or success is reported after failure.

**Common pitfalls:** Priority below `1000`, occupied priority, replacing the NSG, or using workflow name instead of run ID.

### Task 5: Create the exact automation rule

**Expected end state:** Enabled `AR-ZAVA-Auto-Isolate-VM` runs on incident creation, is conditioned on `ZAVA-Learner-Failed-VM-Logons`, and has one run-playbook action targeting the learner Logic App.

```bash
az rest --method get --url "https://management.azure.com${LAW_ID}/providers/Microsoft.SecurityInsights/automationRules?api-version=2024-03-01" --query "value[?properties.displayName=='AR-ZAVA-Auto-Isolate-VM'].properties" -o json
```

**Rubric:** Full credit for exact name, enabled state, created-only trigger, exact analytics-rule condition, and correct playbook; partial for an unnecessary extra condition; no credit for all-incidents, update loops, or manual invocation only.

**Common pitfalls:** Filtering only on title, using created-or-updated and causing comment loops, or modifying UAMI RBAC when the playbook picker issue is actually the Sentinel service account's Automation Contributor assignment.

### Task 6: Prove end-to-end automation

**Expected end state:** Fresh failed-logon activity creates a new incident, starts a successful automatic Logic App run, writes the NSG rule, and adds the required comment to the same incident. Reset occurs only after evidence capture.

```bash
az logic workflow run list -g "$RG" -n "$LA" --query "[].{runId:name,status:status,start:startTime,end:endTime}" -o table
az monitor activity-log list -g "$RG" --offset 2h --query "[?contains(resourceId,'networkSecurityGroups')].{time:eventTimestamp,status:status.value,operation:operationName.value,resource:resourceId}" -o table
```

**Rubric:** Full credit for one coherent automatic chain with matching incident/time/run evidence; partial for a manual designer test; no credit when workflow success lacks NSG/comment evidence.

**Common pitfalls:** Stale runs, continue-on-error masking failure, scheduled-rule latency, RBAC propagation delay, or resetting containment too early.

## Challenge 4 — Validate, Tune, and Report

### Task 1: Establish manual containment time

**Expected end state:** Learner records incident number, UTC start/stop, elapsed seconds, decision, affected entity, and rationale with the staged timer or equivalent evidence.

```powershell
& 'C:\LabFiles\Scripts\Start-ZavaManualContainmentTimer.ps1'
& 'C:\LabFiles\Scripts\Stop-ZavaManualContainmentTimer.ps1'
Get-Content 'C:\LabFiles\zava-containment-timer.json' -Raw
```

**Rubric:** Full credit for reproducible UTC evidence and decision context; partial for one missing field; no credit for an unsupported estimate.

**Common pitfalls:** Mixed time zones, timing portal navigation rather than analysis, or modifying the NSG during the manual baseline.

### Task 2: Measure automated containment time

**Expected end state:** Measurement starts at fresh incident `CreatedTime` and ends at the matching NSG rule write. Logic App run ID/times corroborate the chain.

```kusto
let incidents = SecurityIncident
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Title has "ZAVA-Learner-Failed-VM-Logons"
| project IncidentNumber, IncidentCreated=CreatedTime;
let writes = AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue has "securityRules/write"
| where ResourceId has "/networkSecurityGroups/nsg-zava-workload-"
| project NSGWriteTime=TimeGenerated, ResourceId, CorrelationId;
incidents
| extend JoinKey=1
| join kind=inner (writes | extend JoinKey=1) on JoinKey
| where NSGWriteTime >= IncidentCreated
| extend AutomatedSeconds=datetime_diff("second", NSGWriteTime, IncidentCreated)
| top 1 by NSGWriteTime asc
```

**Rubric:** Full credit for correlated incident, NSG write, and run; partial for workflow duration only; no credit for unrelated historical events.

**Common pitfalls:** Joining incident ID to Activity correlation ID, measuring run start instead of containment, or ignoring ingestion latency.

### Task 3: Tune the noisy rule

**Expected end state:** `ZAVA-Noise-Administrative-Enumeration` remains enabled and excludes only the paired benign source `svc-zava-audit@zavacorp.example` from `198.51.100.23`.

```kusto
| where not(Account =~ "svc-zava-audit@zavacorp.example" and SourceIp == "198.51.100.23")
```

```bash
az rest --method get --url "https://management.azure.com${LAW_ID}/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" --query "value[?properties.displayName=='ZAVA-Noise-Administrative-Enumeration'].{enabled:properties.enabled,query:properties.query}" -o json
```

**Rubric:** Full credit for enabled rule and paired exclusion; partial for independently broad exclusions; no credit for disabling the rule or omitting either literal.

**Common pitfalls:** Using `or` inside `not`, field-name mismatch, or expecting historical incidents to disappear.

### Task 4: Prove reduction and retained coverage

**Expected end state:** Learner records actual UTC tuning time, compares equivalent before/after windows, and proves true-positive and failed-logon rules remain enabled and functional. A representative noise incident comment contains `Challenge4-TunedFalsePositive` and rationale.

**Rubric:** Full credit for equal windows, reduced benign volume, retained/fresh detections, and exact marker; partial for too short an observation period; no credit for disabled/broken coverage.

**Common pitfalls:** Unequal windows, repeated incident snapshots, assuming tuning is retroactive, or placing the marker in a rule description.

### Task 5: Create the shared workbook

**Expected end state:** Shared workbook visible display name begins `wb-zava-triage-report-`, `sourceId` equals `$LAW_ID`, and the definition contains incident volume, true-positive timeline, manual-versus-automated timing, noise reduction, and containment status.

```bash
WB_ARM_NAME=$(az resource list -g "$RG" --resource-type Microsoft.Insights/workbooks --query "[?starts_with(properties.displayName,'wb-zava-triage-report-')].name | [0]" -o tsv)
az resource show -g "$RG" -n "$WB_ARM_NAME" --resource-type Microsoft.Insights/workbooks --query "{armName:name,displayName:properties.displayName,sourceId:properties.sourceId,serializedData:properties.serializedData}" -o json
```

**Rubric:** Full credit for shared workbook, correct display name/source, and all five sections; partial for three or four sections; no credit for a private/unsaved workbook or wrong workspace. Never fail a valid workbook because its ARM name is a GUID.

**Common pitfalls:** Validating the ARM name instead of `properties.displayName`, wrong `sourceId`, stale-name/soft-delete conflicts, or repeated refreshes causing throttling.

### Task 6: Document and validate final state

**Expected end state:** Representative tuned-noise incident contains `Challenge4-TunedFalsePositive`, exact benign pair, retained-coverage statement, and measured timing comparison or workbook reference. Validation uses `Validate-Challenge-04-TuneAndReport` without adding `.ps1` to the displayed tag.

**Rubric:** Full credit for complete comment, workbook, retained coverage, timing evidence, and successful validation; partial for incomplete comment/timing evidence; no credit for missing marker or workbook.

**Common pitfalls:** Commenting on the wrong incident, resetting containment before evidence capture, or treating the legacy validator filename warning as a learner failure.

## Final validation expectations

- **`Validate-Challenge-01-UnifiedDetection`:** DCR and VM association, recent VM 4625 rows, both enabled learner rules, learner incident evidence, and exact Challenge 1 tag/comment.
- **`Validate-Challenge-02-Investigation`:** Seeded true-positive incident, exact Challenge 2 tag/comment, at least three evidence tables, and a `ZAVA-Hunt-TruePositive*` artifact where exposed by the API.
- **`Validate-Challenge-03-AutomatedResponse`:** Consumption Logic App with the precreated `id-zava-playbook-*` UAMI attached, exact automation scope, successful run after a matching incident, safe NSG ordering, preserved RDP rule, and deterministic comment. A system-assigned-only identity fails this model. Workflow success alone is insufficient.
- **`Validate-Challenge-04-TuneAndReport`:** Enabled paired tuning, reduced-noise evidence, retained detections, exact marker, shared workbook with correct visible display name/source and five sections, and actual timing evidence.

The physical validator scripts intentionally retain legacy filenames. Existing validation tags omit `.ps1`; related lint warnings are waived.

## Cross-cutting troubleshooting

### Sentinel, Logic Apps, and RBAC

- Verify trigger history before action history; `Skipped` normally indicates a condition mismatch.
- Inspect action inputs and outputs rather than relying only on overall run status.
- Confirm `identity.type` contains `UserAssigned` and `identity.userAssignedIdentities` contains the exact precreated UAMI resource ID.
- Confirm each managed connection/action is configured to use that UAMI; attachment alone does not rewrite an existing connection.
- The Sentinel service account's Automation Contributor assignment authorizes Sentinel to invoke playbooks. It does not authorize workflow actions.
- The UAMI's predeployed Sentinel Responder and NSG-scoped Network Contributor assignments authorize downstream operations. Learners do not add or repair these assignments.
- RBAC and connector authorization can take time to propagate. Retry with backoff rather than creating identities, assignments, connections, or workflows repeatedly.

### AMA, DCR, and workspace cap

- Check DCR region, Minimal event selection, stream, destination, association, AMA health, local Security log, and cap in that order.
- Current ARM cap is 2 GB/day; use 3 GB/day only after the ARM source of truth changes to 3.
- A DCR can exist without collecting until an association exists. Data arrival also does not imply immediate rule execution.
- Do not install the legacy Log Analytics agent.

### NSG containment

- Lower numeric priority evaluates first. Preserve `Allow-RDP-CloudLabs` at `1000`.
- Enumerate occupied priorities; `1100` is acceptable only when unused and before workload allows that quarantine must supersede.
- Do not delete or replace the NSG, NIC, public IP, management rule, or NSG diagnostic setting.

### Azure platform issues

- Wrong region commonly blocks DCR association or collection.
- Soft-deleted or stale resources can block recreation under a desired name.
- Azure Activity, Log Analytics, Logic Apps, workbooks, and storage-backed operations have independent latency and throttling. Retry with backoff instead of changing SKU or creating duplicates.
- No VM auto-shutdown is configured by intentional waiver; do not flag its absence.
