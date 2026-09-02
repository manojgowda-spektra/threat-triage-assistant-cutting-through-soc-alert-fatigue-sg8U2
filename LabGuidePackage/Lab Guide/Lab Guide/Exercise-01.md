# Challenge 1: Establish Unified Detection

### Estimated Duration: 1.25 Hour(s)

## Scenario

Zava Corporation's SOC already has Microsoft Sentinel enabled and receiving baseline Azure and seeded SOC telemetry. Your first challenge is to close the endpoint visibility gap: bring Windows Security Events from the lab VM into the same Sentinel workspace, create learner-owned detections, and prove that endpoint and Azure evidence both land in the unified incident queue.

## Overview

In this challenge, you will configure Windows Security Events collection through the Azure Monitor Agent (AMA) by creating a new Data Collection Rule (DCR) for this lab deployment. You must use the **Minimal** Windows Security Events set so required failed-logon evidence reaches the **SecurityEvent** table without exhausting the short-lab ingestion allowance. You will verify failed logon events in **SecurityEvent**, create two scheduled analytics rules, and document a learner-created incident with the required tag and comment marker.

Use the Microsoft Defender portal as your primary SOC experience. If you are prompted to sign in again, use:

- User: <inject key="AzureAdUserEmail"></inject>
- Password: <inject key="AzureAdUserPassword"></inject>

Use subscription <inject key="SubscriptionID"></inject>, tenant <inject key="TenantID"></inject>, and resource group **<inject key="resourceGroupName"></inject>**.

## Objectives

- Task 1: Confirm the Sentinel workspace and lab assets for this challenge.
- Task 2: Create and configure Windows Security Events via AMA with a new lab DCR.
- Task 3: Generate and validate fresh failed logon telemetry.
- Task 4: Create the failed VM logon analytics rule.
- Task 5: Create the endpoint-and-Azure correlation analytics rule.
- Task 6: Confirm unified incidents and add the required tag and comment.

## Task 1: Confirm the Sentinel workspace and lab assets

In this task, you will identify the resources you will use throughout Challenge 1 and avoid changing the pre-provisioned baseline rules.

1. Sign in to the Microsoft Defender portal at <https://security.microsoft.com> with the lab credentials shown above.
2. Confirm that Microsoft Sentinel is available and that the active workspace is **<inject key="logAnalyticsWorkspaceName"></inject>**.
3. Confirm the following lab resources exist in **<inject key="resourceGroupName"></inject>**:
   1. Windows VM: **<inject key="labVmName"></inject>**.
   2. Network security group: **<inject key="networkSecurityGroupName"></inject>**.
   3. Virtual network: locate by prefix **vnet-zava-soc-**.
4. In Microsoft Defender portal, use **Microsoft Sentinel > Configuration > Analytics** when reviewing existing analytics rules.
5. Review the existing incident queue briefly. You should see pre-seeded incidents from baseline ZAVA rules. Do not disable or tune those rules in this challenge.
6. Record the current UTC time as your Challenge 1 start time. Use this value when you choose KQL lookback windows later.

> [!Important]
> This lab starts after Microsoft Sentinel has already been enabled. Do not perform first-time Sentinel enablement, tenant-wide connector setup, or unrelated content hub installation.

## Task 2: Create and configure Windows Security Events via AMA with a new lab DCR

In this task, you will connect the lab VM's Windows Security log to the Sentinel workspace by creating a DCR, associating it with the VM, and selecting the required collection set that includes failed logon events.

1. In Microsoft Defender portal, use **Microsoft Sentinel > Configuration > Data connectors** and open **Windows Security Events via AMA**.
2. Start the workflow to add or create a data collection rule for the connector.
3. Create a new DCR named exactly **dcr-zava-securityevents-<inject key="DeploymentID" enableCopy="false"/>**.
   - If the portal enforces uniqueness or adds a suffix, keep the exact prefix **dcr-zava-securityevents-<inject key="DeploymentID" enableCopy="false"/>** so the DCR is clearly tied to this lab deployment.
4. Create the DCR in subscription <inject key="SubscriptionID"></inject> and resource group **<inject key="resourceGroupName"></inject>**.
5. Set or confirm the destination workspace as **<inject key="logAnalyticsWorkspaceName"></inject>**. When you create the DCR from the Sentinel connector page, the selected Sentinel workspace should provide this destination context.
6. In the DCR resources step, add and associate the VM **<inject key="labVmName"></inject>**.
7. Select the **Minimal** Windows Security Events set. The Minimal set includes sign-in evidence such as successful and failed logon events, including Event ID 4625, while avoiding unnecessary audit volume.
8. Do not select **Common** or **All events** for this lab. Those event sets can generate enough **SecurityEvent** ingestion to hit the workspace's **2 GB/day** cap, which can stop later evidence from arriving and can break downstream detections, workbook queries, and validations.
9. Review and create the DCR. Wait until the portal shows validation success and the create operation completes.
10. Confirm the Azure Monitor Agent is present on the VM and that the DCR resources view lists **<inject key="labVmName"></inject>** as an associated resource.
11. Allow several minutes for the DCR association to reach the VM and for the first telemetry to arrive.

> [!Important]
> Use **Minimal** exactly for this challenge. If you accidentally choose **Common** or **All events**, return to the DCR configuration and correct it to **Minimal** before generating additional endpoint activity.

> [!Tip]
> The AMA extension showing provisioning success confirms that the extension package was installed. Data flow is proven only after workspace queries return current rows from the VM.

## Task 3: Generate and validate fresh failed logon telemetry

In this task, you will create benign endpoint activity, then use KQL to prove that failed logon evidence is flowing to **SecurityEvent**.

1. On the Windows lab VM, run the staged helper script **C:\LabFiles\Scripts\Generate-ZavaEndpointSignals.ps1** from an elevated PowerShell session. A convenience copy may also be available on the Public Desktop.
2. Wait 5 minutes, then query the Sentinel workspace logs for the VM's AMA heartbeat:

   ```kusto
   Heartbeat
   | where TimeGenerated > ago(30m)
   | where Category == "Azure Monitor Agent"
   | where Computer startswith "vm-zava-soc-" or _ResourceId has "/virtualMachines/vm-zava-soc-"
   | summarize Samples=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Computer, _ResourceId
   | order by LastSeen desc
   ```

3. Query for recent Windows failed logons in **SecurityEvent**:

   ```kusto
   SecurityEvent
   | where TimeGenerated > ago(2h)
   | where EventID == 4625
   | where Computer startswith "vm-zava-soc-" or _ResourceId has "/virtualMachines/vm-zava-soc-"
   | project TimeGenerated, Computer, Account, TargetAccount, TargetUserName, IpAddress, WorkstationName, Activity, LogonTypeName, _ResourceId
   | order by TimeGenerated desc
   ```

4. If the query returns no rows, wait another 5 minutes and retry. Use a bounded retry pattern for ingestion latency rather than widening the query to the entire retention period.
5. Summarize the failed logon pattern so you know whether the analytics rule threshold will be met:

   ```kusto
   SecurityEvent
   | where TimeGenerated > ago(2h)
   | where EventID == 4625
   | where Computer startswith "vm-zava-soc-" or _ResourceId has "/virtualMachines/vm-zava-soc-"
   | summarize FailedLogons=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), SourceIps=make_set(IpAddress, 20), Accounts=make_set(TargetAccount, 20) by Computer, _ResourceId, bin(TimeGenerated, 15m)
   | where FailedLogons >= 3
   | order by LastSeen desc
   ```

> [!Note]
> Microsoft Sentinel scheduled analytics rules require queries that return **TimeGenerated** within the configured lookback period. Keep this column in your rule outputs.

## Task 4: Create the failed VM logon analytics rule

In this task, you will create a scheduled analytics rule named **ZAVA-Learner-Failed-VM-Logons** that turns repeated failed logons from the lab VM into alerts and incidents.

1. In Microsoft Defender portal, go to **Microsoft Sentinel > Configuration > Analytics** and create a new scheduled analytics rule with these high-level settings:
   1. Name: **ZAVA-Learner-Failed-VM-Logons**.
   2. Severity: Medium.
   3. Status: Enabled.
   4. MITRE ATT&CK tactic: Credential Access or Initial Access, depending on how you frame the detection.
2. Use this KQL as the rule query:

   ```kusto
   SecurityEvent
   | where TimeGenerated > ago(30m)
   | where EventID == 4625
   | where Computer startswith "vm-zava-soc-" or _ResourceId has "/virtualMachines/vm-zava-soc-"
   | summarize FailedLogons=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), SourceIps=make_set(IpAddress, 20), Accounts=make_set(TargetAccount, 20) by Computer, _ResourceId, bin(TimeGenerated, 10m)
   | where FailedLogons >= 3
   | extend TimeGenerated = LastSeen
   | project TimeGenerated, FirstSeen, LastSeen, Computer, _ResourceId, FailedLogons, SourceIps, Accounts
   ```

3. Map useful entities from the query results so incidents carry investigation context:
   1. Host entity from **Computer**.
   2. Azure resource entity from **_ResourceId**, if available in the entity mapping experience.
   3. Account and IP-related evidence from **Accounts** and **SourceIps** as custom details if array entity mapping is not suitable.
4. Configure the query schedule to run frequently enough for the lab, such as every 5 minutes with a 30-minute lookback.
5. Set the alert threshold so that at least one query result creates an alert.
6. Keep incident creation enabled so alerts from the rule become incidents in the unified queue.
7. Create and enable the rule, then confirm it appears under active scheduled analytics rules.

> [!Tip]
> If results simulation shows no current data, return to Task 3, regenerate endpoint activity, wait for ingestion, and retest the KQL before saving the rule.

## Task 5: Create the endpoint-and-Azure correlation analytics rule

In this task, you will create a second scheduled analytics rule named **ZAVA-Learner-Endpoint-And-Azure-Correlation**. This rule correlates endpoint failed logon activity with Azure control-plane or seeded scenario evidence for the same lab VM context.

1. Create another scheduled analytics rule with these high-level settings:
   1. Name: **ZAVA-Learner-Endpoint-And-Azure-Correlation**.
   2. Severity: Medium.
   3. Status: Enabled.
   4. Description: Correlates Windows failed logons from the lab VM with Azure Activity or ZAVA seeded evidence.
2. Build and test a correlation query. Start with this version, then adjust only if your workspace's seeded custom columns differ:

   ```kusto
   let EndpointFailedLogons =
       SecurityEvent
       | where TimeGenerated > ago(2h)
       | where EventID == 4625
       | where Computer startswith "vm-zava-soc-" or _ResourceId has "/virtualMachines/vm-zava-soc-"
       | summarize EndpointFailures=count(), EndpointFirst=min(TimeGenerated), EndpointLast=max(TimeGenerated), EndpointSourceIps=make_set(IpAddress, 20), EndpointAccounts=make_set(TargetAccount, 20) by Computer, VmResourceId=tolower(_ResourceId)
       | where EndpointFailures >= 3
       | extend CorrelationKey = "LabVm";
   let AzureControlPlaneEvidence =
       AzureActivity
       | where TimeGenerated > ago(48h)
       | where _ResourceId has "/virtualMachines/vm-zava-soc-" or ResourceProviderValue in~ ("Microsoft.Compute", "Microsoft.Network")
       | summarize AzureOperations=make_set(OperationNameValue, 20), AzureFirst=min(TimeGenerated), AzureLast=max(TimeGenerated) by CorrelationKey="LabVm";
   let SeededScenarioEvidence =
       ZavaSOCSeed_CL
       | where TimeGenerated > ago(48h)
       | extend ExpectedEntity=tostring(column_ifexists("ExpectedEntity_s", column_ifexists("ExpectedEntity", "")))
       | extend ScenarioType=tostring(column_ifexists("ScenarioType_s", column_ifexists("ScenarioType", "")))
       | extend ZavaCaseId=tostring(column_ifexists("ZavaCaseId_s", column_ifexists("ZavaCaseId", "")))
       | where ExpectedEntity has "vm-zava-soc-" or ScenarioType has_any ("VM", "NSG", "Access")
       | summarize SeedCases=make_set(ZavaCaseId, 20), SeedScenarioTypes=make_set(ScenarioType, 20), SeedFirst=min(TimeGenerated), SeedLast=max(TimeGenerated) by CorrelationKey="LabVm";
   EndpointFailedLogons
   | join kind=leftouter AzureControlPlaneEvidence on CorrelationKey
   | join kind=leftouter SeededScenarioEvidence on CorrelationKey
   | where isnotempty(AzureOperations) or isnotempty(SeedCases)
   | extend TimeGenerated = EndpointLast
   | project TimeGenerated, Computer, VmResourceId, EndpointFailures, EndpointFirst, EndpointLast, EndpointSourceIps, EndpointAccounts, AzureOperations, AzureFirst, AzureLast, SeedCases, SeedScenarioTypes, SeedFirst, SeedLast
   ```

3. Map the **Computer** and **VmResourceId** values as host/resource evidence where possible. Add custom details for **EndpointFailures**, **AzureOperations**, **SeedCases**, and **SeedScenarioTypes**.
4. Configure a 5-minute run interval and a lookback window that covers the endpoint activity and seeded evidence. A 2-hour endpoint window with a 48-hour seeded evidence window is acceptable for this challenge.
5. Keep incident creation enabled and use alert grouping that helps you inspect the correlated evidence without flooding the queue.
6. Create and enable the rule.

> [!Note]
> The second rule is intentionally a correlation rule. It should not fire solely because seeded data exists; it should require fresh endpoint failed logon evidence and at least one Azure Activity or **ZavaSOCSeed_CL** context record.

## Task 6: Confirm unified incidents and add the required tag and comment

In this task, you will prove that your learner-created rules generate incidents in the unified incident queue, then document one incident with the exact evidence marker required by validation.

1. Generate fresh endpoint activity again by running **C:\LabFiles\Scripts\Generate-ZavaEndpointSignals.ps1** on **<inject key="labVmName"></inject>** if your rules have not fired yet.
2. Wait for at least one scheduled run of each analytics rule. Review active rules or rule run information to confirm both rules are enabled:
   1. **ZAVA-Learner-Failed-VM-Logons**.
   2. **ZAVA-Learner-Endpoint-And-Azure-Correlation**.
3. Use KQL to confirm alerts from your learner-created rules exist:

   ```kusto
   SecurityAlert
   | where TimeGenerated > ago(4h)
   | where AlertName in ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation") or DisplayName in ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation")
   | project TimeGenerated, AlertName, DisplayName, ProviderName, ProductName, Entities, SystemAlertId
   | order by TimeGenerated desc
   ```

4. Use KQL to confirm related incidents are visible from Sentinel incident data:

   ```kusto
   SecurityIncident
   | where TimeGenerated > ago(4h)
   | where Title has_any ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation") or RelatedAnalyticRuleIds has_any ("ZAVA-Learner-Failed-VM-Logons", "ZAVA-Learner-Endpoint-And-Azure-Correlation")
   | project TimeGenerated, IncidentNumber, Title, Severity, Status, Owner, Labels, RelatedAnalyticRuleIds
   | order by TimeGenerated desc
   ```

5. Open one incident created from either learner rule in the unified incident queue. Prefer the correlation rule incident if both are available.
6. Add the incident tag **Challenge1-UnifiedDetection**.
7. Add an incident comment that contains this exact marker: **Challenge1-UnifiedDetection confirmed**.
8. In the same comment, summarize the data sources correlated, the analytics rule that fired, and the incident ID. A concise example is:

   **Challenge1-UnifiedDetection confirmed** — SecurityEvent failed logons from the lab VM correlated with Azure Activity or **ZavaSOCSeed_CL** context. Rule: **ZAVA-Learner-Endpoint-And-Azure-Correlation**. Incident ID: replace with the incident number shown in the queue.

9. Confirm the incident activity log or comments/history view shows your saved comment and that the incident still carries the tag **Challenge1-UnifiedDetection**.

<validation step="Validate-Challenge-01-UnifiedDetection"/>

## Summary

You created a new Windows Security Events via AMA DCR named with the **dcr-zava-securityevents-<inject key="DeploymentID" enableCopy="false"/>** deployment-specific prefix, associated it with **<inject key="labVmName"></inject>**, and sent **Minimal** Windows Security Events to **<inject key="logAnalyticsWorkspaceName"></inject>** without selecting high-volume Common or All event sets. You validated failed logon telemetry in **SecurityEvent**, created two learner-owned scheduled analytics rules, and proved that endpoint and Azure evidence appears in the unified incident queue. You also left a durable SOC handoff artifact by tagging an incident with **Challenge1-UnifiedDetection** and adding the required comment marker **Challenge1-UnifiedDetection confirmed**.