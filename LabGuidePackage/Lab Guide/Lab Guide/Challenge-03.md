# Challenge 3: Build the Automated Response Playbook

### Estimated Duration: 1.5 Hour(s)

## Scenario

Zava Corporation has proven that endpoint logon activity and Azure control-plane activity can be investigated in one Microsoft Sentinel incident queue. The SOC now needs to move from manual response to consistent containment. In this challenge, you will create a Microsoft Sentinel playbook backed by an Azure Logic Apps Consumption workflow. The workflow will use the precreated user-assigned managed identity for this lab, change only the lab network security group, preserve CloudLabs management access, and document the response directly on the incident.

## Overview

You will create a new Consumption Logic App playbook in **<inject key="resourceGroupName"></inject>** with the name prefix **la-zava-isolate-notify-**. For example, you can use **la-zava-isolate-notify-<inject key="DeploymentID" enableCopy="false"></inject>** if the generated name is accepted in your portal session. The prefix must remain unchanged so validation can identify the playbook.

The lab already created and authorized the user-assigned managed identity **<inject key="playbookManagedIdentityName"></inject>**. Its resource ID is **<inject key="playbookManagedIdentityResourceId"></inject>**. Attach this identity to your new Consumption Logic App and configure managed-identity connections backed by this user-assigned identity wherever the selected connector supports it. Do not create or rely on a learner-created system-assigned managed identity.

The automation rule final state must run only when a new incident is created from analytics rule **ZAVA-Learner-Failed-VM-Logons**. When triggered, the playbook must create or update NSG rule **Deny-Inbound-Zava-Quarantine** while preserving CloudLabs management access, then add an incident comment containing the exact marker **Challenge3-AutomatedContainment**.

> [!Important]
> Microsoft Sentinel uses a Microsoft Sentinel service account to run incident-triggered playbooks from automation rules. Microsoft Learn states that this service account needs **Microsoft Sentinel Automation Contributor** on the resource group that contains the playbook. For this lab, that prerequisite is preconfigured for **<inject key="resourceGroupName"></inject>**. Your task is to build the Logic App, attach the precreated user-assigned managed identity, configure the supported managed-identity connections, and create the automation rule. Do not create role assignments.

## Objectives

- Task 1: Confirm the containment design and required resources.
- Task 2: Create the incident-triggered Consumption Logic App playbook.
- Task 3: Attach the precreated user-assigned managed identity and configure connector authentication.
- Task 4: Implement NSG quarantine without breaking CloudLabs access.
- Task 5: Create the Sentinel automation rule for failed VM logon incidents only.
- Task 6: Trigger, verify, and validate automated containment.

## Task 1: Confirm the containment design and required resources

In this task, you will confirm the exact resources, trigger scope, identity, and safe containment behavior before building automation.

1. Sign in to the Microsoft Defender portal and Azure portal using the assigned lab account.
   - Username: <inject key="AzureAdUserEmail"></inject>
   - Password: <inject key="AzureAdUserPassword"></inject>
   - Subscription: <inject key="SubscriptionID"></inject>
   - Tenant: <inject key="TenantID"></inject>
2. Identify the deployed lab resources for this deployment:
   1. Resource group: **<inject key="resourceGroupName"></inject>**.
   2. Log Analytics workspace and Sentinel workspace: **<inject key="logAnalyticsWorkspaceName"></inject>**.
   3. Windows lab VM: **<inject key="labVmName"></inject>**.
   4. Network security group: **<inject key="networkSecurityGroupName"></inject>**.
   5. Precreated playbook identity: **<inject key="playbookManagedIdentityName"></inject>**.
3. Open the managed identity resource **<inject key="playbookManagedIdentityName"></inject>** and confirm that it is a **User assigned managed identity** in the same resource group. Keep its resource ID available: **<inject key="playbookManagedIdentityResourceId"></inject>**.
4. Plan the playbook name before creating it. Use a Consumption Logic App workflow name that starts with **la-zava-isolate-notify-**, such as **la-zava-isolate-notify-<inject key="DeploymentID" enableCopy="false"></inject>** or a shortened suffix based on your deployment identifier. Keep the prefix exact.
5. In Microsoft Defender portal, use **Microsoft Sentinel > Configuration > Automation** to review whether **AR-ZAVA-Auto-Isolate-VM** already exists as a disabled or incomplete shell. If it does, you will update it; if it does not, you will create it.
6. In Microsoft Defender portal, use **Microsoft Sentinel > Configuration > Analytics** to confirm the analytics rule **ZAVA-Learner-Failed-VM-Logons** exists and is enabled from Challenge 1.
7. Review the existing inbound rules on **<inject key="networkSecurityGroupName"></inject>** and identify the rule or source path that CloudLabs uses to keep lab management access available.
8. Decide the containment rule behavior before implementation:
   1. The rule name must be **Deny-Inbound-Zava-Quarantine**.
   2. Direction must be inbound.
   3. Action must be deny.
   4. Protocol and destination ports should cover inbound workload access you are quarantining.
   5. The rule must not block the CloudLabs management access rule or source path.
   6. The priority must be chosen so the quarantine rule takes precedence over normal workload inbound allow rules but not over the existing CloudLabs management allow path.
9. Confirm that the playbook needs only these effective capabilities:
   1. Receive Microsoft Sentinel incident details from the incident trigger.
   2. Add a Microsoft Sentinel incident comment.
   3. Read and create or update security rules on **<inject key="networkSecurityGroupName"></inject>**.

> [!Important]
> Azure network security group rules are evaluated by priority, where a lower number is evaluated first. Preserve CloudLabs access by keeping the existing CloudLabs management allow path ahead of the quarantine deny rule, or by otherwise excluding that management path from the deny behavior. Do not remove baseline allow rules unless the lab explicitly tells you to.

## Task 2: Create the incident-triggered Consumption Logic App playbook

In this task, you will create a Consumption Logic App as a Sentinel incident-response playbook.

1. In the Azure portal, create a new **Logic App (Consumption)** resource in **<inject key="resourceGroupName"></inject>**. Name it with the exact prefix **la-zava-isolate-notify-** and place it in the same region as the lab resource group.
2. Do not enable or depend on a system-assigned managed identity during creation. The identity you will use is the existing user-assigned managed identity **<inject key="playbookManagedIdentityName"></inject>**.
3. Open the Logic App designer and configure the workflow to start with the Microsoft Sentinel incident trigger so it can be selected by a Sentinel automation rule that runs on incident creation.
4. Normalize the incident payload into variables or composed values that the rest of the workflow can reuse:
   1. Incident ARM ID.
   2. Incident title.
   3. Incident number or incident identifier.
   4. Alert or analytics rule name from the incident payload.
   5. Affected host or VM entity, expected to resolve to **<inject key="labVmName"></inject>** for this lab scenario.
   6. Current UTC timestamp.
   7. Logic App workflow run identifier.
5. Add a guard condition inside the playbook so the NSG containment branch continues only when the incident was generated by **ZAVA-Learner-Failed-VM-Logons** and the VM entity or title matches the lab VM.
6. Add a safe no-op branch for nonmatching incidents. The no-op branch should not change NSG rules and should not write the **Challenge3-AutomatedContainment** marker.
7. Save the workflow after each major design section so that connection and schema errors are visible before you attach the playbook to automation.

> [!Tip]
> Keep the playbook small and auditable. A good flow is: Sentinel incident trigger, extract incident fields, confirm the rule and VM match, update the NSG rule, then add the incident comment.

## Task 3: Attach the precreated user-assigned managed identity and configure connector authentication

In this task, you will attach the lab-provided user-assigned managed identity to the Logic App and configure supported workflow connections to use that identity. Microsoft Learn documents that Consumption Logic Apps can have user-assigned managed identities attached, and that managed connector definitions can reference the user-assigned identity resource ID for connections that support managed identity.

1. In the Azure portal, open the Logic App **Identity** blade.
2. Select **User assigned**, add the existing managed identity **<inject key="playbookManagedIdentityName"></inject>**, and confirm the identity is associated with the Logic App.
3. Keep **System assigned** disabled unless the portal temporarily requires you to view an identity blade. Do not build workflow connections that rely on the system-assigned identity.
4. Configure Microsoft Sentinel connector actions in the workflow to authenticate with managed identity. If the connector presents an identity selector, choose the user-assigned managed identity **<inject key="playbookManagedIdentityName"></inject>**. If the connection has a JSON view or connection parameter for identity, the identity resource ID must match **<inject key="playbookManagedIdentityResourceId"></inject>**.
5. Configure the Azure Resource Manager, Azure Network, or equivalent action used for the NSG update to authenticate with managed identity backed by **<inject key="playbookManagedIdentityName"></inject>** where the selected connector supports user-assigned managed identity.
6. Avoid personal-user OAuth connections, service-principal secrets, broad subscription access, tenant-wide permissions, new role assignments, or fallback to a system-assigned identity. The precreated user-assigned managed identity is the authorization boundary for this challenge.
7. Test or validate the workflow actions that the managed identity connection is expected to perform:
   1. Receive the Microsoft Sentinel incident trigger payload.
   2. Add a Microsoft Sentinel incident comment.
   3. Read **<inject key="networkSecurityGroupName"></inject>**.
   4. Create or update **Deny-Inbound-Zava-Quarantine** on the lab NSG.
8. Reopen the Logic App designer after identity and connection changes settle and confirm that Microsoft Sentinel actions and Azure Resource Manager or network actions are using the intended managed-identity connection, not a personal user connection and not a system-assigned identity connection.

> [!Note]
> Two permission paths are involved and they are different. First, Microsoft Sentinel needs **Microsoft Sentinel Automation Contributor** at the playbook resource group so an automation rule can invoke a playbook; this prerequisite is preconfigured for **<inject key="resourceGroupName"></inject>** by the lab platform. Second, the Logic App workflow actions use the attached user-assigned managed identity **<inject key="playbookManagedIdentityName"></inject>**, which is already scoped by the deployment for Sentinel incident updates and the lab NSG. Do not create role assignments in this lab.

## Task 4: Implement NSG quarantine without breaking CloudLabs access

In this task, you will implement the containment action that creates or updates **Deny-Inbound-Zava-Quarantine** on the lab NSG.

1. In the Logic App, add the Azure action or HTTP-to-Azure-Resource-Manager action that creates or updates an inbound security rule on **<inject key="networkSecurityGroupName"></inject>**.
2. Configure the action to be idempotent: if **Deny-Inbound-Zava-Quarantine** already exists, update it to the desired state instead of creating a duplicate rule.
3. Set the rule properties to enforce quarantine while preserving management:
   1. Name: **Deny-Inbound-Zava-Quarantine**.
   2. Direction: inbound.
   3. Access: deny.
   4. Source: any source not covered by the CloudLabs management allow path.
   5. Destination: the lab VM private IP, the lab VM NIC target, or the workload subnet target used by the deployment.
   6. Destination ports: the inbound workload ports being quarantined, or all inbound ports if the CloudLabs management path is protected by a higher-precedence allow rule.
   7. Priority: a unique value that evaluates after the CloudLabs management allow rule and before normal workload inbound allow rules.
   8. Description: include the incident identifier and the text **Challenge3-AutomatedContainment** for auditability.
4. Add error handling that stops the workflow as failed if the NSG update fails. Do not write the success comment unless the NSG action succeeds.
5. Add a read-back step that retrieves the updated NSG rule and confirms the effective values before the comment step runs.
6. Do not use the reset script during this task. The reset method is reserved for after validation, or for recovery if instructed by the facilitator.

> [!Important]
> The containment target is the lab NSG only. Do not delete the VM, stop the VM, remove the NIC, change public IP settings, alter tenant-wide security settings, or modify unrelated network resources.

## Task 5: Create the Sentinel automation rule for failed VM logon incidents only

In this task, you will attach the playbook to a Microsoft Sentinel automation rule with a narrow incident trigger.

1. In Microsoft Defender portal, go to **Microsoft Sentinel > Configuration > Automation** and create or update automation rule **AR-ZAVA-Auto-Isolate-VM** for **<inject key="logAnalyticsWorkspaceName"></inject>**.
2. Configure the trigger as a new incident trigger, not an alert-only trigger and not an incident-update trigger.
3. Add a condition so the rule runs only when the analytics rule name is **ZAVA-Learner-Failed-VM-Logons**.
4. Do not add broad conditions such as all high-severity incidents, all failed logon incidents, all incidents from Microsoft Sentinel, or all incidents containing the VM name.
5. Add a single run-playbook action that calls the Consumption Logic App playbook you created with prefix **la-zava-isolate-notify-**.
6. Confirm the selected playbook is active and that the rule can save without granting additional permissions. Microsoft Learn documents that unavailable playbooks usually indicate Microsoft Sentinel does not have the required **Microsoft Sentinel Automation Contributor** permission on the playbook resource group; this lab preconfigures that permission, so do not grant permissions yourself.
7. Enable the automation rule and keep its order deterministic relative to other automation rules in the workspace.
8. Review the final automation rule configuration and verify all of these statements are true:
   1. Rule name is exactly **AR-ZAVA-Auto-Isolate-VM**.
   2. Rule is enabled.
   3. Trigger is new incident creation.
   4. Analytics rule filter is exactly scoped to **ZAVA-Learner-Failed-VM-Logons**.
   5. Action runs the completed Logic App playbook with prefix **la-zava-isolate-notify-**.

## Task 6: Trigger, verify, and validate automated containment

In this task, you will generate fresh failed-logon activity, verify the playbook run, confirm the NSG state, and leave the required incident evidence.

1. On **<inject key="labVmName"></inject>**, run the staged helper script **C:\LabFiles\Scripts\Generate-ZavaEndpointSignals.ps1** to generate fresh benign failed-logon activity for the learner-created rule.
2. Wait for the **ZAVA-Learner-Failed-VM-Logons** scheduled analytics rule to create a new incident. Use a bounded retry pattern and account for ingestion and analytics scheduling latency.
3. Confirm that automation rule **AR-ZAVA-Auto-Isolate-VM** ran against the new incident and called the completed Logic App playbook.
4. Review the Logic App run history in the Azure portal and confirm the latest run completed successfully after the new incident creation time.
5. Confirm **<inject key="networkSecurityGroupName"></inject>** contains **Deny-Inbound-Zava-Quarantine** with deny inbound behavior and that the CloudLabs management access rule or source path remains available.
6. Open the related Microsoft Sentinel incident and confirm the playbook added an incident comment containing the exact marker **Challenge3-AutomatedContainment**.
7. Confirm the same comment also includes the incident title, **<inject key="labVmName"></inject>**, **Deny-Inbound-Zava-Quarantine**, a UTC timestamp, and the Logic App playbook run ID.
8. If the comment is missing but the playbook run succeeded, correct the managed-identity connection selection or comment action and trigger a new **ZAVA-Learner-Failed-VM-Logons** incident for a clean end-to-end test. Keep the user-assigned managed identity **<inject key="playbookManagedIdentityName"></inject>** as the workflow identity and do not add role assignments.
9. If the containment rule blocks your lab session, use the staged reset method **C:\LabFiles\Scripts\Reset-ZavaNSGContainment.ps1** only after validation, or when instructed by your facilitator. A convenience copy may also be available on the Public Desktop.
10. Run the validation for this challenge.

<validation step="Validate-Challenge-03-AutomatedResponse"/>

## Summary

You created the automated response path for Zava's SOC. A new incident from **ZAVA-Learner-Failed-VM-Logons** now triggers **AR-ZAVA-Auto-Isolate-VM**, runs your Consumption Logic App playbook with prefix **la-zava-isolate-notify-**, uses the precreated user-assigned managed identity **<inject key="playbookManagedIdentityName"></inject>** for supported managed-identity connections, creates or updates **Deny-Inbound-Zava-Quarantine** on the lab NSG without breaking CloudLabs management access, and records a deterministic incident comment containing **Challenge3-AutomatedContainment**. The Microsoft Sentinel service-account permission to invoke playbooks and the user-assigned managed identity's scoped access are deployment prerequisites; learners do not create role assignments in this challenge.
