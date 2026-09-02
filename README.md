# Threat Triage Assistant: Cutting Through SOC Alert Fatigue

Challenge Lab · Azure · Advanced · 360 minutes · 4 challenges · 4 inline validations

Learners build an Azure SOC on Microsoft Sentinel through the Microsoft Defender portal: unified
detection across connected sources, KQL hunting and incident investigation, an automated response
playbook on Azure Logic Apps that isolates the lab VM and notifies, then rule tuning and reporting.

## Delivery requirement — read before scheduling

**The environment must be deployed at least 48 hours before the event.** Microsoft Sentinel data,
analytics rule execution and seeded incident generation do not appear immediately. The deployment
scripts enable Sentinel, connect the baseline sources, deploy the baseline analytics rules and seed
a noisy incident queue with one true positive hidden in it, all at provision time. No challenge step
depends on same-day provisioning.

## Package contents

| Path | Purpose |
| --- | --- |
| `DeploymentPackage/deploy-01.json` | ARM template — VM, network, NSG, Log Analytics with Sentinel enabled, data collection endpoint, playbook managed identity with pre-granted roles |
| `DeploymentPackage/deploy-01.parameters.json` | ARM parameters with CloudLabs injection tokens |
| `DeploymentPackage/psscript-01.ps1` | Custom Script Extension bootstrap — lab assets, seed data, baseline rules |
| `LabGuidePackage/Lab Guide/Lab Guide/` | `GettingStarted-V2.md` plus `Challenge-01.md` … `Challenge-04.md` |
| `masterdoc.json` | Guide manifest CloudLabs serves the lab guide from |
| `Validations/` | One PowerShell validator per challenge |
| `permissions/CustomRBAC/custom-rbac-role.json` | Custom role for the lab account |
| `permissions/CustomARMPolicy/azure-policy.json` | Sandbox guardrail policy |
| `solution-guide/solution.md` | Facilitator solution guide |
| `Spec.md` | Package specification |

## Onboarding notes

- **Subscription type:** Dedicated Tenant. **Allow Global Admin Privilege must be ticked before
  launching** — it does not retrofit a running deployment.
- **Licence:** Microsoft 365 E5.
- **Validation steps:** create four steps under Modules whose names match the validator filenames
  exactly. Until they exist nothing is graded and the guide's validation markers render as nothing.
- **The repo must be readable by the CloudLabs docs proxy.** If it stays private, arrange a PAT with
  the CloudLabs team and swap in `masterdoc.PRIVATE-PROXY-ALTERNATIVE.json`; otherwise make the repo
  public and use `masterdoc.json` as shipped.
- **No auto-shutdown schedule is deployed**, deliberately. CloudLabs owns lab lifetime.

## Validation step names

```
Validate-Challenge-01-UnifiedDetection
Validate-Challenge-02-Investigation
Validate-Challenge-03-AutomatedResponse
Validate-Challenge-04-TuneAndReport
```
