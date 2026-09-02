Threat Triage Assistant: Cutting Through SOC Alert Fatigue

Lab Overview
• Cloud: Azure
• Duration: 360 minutes
• Exercises: 4 (Establish Unified Detection, Correlate and Investigate with KQL, Build the Automated Response Playbook, Validate, Tune and Report)
• Validations: 4
• Deployed services: Windows Virtual Machine and VM extensions, Virtual Network, subnet, Network Interface, Public IP address, Network Security Group, Log Analytics workspace with Microsoft Sentinel solution/onboarding and a 3 GB daily cap for the six-hour lab, precreated User-assigned Managed Identity for the learner Logic App playbook, Data Collection Endpoint for AMA readiness, Network Security Group diagnostic settings to Log Analytics for containment and timing evidence, platform-supplied deterministic role assignment inputs for Microsoft Sentinel Automation Contributor, role assignments, and seeded Log Analytics custom table data. The ARM deployment does not provision a Data Collection Rule, Logic App workflow/playbook, Microsoft Sentinel automation rule, learner analytics rules, or workbook; learners create or configure those resources during the challenges.
• Scenario: Zava Corporation's small SOC team is overwhelmed by disconnected alerts, and the learner acts as the SOC engineer using Microsoft Sentinel in the Microsoft Defender portal to build a unified detection, investigation, tuning, and automated containment workflow. The Azure environment provides the core SOC substrate: a Sentinel-enabled Log Analytics workspace, a Windows endpoint, NSG diagnostics for containment evidence, AMA readiness, a precreated managed identity for the learner-built Logic App, and seeded evidence. Learners should use the Minimal Windows Security Events collection set and avoid All Windows Security Events to stay within the lab's 3 GB Log Analytics daily cap.

This Package Includes

Deliverables Included in the Package
• Lab Guide
• Master Document
• Inline Validations

Inline Validations
Pre-configured inline validations enabled

Lab Guide Preview
Preview link for the lab guide documentation:
[\[CloudLabs LabGuide Preview\]](https://experience.cloudlabs.ai/#labguidepreview/<GUID>/1)

Lab Environment Setup & Deployment
Lab provisioning and setup include one or more of the following components:
• ARM template deployment
• Custom Script Extension (CSE)
• Custom image-based environment setup
• Supporting deployment configurations as required

Exclusions
This package does not include:
• Scoring or grading mechanisms for inline validations
• Complex or advanced inline question types

Internal Package Notes and Waivers
• Microsoft Learn fact check for this pass: Microsoft Sentinel playbooks are Azure Logic Apps workflows, Microsoft Sentinel automation rules can run playbooks from incident triggers, Windows Security Events via AMA populate the SecurityEvent table for events such as failed logons, and managed identities require appropriate Microsoft Sentinel and Azure resource permissions for incident actions and NSG updates.
• Challenge 3 identity note: the learner-built Logic App playbook uses the precreated user-assigned managed identity. The learner should assign or reference that identity for playbook actions instead of creating a separate identity path.
• Automation Contributor object ID note: the Microsoft Sentinel Automation Contributor assignment uses a platform-supplied deterministic object ID parameter. It is not a CSE best-effort repair step.
• Log Analytics daily cap note: the workspace daily cap is 3 GB/day for this pass. Learner guidance should continue to prefer Minimal Windows Security Events to keep SecurityEvent ingestion within the lab budget.
• Validation filename waiver: the package intentionally retains legacy validation script filenames because there is no safe delete or rename operation available in this pass. These filenames remain waived until a cleanup pass can remove or rename artifacts without breaking inline validation mappings.
• Auto-shutdown exception: DevTestLab auto-shutdown is intentionally not used per author override and the plan requirement. This SOC scenario is pre-provisioned before delivery and depends on continuous Sentinel workspace, seeded incident, VM, NSG diagnostic, and timing evidence availability during the 48-hour pre-provisioning window and the event window.
• Legacy ingestion migration note: seed ingestion may use the legacy Log Analytics HTTP Data Collector API. Microsoft Learn states that the Log Analytics HTTP Data Collector API is deprecated and will be retired on September 14, 2026; migrate seed ingestion to the Azure Monitor Logs Ingestion API with Data Collection Rules/Data Collection Endpoints before that date or earlier if tenant policy requires it.
• Stray artifact note: the package currently contains a one-byte artifact named x. It remains a publish cleanup blocker unless a writer can safely remove it; if it cannot be removed by available writer tooling, treat it as a publish blocker rather than candidate-facing lab content.
