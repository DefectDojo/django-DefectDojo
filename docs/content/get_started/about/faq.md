---
title: "❓ Frequently Asked Questions"
description: "DefectDojo FAQ"
draft: "false"
weight: 2
chapter: true
aliases:
  - /en/about_defectdojo/faq
---
Answers to common questions about DefectDojo Open-Source and DefectDojo Pro. Where the two editions answer a question differently, both answers are shown side by side.

## Choosing an edition

### What's the difference between Open-Source and Pro?

Both editions share the same data model and the same parsers. Open-Source is free and self-hosted. Pro adds connectors, prioritization, a Triage Engine for automation, saved and scheduled reporting, AI features, compliance evidence, enterprise sign-on and commercial support. The [Feature comparison](/get_started/about/defectdojo_versions/) covers every difference and why it matters.

### Can I move from Open-Source to Pro and keep my data?

Yes. You export your Open-Source database and uploaded files, and they are restored into Pro, which then upgrades the schema to its own version. Any 2.x release, and 3.0.200 or later, can be migrated.

| Moving to DefectDojo Cloud | Moving to self-hosted Pro |
|---|---|
| You provide the database dump and files; the DefectDojo team restores them into your Cloud instance. See [Migrating to DefectDojo Cloud](/get_started/pro/cloud/migrating_from_open_source/). | You restore them into your own database and storage. See [Migrating to Self-Hosted DefectDojo Pro](/get_started/pro/onprem/migrating_from_open_source/). |

### Can Pro be self-hosted, or run without internet access?

Yes to both. Pro runs on DefectDojo Cloud, or on your own infrastructure with [Docker Compose or Kubernetes](/get_started/pro/onprem/installation_options/). An [air-gapped instance](/get_started/pro/onprem/airgapped/) makes no outbound connections; threat-intelligence data is loaded from a file instead.

### Which Pro features need an add-on license?

**Sensei** (AI code and cloud scanning with fixes, Threat Modeling, Sensei Advisor and the Triage Engine's AI steps) and the **PSIRT Advisory Engine**. Entries for an unlicensed feature show a `LOCKED` badge in the sidebar. Everything else on the [Feature comparison](/get_started/about/defectdojo_versions/) is part of Pro.

### Why don't I see a feature described in the docs?

In Pro, check these in order:

1. **Feature Flags.** Many capabilities are switched on by an administrator under [Feature Flags](/admin/feature_flags/pro__feature_flags/).
2. **License.** Sensei and PSIRT need an add-on license.
3. **Permissions.** The sidebar only shows the pages your role can open.
4. **Deployment.** A few settings exist only on self-hosted instances (for example AI Model Settings and Version Manager) or only on DefectDojo Cloud (for example Firewall Rules).

In Open-Source, check that the page describes Open-Source: the edition switch at the top of the navigation shows the pages for the edition you choose.

## Modelling your environment

### How should I map my organization to Organizations and Assets?

Start from who fixes things and who reads the reports. Most structures follow one of three patterns, or a mix: one Organization per team, one per technology domain (applications, cloud, containers, networks), or one per business unit or product line. Access is granted per Organization and Asset, so a structure that matches ownership also makes permissions simple.

[Plan your hierarchy](/asset_modelling/pro_hierarchy/plan_your_hierarchy/) walks through each pattern with examples, and the [common use cases](/get_started/common_use_cases/common_use_cases/) show how different teams have set it up.

### What should one Asset represent?

Whatever is fixed and released as a unit: usually an application, a service or a repository. Match it to how your scanners group results (projects, repositories, cloud accounts), so each scan lands on one Asset and reimports keep its history in one place. A hundred small Assets are easier to report on and assign than one Asset holding everything.

### Can Assets have parents and children?

| Open-Source | Pro |
|---|---|
| No. Each Asset sits directly under one Organization: Organization → Asset → Engagement → Test → Finding. | Yes. The [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/) lets an Asset be a parent of other Assets (a product made of services, for example), and findings roll up through the tree. |

### Can one Asset belong to more than one Organization?

| Open-Source | Pro |
|---|---|
| No. | Yes, once shared membership is switched on. An Asset has one primary Organization and can be added to others, so a shared service can appear under every team that depends on it. Shared membership is off by default; on a self-hosted install an administrator turns it on with the `DD_V3_ORGANIZATION_NONEXCLUSIVE` environment variable, and on DefectDojo Cloud you ask Support to turn it on. |

### Can DefectDojo build my hierarchy from a CMDB, Backstage, my code hosts or my cloud accounts?

| Open-Source | Pro |
|---|---|
| No. Create Organizations and Assets in the UI or through the API, or let an import create them with `auto_create_context`. | Yes. Asset connectors for GitHub, GitLab, Bitbucket, Azure DevOps, Backstage, ServiceNow CMDB, JSM Assets, runZero, Google Cloud and Microsoft Azure create Assets from the systems you already maintain. Some keep them in sync: Backstage carries renames, descriptions and owners across, and a CMDB can supply each Asset's business criticality. See the [Upstream Connectors tool reference](/connectors/toolreference/upstream/). |

### Can an AI assistant help me set up or reorganize my hierarchy?

In Pro, yes, in two ways:

- **Before you build anything**, [Plan your hierarchy](/asset_modelling/pro_hierarchy/plan_your_hierarchy/) has a copyable prompt for any LLM. It interviews you about your teams, systems, tools and reporting needs, then drafts a tree with its reasoning. It does not connect to DefectDojo.
- **On a live instance**, the [MCP server's Asset Hierarchy toolset](/metrics_reports/ai/mcp_server_pro/#asset-hierarchy-toolset) lets your assistant explore the hierarchy, find orphaned Assets, duplicate names and empty Organizations, create Organizations and Assets, and move Assets under new parents. For example: *"Run the hierarchy cleanup review and show me the orphaned Assets."*

The assistant works with your own permissions, and its changes apply immediately. Moving an Asset can change who can see it, so ask the assistant to tell you who gains or loses visibility before it makes a change.

### How do I restructure many Assets at once without breaking anything?

| Open-Source | Pro |
|---|---|
| Edit Assets one at a time, or script the change with the API. | Use a [Change Plan](/asset_modelling/pro_hierarchy/change_plans/): build the moves from a list or a CSV file, review a preview of every change, then apply the whole plan, and undo it if needed. A plan is marked stale if the data changes after you draft it. |

[You can reorganize later](/asset_modelling/pro_hierarchy/reorganize_later/) explains what moves with an Asset and what stays put.

### A connector created Assets in a default Organization. How do I sort them out?

In Pro, open the **Needs Attention** list under Assets. It shows every Asset still sitting in a connector's default Organization or missing the business data that drives priority, and lets you fix them in bulk. See [Finish onboarding](/asset_modelling/pro_hierarchy/finish_onboarding/).

### Should every scan get its own Engagement?

Usually not. For automated scanning, use one long-running CI/CD Engagement per pipeline (or per branch) and **reimport** each new scan into the same Test, so DefectDojo can close findings that disappear and reopen ones that return. Use separate Engagements for distinct, time-boxed activities such as a penetration test or an audit. See [Import from API](/import_data/import_scan_files/api_pipeline_modelling/) for pipeline patterns.

### Should I use Endpoints or Locations?

| Open-Source | Pro |
|---|---|
| Open-Source records where a finding lives as Endpoints (the URLs and hosts a finding affects, stored as URL Locations in 3.x) and Components (the package name and version recorded on each finding, one per finding). | Locations are switched on with a one-way feature flag, and existing Endpoints are migrated (see [Migrating from Endpoints](/asset_modelling/locations/pro__migrating_from_endpoints/)). Pro adds Location types for dependencies, source code, cloud resources and container images. Each Location is a record of its own, linked many-to-many to every Asset and Finding it relates to, and they feed SBOM export and PSIRT. |

### What business information should I record on an Asset?

Business criticality, whether it is internet-accessible, its production status, revenue and the number of user records it holds.

| Open-Source | Pro |
|---|---|
| These fields describe the Asset for people reading it. | They feed the Asset's [Prioritization Engine](/asset_modelling/pro_hierarchy/priority_sla/), so a critical, internet-facing Asset's findings rank above the same findings elsewhere. They can also assign the Asset's SLA automatically. |

## Getting findings in

### What tools are supported?

| Open-Source | Pro |
|---|---|
| 360+ built-in [parsers](/supported_tools/) for SAST, DAST, SCA, container, cloud and infrastructure tools. | Every Open-Source parser, plus the [Universal Parser](/import_data/pro/specialized_import/universal_parser/) for any other JSON, CSV or XML report, and 140+ [Upstream Connectors](/connectors/upstream/about/) that pull results from tools directly. |

### What is the difference between Import and Reimport?

- **Import** records a report as a single point-in-time event. Each import creates a new Test containing the resulting Findings.
- **[Reimport](/import_data/import_intro/reimport/)** updates an existing Test with a new set of results. DefectDojo compares the incoming report with the Test, records the changes, and adjusts the Findings to match: new ones are added, ones no longer reported are closed, and ones that return are reopened.

Think of Import as recording a single receipt, and Reimport as keeping a running ledger. Use Import for one-off reports such as a penetration test, and Reimport for anything you scan repeatedly.

Deduplication also behaves differently: two separate imports into the same Asset label their duplicates against each other, while Reimport never creates a Finding it identifies as a [duplicate](/triage_findings/finding_deduplication/avoid_excess_duplicates/) within the Test.

### How do I connect a CI/CD pipeline?

Call the [DefectDojo REST API](/import_data/import_scan_files/api_pipeline_modelling/) from your pipeline to import or reimport each scan. Pro users can also use the [Universal Importer and DefectDojo CLI](/import_data/pro/specialized_import/external_tools/), which wrap the API in a command you can drop into any pipeline, or skip the pipeline entirely with [Upstream Connectors](/connectors/upstream/about/).

### How can I troubleshoot import errors?

First confirm that your tool is on the [parser list](/supported_tools/) and that the file is in the format the parser expects; comparing it with the sample files used by the parser's unit tests is a quick check. Report formats sometimes change without warning, and the community welcomes [contributions](/get_started/contributing/how-to-write-a-parser/) that keep parsers current.

In Pro, [Diagnostics](/admin/diagnostics/pro__diagnostics/) lists import failures alongside other integration errors, and the [Universal Parser](/import_data/pro/specialized_import/universal_parser/) can read a report that no built-in parser supports.

### How should I handle very large scan files?

Where your tool allows it, export smaller reports split by project, application or other context. Smaller files import faster, and the split organizes your Findings the same way. Pro processes Findings in the background once a file is uploaded and validated; self-hosted Pro also has a configurable [upload size limit](/get_started/pro/onprem/docker_compose/upload_size_limits/).

## Prioritization and triage

### What does a Finding's status mean?

Every Finding is either Active or Inactive. Other statuses, such as Verified, False Positive, Out of Scope or Risk Accepted, are applied as triage decisions. See [Finding Status Definitions](/triage_findings/findings_workflows/finding_status_definitions/).

### How is Priority calculated, and can I change it?

| Open-Source | Pro |
|---|---|
| Findings are ordered by severity and CVSS. | Every Finding gets a priority score and a risk band (Urgent, Needs Action, Medium or Low). Each Asset uses a **Prioritization Engine** that weighs severity, EPSS, CISA KEV, threat intelligence, reachability, how many Assets share the root cause, and the Asset's business data. You can change the weights and thresholds, and keep different engines for different kinds of Asset. See [Assign Priority, Risk and SLAs](/asset_modelling/pro_hierarchy/priority_sla/). |

### Where do EPSS and KEV data come from?

| Open-Source | Pro |
|---|---|
| Only from the scanner. Parsers that report EPSS scores or KEV status fill in those fields; DefectDojo does not look them up itself. | From FIRST and CISA directly. Every Finding with a CVE gets its EPSS score and KEV status (including known ransomware use) automatically, updated every 24 hours, whatever tool found it. See [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/) and [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/). |

### How does deduplication work across tools, and how do I tune it?

DefectDojo compares a new Finding against existing ones using a hash of chosen fields, the tool's own unique ID, or both. See [How DefectDojo deduplicates findings across security tools](/triage_findings/finding_deduplication/deduplication_across_tools/).

| Open-Source | Pro |
|---|---|
| Same-tool deduplication: a Finding is matched against earlier Findings from the same scanner. There is no cross-tool setting; Findings from two different tools match only when both tools are configured to hash the same fields and the values come out identical. The algorithm and hash fields are set per parser in configuration files or environment variables, not in the UI. See [Deduplication Tuning](/triage_findings/finding_deduplication/os__deduplication_tuning/). | Same-tool and cross-tool deduplication, so the same issue reported by different scanners is worked once. Choose from several matching algorithms per tool, and tune reimport matching, in the UI, and use [Dedupe Pools](/triage_findings/finding_deduplication/pro__dedupe_pools/) to decide which Assets share matching. See [Deduplication Tuning](/triage_findings/finding_deduplication/pro__deduplication_tuning/). |

### What is a Root Cause, and how is it different from a duplicate or a Finding Group?

- A **duplicate** is the same Finding reported twice; DefectDojo keeps one and marks the other.
- A **Finding Group** gathers related Findings within one Test, for example by component, so they can be ticketed together. It is available in both editions.
- A **[Root Cause](/triage_findings/finding_correlation/pro__root_cause_correlation/)** (Pro) links distinct Findings across every Asset that share one fix: the same component version, CVE, cloud resource or container image. It is ranked by how many Assets it affects, so one upgrade can be planned once and tracked to every Finding it clears.

### Can I automate triage decisions?

| Open-Source | Pro |
|---|---|
| Script it against the REST API. | Build a rule in the [Triage Engine](/automation/triage_engine/about/). For example: when a scan lands from a given tool, close its informational Findings, assign the rest to the Asset's owner and open a ticket for the criticals. New rules start in Simulate mode, and a preview shows what a rule would change before it runs for real. |

### How do I find out when a pipeline stops sending scans?

In Pro, set **Scan Cadence** policies that say how often each Organization, regulation, criticality level or Asset must be scanned. Each Asset then shows as Compliant, Due, Overdue or Never scanned, with dated attestations for auditors. A Triage Engine rule can also alert you when an expected scan does not arrive. See [Scan cadence policies](/sensei/scan_cadence_policies/).

## Remediation, risk and SLAs

### How do I accept a risk, and can I require a second person to approve it?

| Open-Source | Pro |
|---|---|
| Use simple or full risk acceptance on the Asset. A full acceptance records the decision, an owner, proof and an expiry date, and what happens to the Findings when it expires. There is no approval step. See [Risk Acceptances](/triage_findings/findings_workflows/os__risk_acceptance/). | Everything in Open-Source, plus an approval workflow: an acceptance is proposed, reviewed by someone with permission to approve, and only then becomes active. Self-approval is blocked, and an expired acceptance needs a fresh review to be extended. See [Risk Acceptances](/triage_findings/findings_workflows/pro__risk_acceptance/). |

### How are SLA deadlines calculated?

| Open-Source | Pro |
|---|---|
| Each Asset has an SLA configuration that sets a number of days per severity, with an option to restart the clock when a Finding reopens. See [SLA Configuration](/asset_modelling/os_hierarchy/os__sla_configuration/). | SLAs can run by severity or by risk band, start from detection, publication or fix availability, be capped by the CISA KEV due date, follow FedRAMP vulnerability-response deadlines, and be assigned to Assets automatically by business criticality. See [Remediation Deadlines](/federal_compliance/remediation_slas/). |

### How do I give engineers a list of fixes instead of thousands of findings?

In Pro, two features do this:

- **[Root Causes](/triage_findings/finding_correlation/pro__root_cause_correlation/)** group Findings by the fix that clears them.
- The **[Remediation Center](/triage_findings/remediation_center/pro__remediation_center/)** turns open Findings into concrete remediation actions (upgrade this package, patch that host, change this setting), each due by the earliest SLA among its Findings. Campaigns roll one change up across every place it is needed.

Open-Source has no equivalent. Its closest feature, Finding Groups, bundles related Findings from a single Test into one Jira issue.

### Can Findings sync both ways with my ticketing system?

| Open-Source | Pro |
|---|---|
| Jira syncs both ways: status and comment changes in Jira come back to DefectDojo. GitHub Issues are created and updated from DefectDojo. | Jira syncs both ways. [Downstream Connectors](/connectors/downstream/about/) also create and update tickets in Azure DevOps, GitHub, GitLab Boards, Bitbucket, Linear, Shortcut, ServiceNow, Zendesk, ServiceDesk Plus, Freshservice, PagerDuty and Opsgenie. |

### How can I delete Findings?

We recommend keeping closed Findings as Inactive rather than deleting them: deleting a Finding removes its notes and history, which makes metrics and audit records incomplete. If you do need to delete Findings, you can:

- Run a [Bulk Delete](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings) on the Findings you select.
- Call `DELETE /findings/{id}` through the API.
- Delete a parent object, such as a Test, Engagement, Asset or Organization. Everything beneath it is deleted too; the objects above it are kept.

## Reporting and compliance

### Can I save a report and run it again, or on a schedule?

| Open-Source | Pro |
|---|---|
| The [Report Builder](/metrics_reports/reports/using-the-report-builder/) generates an HTML report from widgets you choose. The report is not saved, so you rebuild it each time. | Save a report **template** built from reusable blocks and a branded theme, and rerun it at any time. Templates can run on a schedule through the API or the MCP server, from a Triage Engine rule (for example one report per Asset after each import), or as a scheduled executive PDF from a dashboard. See [Report Builder](/metrics_reports/reports/report-builder/). |

### Can I get reports as PDF, or as data for another system?

| Open-Source | Pro |
|---|---|
| Reports are HTML, and you can save one as a PDF with your browser's **Print** option. Findings can be exported to CSV or Excel. | Reports can be PDF, HTML, CSV, Excel or JSON. The [Insights](/metrics_reports/pro_metrics/pro__overview/) dashboards and custom dashboards also export to PDF. |

### Can DefectDojo produce FedRAMP POA&Ms or OSCAL files?

In Pro, yes. [Compliance](/federal_compliance/) maintains POA&M items from your Findings and freezes a monthly snapshot as the official FedRAMP POA&M workbook and as an OSCAL POA&M, validated against the NIST schema. EU evidence packs export OSCAL Assessment Results. DefectDojo does not generate a System Security Plan. See [The POA&M Ledger](/federal_compliance/poam_ledger/).

### Does DefectDojo help with the EU Cyber Resilience Act?

In Pro, yes:

- [CRA Article 14 reports](/psirt/cra-article14-reporting/) track the 24-hour early warning, the 72-hour notification and the final report from the moment you become aware of an actively exploited vulnerability or a severe incident. DefectDojo prepares each report package; you submit it to the authority.
- [Evidence packs](/federal_compliance/eu_evidence_packs/) collect evidence for the CRA's vulnerability-handling requirements, and for DORA and NIS2.
- The [PSIRT](/psirt/) Advisory Engine publishes security advisories and VEX for your products.

### Can I export an SBOM or VEX?

In Pro, yes: CycloneDX and SPDX SBOMs for an Asset, and CycloneDX VEX from its Findings. See [Exporting SBOMs and VEX](/asset_modelling/locations/pro__exporting_sboms_and_vex/). The PSIRT Advisory Engine also publishes CSAF advisories and VEX.

## AI

### What can the MCP server do, and which AI assistants work with it?

The Pro [MCP server](/metrics_reports/ai/mcp_server_pro/) connects an AI assistant to your DefectDojo data. Out of the box the assistant can read and summarize Findings, Assets, Organizations, Engagements, Tests, users and roles. An administrator can add toolsets that let it build and schedule reports, create and share dashboards, and organize the Asset Hierarchy. The page has quick-start guides for Claude, OpenAI and Gemini, and any assistant that supports remote MCP servers over HTTPS can connect.

Open-Source does not include an MCP server.

### Can an AI assistant see data I can't?

No. The assistant connects with your own API token, so every request runs with your permissions: it sees only what you can see and can change only what you can change.

### Does DefectDojo send my data to an AI model, and can I use my own?

Only when you use a Sensei feature, and those features are optional. The rest of DefectDojo runs without AI.

Sensei is never trained on your data. DefectDojo uses your data only to complete the request you made and keeps no copy outside your instance. Our AI provider does not train on your data either.

**On DefectDojo Cloud**, Sensei is an AI agent built by DefectDojo. It runs inside your dedicated DefectDojo instance and reaches its models within DefectDojo's Google Cloud environment, using credentials unique to your instance. Your data is never mixed with another customer's. We improve the models behind Sensei over time, and you get those updates without changing anything.

**On self-hosted DefectDojo Pro**, Sensei is the agent harness and you bring the model. Connect the provider you already use (Anthropic, OpenAI, Amazon Bedrock or Google Vertex AI) in [AI Model Settings](/sensei/ai_model_settings/).

Model traffic goes directly from your instance to your own provider account and never passes through DefectDojo. Your provider's data terms apply to those requests.

If you connect an AI assistant through the [MCP server](/metrics_reports/ai/mcp_server_pro/), the data it reads goes to that assistant, under that assistant's terms.

### Does Sensei change my code without approval?

No. Sensei delivers code fixes as pull requests in your repository, which you review and merge like any other change. On repositories where you turn on hands-off mode, Sensei opens fix pull requests without waiting for someone to approve each one; the pull request still goes through your normal review. Fixes to cloud resources always need a person to approve them. See [Fixing Findings with Sensei](/sensei/fixing_findings/).

### Can AI mark a Finding as a false positive?

Not on its own. A Triage Engine rule can ask AI to review a Finding (Sensei license). The AI answers with a suggestion, such as *Likely false positive* or *Not affected*, and the suggestion waits in **AI Proposals** for a person to accept or reject it. A Finding's status changes on the model's word only if a rule author explicitly builds the rule that way.

## Administration and access

### How does access control work?

| Open-Source | Pro |
|---|---|
| Superusers manage everything. Other users see and work on the Organizations and Assets they are added to, and staff users can make non-destructive changes. See [Open-Source Permissions](/admin/user_management/os__authorized_users/). | Role-based access: give users and groups a role (Reader, Writer, Maintainer, Owner, API Importer, or a fine-grained [custom role](/admin/user_management/pro__custom_rbac_roles/) where you choose exactly which actions it may perform) on each Organization or Asset, or globally. See [Permissions in DefectDojo](/admin/user_management/about_perms_and_roles/). |

### How do I set up single sign-on, MFA or SCIM?

| Open-Source | Pro |
|---|---|
| Open-Source uses local accounts with a configurable password policy. | Configure [single sign-on](/admin/sso/) (SAML, OpenID Connect, Google, Microsoft Entra ID, Okta, Keycloak, Auth0, GitLab or GitHub Enterprise) or LDAP under **Connect > Authorization**, require [MFA](/admin/user_management/pro__mfa/), and provision users and groups from your identity provider with [SCIM](/admin/sso/pro__scim/). |

### Where can I see who changed what?

| Open-Source | Pro |
|---|---|
| Each object keeps a history of its changes. See [Audit Logs](/admin/user_management/os__audit_logging/). | **Audit Logs** cover the whole instance: who changed what and when, searchable in one place, with secret values masked. See [Audit Logging](/admin/user_management/pro__audit_log_index/). |

### An integration stopped working. Where do I look?

In Pro, open [Diagnostics](/admin/diagnostics/pro__diagnostics/) under **Connect**. It collects failures from connectors, ticketing, Jira, SSO, imports, rules and notifications in one place, with secrets removed. In Open-Source, check the logs of the `uwsgi` and `celeryworker` containers.

### How do I keep DefectDojo up to date?

| Open-Source | Pro |
|---|---|
| Pull the new release and rebuild, following the [upgrade notes](/releases/os_upgrading/upgrading_guide/) for every version in between. | On DefectDojo Cloud, DefectDojo deploys each new version for you. Self-hosted instances follow the [upgrade procedure](/get_started/pro/onprem/upgrading/) for Docker Compose or Kubernetes. |
