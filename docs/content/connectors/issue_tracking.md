---
title: "Issue Tracking Integration"
description: "Sync DefectDojo findings with your issue tracking system to streamline remediation and accountability."
weight: 6
aliases:
  - /issue_tracking/
  - /issue_tracking/intro/
  - /issue_tracking/intro/intro/
---

## Overview

The DefectDojo issue tracking integrations connect your vulnerability management workflows with your existing issue tracking system. By automatically creating and updating issues from security findings, DefectDojo helps ensure vulnerabilities are visible, owned, and addressed within the same tools your development and operations teams already use.

| Edition      | Supported Issue Tracking Integrations |
|--------------|---------------------------------------|
| Community Edition  | * [Jira](/connectors/os_jira/os__jira_guide/)                          |
| Pro          | * [Jira](/connectors/toolreference/jira/) ([legacy guide](/connectors/downstream/pro__jira_guide/))<br>* [Azure DevOps](/connectors/toolreference/azure_devops_boards/)<br>* [Bitbucket](/connectors/toolreference/bitbucket/#downstream-connector)<br>* [Freshservice](/connectors/toolreference/freshservice/)<br>* [GitHub](/connectors/toolreference/github/#downstream-connector)<br>* [GitLab Boards](/connectors/toolreference/gitlab/#downstream-connector)<br>* [Linear](/connectors/toolreference/linear/)<br>* [PagerDuty](/connectors/toolreference/pagerduty/)<br>* [ServiceDesk Plus](/connectors/toolreference/servicedesk_plus/)<br>* [ServiceNow](/connectors/toolreference/servicenow/)<br>* [Shortcut](/connectors/toolreference/shortcut/)<br>* [Zendesk](/connectors/toolreference/zendesk/) |


When enabled, DefectDojo can create issues automatically, or selectively from Assets or Engagement. As Findings are updated in DefectDojo—resolved, mitigated, or reactivated—the corresponding issues can be kept in sync, ensuring both systems reflect the current state of risk.

## What Gets Tracked

Each issue can include key vulnerability details such as severity, description, evidence, and remediation guidance. Links between DefectDojo and the issue tracking system provide traceability from discovery through resolution, supporting reporting, audits, and continuous improvement.

## Why Issue Tracking Integrations Matter

Security findings are most effective when they are actionable. Integrating DefectDojo with an issue tracking system bridges the gap between detection and remediation by embedding security work directly into established engineering workflows. This reduces context switching, improves accountability, and helps teams remediate issues faster.

