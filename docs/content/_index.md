---
title: "DefectDojo Documentation"
description: "Docs for DefectDojo, the open-source vulnerability management and ASPM platform that imports, deduplicates and tracks findings from 500+ security tools."
date: 2021-02-02T20:46:29+01:00
draft: false
---
## What is DefectDojo?

DefectDojo is a vulnerability management and application security posture management (ASPM) platform. It does not scan code or infrastructure itself. It imports results from more than 500 security tools, including SAST, DAST, SCA, secrets, container, cloud and infrastructure scanners, and turns them into one deduplicated list of Findings that your team can triage, track and report on.

DefectDojo comes in two editions. The Community Edition is free and open source under the BSD 3-Clause License, and you host it yourself. It is an OWASP Flagship project, maintained by DefectDojo, Inc. and the open-source community. DefectDojo Pro is the commercial edition from DefectDojo, Inc., available in the cloud or on premises. It adds a newer UI, Connectors that pull findings from tools on a schedule, the Rules Engine, Pro dashboards and Sensei for AI triage and code fixes. See [Pro features](/get_started/pro/pro_features/) for the full list.

## What you can do with DefectDojo

- Import scan files by hand, through the REST API, from a CI/CD pipeline, or with [Connectors](/connectors/about/).
- Reimport into the same Test on every pipeline run, so DefectDojo can close Findings that are fixed and reopen ones that come back. See [Reimport](/import_data/import_intro/reimport/).
- Deduplicate Findings within a tool, across tools and across reimports. See [how deduplication works across tools](/triage_findings/finding_deduplication/deduplication_across_tools/).
- Triage with severity, SLAs, false positive history and risk acceptance.
- Push Findings to Jira and other issue trackers so developers fix them where they already work.
- Report on security posture with dashboards, metrics and exportable reports.

## Common questions

### Is DefectDojo a vulnerability scanner?

No. DefectDojo does not run scans. It collects the output of the scanners you already use, such as Semgrep, Snyk, Trivy, Burp Suite, ZAP, Tenable and cloud security tools, and manages those results in one place. The [supported tools](/supported_tools/) list shows every format DefectDojo can import.

### Is DefectDojo free?

The DefectDojo Community Edition is free to download, use and modify under the BSD 3-Clause License. You run it on your own servers, usually with Docker Compose. DefectDojo Pro is a paid subscription that includes hosting options, support and the Pro-only features.

### How does DefectDojo handle duplicate findings?

DefectDojo builds a hash code for each Finding from fields configured per tool, such as title, CWE, vulnerability IDs, component, file path and line, or uses the tool's own ID for the result when the tool provides one. With deduplication turned on, a new Finding that matches an existing one in the same Asset is marked as a duplicate of the oldest match, so your team triages the issue once. Matching works across repeated scans from one tool, and across different tools that hash the same fields. See [deduplication across tools](/triage_findings/finding_deduplication/deduplication_across_tools/).

### Which issue trackers does DefectDojo work with?

The Community Edition integrates with Jira. DefectDojo Pro also creates and syncs issues in Azure DevOps, Bitbucket, GitHub, GitLab, Linear, ServiceNow, Shortcut, Zendesk and other trackers. See [issue tracking](/connectors/issue_tracking/).

### How is DefectDojo organized?

DefectDojo groups work as Organizations, Assets, Engagements and Tests. An Asset is something you secure, such as an application, repository or service. Each scan you import becomes a Test inside an Engagement on that Asset, and each result in the scan becomes a Finding. See [the DefectDojo data model](/asset_modelling/os_hierarchy/os__asset_hierarchy/).

New here? Start with [About DefectDojo](/get_started/about/about_defectdojo/), then browse the [supported tools](/supported_tools/).
