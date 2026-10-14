---
title: "DefectDojo Documentation"
description: "Docs for DefectDojo, the open-source vulnerability management and ASPM platform that imports, deduplicates and tracks findings from 500+ security tools."
date: 2021-02-02T20:46:29+01:00
draft: false
---
## What is DefectDojo?

DefectDojo is a vulnerability management and application security posture management (ASPM) platform. It does not scan code or infrastructure itself. It imports results from more than 500 security tools, including SAST, DAST, SCA, secrets, container, cloud and infrastructure scanners, and turns them into one deduplicated list of Findings that your team can triage, track and report on.

DefectDojo comes in two editions:

- **Community Edition** is free and open source, and you host it yourself. It began as an OWASP project and is maintained by DefectDojo, Inc. and the open-source community.
- **DefectDojo Pro** is the commercial edition from DefectDojo, Inc., available in the cloud or on premises. It adds a newer UI, Connectors that pull findings from tools on a schedule, the Rules Engine, Pro dashboards and Sensei for AI triage and code fixes. See [Pro features](/get_started/pro/pro_features/) for the full list.

## What you can do with DefectDojo

- **Import** scan files by hand, through the REST API, from a CI/CD pipeline, or with [Connectors](/connectors/about/).
- **Reimport** into the same Test on every pipeline run. DefectDojo can close Findings that are fixed and reopens ones that come back. See [Reimport](/import_data/import_intro/reimport/).
- **Deduplicate** Findings within a tool, across tools and across reimports. See [how deduplication works across tools](/triage_findings/finding_deduplication/deduplication_across_tools/).
- **Triage** with severity, SLAs, false positive history and risk acceptance.
- **Push** Findings to Jira and other issue trackers so developers fix them where they already work.
- **Report** on security posture with dashboards, metrics and exportable reports.

New here? Start with [About DefectDojo](/get_started/about/about_defectdojo/), then browse the [supported tools](/supported_tools/).
