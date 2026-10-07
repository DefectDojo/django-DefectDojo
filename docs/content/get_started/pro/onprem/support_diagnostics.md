---
title: "Support Diagnostics (self-hosted)"
description: "What a self-hosted DefectDojo Pro instance sends to DefectDojo support by default, how to opt in, and how the cloud portal secret is treated"
draft: false
weight: 11
audience: pro
---

DefectDojo Pro can report server errors and slow requests to DefectDojo support automatically, so a problem can be investigated without you collecting logs first. On a self-hosted instance both reports are **off by default**. Nothing is sent until you turn them on.

## The two reports

| Report | What it sends | Feature flag |
| --- | --- | --- |
| Error diagnostics | For a server error (HTTP 5xx): the affected user and their permissions, the server stack trace, and a screenshot of the page shown just before the error. Also covers failures that connector syncs, ticket pushes and Sensei scans report. | `error_diagnostics_reporting` |
| Performance diagnostics | For a request that runs an abnormal number of SQL queries or spends abnormal time in SQL: the endpoint, the affected user and the query counts. No SQL text. | `performance_diagnostics_reporting` |

Both go to the DefectDojo cloud portal (`CLOUD_PORTAL_URL`, `https://cloud.defectdojo.com` by default). The person who hit the error is not notified.

The default depends on the license: off when the license is for a self-hosted (`local`) deployment, on for DefectDojo Cloud.

## Turning a report on or off

Neither flag appears on the Feature Flags page. Set them with the `set_feature` management command in any DefectDojo container:

```bash
# turn error reports on
python3 manage.py set_feature error_diagnostics_reporting True --tier system

# turn them off again
python3 manage.py set_feature error_diagnostics_reporting False --tier system

# go back to the default for your license
python3 manage.py set_feature error_diagnostics_reporting --clear --tier system

# see every flag, its default for this license and its effective value
python3 manage.py set_feature --list
```

The same commands work for `performance_diagnostics_reporting`. The change applies to every container without a restart.

An air-gapped instance (`DD_AIRGAPPED=true`, or the **Airgapped instance** flag) never sends either report, whatever the flags say.

## The cloud portal secret on a self-hosted instance

A few endpoints exist for the DefectDojo cloud portal to call: the full health check, metrics, setting the license and the cloud firewall. They authenticate with the `CLOUD_PORTAL_SECRET_KEY` setting.

DefectDojo ships default values for that setting in its deployment files, and those values are public. On a self-hosted instance these endpoints refuse a shipped value, and the system checks log this warning at startup:

```
?: (pro.W003) CLOUD_PORTAL_SECRET_KEY is unset or set to a value that ships in DefectDojo's deployment files.
```

Nothing on a self-hosted instance needs those endpoints, so the warning is safe to leave. To use them, set `CLOUD_PORTAL_SECRET_KEY` to a long random string (for example, `openssl rand -hex 25`) on every DefectDojo container. The Helm chart's secret generation already does this.
