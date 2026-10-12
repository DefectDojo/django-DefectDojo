---
title: "Running an Airgapped Instance"
description: "Stop a self-hosted DefectDojo Pro instance from calling DefectDojo or any third-party feed when it has no route off its network"
draft: false
weight: 11
audience: pro
---

A self-hosted DefectDojo Pro instance makes a few outbound calls on its own: it checks for new versions, refreshes the external tools list, reads product announcements, downloads threat intelligence bundles, and relays error and performance diagnostics to DefectDojo. On a network with no route out, every one of those calls fails and logs an error.

Airgapped mode stops all of them with one setting.

## Turning it on

Set the `DD_AIRGAPPED` environment variable on every DefectDojo container (uwsgi, the Celery workers, Celery beat and the initializer):

```
DD_AIRGAPPED=True
```

Restart the stack after setting it. The variable takes effect from the first boot, before the database is reachable, so a fresh deployment never attempts a call.

On Docker Compose deployments the shipped compose files pass `DD_AIRGAPPED` through, so it can go in your environment file. On Kubernetes, add it to the chart's extra environment variables for the Django pods.

You can also turn it on without a restart: a superuser turns on the **Airgapped instance** feature flag under **Settings → Feature Flags**. The flag and the variable do the same thing, but the variable wins. While `DD_AIRGAPPED` is set, the flag shows as on and is marked as managed by the deployment, so it cannot be turned off from the page.

## What stops

| Call | Destination | When airgapped |
| --- | --- | --- |
| Version check (hourly, and **Check for update**) | DefectDojo's container registry | Skipped. The instance does not report newer releases. |
| External tools refresh (daily, and the first visit to **External Tools**) | DefectDojo's public storage bucket | Skipped. The page lists the tools already on the instance; if there are none, it shows a message with the support address instead. Downloads are refused. |
| Product announcements (every 3 hours) | `intel.defectdojo.com`, then DefectDojo's storage bucket | Skipped, including the fallback. |
| Threat intelligence bundle download (daily) | `intel.defectdojo.com` | Skipped. Threat intelligence scoring keeps working with bundles you load from a file (see below). |
| Error and performance diagnostics | DefectDojo's cloud portal | Turned off. Reports already queued are dropped, not sent. |
| Support requests, community board and documentation search | DefectDojo's cloud portal and documentation site | The support pages show the DefectDojo support address instead. See [Support](/navigation/pro__support/#airgapped-instances). |

Each skipped call writes one `INFO` log line naming what was skipped, so you can confirm the mode is active from the worker logs.

## What does not change

Airgapped mode only stops calls that DefectDojo makes on its own. Integrations you configure yourself keep working, because on an isolated network they point at systems inside it:

- Jira, webhooks, email and other notification channels
- Connectors and scan tools
- SSO identity providers
- LLM providers
- PSIRT feed sources, and the KEV, EPSS and OSV finding enrichment lookups. These are off until you turn them on. Leave them off unless you point them at an internal mirror.

## Loading threat intelligence offline

Download the bundle and its `.sig` signature file on a connected machine, copy both into the instance side by side, and load the bundle with:

```
python manage.py load_threat_intel_bundle --file /path/to/intel-<date>.tar.zst
```

The loader verifies the signature and re-scores the affected findings, the same as the scheduled download. Run without `--file`, the command would download a bundle, so on an airgapped instance it refuses and asks for a file instead.

## The cloud portal URL

On a self-hosted instance, `CLOUD_PORTAL_URL` (`dojo.cloudPortalUrl` in the Helm chart) is used only for diagnostics and the support pages. It is not used for licensing: the license is validated locally. Airgapped mode stops both uses, so the value is never contacted. The Helm chart still requires a value; set any placeholder that cannot resolve, for example `https://cloud-portal.invalid`.
