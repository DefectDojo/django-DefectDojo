---
title: "Docker Scout"
description: "How to set up the Docker Scout Upstream Connector for DefectDojo"
weight: 50
audience: pro
---
The Docker Scout connector uses the Docker Scout metrics exporter API to report the vulnerability posture of your organization's images. DefectDojo discovers each Docker Scout stream (your runtime environments) and imports a summary of the vulnerabilities and policy compliance for each.

#### Prerequisites

You will need a Docker personal access token created by an **owner** of a Docker organization that is **enrolled in Docker Scout**. The metrics exporter is an organization-level feature, so a personal account, or an organization that is not enrolled in Docker Scout, will not return data.

Create the token from your Docker account settings under **Personal access tokens**, and note your Docker **organization namespace**, which you will also need.

#### Connector Mappings

1. Enter `https://api.scout.docker.com` in the **Location** field.
2. Enter your Docker personal access token in the **Secret** field.
3. Enter your Docker **Organization** namespace.
4. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

DefectDojo creates a separate Record for each Docker Scout stream, and imports one finding per severity for the vulnerabilities Docker Scout counts in that stream, plus a finding for each image that fails your Docker Scout policy. Docker Scout's metrics API reports aggregate counts rather than individual CVEs, so these findings summarize the posture of a stream. Open the stream in Docker Scout for per-image and per-CVE detail.

See the [Docker Scout documentation](https://docs.docker.com/scout/) for more information.
