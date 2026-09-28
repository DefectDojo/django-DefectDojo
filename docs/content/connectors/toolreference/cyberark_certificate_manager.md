---
title: "CyberArk Certificate Manager"
description: "How to set up the CyberArk Certificate Manager Upstream Connector for DefectDojo"
weight: 42
audience: pro
---
The CyberArk Certificate Manager connector imports **PKI/certificate posture findings**. DefectDojo creates a Record for each certificate's **owning application** (SaaS) or **policy folder** (self\-hosted).

**These findings are DefectDojo's own analysis, not a vendor vulnerability list.** The connector enumerates your certificates and evaluates four posture rules against each one — **expiry**, **weak key**, **SHA\-1 signature**, and **self\-signed** — then raises findings from the results. If you go looking for a matching "vulnerabilities" list inside Certificate Manager, there isn't one.

Both editions are supported, and the connector normalizes them so the same rules apply to each:

* **`cloud`** — Certificate Manager SaaS, formerly TLS Protect Cloud.
* **`tpp`** — Certificate Manager Self\-Hosted, formerly Trust Protection Platform.

#### Prerequisites

* **Cloud:** a SaaS **API key**.
* **Self-hosted:** an **OAuth client ID** registered on the server, plus a **service account username and password**.

#### Connector Mappings

1. Enter your Certificate Manager URL in the **Location** field — `https://api.venafi.cloud` (or your region's host) for cloud, or your Trust Protection Platform host for self\-hosted.
2. Set **Edition** to `cloud` or `tpp`. It defaults to `cloud`.
3. For the **cloud** edition, enter the SaaS API key in **API Key (cloud)** and leave the `tpp` fields blank.
4. For the **tpp** edition, enter the **Client ID (tpp)**, **Username (tpp)** and **Password (tpp)**, and leave the cloud API key blank.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Because the credential fields are shared between editions, only the ones matching your chosen **Edition** are required — the others should be left empty.
