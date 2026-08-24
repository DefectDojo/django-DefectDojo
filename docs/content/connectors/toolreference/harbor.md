---
title: "Harbor"
description: "How to set up the Harbor Upstream Connector for DefectDojo"
weight: 71
audience: pro
---
The Harbor connector uses the Harbor v2.0 REST API to import container image vulnerabilities across your whole registry. DefectDojo enumerates every Harbor **project** and creates a Record for each one, then walks the project's repositories and artifacts and imports the vulnerabilities from each **scanned** artifact — carrying the image (repository + tag/digest) as finding context. There is no per\-image configuration.

#### Prerequisites

You will need a Harbor account (or a **robot account**) with pull/read access to the projects you want to import. We recommend a dedicated robot account: in Harbor, open a project (or **Administration \> Robot Accounts** for a system robot), create a robot with the **pull** permission on repositories and artifacts, and copy its full name and secret. Robot names start with `robot$` by default, but the prefix is configurable per Harbor instance (some use `robot_`) — copy the name exactly as Harbor displays it. A regular username/password also works.

#### Connector Mappings

1. Enter your Harbor URL in the **Location** field — for example `https://harbor.example.com`. DefectDojo appends the `/api/v2.0` API path automatically.
2. Enter the Harbor username, or a robot account name exactly as Harbor shows it (`robot$<name>` by default), in the **Username** field.
3. Enter the password or robot account secret in the **Secret** field. It is sent using HTTP Basic authentication.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Harbor project becomes a Record. For every artifact that has a completed scan, its vulnerabilities are imported as findings; the affected package/version, a CVSS\-derived severity, the CVE, the CWE, and a remediation (fixed version) are included where Harbor provides them. Only scanned artifacts are imported — trigger a scan in Harbor for images that have not been scanned yet.
