---
title: "NeuVector"
description: "How to set up the NeuVector Upstream Connector for DefectDojo"
weight: 93
audience: pro
---
The NeuVector connector uses the [NeuVector](https://github.com/neuvector/neuvector) controller REST API to import container **image vulnerability scans**. DefectDojo discovers every image NeuVector has scanned and creates a Record for each, then imports that image's scan report as findings.

#### Prerequisites

You will need a NeuVector **username and password** for a controller account with permission to read scan results. The connector logs in with these credentials to obtain a session token; the password and token are never logged.

#### Connector Mappings

1. Enter your NeuVector controller URL in the **Location** field, including the REST API port — for example `https://neuvector.example.com:10443`.
2. Enter the controller **Username** and **Password**.
3. If your controller uses a self-signed certificate, set **Skip TLS Verification** to `true`.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each scanned **image** to a Record and each **CVE** in its scan report to a finding. The severity comes from NeuVector's own rating, and the affected package and version, CVSSv3 score and vector, fix version (as mitigation) and reference link are carried over. Findings are de-duplicated on the image, CVE, package, version and severity.

See the [NeuVector API documentation](https://open-docs.neuvector.com/automation/automation) for more information.
