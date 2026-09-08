---
title: "Bright Security"
description: "How to set up the Bright Security Upstream Connector for DefectDojo"
weight: 28
audience: pro
---
The Bright Security connector uses the [Bright](https://brightsec.com) (formerly NeuraLegion) API to import **DAST findings**. DefectDojo discovers every scan the token can access and creates a Record for each completed scan, then imports that scan's issues as findings.

#### Prerequisites

You will need a Bright **API key**, created in the Bright app under **User settings → API keys** (an `Org` or personal key). The key is sent in the `Authorization: Api-Key` header and is never logged.

#### Connector Mappings

1. Keep the pre-filled **Location**, `https://app.brightsec.com`, or enter your Bright host explicitly.
2. Enter the Bright API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each completed **scan** to a Record and each **issue** to a finding: the severity comes from Bright's own rating (Critical/High/Medium/Low), the CVSS score, CWE and remediation are carried over, the affected entry point becomes the endpoint, and the request/response evidence is included in the description. Findings are recorded as dynamic findings and de-duplicated on Bright's issue id.

See the [Bright API documentation](https://docs.brightsec.com/) for more information.
