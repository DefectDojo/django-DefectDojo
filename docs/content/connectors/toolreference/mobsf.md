---
title: "MobSF"
description: "How to set up the MobSF Upstream Connector for DefectDojo"
weight: 91
audience: pro
---
The MobSF connector uses the [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) REST API to import mobile application (APK/IPA) static-analysis results. DefectDojo discovers every app that has been scanned on your MobSF instance and creates a Record for each one, then imports that app's static-analysis findings.

#### Prerequisites

You will need your MobSF **REST API key**. Find it on the MobSF home page under **API** (also shown in the MobSF docs as the `Authorization` value). The key is sent on every request and is never logged.

#### Connector Mappings

1. Enter your MobSF base URL in the **Location** field (for example `https://mobsf.example.com`).
2. In the **Secret** field, enter the MobSF REST API key.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each scanned **app** to a Record and imports its findings from the MobSF JSON report across several sections — application permissions, code analysis, the signing certificate, the Android manifest, Android API usage and binary analysis. Each finding is tagged with **CWE 919** (mobile), and its severity comes from MobSF's own rating (high, warning, info, secure/good) — a *dangerous* permission is treated as High. Findings are recorded as static findings and de-duplicated on the scan, section, title, severity and file path.

See the [MobSF REST API documentation](https://mobsf.github.io/docs/#/rest_api) for more information.
