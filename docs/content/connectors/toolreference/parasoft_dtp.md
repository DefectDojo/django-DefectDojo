---
title: "Parasoft DTP"
description: "How to set up the Parasoft DTP Upstream Connector for DefectDojo"
weight: 103
audience: pro
---
The Parasoft DTP connector imports **static analysis violations** from a Parasoft DTP server. DefectDojo creates a Record for each DTP **report filter**.

#### Prerequisites

A Parasoft DTP **username and password**, used over HTTP Basic authentication. The password is never logged.

#### Connector Mappings

1. Enter your Parasoft DTP server URL in the **Location** field, including its port if it uses a non\-standard one.
2. Enter the DTP username in the **Username** field.
3. Enter the password in the **Password** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each report filter becomes a Record, carrying that filter's static analysis violations **from the latest build** — so findings describe the current state of the code rather than accumulating across builds.
