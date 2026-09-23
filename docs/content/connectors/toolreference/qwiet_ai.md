---
title: "Qwiet AI"
description: "How to set up the Qwiet AI Upstream Connector for DefectDojo"
weight: 111
audience: pro
---
The Qwiet AI connector imports **SAST, SCA and secret findings** from Qwiet AI (formerly ShiftLeft), and carries Qwiet's **reachability signal** — an indication of whether vulnerable code is actually reachable — which DefectDojo has no other source for. DefectDojo creates a Record for each **application** in your organization.

#### Prerequisites

A Qwiet AI **preZero access token**, sent as a bearer token and never logged. Your organization is read from the token itself, so you do not normally need to supply it.

#### Connector Mappings

1. Enter `https://app.shiftleft.io` in the **Location** field — the host is still the legacy ShiftLeft domain. DefectDojo appends the API path itself.
2. Enter the access token in the **Access Token** field.
3. Optionally, enter an **Organization ID** to override the organization. Leave it blank to use the organization encoded in the access token.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each application becomes a Record, carrying its SAST, SCA and secret findings together.
