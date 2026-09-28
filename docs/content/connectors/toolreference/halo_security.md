---
title: "Halo Security"
description: "How to set up the Halo Security Upstream Connector for DefectDojo"
weight: 70
audience: pro
---
The Halo Security connector imports **attack surface findings** from Halo Security. DefectDojo creates a Record for each **monitored target**.

#### Prerequisites

A Halo Security **API key**. This connector uses a single key — there is no secret, key pair, or OAuth flow to configure.

#### Connector Mappings

1. Enter `https://api.halosecurity.com/api/v1` in the **Location** field.
2. Enter your Halo Security API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each monitored target becomes a Record, carrying the account's **active** issues that affect it, enriched from Halo's issue catalogue.

A finding's identity combines the issue **and** the target it was found on. Halo's issue IDs are catalogue identifiers shared across targets, so the same issue affecting two targets is correctly tracked as two findings rather than collapsing into one.
