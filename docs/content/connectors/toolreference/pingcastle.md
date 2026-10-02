---
title: "PingCastle"
description: "How to set up the PingCastle Upstream Connector for DefectDojo"
weight: 105
audience: pro
---
The PingCastle connector imports **Active Directory security posture findings** from a PingCastle Enterprise reporting server. DefectDojo creates a Record for each **Active Directory domain** the reporting server monitors, and that domain's **latest HealthCheck report** supplies its findings.

This is a different category from most connectors in this list — identity and Active Directory posture, rather than application, cloud or container scanning.

#### Prerequisites

The PingCastle Enterprise **API key** — the same key your PingCastle agents use when they submit reports (the `--api-key` value passed alongside `--api-endpoint`). It is sent as the `X-API-Key` header.

#### Connector Mappings

1. Enter your **PingCastle Enterprise reporting server** URL in the **Location** field — the same address your agents submit to via `--api-endpoint`.
2. Enter the PingCastle Enterprise API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each monitored domain becomes a Record. DefectDojo reads the same HealthCheck risk rules that the file-based PingCastle parser reads from a local XML export, so findings are consistent whichever route you use.
