---
title: "TruffleHog"
description: "How to set up the TruffleHog Upstream Connector for DefectDojo"
weight: 133
audience: pro
---
The TruffleHog connector imports **secret detections** from TruffleHog Enterprise. DefectDojo creates a Record for each configured **scan source** — a repository, bucket or registry — and that source's detections become its findings. No per\-source configuration is required.

**Secret handling.** Findings carry only the **redacted** secret as TruffleHog reports it. Raw secret material is read solely to compute the deduplication digest, and never reaches a finding field, a log line, or an error message. Response bodies are never logged, even with debug logging enabled, so a debug session cannot leak secret material.

**Not to be confused with `trufflehog3`.** The separate `trufflehog3` parser in the supported tools list is a different tool with a different report format — it is not this connector's file equivalent.

#### Prerequisites

A TruffleHog **Enterprise** API token, sent as a bearer token.

#### Connector Mappings

1. Enter your TruffleHog Enterprise API host in the **Location** field.
2. Enter the Enterprise API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each configured scan source becomes a Record.
