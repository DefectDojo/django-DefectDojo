---
title: "TruffleHog"
description: "How to set up the TruffleHog Upstream Connector for DefectDojo"
weight: 133
audience: pro
---
The TruffleHog connector imports **secret detections** from TruffleHog Enterprise. DefectDojo creates a Record for each configured **scan source** — a repository, bucket or registry — and that source's detections become its findings. No per\-source configuration is required.

**Secret handling.** Findings carry only the **redacted** secret as TruffleHog reports it. Raw secret material is read solely to compute the deduplication digest, and never reaches a finding field, a log line, or an error message. Response bodies are never logged, even with debug logging enabled, so a debug session cannot leak secret material.

**Finding identity.** Each finding carries the same `unique_id_from_tool` the Trufflehog Scan parser sets: a one-way digest of the detector, the repository, the file path and the raw secret, with the commit left out. A sync and a file import of the same detection agree on it, and a secret that moves to another commit keeps it. The scan type deduplicates on Hash Code by default; switch it to "Unique ID from tool" to match on the ID.

**Not to be confused with `trufflehog3`.** The separate `trufflehog3` parser in the supported tools list is a different tool with a different report format — it is not this connector's file equivalent.

#### Prerequisites

A TruffleHog **Enterprise** API token, sent as a bearer token.

#### Connector Mappings

1. Enter your TruffleHog Enterprise API host in the **Location** field.
2. Enter the Enterprise API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each configured scan source becomes a Record.
