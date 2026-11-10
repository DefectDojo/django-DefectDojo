---
title: "TruffleHog"
description: "How to set up the TruffleHog Upstream Connector for DefectDojo"
weight: 133
audience: pro
---
The TruffleHog connector imports **secret detections** from TruffleHog Enterprise. DefectDojo creates a Record for each configured **scan source** — a repository, bucket or registry — and that source's detections become its findings. No per\-source configuration is required.

**Secret handling.** Findings carry only the **redacted** secret as TruffleHog reports it. Raw secret material is read solely to compute the deduplication digest, and never reaches a finding field, a log line, or an error message. Response bodies are never logged, even with debug logging enabled, so a debug session cannot leak secret material.

**Finding identity.** Each finding carries the same `unique_id_from_tool` the Trufflehog Scan parser sets: a one-way digest of the detector, the repository, the file path and the raw secret, with the commit left out. A sync and a file import of the same detection agree on it, and a secret that moves to another commit keeps it. The scan type deduplicates on Hash Code by default; switch it to "Unique ID from tool" to match on the ID.

**One finding per secret per file.** Within one sync the connector folds repeats of a detection into one finding, and `nb_occurences` counts them. By default the fold key includes the commit, so a secret present in several commits is several findings, as the file parser reports by default. Turn on **Fold Commits** on the connection to fold on the unique ID instead: one finding per secret per file, however many commits it appears in, with every commit listed in the description. This is the connector counterpart of the parser's `DD_TRUFFLEHOG_FOLD_COMMITS` setting. Turn it on only where this scan type deduplicates on Unique ID From Tool, or on Unique ID or Hash Code. On Hash Code alone (the default for this scan type), the folded finding's description grows with every commit, so its identity changes each time a sync finds the secret in a new commit, not only once when the toggle is switched.

**Not to be confused with `trufflehog3`.** The separate `trufflehog3` parser in the supported tools list is a different tool with a different report format — it is not this connector's file equivalent.

#### Prerequisites

A TruffleHog **Enterprise** API token, sent as a bearer token.

#### Connector Mappings

1. Enter your TruffleHog Enterprise API host in the **Location** field.
2. Enter the Enterprise API token in the **Secret** field.
3. Optionally, turn on **Fold Commits** to report one finding per secret per file instead of one per commit (see above). It is off by default and can be changed later.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each configured scan source becomes a Record.
