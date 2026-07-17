---
title: "Source Code Locations"
description: "Code locations model where a static-analysis finding lives in source, and record its movement history as code evolves"
weight: 6
audience: pro
---

**Source Code Locations** extend the Locations model to static analysis: alongside URLs (DAST) and Dependencies (SCA), a **Code** location describes where a SAST finding lives in source — identified by its **file path and line number**.

> Source Code Locations require the Locations feature (Beta). To enable Locations on your instance, contact [support@defectdojo.com](mailto:support@defectdojo.com).

## What They Model

Every static finding that reports a file path gets a Code location. The location's canonical value is `path/to/file.py:42` (or just the file path when the tool reports no line). Like all Locations, code locations are shared objects: two findings at the same file and line reference the same location, and the location carries per-finding and per-asset reference statuses.

Code locations are **scan-managed**: they are created and updated by imports and reimports, not by hand. There is no "New Source Code Location" action — the scanner is the source of truth for where code findings live.

## Where to Find Them

- **All Source Code** in the sidebar lists every code location in the instance, with the same filtering and tagging as URLs and Dependencies.
- **View Source Code** in an Asset's Locations menu scopes the list to one asset.
- A finding's page shows its current code location and, when the finding has moved, its **location history**.

## Movement History

Source code moves constantly: commits shift line numbers, refactors rename files. When [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) is enabled for a tool, a finding that moves keeps its identity, and its code location references record the trail:

- The finding's reference to the **old** location is mitigated and stamped with *where the finding moved* and *why the match was made* (nearest line, dataflow, file rename ...).
- A reference to the **new** location is created and stays active.

The result is a browsable supersession chain — "this finding lived at `auth.py:42`, then `auth.py:57`, then `session.py:31`" — rendered as a timeline on the finding page. The same history mechanism covers URL moves and dependency version bumps, so all three location types share one timeline UI.

History is recorded from the moment Locations is enabled on the instance. Findings that moved before that keep their current location; past hops were applied but not recorded. For instances with years of pre-feature history, the [churn consolidation command](/triage_findings/finding_deduplication/pro__location_drift_matching/#consolidating-historical-churn) can reconstruct trails while merging historical close-and-recreate chains.

## Status Correctness

Code location reference statuses are kept truthful by reimport on **every** matching algorithm, whether or not drift matching is enabled:

- A matched finding's current code reference is synced on each reimport, so a finding that moved does not leave its old reference active forever.
- The same toggle-independent sync applies to dependency references: when an SCA finding's package version bumps, the old version's reference is mitigated rather than remaining active alongside the new one.

## Relationship to Finding Fields

The finding's own `file_path` / `line` fields remain the authoritative scalars (they are what filters, hashes, and the API expose); the Code location is the shared, reference-counted view of that same coordinate. Reimport refreshes the scalars from the latest scan and the location machinery derives locations from them — the two can not drift apart.
