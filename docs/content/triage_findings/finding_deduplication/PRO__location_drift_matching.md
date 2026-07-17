---
title: "Location Drift Matching (Pro)"
description: "Track findings as their locations change across reimports — line shifts, file renames, URL moves, and dependency version bumps no longer close and recreate findings"
weight: 6
audience: pro
---

**Location Drift Matching** lets reimport recognize a finding whose *location* moved as the **same finding**. Without it, reimport matches findings by an exact identity hash that includes location fields — so every location movement closes the old finding and creates an identical new one:

- A commit shifts code and the finding's **line number** changes.
- A refactor **renames or moves the file**.
- A web application's **URL, port, or host** changes between DAST scans.
- A dependency **version bump** changes the vulnerable package version an SCA tool reports.

Each of these previously produced a closed finding plus a "new" finding — losing the status, notes, SLA clock, risk acceptance, and JIRA linkage on the original, and generating false "new critical finding" noise. With Location Drift Matching enabled, one finding is maintained in place: its location is updated from the latest scan and its history is preserved.

> Location Drift Matching is a DefectDojo Pro feature. It is **off by default** and enabled per security tool.

## Enabling Location Tracking

Location tracking is configured per tool under:
**Settings > Pro Settings > Deduplication Settings > Reimport Deduplication**

1. Select the **Security Tool**.
2. Set the **Deduplication Algorithm** to **Hash Code**. Location tracking applies to the Hash Code algorithm only — tools with a reliable **Unique ID From Tool** already track movement through their stable IDs and do not need it.
3. Enable **Track findings as locations change**.

Saving the setting automatically triggers a background re-hash of the tool's existing findings (see [Enabling on Existing Data](#enabling-on-existing-data-upgrades) below), so findings imported before the toggle participate immediately.

## How Matching Works

With tracking enabled, reimport matching happens in two stages:

1. **Stable identity.** The reimport hash is computed *without* the volatile location fields (line, file path, description, component name/version, endpoints) — so a finding's identity captures *what* the finding is, not *where* it currently lives. Findings that did not move still match exactly, first, and are never disturbed.
2. **Evidence pairing.** Within each group of findings that share a stable identity, a location matcher pairs incoming findings with existing ones using location evidence, in deterministic passes from strongest to weakest. A finding is routed to exactly one matcher based on the location data it carries.

### Code findings (SAST)

| Pass | Pairs when | Notes |
|------|-----------|-------|
| Exact | Same file and line | Always wins; a moved neighbor can never "steal" an unmoved finding's match |
| Dataflow | Same source/sink objects (`sast_source_object` / `sast_sink_object`) | For tools that report dataflow; immune to line renumbering |
| Nearest line | Same file, closest line number | Greedy, closest-first; same-file only |
| File rename | Different file | Only when exactly **one** incoming and **one** existing finding remain — ambiguity fails closed |

### URL findings (DAST)

| Pass | Pairs when |
|------|-----------|
| Exact | Identical endpoint set |
| Endpoint set drift | Overlapping endpoint sets (endpoints added/removed) |
| Port move | Same host and path, different port |
| Path drift | Same host, similar path (mutual-best segment similarity) |
| Host move | Different host — only as an unambiguous 1×1 pairing, with a wildcard-DNS guard |

### Dependency findings (SCA)

| Pass | Pairs when |
|------|-----------|
| Exact | Same package, version, and manifest |
| Version bump | Same package, different version |
| Manifest move | Same package, different lockfile/manifest path |

When the same vulnerable package appears in **several manifests**, each manifest's finding is tracked independently — a version bump in one lockfile never swallows the finding from another.

### Severity re-scores

Security tools re-score severities as their rule engines evolve. With tracking enabled, a tool-reported severity change does **not** split a finding's identity: the finding matches, and its severity is updated from the scan — unless a person has re-triaged the severity by hand, in which case the human's value always wins (see below).

## What Is Preserved, What Refreshes

A drift-matched finding keeps everything that matters about its lifecycle: status, notes, risk acceptance, SLA dates, JIRA linkage, and its finding ID.

Its **location fields** (file path, line, dataflow fields, endpoints, component version) refresh from the incoming scan.

Its **descriptive fields** (title, description, severity, component version) refresh from the scan *only when the scan still owns them*: DefectDojo records a digest of each field as last written by import/reimport. If the current value still matches that digest, the tool wrote it and the scan may update it; if a person edited the field since, the human's value is preserved permanently. Findings created before this feature have no digests and are treated as human-owned — reimport will never overwrite their descriptive fields. The single exception is **component version**, which is scan telemetry that people essentially never hand-edit: it refreshes even without a digest, so migrated SCA findings still receive version updates.

### Identity always tracks the tool's report

When a matched finding is refreshed, its stored identity hashes are **adopted from the incoming scan's values** — never recomputed from the finding's current fields. This distinction matters: the finding's fields after a refresh are a *merge* of scan values and human edits, and a hash computed from that merge would contain values no scan will ever report again, silently breaking every future reimport for that finding. Adoption guarantees that a person renaming a finding, re-triaging its severity, or editing its description can never break its ability to match the next scan.

## Location History

Under **Locations** (Beta), every drift match records where the finding used to live: the superseded source-code location, URL, or dependency version is kept as a reference on the finding, stamped with where it moved and why. The finding's location timeline — "this finding lived at `auth.py:42`, then `auth.py:57`, then `session.py:31`" — is visible on the finding page. See [Source Code Locations](/asset_modelling/locations/pro__source_code_locations/).

Location Drift Matching itself works **with or without** the Locations feature: matching pairs on the finding's own fields and endpoints, so findings survive movement either way. Locations adds the recorded, visible history on top. History starts recording from the moment Locations is enabled — earlier moves were applied but not recorded.

## Enabling on Existing Data (Upgrades)

The feature is designed to be self-migrating:

- **Nothing changes until you opt in.** With the toggle off, reimport hashes compute exactly as before.
- **Saving the toggle re-hashes existing findings.** The background job recomputes the tool's stored reimport hashes with the new (location-free) identity, and creates any missing Pro finding records for data migrated from open-source. Once it completes, old and new findings speak the same identity language — a finding imported months ago is tracked exactly like one imported yesterday.
- **Enable between scan runs on large instances.** The re-hash is a background job over the tool's whole finding population. A reimport that lands while it is mid-flight can see a mix of old and new hashes and churn the unprocessed slice once. Flip the toggle at a quiet time, and let the job finish before the next scheduled reimport.
- **Hand-edited titles.** The opt-in re-hash computes from current database values. Every commonly-edited field is excluded from the tracked identity — severity edits are actually *healed* by the re-hash — but if a person renamed a finding's **title** (and title is a hash field for that tool), that one finding will churn once on its next reimport before stabilizing.

## Choosing Hash Fields for Tracked Tools

Location tracking removes the volatile location fields from the reimport hash automatically — you do not need to remove `line` or `file_path` from a tool's hash configuration yourself. Two configurations deserve attention:

- **All-volatile configurations.** If a tool's hash fields are *entirely* location fields (for example just `file_path` + `line`), stripping them leaves nothing, and the hash falls back to the legacy title+CWE identity. Matching still works — the evidence passes carry the discrimination — but identity is much coarser. Prefer configurations that keep at least one stable content field.
- **Location embedded in stable fields.** Field exclusions cannot help when location data hides *inside* a field that must stay in the hash. A tool that titles findings "SQL Injection in queries.py:42" changes its title on every line move — the identity splits and tracking cannot see the pair. For such tools, choose hash fields that avoid the leaking field; **CWE + Content Fingerprint** is the strong combination (see [Content Fingerprint](/triage_findings/finding_deduplication/pro__deduplication_tuning/#content-fingerprint)).

## Interaction with Deduplication

Location tracking is a **reimport** feature: Same Tool and Cross Tool Deduplication are unchanged — their hashes compute exactly as before, and the exclusions never apply to them. Two deliberate integrations:

- **Version bumps no longer block dependency deduplication.** The deduplication location gate normally requires two SCA findings to reference the *identical* package version. For tracking-enabled tools, a shared package identity (ecosystem + package name, with the namespace compared whenever both sides carry one) is enough — consistent with reimport treating a version bump as the same finding. This applies to Same Tool deduplication under Locations only.
- **Clean identity inputs.** Because matched findings adopt scan-reported hashes, the values deduplication consumes always reflect what the tool last reported — human edits can no longer contaminate them.

## Consolidating Historical Churn

Instances that ran for years without tracking accumulate close-and-recreate chains: the same finding closed and reopened as a new record every time it moved. A management command finds those chains (linked hop-by-hop by the same matchers, with a lifetime-overlap guard so findings that genuinely coexisted never merge) and consolidates each chain onto its most recent finding, marking the older copies as duplicates of the survivor:

```bash
# Dry run — reports what would be consolidated, changes nothing
./manage.py consolidate_location_churn --product <id>

# Apply, with a confirmation prompt
./manage.py consolidate_location_churn --product <id> --apply
```

The command is dry-run by default, never runs automatically, and can be scoped with `--test` or `--product`. Under Locations, the survivor's location history is reconstructed from the chain.

## Safeguards and Limits

- **Exact matches always win.** An unmoved finding pairs exactly before any fuzzy pass runs; movers can never steal its match.
- **Ambiguity fails closed.** File renames and host moves pair only when exactly one candidate remains on each side. Two findings that both disappeared while two new ones appeared stay unmatched rather than guess.
- **Very large groups degrade gracefully.** If a single identity bucket exceeds the pairing cap (40,000 comparisons), matching degrades to exact-only for that bucket instead of consuming unbounded time.
- **Accepted trade-off:** the 1×1 rename/host-move passes can create false continuity when one finding disappears and an unrelated finding with the same stable identity appears in the same reimport. This is the deliberate price of tracking renames; the stable identity (same tool, title, CWE, severity ...) bounds how wrong the pairing can be.

## Location Refresh Without the Toggle

Independent of location tracking, reimport keeps every matched finding's location current on **all** algorithms: a finding matched by Unique ID From Tool (or any other algorithm) refreshes its `line`, `file_path`, dataflow fields, and `component_version` from the incoming report, and reported endpoints are attached while vanished ones are mitigated. Values a scan omits never overwrite existing data, and a human-pinned component version is preserved. This closes the long-standing gap where uid-matched SAST findings displayed the line number from their first import forever. It can be disabled instance-wide with `DD_REIMPORT_REFRESH_LOCATION_FIELDS=False`.
