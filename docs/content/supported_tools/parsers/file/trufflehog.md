---
title: "Trufflehog"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/trufflehog/"
---
JSON Output of Trufflehog. Supports version 2 and 3 of https://github.com/trufflesecurity/trufflehog

### Sample Scan Data
Sample Trufflehog scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trufflehog).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- description
- line

### Stable Identity Across Commits
Every finding from a version 3 report carries a `unique_id_from_tool`: a one-way digest
(HMAC-SHA256 under a fixed key) of the detector, the repository, the file path and the raw secret.
The secret cannot be read back from it. The commit, the line and the verification data are not part
of it, so the same secret at the same path keeps its ID when a later scan finds it in another commit,
and a rotated secret at the same path gets a new ID. The repository is compared without a trailing
`.git`, so the git and GitHub sources agree on it. Version 2 reports do not carry an ID.

The default deduplication algorithm stays Hash Code, so nothing changes until you switch the scan
type to "Unique ID from tool" (or "Unique ID from tool or Hash Code") through
`DD_DEDUPLICATION_ALGORITHM_PER_PARSER`. Findings imported before this release have no ID, so each
is closed and recreated once on the first reimport after the switch; from then on they stay matched
across commits.

#### One Finding per Secret per File
Within one report the parser folds repeats of a detection into one finding, and `nb_occurences`
counts them. By default the fold key includes the commit, so a secret present in several commits is
several findings. Set `DD_TRUFFLEHOG_FOLD_COMMITS=True` to fold on the unique ID instead: one finding
per secret per file, however many commits it appears in, with every commit listed in the description.
Leave it off on an instance that deduplicates this scan type on Hash Code, where turning it on would
change the identity of existing findings.
