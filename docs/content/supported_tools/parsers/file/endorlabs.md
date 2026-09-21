---
title: "Endor Labs"
toc_hide: true
---

Import an [Endor Labs](https://www.endorlabs.com/) findings export.

This exists for organisations that cannot grant Endor Labs API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Endor Labs connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON, from Endor Labs' findings list endpoint. The API's `list.objects` envelope is accepted, as is a
bare `objects` array or a bare array of findings.

### Reachability is imported as the finding's impact

Endor Labs is reachability-aware SCA: its distinguishing output is whether the vulnerable code is
actually *called*, not merely present. That verdict is imported as the finding's **impact**, which is
where the connector puts it, so triagers see it prominently rather than having to notice a tag.

The verdict is resolved in the connector's order of precedence — a function-level verdict outranks a
dependency-level one, and a definite verdict outranks a "potentially":

| Endor tag | Impact |
| --- | --- |
| reachable function | Reachable (vulnerable function is called) |
| unreachable function | Unreachable (vulnerable function is not called) |
| potentially reachable function | Potentially reachable (function reachability undetermined) |
| reachable dependency | Reachable (dependency is used) |
| unreachable dependency | Unreachable (dependency is not used) |
| potentially reachable dependency | Potentially reachable (dependency reachability undetermined) |

### Severity

Endor Labs grades its own findings, and the connector maps its levels directly:
`FINDING_LEVEL_CRITICAL`→Critical, `HIGH`→High, `MEDIUM`→Medium, `LOW`→Low. Anything unrecognised or
unspecified is clamped to Info.

### Advisory text is flattened, never rendered

Endor Labs advisory text arrives as HTML, sourced from upstream advisories. It is flattened to plain
text on import: `script` and `style` content is dropped, block tags become newlines, and the result is
HTML-escaped. Nothing from an upstream advisory can be injected into a rendered finding.

### Fields worth noting

- **CVSS** — the v3 score and vector, falling back to the **v4 base score** when Endor publishes only
  v4. Without that fallback a v4-only advisory would import with no score at all.
- **Vulnerability IDs** — the primary identifier followed by Endor's aliases, deduplicated in order,
  so a GHSA and its CVE both land on the finding.
- **Component** — the target dependency name, falling back to its package name.
- **EPSS** — the exploit-prediction probability is written into the description when Endor supplies it.
- **Tags** — Endor's finding tags and categories, with the enum prefix stripped and the rest
  lower-cased and hyphenated. Values ending `_UNSPECIFIED` are dropped: they only record that Endor
  did not determine something.
- **Findings with no vulnerability** — Endor also reports secrets and other non-CVE findings, which
  carry no vulnerability block. Those import with no CVE, score or reachability.

### Scan type and deduplication

The scan type is **`Endor Labs - Connectors Import`** — identical to the string the Endor Labs
connector reports, so a customer who uploads an export *and* later enables the connector gets one set
of findings that deduplicate rather than two copies of everything.

Identity is the Endor finding UUID, which is stable across syncs. When a finding arrives without one,
the connector composes `<vulnerability id>|<component>:<version>` instead, and so does this parser.

### Sample Scan Data

Sample Endor Labs scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/endorlabs).

The samples are constructed from Endor Labs' documented findings schema, with generic package names,
placeholder identifiers and a generic tenant namespace.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vuln_id_from_tool
