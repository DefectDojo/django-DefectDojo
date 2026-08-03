---
title: "NowSecure"
toc_hide: true
---

Import a [NowSecure](https://www.nowsecure.com/) mobile-app assessment export.

This exists for organisations that cannot grant NowSecure API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro NowSecure connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON. NowSecure's findings endpoint answers with a **bare array**, so an export is either that array or
an object carrying it as `findings` alongside the `assessment` that produced it.

Include the assessment when you can: the finding rows carry neither a date nor the platform, so
without it findings import with today's date and no platform tag.

### Only findings that affect the app are imported

NowSecure reports every check it ran, including the ones that found nothing. A row is imported only
when `affected` is true and `hidden` is false — a check that does not affect the app is not a finding,
and a hidden one has been suppressed in NowSecure itself.

### Static and dynamic are decided per finding

One assessment runs **both** a static and a dynamic analysis of the same app, and each finding says
which one found it:

| `analysis_type` | Imported as |
| --- | --- |
| `static` | static |
| `dynamic` | dynamic |
| anything else | neither flag set |

An unrecognised analysis type leaves both flags at their default rather than guessing which kind of
test ran.

### Severity

| NowSecure `severity` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `info`, `informational`, empty | Info |
| anything else | Info |

### Identity

`nowsecure-<check id>[-<vulnerability id>]`. The check id is the rule; the vulnerability id
distinguishes two hits of the same check in one app, and is omitted when NowSecure reports it as zero.
A finding with **no** check id falls back to a slug of its title — something stable is needed and the
title is all there is.

### Fields worth noting

- **Vulnerability identifiers** are read from the title, description and detail, then **sorted** and
  deduplicated case-insensitively. That is the connector's extractor behaviour, and it differs from the
  order-preserving path other connectors use — mirrored so the two import paths agree.
- **Mitigation** is NowSecure's developer recommendation, left empty when it has none.
- **The CVSS score is set unconditionally**, so an unscored finding lands as `0.0`. Mirrored for
  parity; flagged as a follow-up for both sides.
- **Every finding is active** — NowSecure reports what it found in this assessment.

### Sample Scan Data

Sample NowSecure scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nowsecure).

The samples are constructed from NowSecure's documented assessment and finding responses and cover a
static and a dynamic finding, an unrecognised analysis type, a finding with no check id, duplicate CVEs
in mixed case, an unscored finding, a check that does not affect the app, and a hidden one. Package and
account identifiers are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
