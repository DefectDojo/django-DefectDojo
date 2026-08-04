---
title: "Rapid7 InsightAppSec"
toc_hide: true
---

Import a [Rapid7 InsightAppSec](https://www.rapid7.com/products/insightappsec/) vulnerability export.

This exists for organisations that cannot grant InsightAppSec API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro InsightAppSec connector pulls
the same data over the API; this parser accepts the same data as a file.

### File Types

JSON — the vulnerability-list response, with rows under `data`. A bare array of rows is accepted too.

**Include the attack-module metadata.** InsightAppSec names a vulnerability only by the *id* of the
attack module that found it; the readable name ("SQL Injection") and the explanatory prose come from a
separate call. Without it, every finding is titled `InsightAppSec finding`. Supply it as:

- a top-level `modules` array of module objects, or
- a `modules` object keyed by module id, or
- the module endpoint's own `{"data": [...]}` response under `modules`.

### Only open findings are imported

A row is imported when its `status` is `UNREVIEWED` or `VERIFIED`. `REMEDIATED`, `DUPLICATE`,
`IGNORED` and `FALSE_POSITIVE` are left out so a reimport **closes** them in DefectDojo rather than
resurrecting them.

Both the status and the severity are matched **case-sensitively**, against InsightAppSec's own
uppercase enums — a lowercase `verified` is not a value the API sends, and accepting it would be this
parser inventing tolerance the API path does not have.

### Severity

| InsightAppSec `severity` | Severity |
| --- | --- |
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW` | Low |
| `INFORMATIONAL`, `SAFE` | Info |
| anything else | Info |

The raw label is always recorded as the severity justification, so a value that graded as Info because
it was unrecognised is still auditable.

### Deduplication is the unique id alone

This scan type's configuration pairs `unique_id_from_tool_or_hash_code` with a hash of
**`unique_id_from_tool` and nothing else** — no title, no severity. InsightAppSec's vulnerability id is
stable across scans, so it is the whole identity; adding a volatile field would split a finding that
had merely been regraded.

### Evidence is flattened, not rendered

The evidence InsightAppSec captures is the application's own response to an attack payload — the least
trustworthy text in the export. The connector flattens it: script and style content is dropped, tags
are removed, and the result is HTML-escaped. This parser reproduces that byte for byte, including Go's
spelling of the apostrophe entity (`&#39;`, where Python would write `&#x27;`).

One consequence worth knowing: **an attack payload that is only markup flattens to nothing.** A value
of `<script>alert(1)</script>` leaves an empty `Attack value` line. That is the connector's behaviour,
mirrored here rather than corrected.

Only the first **three** evidence entries are printed, followed by a count of the rest — a single
vulnerability can carry hundreds of variances, and the description is context rather than an evidence
archive.

### Fields worth noting

- **Title** is `<module> in "<parameter>" parameter`. The quotes are the connector's and they matter: a
  parameter called `id` is otherwise indistinguishable from prose.
- **`vuln_id_from_tool`** is the module's name, falling back to its id and then to the vulnerability id.
- **CVSS** is recorded only when the vector really is v3. InsightAppSec also reports v2 vectors, and
  the same number means different things on the two scales.
- **References** are the InsightAppSec UI link, then the module's reference links in sorted key order —
  the connector sorts because a Go map has no order, and matching that keeps the two paths identical.

### Sample Scan Data

Sample Rapid7 InsightAppSec scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/insightappsec).

The samples are constructed from InsightAppSec's documented vulnerability and module responses and
cover five evidence entries (so the omission note appears), a markup-only attack payload, a CVSS v2
vector, an unrecognised severity, a module with no metadata, and one row for each closed-out status.
Hostnames and identifiers are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
