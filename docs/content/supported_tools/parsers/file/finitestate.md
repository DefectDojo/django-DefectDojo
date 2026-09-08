---
title: "Finite State"
toc_hide: true
---

Import a [Finite State](https://finitestate.io/) findings export.

This exists for organisations that cannot grant Finite State API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Finite State connector pulls
the same data over the API; this parser accepts the same data as a file.

### File Types

JSON. Finite State answers GraphQL, so a saved export is its findings response:

```json
{
  "asset":        {"id": "asset-0001", "name": "Generic Router"},
  "assetVersion": {"id": "ver-0001", "name": "1.4.0", "relativeRiskScore": 2.5},
  "data": {"allFindings": [ ... ]}
}
```

One export is **one firmware build**, so the asset and build context is stated once for the file
rather than repeated on every row — though a row carrying its own `asset`/`assetVersion` overrides it,
for an export that repeats the context per finding. A finding on firmware means little without knowing
which build it is in, which is why the connector passes both into every conversion.

An unwrapped `allFindings`, a `findings` list, and a bare array of findings are all accepted. An
export with no build context still imports; it simply carries no asset lines and no build tag.

### VEX status is the part that carries real semantics

A Finite State finding can carry a **VEX assertion** — a product team's statement about whether the
vulnerability actually applies to this build:

| `currentStatus.status` | Imported as |
| --- | --- |
| `NOT_AFFECTED` | inactive, **out of scope** (plus false positive — see below) |
| `FIXED` | inactive, **mitigated**, recording when |
| `UNDER_INVESTIGATION` | active, **under review** |
| `AFFECTED`, anything unrecognised, or no status block | **active** |

`NOT_AFFECTED` must not sit in DefectDojo as active: leaving it there would put an answered question
back in the queue on every import. It is additionally marked a **false positive** when the
justification says the vulnerable code is not there to be reached —
`COMPONENT_NOT_PRESENT`, `VULNERABLE_CODE_NOT_PRESENT`, `VULNERABLE_CODE_NOT_IN_EXECUTE_PATH`. A
justification like `INLINE_MITIGATIONS_ALREADY_EXIST` means the flaw is real but handled: out of
scope, and **not** a false positive. The distinction matters for metrics.

Anything unrecognised stays **active**, which is the safe direction to be wrong in — a finding wrongly
left active gets triaged, while one wrongly closed is never seen again.

### Severity

| Source | Used when |
| --- | --- |
| `severity` | it is a word Finite State uses |
| `cvssSeverity` | `severity` is not one of those words |

`critical`/`high`/`medium`/`low` map across; `info`, `none` and **`unknown`** all mean Info. Note that
`unknown` is a value the platform actually uses, so a finding graded `unknown` is Info even when its
CVSS severity says Critical — the fall-through only happens for a word the platform does not use at
all. Treating `unknown` as missing would silently upgrade every unscored finding.

### Scores

- **CVSS**: the finding's own `cvssScore` wins; otherwise the first CVE's `cvssBaseMetricV3` base
  score. The vector string comes from the first CVE that carries one.
- **EPSS**: per-CVE, so the **highest** across the finding's CVEs is used — that is the finding's real
  exploitation likelihood. The percentile travels with the score it belongs to rather than being
  mixed in from another CVE.

### Fields worth noting

- **The first affected component** is the component; Finite State can list several, and the first is
  the one the finding is filed against.
- **CWE** is the first `cweId` that parses, accepting `CWE-79` or `79`; an unparseable one is skipped
  rather than ending the search.
- **Tags** carry `firmware-build:<name or id>`, the category and subcategory, the source types, the
  tools that produced the finding, `regression`, and `weaponized`/`exploited-in-the-wild` from any of
  the finding's CVEs. The build tag is what lets a reader tell which firmware a finding belongs to
  without opening it, which matters when several builds of one product share a product.
- **The description is not trimmed**, matching the connector, so it keeps its trailing newline.

### Deduplication

This scan type has **no curated hashcode field list**, so it deduplicates with DefectDojo's default
algorithm — which is what the connector's own findings already do. Choosing hashcode fields here would
also change how those findings deduplicate, so it is left alone.

### Sample Scan Data

Sample Finite State scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/finitestate).

The samples are constructed from the platform's GraphQL schema and cover an affected finding with two
CVEs at different EPSS scores, a `NOT_AFFECTED` finding justified by absence, another justified by
inline mitigations, a fixed one, one under investigation, one with no status block, an unrecognised
severity in both fields, an unparseable CWE followed by a bare number, an unparseable timestamp, and
an export with no build context at all. Asset, build and component names are generic.
