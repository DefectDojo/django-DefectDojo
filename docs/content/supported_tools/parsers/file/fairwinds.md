---
title: "Fairwinds Insights"
toc_hide: true
---

Import a [Fairwinds Insights](https://www.fairwinds.com/insights) action-items export.

This exists for organisations that cannot grant Fairwinds API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Fairwinds Insights connector
pulls the same data over the API; this parser accepts the same data as a file.

### File Types

JSON, from Fairwinds' action-items endpoint. A bare array is accepted, as is an object wrapping the
items under `ActionItems`, `items` or `data`.

Note Fairwinds' JSON keys are **PascalCase** — `Title`, `Severity`, `ResourceKind`.

### Severity is a 0.0–1.0 score, not a word

Fairwinds normalises severity to a **float**. It is neither a severity word nor a CVSS score, and
treating the number as CVSS would put every finding at Info. The breakpoints are Fairwinds' own:

| Fairwinds `Severity` | Severity |
| --- | --- |
| ≥ 0.9 | Critical |
| ≥ 0.7 | High |
| ≥ 0.4 | Medium |
| ≥ 0.1 | Low |
| below 0.1, or unparseable | Info |

### One stream, several scanners

Fairwinds aggregates Polaris, Trivy, OPA, kube-bench, Goldilocks and others into a single action-item
stream, so an item may be about a **container image** or a **Kubernetes manifest**. The component
reflects whichever it is: the image and tag when there is one, otherwise the Kubernetes resource name.

The originating tool is imported as a `tool:<report type>` tag, so findings can be filtered by which
scanner produced them.

### Fields worth noting

- **A fixed item is imported closed** (`is_mitigated`, not active) — Fairwinds tracks the `Fixed` flag,
  and importing it active would put resolved work back in the open queue.
- **Resource** is rendered `namespace/kind/name`, with `(container: …)` appended when Fairwinds
  identified one. Any segment may be missing and is simply skipped.
- **CVEs** are extracted from the title and description; Fairwinds has no dedicated CVE field.
- **Tags** carry the tool, category, cluster, namespace, event type and Fairwinds' own tags. The
  cluster tag is added unconditionally, so an item with no cluster gets a bare `cluster:` tag — that is
  the connector's behaviour, reproduced rather than tidied, since tidying it here would be a
  difference between a file import and an API sync.
- **Description text is flattened**, not rendered as markup.

### Scan type and deduplication

The scan type is **`Fairwinds Insights - Connectors Import`** — identical to the string the Fairwinds
Insights connector reports, so a customer who uploads an export *and* later enables the connector gets
one set of findings that deduplicate rather than two copies of everything.

### Sample Scan Data

Sample Fairwinds Insights scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/fairwinds).

The samples are constructed from Fairwinds' documented action-item schema and cover every severity band,
a Trivy image finding and a Polaris manifest finding, a fixed item, an item with no title or
coordinates, an OPA admission event, and a malformed severity value. Cluster, namespace and image names
are generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
