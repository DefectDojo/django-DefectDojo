---
title: "Qwiet AI"
toc_hide: true
---

Import a [Qwiet AI](https://qwiet.ai/) findings export (formerly ShiftLeft).

This exists for organisations that cannot grant Qwiet API credentials — air-gapped networks, procurement
restrictions, a pending security review. The DefectDojo Pro Qwiet connector pulls the same data over the
API; this parser accepts the same data as a file.

### File Types

JSON — the findings response for an app, wrapped as `{"ok": true, "response": [...]}`. A bare array of
findings, or an object with a `findings` list, is accepted too.

### Most of the data is in tags, not fields

Qwiet carries the interesting metadata as a **list of key/value tag objects** rather than as fields:

| Tag key | Becomes |
| --- | --- |
| `cve` | the vulnerability id |
| `package_url` | `component_name` and `component_version` |
| `cvss_score` | `cvssv3_score` |
| `cwe_category` | `cwe` |
| `reachability` | the severity justification and a `reachability:` tag |

They are objects in a list, not a map, so each is read by key — looking for fields of those names would
find nothing at all.

The package URL is reduced to its **last path segment**: `pkg:maven/org.example/lib@1.2.3` is `lib`
version `1.2.3`. The namespace before it is the group, not the artefact DefectDojo matches a component
on.

### Reachability

Reachability is the reason to use this tool, and it is recorded as the **severity justification** rather
than changing the grade — so a reviewer can see why two findings of equal severity are not equally
urgent.

A dependency finding (`type: oss_vuln`) that has `related_findings` is treated as reachable **even with
no reachability tag**: those related findings *are* the path Qwiet traced through the application.

### Severity

| Qwiet `severity` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `info`, or anything unrecognised | Info |

### One hash for two kinds of finding

This scan type's hash spans `file_path`, `cwe` **and** `component_name`, because Qwiet reports both code
findings and dependency findings: a given finding has a file path or a component, rarely both, and the
unused half hashes as empty.

### Fields worth noting

- **File locations** are `<path>:<line>`. Only the **first** becomes `file_path` and `line` — a
  data-flow finding spans several files and DefectDojo has one path — but the whole list stays in the
  description. An unparseable line number keeps the path rather than discarding the location.
- **The source and sink methods** are the two ends of the flow Qwiet traced, which is what a reviewer
  needs to judge whether the path is real.
- **Identity** is `qwiet-<internal id>`, falling back to the display id; the internal id is what is
  stable across scans.

### Sample Scan Data

Sample Qwiet AI scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qwiet).

The samples are constructed from Qwiet's documented findings response and cover a reachable code finding
with a two-file data flow, a dependency finding reachable through related findings, an explicitly
unreachable one, an unparseable score and CWE, an unparseable line number, a finding with no tags at all,
and one with no title or internal id. Package and class names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- file_path
- cwe
- component_name
