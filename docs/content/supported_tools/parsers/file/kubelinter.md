---
title: "KubeLinter"
toc_hide: true
---

[KubeLinter](https://github.com/stackrox/kube-linter) checks Kubernetes manifests and Helm charts
against a set of configuration checks — privileged containers, writable root filesystems, containers
running as root, `:latest` image tags, missing resource requests, missing anti-affinity.

It runs against **files**, so it needs no cluster access.

### Field mapping

| KubeLinter | DefectDojo |
|---|---|
| `Reports[].Check` (e.g. `no-read-only-root-fs`) | `title`, `vuln_id_from_tool` |
| `Reports[].Diagnostic.Message` | `description` |
| `Reports[].Remediation` | `mitigation` |
| `Object.Metadata.FilePath` | `file_path` |
| `Object.K8sObject` | `component_name`, as `namespace/Kind/name` |
| — | `severity`, a fixed value; see below |

Every KubeLinter check ships a remediation sentence, so that becomes the **mitigation** rather than
being buried in the description.

The offending object is named `Kind/name`, prefixed with the namespace when KubeLinter reported one. An
empty namespace means the manifest did not set one, and the description says `(not set)` rather than
printing nothing — that is a different thing from a namespace called `default`.

**There is no severity and no line number.** A report carries no severity, score or confidence, and
KubeLinter identifies the manifest but not the line within it. Every finding imports at **Medium**;
triage by check name, which is the title. Bear in mind the default check set mixes security checks
(`privileged-container`, `run-as-non-root`) with reliability ones (`unset-cpu-requirements`,
`no-anti-affinity`), so a blanket severity would be wrong either way.

### A clean report is not an empty document

KubeLinter always emits its whole enabled-check registry under `Checks`, plus a `Summary`. Only
`Reports` holds findings, so a clean scan is a 15 KB document that found nothing. Do not read file size
as evidence that something was found.

Note also that a clean scan sets **`"Reports": null`**, not `[]`. Anything consuming the report directly
has to tolerate that, or it will fail on precisely the case a new user hits first.

### Sample Scan Data

Sample KubeLinter files are available at
[unittests/scans/kubelinter](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kubelinter).

### Generating an importable file

```bash
kube-linter lint --format json ./manifests > kubelinter.json
```

KubeLinter reports absolute paths, resolved from the path you give it, so `file_path` reflects wherever
the manifests were when they were scanned.

The fixtures committed with this parser were produced with **KubeLinter 0.8.3** by three separate runs
against the manifests committed alongside them in `unittests/scans/kubelinter/`:

| Fixture | Findings |
|---|---|
| `kubelinter_no_vuln.json` | 0 — `clean.yaml` |
| `kubelinter_one_vuln.json` | 1 — `single.yaml`, a writable root filesystem |
| `kubelinter_many_vuln.json` | 7 — `many.yaml`: `:latest` tag, privileged, root user, no resource requests |

Getting a genuinely clean manifest takes more than the security settings. KubeLinter's defaults also
require a declared `containerPort` matching each probe's `httpGet` port, and inter-pod anti-affinity once
`replicas` is above one — a manifest that is secure but omits either is not a zero-finding scan.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no line number, findings
are distinguished by check, manifest and the diagnostic message, which names the container.
