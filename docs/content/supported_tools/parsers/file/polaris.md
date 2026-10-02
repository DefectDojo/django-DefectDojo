---
title: "Polaris"
toc_hide: true
---

[Polaris](https://github.com/FairwindsOps/polaris) audits Kubernetes workloads against a configurable
set of checks across three categories — Security, Reliability and Efficiency. It runs against manifests
with `--audit-path`, so it needs no cluster access, and it also audits a live cluster.

This is the open-source Polaris CLI, not the hosted Fairwinds Insights Asset.

### Only failing checks become findings

**Polaris reports every check it ran, passing and failing alike**, each with a `Success` boolean, and
finishes with an overall `Score`. Only the failures are imported. A compliant manifest scores 100 and
still produces dozens of result entries, so importing everything would turn a clean manifest into dozens
of findings.

### Field mapping

| Polaris | DefectDojo |
|---|---|
| check `Message` | `title` |
| check id (the map key, e.g. `runAsRootAllowed`) | `vuln_id_from_tool` |
| check `Severity` (`danger` / `warning` / `ignore`) | `severity` (High / Medium / Info) |
| check `Category`, `Details`, scope | `description` |
| `Kind`, `Name`, `Namespace`, container name | `component_name` |
| `SourceName`, when `SourceType` is `Path` | `file_path` |

Polaris nests its checks at **three levels**: the workload object, its pod template, and each container
inside that template. All three are walked, and the description records which level a finding came from —
that is what tells a reader whether the fix belongs on the Deployment, the pod spec or one container.

The component is `Kind/name`, prefixed with the namespace when Polaris reported one and suffixed with the
container name for container-level checks (`Deployment/generic-app/server`).

`SourceName` is only used as `file_path` when `SourceType` is `Path`. Auditing a live cluster sets
`SourceType: Cluster` and puts a cluster name there, which would be wrong to report as a file. Polaris
never reports a line number.

### Sample Scan Data

Sample Polaris files are available at
[unittests/scans/polaris](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/polaris).

### Generating an importable file

```bash
polaris audit --audit-path ./manifests --format json > polaris.json
```

The report contains an `AuditTime` wall-clock stamp, so two runs over identical input are not
byte-identical. The committed fixtures have it pinned for that reason; nothing else was altered.

The fixtures were produced with **Polaris 10.2.1** by three separate runs against the manifests
committed alongside them in `unittests/scans/polaris/`:

| Fixture | Findings |
|---|---|
| `polaris_no_vuln.json` | 0 — `clean.yaml`, score 100 |
| `polaris_one_vuln.json` | 1 — `single.yaml`, a writable root filesystem |
| `polaris_many_vuln.json` | 21 — `many.yaml`: 3 workload-level, 4 pod-level, 14 container-level |

A genuinely clean Polaris scan takes more than a hardened container. Its default checks also want a
**NetworkPolicy** and a **PodDisruptionBudget** selecting the workload — separate objects, so `clean.yaml`
is a multi-document manifest — plus `priorityClassName`, `topologySpreadConstraints`, a `seccompProfile`,
`imagePullPolicy: Always`, and an `app.kubernetes.io/instance` label matching `metadata.name`. A manifest
that is secure but omits any of those is not a zero-finding scan.

### Default deduplication hashcode fields

`title`, `cwe`, `line`, `file_path`, `description` — the legacy default. With no line number, findings are
distinguished by the check, the manifest and the description, which names the object and container.
