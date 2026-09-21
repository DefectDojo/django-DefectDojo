---
title: "Tracee"
toc_hide: true
---
Import Tracee events in JSON format. Tracee is Aqua Security's eBPF runtime security tracer: it
instruments syscalls and LSM hooks in the kernel and reports what it sees.

Generate a report with:

```
tracee --output json > tracee.json
```

One JSON object per line is written; a JSON array is also accepted. Tracee interleaves its own
structured log lines (objects with a `level` and no `eventName`) onto the same stream, and those
are skipped rather than imported.

### What one Finding represents
Tracee emits two quite different kinds of record on one stream, and the distinction decides both
what a Finding means and what severity it gets:

- A **signature detection** is Tracee concluding that observed behaviour matches a known threat.
  It carries a `metadata` block with a signature id, a MITRE technique and a severity. This is a
  verdict.
- A **traced event** is a raw syscall or LSM hook that matched the policy the operator asked
  Tracee to trace — `security_inode_unlink`, `setuid`, `sched_process_exec`. Tracee is not
  claiming anything is wrong here; the operator asked to see these.

**One record becomes one Finding** in both cases. A detection is titled with its signature id and
name (`TRC-102: Anti-Debugging detected`); a traced event is titled `Traced event: <name>` so the
two are never confused in a queue. The process, container, image, Kubernetes pod and namespace,
matched policies and the event's arguments are written into the description.

As with any runtime source, repeats are handled after import: deduplication is keyed on the
signature or event name and the container, not the timestamp, so recurring activity becomes one
Finding with the rest recorded as duplicates.

### Severity Mapping
For **signature detections**, severity is the one Tracee assigned. The scale is the `Severity`
enum in Tracee's own [api/v1beta1/threat.proto](https://github.com/aquasecurity/tracee/blob/main/api/v1beta1/threat.proto):

| Tracee severity | DefectDojo severity |
| --- | --- |
| 0 | Info |
| 1 | Low |
| 2 | Medium |
| 3 | High |
| 4 | Critical |

An unrecognised value falls back to Medium.

For **traced events**, Tracee assigns no severity, and it would be wrong to invent one. A traced
`setuid` is not a finding about the code; it is the operator's own tracing policy doing what it
was asked. These import as **Info**: the activity is recorded and searchable, and it does not
compete for attention with detections. Teams who want particular traced events to carry weight
should raise them on the event name in `vuln_id_from_tool` rather than expect Tracee to have
graded them.

### Sample Scan Data
Sample Tracee scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/tracee).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
