---
title: "Falco"
toc_hide: true
---
Import Falco alerts in JSON format. Falco is the CNCF runtime security engine: it watches kernel
events and raises an alert whenever one matches a rule.

Generate a report with:

```
falco -o json_output=true -o json_include_output_property=true > falco.json
```

`json_output=true` writes one JSON object per line. A JSON array of the same objects is also
accepted, since some Falco output channels batch alerts that way.

### What one Finding represents
Falco produces a stream of events, not a set of static defects, so this needs stating: **one
Falco alert becomes one Finding.** Each alert is a distinct thing that happened — at a time, in a
container, to a file, by a process — and folding alerts together on the way in would discard
that detail.

Repeats are handled after import rather than during it. Deduplication is keyed on the rule and
the container, not the timestamp, so a rule that fires two hundred times against one workload
becomes one Finding with the rest recorded as duplicates. That keeps the queue usable without
throwing away the individual alerts. If you would rather see every alert separately, change the
deduplication configuration for this scan type rather than the import.

Each Finding is titled with the rule name, and the alert's process, user, container, image,
Kubernetes namespace and pod, and the file or connection involved are written into the
description. The file or connection (`fd.name`) is also set as the Finding's file path, and
Falco's tags — which include the MITRE technique ids and the rule's maturity level — arrive as
Finding tags.

### Severity Mapping
Falco has a real severity scale. Every rule declares a `priority`, and those priorities are the
syslog levels, [documented here](https://falco.org/docs/concepts/rules/basic-elements/#priority).
They map straight across:

| Falco priority | DefectDojo severity |
| --- | --- |
| Emergency | Critical |
| Alert | Critical |
| Critical | Critical |
| Error | High |
| Warning | Medium |
| Notice | Low |
| Informational | Info |
| Debug | Info |

The three highest syslog levels all collapse onto Critical because DefectDojo has five severities
where Falco has eight, and Emergency, Alert and Critical are all "act now" in Falco's own
guidance. An unrecognised priority falls back to Medium.

### Sample Scan Data
Sample Falco scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/falco).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
