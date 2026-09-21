---
title: "KubeEye"
toc_hide: true
---
Import KubeEye inspection results in JSON format. KubeEye inspects a Kubernetes cluster against a
set of rules covering node health, file integrity, kernel and systemd settings, command output,
control plane component status, service connectivity and Prometheus rules.

Export a completed inspection with:

```
kubectl get inspectresult <name> -o json
```

A Kubernetes `List` of several results is accepted as well as a single one.

KubeEye keeps one list per kind of inspection under `spec`, and every entry in every list embeds
the same `name`, `assert` and `level` fields. Entries where `assert` is `true` are the ones where
the inspection found the problem it was looking for, and those become Findings; entries where it is
`false` are checks that passed and are not imported. Each Finding is titled with the kind of
inspection and the rule that raised it, so a node disk check and a Prometheus rule are
distinguishable at a glance.

The node, namespace or cluster the entry belongs to becomes the component, and file inspections
record the path along with the diff KubeEye captured.

### Severity Mapping
KubeEye has a real, if short, severity scale. Its rules declare a level, and the levels are the
three declared in
[inspectresult_types.go](https://github.com/kubesphere/kubeeye/blob/master/apis/kubeeye/v1alpha2/inspectresult_types.go):

| KubeEye level | DefectDojo severity |
| --- | --- |
| danger | High |
| warning | Medium |
| ignore | Info |

`ignore` maps to Info rather than being dropped: KubeEye sets it on rules a cluster has chosen to
acknowledge, so the result is worth recording without competing for attention. A level KubeEye did
not set, or one this list does not know, falls back to Medium.

### Sample Scan Data
Sample KubeEye scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kubeeye).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
