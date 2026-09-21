---
title: "Kyverno"
toc_hide: true
---
Import Kyverno policy reports in JSON format. Kyverno is the Kubernetes-native policy engine; it
evaluates policies against cluster resources and records the outcome as a report object.

Generate a report with:

```
kyverno apply <policy.yaml> --resource <resource.yaml> --policy-report --output-format json
```

or export the reports a cluster has already produced:

```
kubectl get policyreport -A -o json
```

Two API groups are in circulation and both are accepted: the original `wgpolicyk8s.io`
PolicyReport and ClusterPolicyReport, and the newer `openreports.io` Report and ClusterReport that
current Kyverno releases emit. A Kubernetes `List` wrapping several reports is accepted too.

Only `fail`, `warn` and `error` results become Findings. A `pass` means the resource satisfied the
policy and a `skip` means the rule did not apply to it, so neither is a finding. Where one result
names several resources, each resource becomes its own Finding, because each is a separate thing
to fix.

DefectDojo also ships a generic **OpenReports** scan type for the `openreports.io` format. The
Kyverno scan type is the one to use for Kyverno: it accepts the cluster-scoped report kinds as
well as the namespaced ones, filters passes and skips, and takes severity from the policy.

### Severity Mapping
Kyverno results do carry a severity, contrary to what a pass/fail engine might suggest: policy
authors declare one with the `policies.kyverno.io/severity` annotation, and Kyverno copies it onto
every result the policy produces. That is used when present:

| Kyverno severity | DefectDojo severity |
| --- | --- |
| critical | Critical |
| high | High |
| medium | Medium |
| low | Low |
| info | Info |

Many policies do not set the annotation. Rather than default those to one value, severity is
derived from the outcome Kyverno reported, which is the only other signal in the result:

| Result | DefectDojo severity | Reasoning |
| --- | --- | --- |
| `fail` | Medium | The resource violates the policy. |
| `warn` | Low | The policy is in Audit mode, so the cluster admitted the resource anyway. |
| `error` | High | Kyverno could not evaluate the rule, so the resource is unverified. |

Each Finding's description states which of the two routes was taken, so it is always visible
whether a severity came from the policy author or was derived.

### Sample Scan Data
Sample Kyverno scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kyverno).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
