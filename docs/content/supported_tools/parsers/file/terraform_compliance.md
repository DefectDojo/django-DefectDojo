---
title: "terraform-compliance"
toc_hide: true
---
Import terraform-compliance results. terraform-compliance is a BDD policy framework for Terraform:
policies are written as Gherkin scenarios and evaluated against a Terraform plan.

terraform-compliance has no report flag of its own. It runs on top of the radish BDD runner and
passes unrecognised arguments straight through to it, so a machine-readable report comes from one
of radish's writers. Generate one with:

```
terraform show -json plan.out > plan.json
terraform-compliance --features <features-dir> --planfile plan.json --junit-xml report.xml
```

Both of radish's writers are accepted, and the format is detected from the file:

- **`--junit-xml` is the one to prefer.** Its failure text is terraform-compliance's own message,
  which names the offending resource, the property and the value that was found.
- **`--cucumber-json` also imports**, but radish records only whitespace as the failure message for
  a terraform-compliance step. Those Findings identify the policy that failed and the line it
  failed on, but cannot name the resource. The description says so explicitly rather than leaving
  the gap looking like missing data.

### What one Finding represents
**One scenario becomes one Finding.** A scenario is a single policy requirement written as a
sentence — "Postgres servers must not use a public network" — which is the unit a team writes,
reviews and remediates. Its steps are the mechanics of checking it, so a scenario that fails on its
third step is one finding, not three.

### Severity Mapping
terraform-compliance has no severity concept. A scenario passes or fails, and the framework has no
notion of how serious a failure is — that lives in the policy author's head and in whatever the
scenario was written to assert.

Every Finding is therefore imported as **Medium**, deliberately and uniformly. The alternative
would be to guess from the scenario's wording, which is free text written by whoever authored the
policy and carries no reliable signal.

To grade these, key off the scenario name in `vuln_id_from_tool` with DefectDojo's rule engine. The
scenario name is stable, is chosen by the team that wrote the policy, and is the natural handle for
saying "this particular requirement is a High for us".

### Sample Scan Data
Sample terraform-compliance scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/terraform_compliance).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
