---
title: "OpenVEX"
toc_hide: true
---

[OpenVEX](https://openvex.dev/) is an implementation of the Vulnerability Exploitability eXchange (VEX)
model: a document in which a software producer states whether their product is *actually* affected by a
known vulnerability.

### ★ VEX is a suppression signal, not a finding source

Read this before using the parser, because getting it backwards is worse than not importing VEX at all.

The entire purpose of a VEX document is to tell you which vulnerabilities you can **stop** worrying
about. A `not_affected` statement is the producer saying "your scanner flagged this, and we are telling
you it is not exploitable here." If that arrived in DefectDojo as a new active finding, the document's
meaning would be inverted — reassurance would become new work.

This parser therefore imports `not_affected` and `fixed` statements as **inactive**, so they suppress
matching findings rather than adding to them.

### Status handling

| OpenVEX `status` | Active? | Disposition in DefectDojo |
|---|---|---|
| `not_affected` | **No** | `out_of_scope`, `false_p` or `is_mitigated`, chosen by the justification (below) |
| `fixed` | **No** | `is_mitigated` |
| `affected` | **Yes** | Active. The producer asserts real exposure, usually with an `action_statement`. |
| `under_investigation` | Yes | Active but `verified=False`, severity Info — the producer has not decided yet |
| anything else | Yes | Active. A status a future spec revision adds must never silently suppress a real vulnerability. |

`affected` is deliberately the one status that produces an active finding: it is the producer stating
their product **is** exposed, and its `action_statement` is the only actionable instruction VEX carries.
Suppressing that would lose the most valuable statement in the format.

### Justifications on `not_affected`

The specification requires a justification on every `not_affected` statement, and the five permitted
values say materially different things. Rather than collapsing them into one disposition, each maps to
the DefectDojo field that matches it:

| `justification` | Disposition | Why |
|---|---|---|
| `inline_mitigations_already_exist` | `is_mitigated` | A real mitigation exists in the product |
| `vulnerable_code_not_present` | `false_p` | The scanner's match does not correspond to real code |
| `vulnerable_code_not_in_execute_path` | `false_p` | Present but unreachable |
| `vulnerable_code_cannot_be_controlled_by_adversary` | `false_p` | Reachable but not exploitable |
| `component_not_present` | `out_of_scope` | The finding does not apply to this product |
| *(missing)* | `out_of_scope` | Conservative default; the document is incomplete, and this is noted in the description |

The justification and any `impact_statement` are always recorded in the finding description, so the
producer's reasoning is auditable rather than lost in a status flag.

### Severity

VEX carries no severity — it states exploitability, not impact. `affected` findings are **Medium** so a
producer-asserted exposure is not filtered out of sight by a minimum-severity setting. Every other
status is **Info**, because those findings exist to suppress rather than to be worked; ranking them
higher would push suppressed rows in front of real ones.

### Spec versions

Both serialisations are accepted. OpenVEX v0.0.1 used bare strings for `vulnerability` and `products`;
v0.2.0 uses objects keyed by `name` and `@id`. Older producers still emit the v0.0.1 shape, and failing
to read it would silently drop suppression statements — the worst failure mode for a VEX parser — so
both are supported. `aliases` on a v0.2.0 vulnerability object are imported alongside the primary
identifier.

### Sample scan data

Sample OpenVEX files are available at
[unittests/scans/openvex](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openvex).

### Generating an importable file

With [`vexctl`](https://github.com/openvex/vexctl), the reference CLI from the OpenVEX project:

```bash
vexctl create --product="pkg:oci/generic-app@sha256:abc123" --vuln="CVE-2024-0001" --status="not_affected" --justification="vulnerable_code_not_present" > vex.openvex.json
```

The fixtures committed with this parser were produced with **vexctl v0.4.4**:

```bash
vexctl create --product="pkg:apk/alpine/apk-tools@2.10.6-r0?arch=x86_64&distro=alpine-3.10.9" --vuln="CVE-2024-10001" --status="not_affected" --justification="vulnerable_code_not_present"
vexctl create --product="pkg:apk/alpine/busybox@1.30.1-r3?arch=x86_64&distro=alpine-3.10.9" --vuln="CVE-2024-10002" --status="affected"
vexctl create --product="pkg:apk/alpine/alpine-baselayout@3.1.2-r0?arch=x86_64&distro=alpine-3.10.9" --vuln="CVE-2024-10003" --status="fixed"
```

Many scanners can also emit OpenVEX, including `trivy` and `grype`.

### Default deduplication hashcode fields

`vuln_id_from_tool`, `component_name`, `component_version` — the same fields CycloneDX and SPDX use, so
a VEX statement deduplicates onto the SBOM finding for the same component and CVE. That is exactly how
a suppression is meant to land.
