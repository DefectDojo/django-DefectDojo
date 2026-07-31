---
title: "Control Coverage"
description: "Which 800-53 controls your scanners test, and open weaknesses per control"
weight: 6
audience: pro
---

The control coverage view answers a simple question: which 800-53 controls do my scanners actually
test, and where are the open weaknesses per control?

![The control coverage heatmap](images/07-control-coverage.png)

## Where mappings come from

Many scanners already emit control references, and DefectDojo extracts them into control mappings
automatically. Among others:

* **Prowler** writes NIST 800-53 control lists into finding references.
* **Tenable** plugins carry 800-53 cross-references.
* **InSpec** and **MITRE SAF** profiles tag their checks with `nist` identifiers.

Extraction is grounded in the imported catalog, so an identifier the catalog does not recognize
never produces a mapping.

Findings that carry no control references of their own are attributed to the default scan controls
on the Compliance Profile — see [Compliance Profile](compliance_profile).

### Backfilling existing findings

Extraction runs as findings arrive. To map findings that were already imported before the feature
was enabled, backfill them:

```
manage.py extract_control_mappings --product <id>
```

Use `--all` to scan every active finding instead of one product. The command reports how many
mappings it created, and it leaves manual and suppressed mappings alone.

## Correcting a mapping

Mappings you create or correct by hand always win over extracted ones, and a mapping you delete
stays deleted — re-imports will not resurrect it.

## What the view shows

* A **heatmap by control family**.
* Per control, the **open findings mapped to it**.

Controls come from the bundled catalogs: NIST 800-53 Rev 5 and NIST 800-171 Rev 2, both imported
on startup.

**Coverage is advisory while the feature is in beta.** Control coverage reflects what your scanners
report and what the bundled catalogs recognize. It is not an attestation that a control is
implemented or effective. Confirm coverage against your System Security Plan before relying on it
for an assessment.

## Auditability

Control mappings are under audit history. Every change records who, what, and when.
