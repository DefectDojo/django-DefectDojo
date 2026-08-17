---
title: "DISA STIG Checklists"
description: "Import .ckl and .cklb checklists and track the open items as findings"
weight: 4
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: STIG checklist import is only available in DefectDojo Pro.</span>

DefectDojo Pro imports DISA STIG Viewer checklists directly, so the items an assessor marked
**Open** become findings you can age against an SLA, assign, report on, and remediate alongside
everything else.

Choose the **DISA STIG Checklist** scan type on the Add Findings page, or pass
`scan_type=DISA STIG Checklist` to the import API.

## Supported files

Both STIG Viewer formats are read by the same scan type:

* **`.ckl`** — STIG Viewer 2.x, XML.
* **`.cklb`** — STIG Viewer 3.x, JSON.

The format is detected from the file's contents rather than its name, so a checklist that was
renamed, or exported by a tool that uses a different extension, imports the same way. A checklist
that records several STIGs against one asset is fully imported: every benchmark's items are
included, and each finding names the STIG it came from.

One checklist describes one asset. See [Importing more than one asset](#importing-more-than-one-asset)
below for how to organize them.

## How checklist statuses map to findings

Every status is imported, so the finding list mirrors the checklist rather than only its failures.

| Checklist status | Finding state | Meaning |
| --- | --- | --- |
| Open | Active, Verified | Needs remediation |
| Not Reviewed | Active, not Verified | Still to be assessed |
| Not A Finding | Mitigated (inactive) | Assessed as compliant |
| Not Applicable | Out of Scope (inactive) | Does not apply to this asset |

Importing **Not Reviewed** items as active-but-unverified is deliberate: on a freshly generated
checklist most items carry that status, and they represent assessment work that has not happened
yet. Filter the finding list on **Verified** to separate confirmed failures from items still
awaiting review.

Re-importing an updated checklist for the same asset moves findings between these states. An item
you have since fixed (Open → Not A Finding) closes, an item that has regressed (Not A Finding →
Open) reopens, and an item you removed from the checklist entirely is closed as no longer reported.

## Severity

STIG severity is the rule's DISA category, and it maps to DefectDojo severity directly:

| DISA category | Severity |
| --- | --- |
| CAT I (high) | High |
| CAT II (medium) | Medium |
| CAT III (low) | Low |

The category itself is recorded in the finding's **Impact** field. If an assessor overrode the
severity in the checklist, the override is what the finding carries, the assessor's reason is kept
in **Severity Justification**, and Impact still shows the rule's own category — so a downgrade is
visible rather than silent.

## What each finding contains

| Finding field | From the checklist |
| --- | --- |
| Title | The V-number and the rule title |
| Description | Group title, rule version (STIG-ID), rule ID, the STIG itself, the discussion, and any finding details or comments the assessor recorded |
| Mitigation | The rule's fix text |
| Steps to Reproduce | The rule's check content — how to assess the item |
| References | The STIG and release, and every CCI the rule cites |
| Component | The STIG and its version and release, for example `RHEL_9_STIG` `V2R3` |
| Endpoint | The asset the checklist was run against |

The asset is taken from the checklist's own target data, preferring its FQDN, then its host name,
then its IP address. A checklist saved without any of the three still imports; its findings simply
carry no endpoint.

## Deduplication

A finding is identified by its **V-number on the asset it was assessed against**. Two consequences
worth knowing:

* The same rule failing on two different assets stays **two findings**, so per-asset remediation
  is tracked separately.
* Upgrading to a newer release of the same STIG **keeps finding history**. The rule ID carries a
  revision suffix that changes with every STIG release, so it is recorded for reference only and
  never used to identify a finding.

## Importing more than one asset

Because closing on re-import is driven by an item's absence from the report, give **each asset its
own test** and re-import that asset's newer checklist into it. That is the arrangement the import
defaults assume.

If you would rather collect several assets' checklists in a single test, turn **Close Old Findings**
off when you import, otherwise each upload will close the previous asset's items.

## Compliance control coverage

STIG rules cite **CCIs** (Control Correlation Identifiers), DISA's index into the NIST control
catalog, and every CCI on a rule is recorded in the finding's references. If the
[Federal Compliance](/federal_compliance/) feature is enabled, those CCIs are crosswalked to their
NIST 800-53 controls automatically, so a checklist import populates
[Control Coverage](/federal_compliance/control_coverage/) and carries control attribution into the
POA&M ledger without any further configuration.
