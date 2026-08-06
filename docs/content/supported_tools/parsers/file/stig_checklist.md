---
title: "DISA STIG Checklist"
toc_hide: true
---

Import a DISA STIG checklist saved from STIG Viewer, so the items requiring remediation become
findings that are tracked, aged against your SLAs and assigned like any other.

### File Types

Both checklist formats are accepted:

- **`.ckl`** — XML, written by STIG Viewer 2.x.
- **`.cklb`** — JSON, written by STIG Viewer 3.x.

The format is detected from the file's content rather than its name, so a checklist that has been
renamed (a `.ckl` saved as `.xml`, for example) imports correctly. Both formats produce identical
findings for identical content. Checklists holding several `iSTIG` blocks — one host assessed
against several STIGs — are supported, as are checklists exported by tools other than STIG Viewer.

Note this parser reads *checklists*, not XCCDF benchmark results. To import the output of an
OpenSCAP/SCAP compliance scan, use the Openscap parser instead.

### Statuses

Every checklist item is imported, so the finding list mirrors the checklist:

| Checklist status | Finding state | Meaning |
|------------------|---------------|---------|
| Open | Active, Verified | Requires remediation. |
| Not Reviewed | Active, not Verified | Still needs to be assessed. |
| Not A Finding | Mitigated (inactive) | Assessed as compliant. |
| Not Applicable | Out of Scope (inactive) | Does not apply to this asset. |

Reimporting a newer checklist for the same asset moves findings between those states: an item that
changes from Open to Not A Finding is closed, and one that regresses from Not A Finding to Open is
reactivated.

### Severity

The rule's DISA category maps to severity — `high` to High, `medium` to Medium and `low` to Low —
and the category itself (CAT I, CAT II, CAT III) is recorded in Impact. An item with no severity
recorded is imported at Info rather than dropped, since it still has to be tracked.

Where an assessor has overridden the severity, the override sets the finding's severity and the
reason is recorded in the severity justification. Impact keeps the rule's own category, which an
override does not change.

### Fields

`Check_Content` becomes the steps to reproduce, `Fix_Text` becomes the mitigation, and the
discussion, finding details and assessor comments are collected into the description. Every CCI the
rule cites is recorded on its own line in References. DefectDojo Pro's federal compliance pack reads
those CCIs to map each item onto its NIST 800-53 controls, which populates control coverage.

The V-number is used as the finding's identifier, because it is stable across STIG releases. The
`Rule_ID` carries a revision suffix (`SV-257777r925318_rule`) that changes with every release, so it
is recorded in the description for reference only.

### Recommended Usage

**Import each asset's checklist into its own Test, and reimport newer checklists of that asset into
the same Test.** Closing on reimport is driven by an item being absent from the report, and that
comparison is scoped to one Test — so if checklists from several assets share a Test, turn off
"Close old findings" to avoid closing the other assets' items.

A checklist with no host name, FQDN or IP recorded produces findings with no endpoint, identified by
V-number alone. Two such un-keyed checklists in the same product cannot be told apart; key the asset
in STIG Viewer to keep them distinct.

### Sample Scan Data

Sample DISA STIG Checklist scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/stig_checklist).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- endpoints

Findings are matched on the unique id from the tool, which is the V-number qualified by the host it
was assessed on — so the same rule failing on two hosts stays two findings.
