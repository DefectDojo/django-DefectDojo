---
title: "PCI DSS Evidence Packs"
description: "Assess a cardholder data environment against the PCI DSS vulnerability management requirements and export the workbook an assessor reviews"
weight: 9
audience: pro
---

DefectDojo Pro includes an authored catalog for the PCI DSS v4.0.1 requirements that a
vulnerability management programme answers. A PCI DSS assessment collects the operational facts
DefectDojo already holds, gives an assessor space to record the rest, and produces a dated
workbook in the wording a Report on Compliance uses.

DefectDojo does not determine compliance. It reports what the recorded evidence shows. The
assessor decides what is in place, and a Qualified Security Assessor decides what a Report on
Compliance says. Nothing on these screens is an assessment finding on its own.

## What the catalog covers, and what it is

The catalog holds 30 controls drawn from three requirements:

- Requirement 6, the secure development and patching obligations that bear on vulnerability
  management, including the inventory of components, the remediation window for known
  vulnerabilities, and the assessment of public facing web applications.
- Requirement 11, the testing obligations: quarterly internal scans, quarterly ASV scans, the
  rescans that follow, scanning after a significant change, penetration testing, and segmentation
  testing.
- Requirement 12, the programme obligations that the testing requirements point at: the targeted
  risk analysis behind a self chosen frequency, and the confirmation of PCI DSS scope.

PCI DSS is copyrighted by the PCI Security Standards Council. The catalog does not reproduce the
standard. Every requirement statement in it is a paraphrase written for DefectDojo, alongside the
requirement number so the standard itself can be cited. Read the requirement in the standard
before relying on a wording here.

Several requirements let an entity choose its own frequency. The catalog records which ones, and
those are the requirements that pull Requirement 12.3.1 into the assessment: a self chosen
frequency has to be justified by a targeted risk analysis and reviewed every twelve months.

Three controls apply only to a service provider. Whether this instance is assessed as one is an
instance wide setting, and it also halves two cadences, segmentation testing and scope
confirmation, from twelve months to six.

## Choosing the cardholder data environment

A PCI DSS assessment is rarely an assessment of one system. When you start an assessment you
choose what it covers:

- A single Asset, which behaves exactly as every other regulatory assessment always has.
- An Organization, which covers every Asset in it.
- A chosen set of Assets, for a cardholder data environment that does not line up with one
  Organization.

For a scope wider than one Asset, each requirement is answered for every Asset in the scope and
the weakest answer decides the result. An obligation is not satisfied for a cardholder data
environment while one system in it fails. The per Asset answers are kept in the evidence, so an
assessor can see which one, and the workbook lists them on the scope sheet.

Who can read an assessment follows its scope in both directions. An assessment over a set exposes
every Asset in it, so holding one of those Assets is not enough to open it. A user who can see
every Asset in the scope can.

Assessments that existed before scopes widened are unchanged. They cover the Asset they always
covered.

## What DefectDojo evidences by itself

These requirements read data DefectDojo already holds. Everything else in the catalog is left to
the assessor with a note saying why.

| Requirement | Read from |
|---|---|
| 6.3.1 | How fresh the vulnerability enrichment data is |
| 6.3.2 | The component inventory built from imported SBOM and dependency data |
| 6.3.3 | The SLA configuration and the findings measured against it |
| 6.4.1 | Tests recorded against the Asset with the web application assessment role |
| 11.3.1, 11.3.1.2, 11.3.1.3 | The quarterly scan evidence grid |
| 11.3.2, 11.3.2.1 | The recorded ASV scan results |
| 11.3.1.1, 12.3.1 | Approved targeted risk analyses and their review dates |
| 11.4.2, 11.4.3, 11.4.4 | Penetration testing engagements and their retests |
| 11.4.5, 11.4.6 | Segmentation testing engagements, on the cadence that applies |
| 12.5.1, 12.5.2, 12.5.2.1 | The PCI DSS scope recorded against the Asset and when it was last confirmed |

Two behaviours are worth knowing before reading a result:

A quarter that has not closed yet is reported but not counted. An assessment run in the second
month of a quarter would otherwise report a failure for work that is not yet due. The quarter
still appears on the scan sheet, marked as still running.

Requirement 6.3.3 reads the SLA configuration rather than a separate threshold, so the window it
measures against is the one configured for the Asset. The workbook states where the SLA clock
starts, because PCI DSS counts a patching window from the release of the patch rather than from
the day a scanner noticed.

Requirements DefectDojo cannot evidence are listed in the assessment as manual, each with the
reason. A change control process, a documented inventory procedure and an assessor's judgement
about segmentation are not things a scanner reports.

## How a result is worded

The assessment screens use the vocabulary shared by every regulatory catalog in DefectDojo:
satisfied, partially satisfied, not satisfied, not applicable and unknown. A Report on Compliance
uses different words, so the PCI DSS workbook translates them. The translation happens in the
workbook only. No other framework's assessment is affected.

| In DefectDojo | In the workbook |
|---|---|
| Satisfied | In place |
| Satisfied, with an assessor override recorded | In place with compensating control |
| Partially satisfied | Not in place |
| Not satisfied | Not in place |
| Not applicable | Not applicable |
| Unknown | Not tested |

Partially satisfied becomes not in place deliberately. PCI DSS has no partial credit: a
requirement is in place or it is not, and a softer word would overstate a half met requirement to
an assessor. The DefectDojo status is kept in its own column beside the translation, so nothing
is lost.

In place with compensating control needs checking every time it appears. DefectDojo cannot tell a
compensating control from any other reason an assessor overrode a result, so an override that
lands on satisfied is reported in the column PCI DSS reserves for that case, and the reason is
printed on its own sheet. If the override was not a compensating control, correct it there.

## What is in the workbook

Generating an evidence pack produces two files, as it does for the other catalogs: an OSCAL
assessment results document and a workbook. Both carry a SHA-256 recorded against the pack, and
the same assessment always produces the same bytes, so the hash attests to the evidence rather
than to one particular download. The OSCAL document is validated against its schema. The workbook
has no validator and is recorded as not validated rather than claiming a check that never ran.

The PCI DSS workbook has eight sheets:

- **Cover**, the scope, catalog, period, a count of requirements under each Report on Compliance
  label, and the notes explaining how to read the rest.
- **Scope inventory**, one row per Asset in scope, with the PCI DSS scope recorded against it,
  when that scope was last confirmed, and the confirmation window that applies.
- **Quarterly scans**, one row per quarter per check, with the window, whether the quarter has
  closed, and what the evidence showed.
- **Remediation timeliness**, the SLA position per Asset, including where the SLA clock starts,
  what is past its deadline, and the mean time to remediate by severity.
- **Penetration tests**, the Requirement 11.4 checks with the requirement number each one
  answered and the engagements behind it.
- **Targeted risk analyses**, each approved analysis, the requirement it justifies, its review
  date and whether it is in date.
- **Compensating controls**, every result an assessor overrode, with the reason recorded.
- **Obligation results**, every requirement in the catalog with both status columns, the
  narrative, the attachments and the gathered evidence.

Text in the workbook is written as text rather than as a formula, so a narrative that begins with
an equals sign is not executed by a spreadsheet application when the assessor opens it.

## Related pages

[CRA and DORA Evidence Packs](../eu_evidence_packs) share the assessment screens and the export
pipeline this page describes. The PCI DSS Scan and ASV Evidence page covers recording the
Requirement 11 scan evidence that this assessment reads.
