---
title: "Certification Control Catalogs"
description: "Assess an Asset against ISO/IEC 27001:2022 Annex A, the SOC 2 Trust Services Criteria and the NIS2 technical requirements, and see one body of evidence answer all three"
weight: 10
audience: pro
---

DefectDojo Pro ships three certification catalogs: ISO/IEC 27001:2022 Annex A, the SOC 2 Trust
Services Criteria, and the NIS2 technical and methodological requirements. You assess an Asset
against each one with the same assessment screens used for [CRA and DORA](../eu_evidence_packs/).
The **Shared Evidence** view then shows how one set of operational facts, such as an SLA
configuration or a testing history, answers controls in all three frameworks at once.

**This is an evidence-gathering aid, not a certification.** DefectDojo is not a certification
body and does not determine compliance. Each catalog states this in its own metadata. An
assessment here is preparation, and the evidence it collects is for your auditor to review. The
auditor decides.

## Enable the feature

The cross-framework view ships behind the **Certification Control Catalogs** feature flag, which
is in beta and off by default. An administrator turns it on from **Settings > Feature Flags**. See
[Feature Flags](/admin/feature_flags/pro__feature_flags/).

The flag does not depend on any other flag. Running the assessments that feed the view does,
though:

| What you want | Flags required |
| --- | --- |
| Open the Asset's **Compliance** tab | **Compliance** |
| Start, recompute and review ISO, SOC 2 or NIS2 assessments, and generate evidence packs | **Compliance** and **EU Evidence Packs** |
| See the **Shared Evidence** tab | **Certification Control Catalogs** |

In practice, turn on all three. The three catalogs are loaded on every install whether or not
the flag is on, so they appear as start buttons as soon as the assessment screens are enabled.

## The three catalogs

Each catalog covers the controls that bear on vulnerability management, secure development and
supply chain security. None of them is the whole standard. Control titles and statements are
original paraphrase. The control identifiers match the published standards, but the standards'
own text is not reproduced.

| Catalog | Version | Controls | Scope |
| --- | --- | --- | --- |
| ISO/IEC 27001:2022 Annex A | 2022 | 13 | Organizational controls A.5.7, A.5.20, A.5.21 and A.5.30, and technological controls A.8.8, A.8.9, A.8.19, A.8.25, A.8.26, A.8.28, A.8.29, A.8.31 and A.8.32 |
| SOC 2 Trust Services Criteria | 2017 (2022 points of focus) | 9 | Common criteria CC3.2, CC4.1, CC7.1 to CC7.5, CC8.1 and CC9.2 |
| NIS2 Technical and Methodological Requirements | 2024/2690 | 6 | Annex points 5.1, 6.5, 6.6, 6.10 and 7.1 of Commission Implementing Regulation (EU) 2024/2690, plus Article 21(2)(e) of Directive (EU) 2022/2555, which they expand |

The NIS2 identifiers are Annex points, not Articles. The Articles of Regulation 2024/2690 set
incident thresholds for each entity type and are not part of this catalog.

## Run an assessment

Assessments for these catalogs work exactly like CRA and DORA assessments. The
[CRA and DORA Evidence Packs](../eu_evidence_packs/) page describes every screen in detail. In
short:

1. Open the Asset, select the **Compliance** tab, then select **Compliance Profile**.
2. In the **Regulatory Assessments** section, select **Start ISO/IEC 27001:2022 Annex A**,
   **Start SOC 2 Trust Services Criteria** or **Start NIS2 Technical and Methodological
   Requirements**. These buttons use a period from January 1 of the current year to today. To
   choose your own period, open the **EU Evidence** tab, select **Start Assessment**, and pick
   the catalog in the **Start Regulatory Assessment** dialog.
3. Select **Recompute Evidence** to compute the automated evidence.
4. Open each control's **Evidence** view to read the computed facts, write a narrative, attach
   supporting files, or override the state with a reason. Select **Save Review** to keep changes.
5. Select **Generate Evidence Pack** when the review is done.

Starting an assessment, recomputing, saving a review and generating a pack need edit permission
on the Asset. Run one assessment per catalog. The Shared Evidence view combines them.

## How evidence is derived

Every control is either automated, manual, or hybrid. Automated controls are computed from
records DefectDojo already holds when you select **Recompute Evidence**. The **evidence date** is
the period end, or today if the period is still open.

Several controls share one check, because the frameworks ask the same question in different
words:

| Check | Controls | Satisfied when |
| --- | --- | --- |
| SBOM inventory | ISO A.5.21, SOC 2 CC9.2, NIS2 5.1 | The Asset has SBOM components and the newest was recorded in the period. Partially satisfied if the newest is older than the period. Not satisfied if there are none |
| SLA performance and exceptions | ISO A.8.8, SOC 2 CC7.4, NIS2 6.6 | An SLA configuration enforces at least one severity, no more than 5% of open findings are past SLA, and no risk acceptance has expired unhandled |
| Security testing | ISO A.8.29, NIS2 6.5 | At least one static analysis test, or a test whose type, title or scan type mentions scan, vulnerability, penetration or SAST, has a target end date in the period |
| Scan cadence | SOC 2 CC4.1 | At least one scan or vulnerability test ran in the period. Partially satisfied if the Asset's business criticality is High or Very High and the longest gap between tests is over 7 days |
| Enrichment freshness | ISO A.5.7 | A successful enrichment run that carried both EPSS and KEV finished within 7 days of the evidence date. Partially satisfied for an older or incomplete run |
| Configuration baseline | ISO A.8.9 | Never satisfied automatically. With posture scans in the period, the result is partially satisfied at best, because the control also needs a documented baseline that DefectDojo does not hold. Without a posture scan it stays unknown with a note |
| Drift and new vulnerabilities | SOC 2 CC7.1 | The weaker of enrichment freshness and the configuration baseline. Without a posture scan, only enrichment freshness counts |
| Exposure ranking | SOC 2 CC3.2 | A prioritization engine is set on the Asset or an SLA configuration enforces a severity, and every open finding has a severity |
| Detection monitoring | SOC 2 CC7.2, NIS2 7.1 | Rules are configured and at least one ran in the period. These counts cover the whole instance, not one Asset |
| Published advisories | NIS2 6.10 | A published PSIRT advisory that reaches the Asset was issued in the period. Otherwise the control stays unknown with a note |

For the SLA check, the computed facts also count risk acceptances with no named accepter and
with no compensating control recorded. ISO A.8.8, SOC 2 CC7.4 and NIS2 6.6 all ask for both.
These counts are for the assessor and do not change the state.

The remaining controls are manual: ISO A.5.20, A.5.30, A.8.19, A.8.25, A.8.26, A.8.28, A.8.31 and
A.8.32, SOC 2 CC7.3, CC7.5 and CC8.1, and NIS2 Article 21(2)(e). Their evidence is a document, a
process or a decision record, so they stay unknown after a recompute. Each carries a note naming
what to attach, for example supplier agreements for A.5.20 or change tickets for CC8.1. Attach
the files under **Supporting Files** and record the state yourself.

## The cross-framework view

Open the Asset's **Compliance** tab, then select the **Shared Evidence** tab. It sits next to
**Coverage**.

The sentence above the table counts the checks, the controls they answer, and the frameworks
involved. A control that appears under two checks is counted in both. Each row is one fact the
Asset holds:

| Row | What it shows |
| --- | --- |
| Vulnerability information reaches the product | Enrichment feeds run and findings arrive from named tools |
| Configuration is checked against a baseline | Posture scans check a hardening baseline, and deviations are fixed or risk accepted |
| Exposure is evaluated and ranked | Open findings carry a severity and a ranking method is active |
| Remediation runs on a clock | An enforcing SLA configuration is attached, with closure rates, breaches and time to remediate |
| Exceptions are documented and time-bound | Risk acceptances name an accepter, record a compensating control and expire |
| Testing happened, on a cadence | Security testing ran in the period, with the longest gap recorded |
| Supply chain components are tracked | A bill of materials was imported in the period |
| Detection is monitored, not just run | Rules are configured and ran in the period |
| Coordinated disclosure is operating | A disclosure policy and security contact are published, and advisories were issued |

Each row has three columns:

* **Evidence**: the fact and what it shows.
* **Status**: the row's rolled-up status, which is the weakest status among the controls that
  have been assessed. Controls not yet assessed are left out of the roll-up but stay visible in
  the row.
* **Controls Answered**: one tag per control, labeled with the control and its catalog, colored
  by that control's own status. Hover a tag to see the control title and status.

The rows also include matching controls from the CRA, DORA, PCI DSS and FDA catalogs, so an Asset
assessed against several programs sees one matrix. When more than one framework appears, use
the **All Frameworks** menu to narrow the table to one catalog.

The view never recomputes anything. Each status is read from the stored result of the newest
assessment that covers that control for this Asset. A control whose catalog has never been
assessed shows as **Not Assessed**, never as passing. Recompute the assessments first if you want
the view to reflect current data.

## Export

The cross-framework view has no export of its own. Generate an evidence pack from any of the
assessments instead. The pack's Excel workbook carries a **Shared Evidence** sheet with the
columns **Evidence**, **What it shows**, **Status**, **Frameworks** and **Controls answered**, and
lists each control with its own status. The matrix is frozen when the pack is generated, so later
changes do not alter it. The pack also includes the OSCAL assessment results for the assessed
catalog. See [Generate an evidence pack](../eu_evidence_packs/#generate-an-evidence-pack).

For automation, assessments, control results and pack files are on the public API:
`/api/v2/regulatory_assessments/`, `/api/v2/obligation_results/` and
`/api/v2/evidence_pack_artifacts/`. The cross-framework matrix itself is not on the public API.
Read it from the workbook.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| No **Shared Evidence** tab | **Certification Control Catalogs** is off | Enable it in Feature Flags |
| No **Regulatory Assessments** section and no **EU Evidence** tab, so no way to start an assessment | **Compliance** or **EU Evidence Packs** is off | Enable both in Feature Flags |
| No start buttons | You can view the Asset but not edit it | Ask for a role with edit permission on the Asset |
| Every control in the Shared Evidence view is **Not Assessed** | No assessment has been run for that catalog on this Asset | Start an assessment and recompute it |
| The view shows old statuses | The view reads stored results and does not recompute | Open the assessment and select **Recompute Evidence** |
| A manual control stays unknown after a recompute | Manual controls have no operational record to compute from | Attach the evidence the note names and set the state in the **Evidence** view |
