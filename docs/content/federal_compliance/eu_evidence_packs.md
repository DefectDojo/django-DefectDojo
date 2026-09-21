---
title: "CRA and DORA Evidence Packs"
description: "Assess an Asset against authored EU regulatory catalogs and export its evidence"
weight: 7
audience: pro
---

DefectDojo Pro includes authored catalogs for vulnerability-related obligations in the Cyber
Resilience Act (CRA) and Digital Operational Resilience Act (DORA). A regulatory assessment
collects the operational facts DefectDojo already holds, gives an assessor space to document the
remaining evidence, and produces a dated evidence pack.

DefectDojo does not determine whether a regulation applies to an organization, product, or
service. The catalogs and evidence states are aids to assessment. Confirm applicability,
interpretation, and conclusions with qualified legal and compliance reviewers.

## Enable EU evidence packs

EU evidence packs require the **Compliance** feature and the beta **EU Evidence Packs** feature.
An administrator can enable both from [Feature Flags](/admin/feature_flags/pro__feature_flags/).

## Included catalogs

The bundled catalogs contain short, authored paraphrases. Each obligation records its citation
and links to the corresponding source on EUR-Lex.

The CRA catalog covers Annex I Part II vulnerability handling, the Article 13 support period and
component due diligence requirements, and the Article 14 vulnerability and incident reporting
stages.

The DORA catalog covers ICT asset identification, vulnerability and patch management under
Commission Delegated Regulation (EU) 2024/1774, the testing types in DORA Article 25(1), and the
Article 28(3) third-party register. The third-party register obligation starts as not applicable
because the evidence pack does not manage that register.

The catalog text summarizes assessment topics and does not replace the regulations.

## Start and recompute an assessment

Open an Asset's **Compliance** tab. The **Regulatory assessments** section lists existing
assessments and offers one start button for each regulatory catalog. A new assessment covers the
selected period and creates an evidence result for every obligation.

Open **EU Evidence** to review the assessment. Select **Recompute Evidence** whenever operational
data changes. DefectDojo refreshes the automated facts and the automated evidence state for each
obligation.

The assessment uses five evidence states: satisfied, partially satisfied, not satisfied, not
applicable, and unknown. These states describe the evidence in DefectDojo. They are not legal
conclusions.

## Automated evidence

DefectDojo computes evidence only where it has suitable operational facts.

| Evidence source | Obligations it can support |
| --- | --- |
| SBOM dependency locations | CRA component and SBOM evidence; DORA third-party and open source library tracking |
| SLA settings, finding history, and risk acceptances | CRA remediation; DORA patch priority, deadlines, remediation monitoring, and vulnerability records |
| Tests and engagements in the assessment period | Regular security testing, vulnerability scanning, source code review, and penetration testing |
| EPSS and KEV enrichment runs | Trustworthy vulnerability information sources |
| Asset business criticality | ICT asset classification |
| Published PSIRT advisories | Public disclosure of fixed vulnerabilities |

Optional regulatory profiles, cadence monitoring, reporting cases, and advisory exports can add
more precise facts when those features are installed. If an optional source is absent, the result
stays available for manual assessment and explains which evidence is missing. Other obligations
are manual by design.

## Narratives, attachments, and overrides

Open an obligation's **Evidence** view to inspect the computed facts, record an assessor narrative,
and attach supporting files. Automated facts include the time at which they were computed.

An assessor can override the effective evidence state after providing a reason. Recomputing does
not replace that decision. DefectDojo retains the latest automated state beside the effective
state so reviewers can see when they differ, along with who made the override and when.

## Generate an evidence pack

Select **Generate Evidence Pack** from the assessment. Generation freezes the assessment and its
results at that point in time. Later edits do not change an existing snapshot.

The pack contains two downloadable artifacts:

* An Excel workbook with a cover sheet, one sheet for each obligation family, and a raw evidence
  appendix. Family sheets list the obligation, citation, evidence state, evidence summary, and
  assessor narrative.
* An OSCAL 1.0.4 assessment-results JSON document. DefectDojo validates it against the vendored
  NIST schema before making it available.

Each artifact records its file size and SHA-256 digest. PDF output is deferred while the reporting
module does not expose a reusable server-side HTML-to-PDF path for this report.
