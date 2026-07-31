---
title: "Federal Compliance"
description: "FedRAMP POA&M and ConMon deliverables, CMMC Level 2 assessments, and NIST 800-53 control coverage"
summary: ""
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ""
  description: ""
  canonical: ""
  robots: ""
audience: pro
exclude_search: true
---

DefectDojo Pro can run the vulnerability management side of a federal compliance program. It
keeps a FedRAMP-style Plan of Action and Milestones (POA&M) for each system, produces monthly
Continuous Monitoring (ConMon) deliverables in the official Excel and OSCAL formats, scores CMMC
Level 2 self-assessments, and shows which NIST 800-53 controls your scanners actually exercise.

Everything described in this section lives on the **Compliance** tab of an Asset.

## Enabling the feature

Federal Compliance ships behind the **Compliance** feature flag, which is in beta and off by
default. An administrator turns it on from the feature flags menu — see
[Feature Flags](../admin/feature_flags/PRO__feature_flags). Once enabled, a Compliance tab
appears on each Asset.

## Beta: confirm results before you rely on them

**This feature is in beta.** The bundled NIST 800-171 and 800-53 control statements, the DoD SPRS
point weights, and the POA&M-eligibility rules are provided to help you track and estimate your
posture, and are pending independent validation against the authoritative source documents.

SPRS scores, conditional-eligibility results, and control coverage are **advisory**. Confirm them
against the official DoD NIST SP 800-171 Assessment Methodology and current FedRAMP guidance
before you rely on them for a certification, an assessment submission, or any contractual
purpose.

## In this section

| Page | What it covers |
| --- | --- |
| [Compliance Profile](compliance_profile) | Enrolling an Asset as a system and setting the facts that appear on every deliverable |
| [The POA&M Ledger](poam_ledger) | How POA&M items are created from findings, and the conventions the ledger follows |
| [ConMon Snapshots](conmon_snapshots) | Monthly deliverables in FedRAMP Excel and OSCAL, and the optional OSCAL validation service |
| [Remediation Deadlines](remediation_slas) | The FedRAMP Rev 5 and FedRAMP VDR SLA presets |
| [CMMC Level 2 Assessments](cmmc_assessments) | Scoring a self-assessment against NIST 800-171 Rev 2 |
| [Control Coverage](control_coverage) | Which 800-53 controls your scanners test, and open weaknesses per control |
