---
title: "FDA Cyber Device Evidence Pack"
description: "Record a cyber device profile, track the section 524B lifecycle metrics, and export the evidence pack an assessor reviews"
weight: 9
audience: pro
---

Section 524B of the Federal Food, Drug, and Cosmetic Act asks the manufacturer of a cyber device
for four things: a plan to monitor and address vulnerabilities after release, updates on a
justified cycle with a faster route for the severe ones, a software bill of materials, and the
processes around all of it. DefectDojo already holds much of the underlying record. These features
add the few facts it cannot infer, work out where each obligation stands, and produce the workbook
and bill of materials an assessor reviews.

DefectDojo records and reports what the manufacturer supplies. It does not assess whether a
software bill of materials is complete or accurate, and it does not determine whether a submission
satisfies the FDA. Those are decisions for the manufacturer and its reviewers.

The cyber device features are released behind a feature flag. An administrator turns them on per
instance from the Feature Flags page before they are generally available.

## The cyber device profile

An Asset that is a cyber device carries a profile recording what the assessment needs to know
about it:

- Whether the Asset is a cyber device at all, which is what brings the rest into scope.
- A device identifier, either the unique device identifier or an internal model code.
- The submission stage, premarket or postmarket, so a reviewer knows which one this is.
- The routine security update cycle in days, and the reasoning behind that interval.

The cycle and its justification are recorded together on purpose. The statute asks for a cycle
that is reasonably justified, so an interval with no reasoning attached is reported as a partial
answer rather than a complete one.

The profile also carries the security contact and the vulnerability disclosure policy link. These
are the same two fields the EU regulatory profile uses, because they answer the same question for
both regulators.

## The seven elements per component

Section 524B and the accompanying minimum elements guidance expect a bill of materials to answer
seven things about each component. DefectDojo records all seven:

| Element | Where it comes from |
|---|---|
| Asset location | The Asset the component was found on |
| Component name | The imported bill of materials |
| Version | The imported bill of materials |
| Supplier | The imported document, or recorded by hand |
| Support level | The imported document, or recorded by hand |
| End of support date | The imported document, or recorded by hand |
| Known vulnerabilities | The findings linked to that component |

Unknown is a valid answer for the support facts and is reported as unknown. DefectDojo does not
guess a support level or an end of support date. See
[Working with SBOMs](../../asset_modelling/locations/pro__working_with_sboms) for how imports supply
these and which value wins when more than one source has an opinion.

## The three lifecycle metrics

Three numbers describe how the manufacturer handles what it finds. Each is measured over the
assessment period and can be read on its own or as part of the evidence pack.

**How much of what was found got fixed.** The share of vulnerabilities identified in the period
that were remediated, overall and by severity, with the ones still open listed.

**How long a fix took.** The time from identifying a vulnerability to shipping the patch, reported
as a mean and a median, overall and by severity, alongside how many are still open and how old
they are.

**How long the fix took to arrive.** Releasing a patch is not the same as deploying it. This
measures the time from a release being available to it reaching the devices in the field, and
names the releases that have no completion recorded and the ones with no release date, because a
gap in the record is the thing a reviewer most needs to see.

## The assessment

The bundled catalog holds 13 controls across the four families the statute names: postmarket
monitoring, updates and patches, bill of materials, and processes. Every control statement in the
catalog is a paraphrase written for DefectDojo, alongside the statute section it refers to. The
statute and guidance text is not reproduced. Read the source before relying on a wording here.

Nine of the 13 are evidenced from data DefectDojo already holds:

| Control | Read from |
|---|---|
| Coordinated vulnerability disclosure | The security contact and the disclosure policy link on the profile |
| A justified update cycle | The cycle and rationale on the profile |
| Out of cycle updates for critical vulnerabilities | Critical findings measured against the recorded cycle |
| Updates reaching the field | The field implementation metric |
| A bill of materials covering every kind of component | The component inventory and when it was last imported |
| Machine readable and carrying the minimum elements | The components available to export and how many name a supplier |
| Support level and end of support per component | The share of components with a known support level |
| Known vulnerabilities per component | The findings linked to components |
| Lifecycle metrics tracked and reviewed | The three metrics above |

The remaining four are the manufacturer's own process and paperwork: the monitoring plan, the
watch on third party and open source components, lifecycle risk management, and security testing.
DefectDojo holds no record of any of them, so each is declared manual with a note naming the
evidence to attach.

Two behaviours are worth knowing before reading a result. A period with no critical findings
reports the out of cycle control as not applicable rather than as a pass, because nothing was
asked of the process. The support coverage control fails when too much of the inventory has an
unknown support level, and names the components responsible so somebody can go and find out; the
threshold is 90 percent of components.

An Asset with no cyber device profile does not fail. Every automated control reports that what it
reads is absent and says what to record, because a device nobody has configured yet is not a
device that is out of compliance.

## The evidence pack

Generating a pack produces three files. Each is recorded with its SHA-256 and its size, and the
same assessment always produces the same bytes, so the hash attests to the evidence rather than to
one particular download.

- An OSCAL assessment results document, validated against its schema.
- The workbook, which has no validator and is recorded as not validated rather than claiming a
  check that never ran.
- The bill of materials itself, exported as CycloneDX, so the pack ships the document rather than
  a description of it. It is recorded as not validated for the same reason.

On top of the obligation sheets every regulatory pack carries, the cyber device workbook adds
three:

- **Component inventory**, one row per component with all seven elements and where each support
  fact came from.
- **Lifecycle metrics**, the three metrics above, overall and by severity.
- **Release history**, every release in the period with when it shipped, when it reached the
  field, and how long that took, including the releases that cannot yet be measured.

## Related pages

[CRA and DORA Evidence Packs](../eu_evidence_packs) share the assessment screens and the export
pipeline described here.
