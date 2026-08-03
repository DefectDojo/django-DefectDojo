---
title: "CMMC Level 2 Assessments"
description: "Score a self-assessment against NIST 800-171 Rev 2"
weight: 5
audience: pro
---

The Compliance tab can score a CMMC Level 2 self-assessment against NIST 800-171 Rev 2, using the
DoD Assessment Methodology point weights.

![A CMMC Level 2 assessment scorecard](images/05-cmmc-scorecard.png)

**Beta: treat the score as an estimate.** While this feature is in beta, the bundled point weights
and the resulting SPRS score are advisory and pending validation. Confirm any score against the
official DoD NIST SP 800-171 Assessment Methodology before relying on it for an assessment
submission or a contractual purpose.

## Recording results

Record a result for each of the 110 requirements:

* **Met**
* **Not met**
* **Not applicable**
* **Planned** (on POA&M)

![The requirements workflow](images/06-cmmc-requirements.png)

## What the assessment computes

### SPRS score

110 minus the weight of every requirement that is not met or merely planned. Weights are 1, 3, or
5 points, so scores range from 110 down to -203.

Requirement 3.12.4 (the System Security Plan requirement) scores as not applicable, per the
methodology.

### Whether a conditional status is possible

CMMC allows conditional certification at a score of at least **88** (80 percent) with every open
gap eligible for a POA&M.

The methodology bars certain requirements from POA&Ms entirely. Among requirements weighted above
one point, only **3.13.11** (FIPS-validated cryptography) can be deferred.

### The closeout clock

A conditional assessment has **180 days** to close its POA&M items. The assessment flips to
expired if the clock lapses.

## Statuses

Statuses move from **in progress** to **conditional** or **final**. Conditional assessments show
the days remaining on their closeout clock.

Assessments are under audit history: every change records who, what, and when.
