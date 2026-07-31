---
title: "ConMon Snapshots"
description: "Monthly deliverables in FedRAMP Excel and OSCAL, and the optional OSCAL validation service"
weight: 3
audience: pro
---

On the **Snapshots** tab, **Generate Snapshot** produces the deliverables for a reporting period.
A snapshot **freezes the ledger** as of that moment: later edits never change a deliverable you
have already generated.

![Generated ConMon snapshots](images/04-poam-snapshots.png)

Each row shows the period, its status, the open and late item counts, when it completed, and
download links for both artifacts.

## What a snapshot renders

Each snapshot produces two artifacts:

* The official **FedRAMP POA&M Excel workbook** (template version 3.0), with open, closed, and
  configuration items on their proper worksheets.
* An **OSCAL plan-of-action-and-milestones** document, pinned to OSCAL 1.0.4 — the version
  FedRAMP's current validation rules accept.

### What the OSCAL output carries

The OSCAL document uses FedRAMP's extension namespace for the fields FedRAMP tooling looks for:
POA&M IDs, impacted control IDs, deviation states, vendor dependency, and KEV tracking.

Each risk carries:

* Likelihood and impact facets — initial, and adjusted when a risk adjustment was approved.
* The recommended fix and the planned remediation, as separate responses.
* A risk log recording detection and the latest status review.

Documents are checked against the official NIST schema at generation time.

## Month-over-month metrics

Snapshots also compute the numbers a ConMon package needs: what appeared, what was resolved, what
is late, and the open count by risk rating.

## OSCAL validation service

For stronger checking, a deployment can run the bundled **OSCAL validator service** — a small
container wrapping the FedRAMP-maintained `oscal-cli`.

| Validator service | What happens at generation |
| --- | --- |
| Not configured | Documents are validated against the NIST JSON schema. The deeper check is marked **skipped**. |
| Configured | Documents are additionally validated through `oscal-cli`, and the results are stored with the snapshot. |

To enable it, set `DD_OSCAL_VALIDATOR_URL`, or enable `oscalValidator` in the Helm chart.

**Keep the `import-ssp` URL reachable.** `oscal-cli` dereferences the `import-ssp` href while
validating. If your Compliance Profile names an OSCAL SSP URL that the validator container cannot
reach, validation aborts rather than skipping that step. Either make the URL reachable from the
validator, or leave it unset.

## Immutability

Snapshots and their artifacts are immutable by design. Regenerating a period produces a new
snapshot; it never rewrites an existing one.
