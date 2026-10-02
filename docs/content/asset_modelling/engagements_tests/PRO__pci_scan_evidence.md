---
title: "PCI DSS Scan and ASV Evidence"
description: "Record which tests are PCI scans, track the Requirement 11 quarterly and annual evidence, and export the grid an assessor asks for"
audience: pro
weight: 9
---

PCI DSS Requirement 11 asks an entity to scan on a cadence and to keep the evidence: internal vulnerability scans every quarter, a passing external ASV scan every quarter, penetration tests every year, and segmentation testing on the same yearly cadence or every six months for a service provider. DefectDojo already holds the scans. These features record the few facts a scan report cannot carry, work out where each quarter stands, and produce the grid and workbook an assessor reviews.

DefectDojo records the ASV results an entity reports. It does not perform ASV scans, it is not an Approved Scanning Vendor, and it does not validate an attestation. A passing ASV result is never inferred from an absence of findings; someone records it, or the quarter reads as outstanding.

The scan evidence UI is released behind a feature flag. An administrator turns it on per instance from the Feature Flags page before it is generally available.

## Which tests count as which kind of scan

A test plays a PCI role. The role comes from the test type, so a scanner that is always an internal vulnerability scan is classified once rather than per test:

- **Internal vulnerability scan**: the Requirement 11.3.1 quarterly internal scan.
- **External ASV scan**: the Requirement 11.3.2 quarterly external scan performed by an Approved Scanning Vendor.
- **Web application assessment**: an application scan, which supports Requirement 6.4.
- **Penetration test**: a Requirement 11.4 penetration test delivered as a test rather than an engagement.
- **Segmentation test**: a Requirement 11.4.5 or 11.4.6 test of segmentation controls.

Common scanner names are classified on first run, and the classification only fills a role that has not been set, so it never overwrites a choice someone made. A single test can override its type's role when one scanner is used for two purposes.

## Facts a scan report does not carry

Some of what an assessor asks about is not in the scan file. These are recorded on the test:

- **Authenticated**: whether the scan ran with credentials, as Requirement 11.3.1.2 asks. The three answers are yes, no, and unknown. Unknown is never treated as authenticated.
- **ASV result**: pass, fail, or not applicable, along with the **ASV vendor** and the **attestation reference**. This is the entity's record of what the ASV reported.
- **After a significant change**: links the scan to the change that required it, for Requirements 11.3.1.3 and 11.3.2.1.
- **Note**: anything a reader of the evidence needs to know about this scan.

These can be set on the test edit form, through the API, or supplied with the scan at import and reimport time, so a pipeline that already uploads results can record the evidence in the same call. A reimport that says nothing about them leaves the earlier answers alone.

Engagements carry the penetration testing facts: the **kind** of test (internal, external, application, or segmentation), a link to the engagement that **retested** its findings, and a **methodology reference**.

## Significant changes

A significant change is what makes Requirements 11.3.1.3 and 11.3.2.1 apply: after one, the entity scans again rather than waiting for the next quarter. Record the change with its date, what changed, and which scans it requires (internal, ASV, penetration test). A change is covered when a test of each required role is linked to it, or is dated within the window after it. That window is 30 days by default.

## Unauthenticated system exceptions

Requirement 11.3.1.2 allows a system that cannot accept credentials, provided the entity documents why and what compensates for it. Record the system, the reason, the compensating control, who documented it and when, and the date the exception is next reviewed. An unauthenticated scan covered by an exception reads as needing attention rather than as satisfied, so the exception is visible to an assessor rather than hidden by it.

## The quarterly grid

The **PCI Scan Evidence** page shows one Asset's assessment year as four quarters, with a row per check. Quarters are counted from the Asset's assessment anchor date, not from 1 January, because an assessor counts from the assessment date. Each cell is a verdict with the evidence behind it, and opens to show the tests and findings it rests on.

| Check | Requirement | Satisfied when |
|-------|-------------|----------------|
| Internal scan performed | 11.3.1 | At least one internal vulnerability scan falls in the quarter |
| Scans authenticated | 11.3.1.2 | Every internal scan in the quarter ran authenticated, or each unauthenticated one is covered by a documented exception |
| High and critical resolved | 11.3.1.1 | The critical and high findings those scans raised are no longer active at the quarter's end, or were resolved inside the timeframe the entity set |
| Rescan confirmed | 11.3.1.1 | The resolved findings were confirmed by a later scan, either a reimport that closed them or a later test in the same engagement |
| Passing ASV scan | 11.3.2 | At least one external ASV scan in the quarter carries a pass, with its vendor and attestation reference |
| Significant changes covered | 11.3.1.3 and 11.3.2.1 | Every significant change in the quarter has the scans it requires |

A verdict is one of four: satisfied, needs attention, not satisfied, or not applicable. Needs attention is the middle answer, for a requirement that is met on paper but rests on something an assessor will ask about, such as that documented exception.

## The annual checks

Below the grid are the Requirement 11.4 checks, measured over the trailing twelve months: an internal penetration test, an external penetration test, and a segmentation test. Segmentation is measured over six months when the instance is assessed as a service provider, which is recorded in the system settings. A fourth check follows what the penetration tests found: an exploitable finding is expected to be corrected and then confirmed by a retest engagement linked to the original.

## The dashboard tile and the reminders

The **PCI Quarter Status** widget counts, across every in-scope Asset, how many have an internal scan, an authenticated scan and a passing ASV scan recorded for the quarter that is open today, and how many days are left in it. The counts come from a nightly job, and are scoped to what the person looking at the dashboard is authorized to see.

The same nightly job sends a reminder three weeks before a quarter ends, and again a week before, to the members of each in-scope Asset that is still missing an internal scan or a passing ASV scan. Each reminder is sent once per missing check, not once a day, and nothing is sent for a check that is already satisfied.

## The evidence workbook

The export produces an Excel workbook for the assessor. The summary sheet lists every in-scope Asset with its anchor date and the worst verdict in each of its four quarters. Each Asset then gets its own sheet holding the full grid, the annual checks, and the list of tests the verdicts were read from, so any cell can be traced back to the scan behind it. Every sheet records when the workbook was generated and who asked for it. The export can be narrowed to a single Organization.
