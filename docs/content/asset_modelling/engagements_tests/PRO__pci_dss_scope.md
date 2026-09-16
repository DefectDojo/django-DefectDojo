---
title: "PCI DSS Scope and Patch Clocks"
description: "Record PCI DSS scope per Asset, run the Requirement 6.3.3 patch clock, and export a scope inventory"
audience: pro
weight: 8
---

The PCI DSS scope features let an organization record how each Asset relates to its cardholder data environment, run a patch clock that matches the Requirement 6.3.3 timeline, and export the scope inventory an assessor asks for under Requirement 12.5.1. These features are additive: they record the entity's own determinations and never decide compliance, which remains the assessor's judgment.

The PCI DSS scope features, including their API endpoints, are released behind a feature flag. An administrator turns it on per instance from the Feature Flags page before it is generally available. Until then the regulatory profile and inventory endpoints answer with a 403.

## PCI DSS scope on an Asset

Each Asset can carry a regulatory profile that records its PCI DSS facts:

- **PCI DSS scope**: whether the Asset is in the cardholder data environment, connected to or security-impacting it, or out of scope. This is the Requirement 12.5.1 scoping determination.
- **Component kind**: how the Asset is classified for the Requirement 6.3.2 software inventory, as bespoke or custom software, third-party software, a system component, or a payment page.
- **Public-facing web application**: whether the Asset is a public-facing web application, which is what Requirements 6.4.1 and 6.4.2 turn on. Left unset, this is derived from the Asset being internet accessible and having an external audience. Set it explicitly to override that derivation.
- **Assessment anchor date**: the date the assessment year is anchored to, which sets the start of the Requirement 11 quarterly scan calendar. Left unset, it defaults to 1 January of the current year.

The profile also records when scope was last confirmed and by whom. Use **Confirm Scope Today** to record a confirmation, which supports the Requirement 12.5.2 review cadence (at least every 12 months, or every 6 months for a service provider).

The profile is created the first time it is saved for an Asset, so an Asset that has never been assessed simply reads as not assessed.

## Entity type

The instance records whether the organization is assessed under PCI DSS as a merchant, a service provider, both, or unspecified. This setting lives in the system settings. Service providers confirm scope and test network segmentation every six months rather than annually, so several PCI cadence checks read this value.

## The Requirement 6.3.3 patch clock

DefectDojo Pro seeds an SLA configuration named **PCI DSS 6.3.3** that encodes the Requirement 6.3.3 timeline: critical and high-severity items are due within one month, and medium and low items follow a timeframe set by a targeted risk analysis (Requirement 12.3.1), so they are recorded but not enforced.

This configuration is seeded once and is never made the default and never assigned to an Asset automatically. To apply it, assign it to an Asset the same way as any other SLA configuration.

### SLA start policy

Requirement 6.3.3 runs the one-month clock from when a patch was released, not from when the finding happened to be detected. Each SLA configuration therefore carries an **SLA start policy** that chooses which date the clock starts from:

- **Detection date**: the default, and the same behavior as before. The clock starts when the finding was found.
- **Vulnerability publish date**: the clock starts when the vulnerability was published.
- **Fix-available date**: the clock starts when a fix became available.
- **Earliest known**: the clock starts from the earliest of the dates above.

A computed start that would fall after the detection date is clamped to the detection date, so a policy can only tighten the clock, never lengthen it. A start date set by hand, through the finding edit form or the API, is authoritative and the policy never overrides it; clearing it hands the start back to the policy. A start date that was already in place before a policy was chosen is treated the same way. Changing a configuration's policy recalculates the start and expiration dates of the findings already under it, in the background.

The default detection date policy changes nothing about how a finding's dates are set today.

The fix-available date comes from a scanner or connector that reports a fixed version's release date (mapped through the universal parser). When no such date is known, the fix-available policy falls back to the detection date.

## Targeted risk analyses

PCI DSS Requirement 12.3.1 asks for a targeted risk analysis behind each frequency or timeframe an entity chooses for itself, such as the medium and low patch windows under Requirement 6.3.3. The **Targeted Risk Analyses** page records these:

- Each analysis cites the requirement it justifies (for example 6.3.3, 11.3.1.1, or an Appendix A reference such as A3.2.1), names what is protected and the threats, the likelihood and impact, and the decision reached.
- An analysis is scoped to one Asset, to one Organization, or left entity-wide, and can be linked to the SLA configuration whose frequency it justifies. The scope is fixed when the analysis is created. Members of the Asset or Organization can read it; editing it takes the same permission as editing the Asset or Organization, and entity-wide analyses are managed by administrators.
- An analysis moves from draft to approved, and an approved analysis can be superseded. Approving it records who approved it and sets a review-due date 12 months out, since Requirement 12.3.1 asks for review at least every 12 months. A superseded analysis stays closed; record a new draft to replace it.
- A weekly check alerts the people responsible (the Asset's or Organization's members, or administrators for an entity-wide analysis) when an approved analysis is due for review within 30 days, again when it becomes overdue, and then monthly while it stays overdue.

## Scope inventory export

The scope inventory export produces the list an assessor reviews under Requirement 12.5.1. It returns every Asset the user is authorized to view, with its scope, component kind, public-facing flag, business criticality, SLA configuration, owner, and the date scope was last confirmed, as a CSV file.

## Filtering by scope

The Asset list can be narrowed by PCI DSS scope and by component kind, so an assessor or owner can pull up, for example, only the Assets in the cardholder data environment. An Asset whose scope has never been recorded counts as not assessed, so filtering for not assessed lists everything still waiting on a determination.
