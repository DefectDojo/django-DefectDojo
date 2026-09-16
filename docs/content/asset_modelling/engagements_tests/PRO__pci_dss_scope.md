---
title: "PCI DSS Scope and Patch Clocks"
description: "Record PCI DSS scope per Asset, run the Requirement 6.3.3 patch clock, and export a scope inventory"
audience: pro
weight: 8
---

The PCI DSS scope features let an organization record how each Asset relates to its cardholder data environment, run a patch clock that matches the Requirement 6.3.3 timeline, and export the scope inventory an assessor asks for under Requirement 12.5.1. These features are additive: they record the entity's own determinations and never decide compliance, which remains the assessor's judgment.

The PCI DSS scope UI is released behind a feature flag. An administrator turns it on per instance from the Feature Flags page before it is generally available.

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

## Scope inventory export

The scope inventory export produces the list an assessor reviews under Requirement 12.5.1. It returns every Asset the user is authorized to view, with its scope, component kind, public-facing flag, business criticality, SLA configuration, owner, and the date scope was last confirmed, as a CSV file.

## Filtering by scope

The Asset list can be narrowed by PCI DSS scope and by component kind, so an assessor or owner can pull up, for example, only the Assets in the cardholder data environment.
