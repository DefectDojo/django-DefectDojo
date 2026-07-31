---
title: "The POA&M Ledger"
description: "How POA&M items are created from findings, and the conventions the ledger follows"
weight: 2
audience: pro
---

POA&M items are created and updated automatically from findings. The sync runs shortly after
imports and finding changes, and a nightly sweep catches anything that slipped through. You can
also add items by hand, for weaknesses that no scanner reports.

![The POA&M ledger](images/02-poam-items.png)

## Ledger conventions

The ledger follows FedRAMP conventions:

* **Stable numbering.** Every item keeps a sequence number within its system, and numbers are
  never reused.
* **Grouped findings roll up.** The same CVE across many hosts becomes one item, with each
  affected asset listed on it.
* **Configuration findings can consolidate under CM-6**, instead of flooding the ledger with one
  item per benchmark rule. In the screenshot above, `V-4` is that consolidated item.
* **Closed items never reopen.** If the same weakness comes back, the ledger opens a new item
  that references the old one, so your remediation history stays intact.

## Editing an item

The pencil on any row opens the item for editing.

![Editing a POA&M item](images/03-poam-item-detail.png)

From here you set the point of contact, resources required, and remediation plan, and record any
deviation.

### Deviations

Deviations are tracked as three separate states on each item:

| Deviation | Values |
| --- | --- |
| False Positive | No, Pending, or Yes |
| Risk Adjustment | No, Pending, or Yes |
| Operational Requirement | No, Pending, or Yes |

Each carries a shared **Deviation Rationale**. A risk adjustment also records the **Adjusted Risk
Rating** alongside the original, and both appear on the generated deliverables.

### Vendor dependencies

Items can carry a **Vendor Dependency** flag and the **Vendor Product** name, for weaknesses you
cannot remediate directly. The date of your last vendor check-in is tracked with the item.

## KEV tracking

Items tied to a CISA Known Exploited Vulnerability carry the KEV due date. That date also caps the
remediation deadline — see [Remediation Deadlines](remediation_slas).

## Milestones

Milestones carry a description with scheduled and completed dates, and appear in both the Excel
and OSCAL outputs. They are managed through the compliance API rather than on the item form.

## Adding an item by hand

Add an item for a weakness no scanner reports. Hand-created items behave like synced ones: they
take the next sequence number, accept deviations and milestones, and appear on the next snapshot.

## Auditability

POA&M items, milestones, and deviations are all under audit history. Every change records who,
what, and when.
