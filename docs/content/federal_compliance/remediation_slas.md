---
title: "Remediation Deadlines"
description: "The FedRAMP Rev 5 and FedRAMP VDR SLA presets"
weight: 4
audience: pro
---

Two ready-made SLA configurations ship with the feature. Assign either to your products from SLA
configuration settings, or copy one and adjust it.

## FedRAMP Rev 5

| Severity | Due within |
| --- | --- |
| Critical | 30 days from discovery |
| High | 30 days from discovery |
| Moderate | 90 days |
| Low | 180 days |

Deadlines are enforced, and a finding listed in the CISA KEV catalog is never scheduled past its
CISA due date.

## FedRAMP VDR

The same base windows, further tightened by exploitability and exposure:

| Condition | Due within |
| --- | --- |
| Credibly exploitable **and** internet-reachable | 4 days |
| Credibly exploitable only | 14 days |
| Internet-reachable only | 30 days |
| Neither | The FedRAMP Rev 5 windows above |

**Credibly exploitable** means the finding is KEV-listed, or its EPSS score is at or above your
threshold. **Internet-reachable** is signalled by a finding tag — `internet-reachable` by default.

All the thresholds, tag names, and day counts are editable on the SLA configuration.

**FedRAMP VDR becomes mandatory on December 7, 2026.** FedRAMP's Vulnerability Detection and
Response standard becomes mandatory for cloud service providers on that date. Adopting the VDR
preset ahead of it is the recommended path.

## Relationship to the ledger

SLA deadlines drive the scheduled completion dates on POA&M items, and determine which items count
as late in a snapshot's month-over-month metrics. They also decide what a **past-due-only** scan
item policy includes — see [Compliance Profile](compliance_profile).

For how priority and SLAs work outside a federal context, see
[Assign Priority, Risk and SLAs](../asset_modelling/PRO_hierarchy/priority_sla).
