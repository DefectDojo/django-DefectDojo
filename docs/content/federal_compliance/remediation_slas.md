---
title: "Remediation Deadlines"
description: "The FedRAMP Rev 5 and FedRAMP VDR SLA presets"
weight: 4
audience: pro
---

Two ready-made SLA configurations ship with the feature. Assign either to your Assets from SLA
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

Internet-reachability can also come from the computed asset exposure verdict rather than only a tag.
Turn on **Use Asset Exposure for VDR Tiering** to include it. The two sources union, so enabling it
can only tighten a deadline a tag already set, never loosen one.

**FedRAMP VDR becomes mandatory on December 7, 2026.** FedRAMP's Vulnerability Detection and
Response standard becomes mandatory for cloud service providers on that date. Adopting the VDR
preset ahead of it is the recommended path.

## Deadlines by Potential Agency Impact

The three tiers above give every credibly exploitable, internet-reachable finding the same deadline,
whatever the damage its exploitation would do. FedRAMP's published table does not: it crosses those
same exploitability and reachability conditions with a **Potential Agency Impact N-rating** (PAIN),
and the difference across ratings is large.

Turn on **Use PAIN Ratings for VDR Deadlines** to switch from the three tiers to the full table:

| PAIN rating | Exploitable **and** reachable | Exploitable only | Not credibly exploitable |
| --- | --- | --- | --- |
| N5 — debilitating effect on more than one agency | 2 days | 4 days | 16 days |
| N4 — debilitating on one agency, or disruptive on several | 4 days | 8 days | 64 days |
| N3 — disruptive effect on one agency | 16 days | 32 days | 128 days |
| N2 — narrow customer effect | 48 days | 128 days | 192 days |

Every cell is editable. The shipped numbers are FedRAMP's published Class C values; providers holding
a Class B or Class D certification change the numbers, not the shape.

### Rating your findings

PAIN is set per finding, on the finding itself. It is deliberately a person's judgment rather than
something computed from scanner output: FedRAMP asks the provider to estimate the effect exploitation
would have on the agencies using the service, and explicitly declines to prescribe a method for
arriving at that. A Triage Engine rule can propose a rating from evidence and route the finding for
review — see the **Set Potential Agency Impact** node — but the confirmation is yours to make and
defend.

Two consequences worth knowing before you turn this on:

* **A finding with no rating keeps its base deadline.** Every finding that exists before you start
  rating is unrated, so nothing is re-dated the moment you enable this. Deadlines tighten as you rate.
* **N1 has no row, on purpose.** FedRAMP's table starts at N2, so a finding rated N1 carries no VDR
  deadline and keeps the FedRAMP Rev 5 window. DefectDojo does not invent a row FedRAMP has not
  published.

Enabling PAIN deadlines **replaces** the three tiers rather than combining with them. A finding rated
N2 gets 48 days, not the 4-day tier it would have received without a rating — which is the point of
rating it.

The date each rating was set is recorded, because FedRAMP measures remediation timeframes from
*evaluation* rather than from discovery, and asks reporting to show when each impact reduction
happened. Re-running a rule that assigns the same rating a finding already has does not move that
date.

## Relationship to the ledger

SLA deadlines drive the scheduled completion dates on POA&M items, and determine which items count
as late in a snapshot's month-over-month metrics. They also decide what a **past-due-only** scan
item policy includes — see [Compliance Profile](../compliance_profile).

For how priority and SLAs work outside a federal context, see
[Assign Priority, Risk and SLAs](/asset_modelling/pro_hierarchy/priority_sla/).
