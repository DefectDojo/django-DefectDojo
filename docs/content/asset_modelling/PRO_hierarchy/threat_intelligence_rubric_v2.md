---
title: "Threat Intelligence: Evidence-Based Scoring (Rubric v2)"
description: "How reviewed exploitation evidence will feed the threat intelligence priority floor"
weight: 3
audience: pro
---

> **Not yet available.** This page describes a capability in development. It is not on the Feature
> Flags page and cannot be turned on yet, on DefectDojo Cloud or on a self-hosted instance. Today
> every finding is scored as described in [Threat Intelligence](../threat_intelligence/).

[Threat Intelligence](../threat_intelligence/#how-it-changes-scoring) turns exploit evidence into a
**floor** on the EPSS scale: a finding's external score is at least the floor its strongest evidence
earns. The table of floors is called the **rubric**. Rubric v2 is its next version. It keeps every
floor you know and adds one kind of evidence: **exploitation claims that DefectDojo's analysts have
reviewed and confirmed**.

## What changes

| Evidence | Priority floor (EPSS-equivalent) |
|---|---|
| Confirmed exploitation evidence **and** a confirmed, named threat actor behind it (new) | 45% |
| In CISA KEV **and** used in ransomware | 30% |
| In KEV, exploited in the wild, or **any confirmed exploitation evidence**, a confirmed canary observation included (new) | 20% |
| Weaponized public exploit (Metasploit / Exploit-DB) | 15% |
| Nuclei detection template exists | 12% |
| Public proof-of-concept only | 8% |
| No exploit evidence | no change |

The floors are the same values as today, and the finding's external score is still the greater of
its EPSS-derived value and its highest floor, so the rubric only ever raises a score.

In practice:

- **More findings reach the "known exploitation" floor.** A CVE that is not in CISA KEV but has
  reviewed evidence of exploitation (an incident report, a vendor advisory that states it, a
  honeypot or canary observation) gets the same 20% floor as a KEV listing.
- **The top floor becomes reachable.** Under rubric v1 the 45% floor needed vendor telemetry that
  the feed does not carry, so no finding ever reached it. Under rubric v2 it is reached by confirmed
  evidence with a confirmed, named threat actor behind it, and by nothing less.
- **Nothing becomes weaker.** Without reviewed evidence a vulnerability scores exactly as it does
  today. A KEV entry with ransomware use stays at 30%: CISA's ransomware flag names no actor.

What does **not** raise a floor: an unreviewed or rejected claim, a proof-of-concept on its own, and
a scanner's or vendor's "exploit available" flag (those are shown as they are today, and do not count
as evidence).

## Before it is turned on

Moving an instance to rubric v2 can raise the priority of findings, so DefectDojo measures the move
before making it: for each instance, how many findings would move from which floor to which, and the
vulnerabilities behind the largest moves. Your live priorities stay on rubric v1 until rubric v2 is released.
