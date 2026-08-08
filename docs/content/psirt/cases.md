---
title: "Cases and SLA"
description: "Group matches into work items, and track the triage obligation on them"
draft: false
weight: 7
pro-feature: true
---

A match is an observation. A **case** is the work: several matches about the same
problem, grouped, prioritised and carried to a conclusion. Matching a busy feed set
produces thousands of matches; cases are what turn that into a queue somebody can
finish.

## Grouping

**PSIRT → Cases → Group matches** proposes groupings over every match not already in
a case, most confident first. Four kinds:

| Grouping | What it catches |
|---|---|
| Same vulnerability, one product | one CVE affecting several components in one product |
| Same vulnerability | one CVE wherever it landed |
| Same component | one component carrying several advisories |
| Same advisory | one advisory across several components |

A CVE that arrived on three different feeds appears **once**, not three times — the
grouping keys on the normalised vulnerability identity rather than on the feed
record, so a corroborating source consolidates instead of duplicating.

Each match appears in exactly one suggestion: the most confident grouping that could
claim it. Nothing is created until you pick a group.

Every card shows how many of its matches were **version-proven** and how many are
**name-only**. That distinction matters more than the count: eight version-proven
matches are a confirmed exposure, and eight name-only ones are a research task.

The suggestion list is capped. When it is, the dialog says so — a truncated list
reads as "there is nothing left to group" otherwise.

## The SLA clock

PSIRT tracks a **triage obligation**: the time between an advisory arriving in scope
and a triage decision being recorded against it.

A clock arms when an advisory is either high/critical severity or listed as known
exploited, **and** has at least one live match. Both halves are required — a severe
advisory that touches nothing you run creates no obligation, and neither does a
low-severity advisory nobody is exploiting.

Five tiers, from the advisory's severity and exploitation status:

| Tier | Deadline | Warning at |
|---|---|---|
| Critical, known exploited | 4 hours | 1 hour before |
| Critical | 24 hours | 4 hours before |
| High | 3 days | 12 hours before |
| Medium | 10 days | 2 days before |
| Low | 30 days | 5 days before |

These are defaults. Edit the durations under **SLA policies**; the tier logic itself
is not configurable.

A clock stops when a decision is recorded — the advisory is reviewed, it is
suppressed, or every live match on it has been judged. The third case matters
because an analyst who works the matches individually and never touches the advisory
row has still done the work.

### The tier is fixed when the clock starts

The tier is captured at arm time and never recomputed. A case re-tiered next week did
not retroactively owe a shorter deadline, and a clock that recalculated its own
deadline from current state would erase breaches by making them un-late after the
fact.

For the same reason, a tier can only ever move **up** on a running clock. Moving a
deadline outward is how a breach disappears.

### Pausing

A clock can be paused with a category and a reason, and the deadline moves forward by
exactly the time it was paused — so waiting on somebody else is not charged to the
team.

The reason is **required and recorded permanently**. That is the whole argument for
allowing pauses: an unexplained pause is indistinguishable from avoiding a deadline.

The **triage clock cannot be paused**. Nothing outside the team is being waited on
during triage, so a pause there could only ever hide lateness. Clocks that can be
paused say so; clocks that cannot explain why where the control would be.

### Overdue, then breached

A clock past its deadline reads **Overdue** until a background scan records the miss,
after which it reads **Breached**. The two are different: overdue is a comparison,
breached is a recorded fact that appears in reporting.

**A breach never clears.** If the work finishes afterwards, the clock stops as
*breached*, not as *met* — late work finished is still late. This is deliberate: an
SLA that erases its own misses the moment somebody catches up measures nothing.

A paused clock cannot breach.

## Priority is not the SLA tier

A case carries a **mitigation priority** (P0/K through P3) that you set. It is your
own ranking of the work, and the SLA does not read it — the tier comes from advisory
severity and exploitation.

They are shown as separate columns for that reason. Downgrading a priority does not
move a deadline.

## Scores

A case rolls up the highest CVSS, EPSS and PCRSS across its matches. Setting any of
them by hand marks the case as overridden, and the roll-up then **leaves it alone**
on every subsequent recompute. Recomputing an overridden case is refused until you
confirm you want the hand-set values replaced.

## Closing a case

Closing a case records a conclusion and a mitigation status. It does **not** stop any
SLA clock: a case is a grouping, and the obligation belongs to the advisories inside
it. Closing a case cannot be used to discharge an outstanding triage obligation.

Reopening leaves the mitigation status as the analyst left it.

## Getting findings into DefectDojo

You do not need a case to file a finding. Confirming a match in
[Feed Findings](../feed-findings/) and exporting it creates the DefectDojo finding
directly — one finding per vulnerability identity per product, under a standing
**PSIRT Monitoring** engagement and a **Security Advisory** test.

A component that appears in several products produces a finding in each, because a
vulnerable library shipped in eight products is a problem in eight products. The
export reports every product it touched.

Re-exporting the same match updates the finding it already created; it never
duplicates. A second advisory carrying the same CVE attaches as corroborating
evidence to the finding that exists.
