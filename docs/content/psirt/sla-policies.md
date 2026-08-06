---
title: "SLA Policies"
description: "Tune how long each severity tier gets before a PSIRT clock warns and breaches"
draft: false
weight: 10
pro-feature: true
---

SLA Policies is where you set how much time each severity tier gets. It is the
tuning surface for the clocks described in [Cases and SLA](../cases/) — that page
explains what a clock is and how pausing works; this one is about changing the
numbers.

The page separates two things deliberately.

## The clock definition is the obligation

Each card is a clock definition: what arms it, what stops it, and whether it can
be paused. Those are decided in code, so the card shows them read-only. The
shipped definition is **Triage SLA**, which runs on a source advisory from the
moment it arrives in scope until a triage decision is recorded.

The one control on a definition is its switch. Disabling a definition stops it
arming new clocks; clocks already running are unaffected, because a clock that
already started measures a real obligation.

Beside each definition is a live count of the clocks currently running or paused
under it, so you can see what a change is about to affect.

## The tiers are the calibration

Each definition has a ladder of tiers. A tier says: for work that resolves to
*this* severity, allow this long, and start warning this far before the deadline.

The shipped triage ladder:

| Tier | Deadline | Warns |
|---|---|---|
| `critical_exploited` | 4 hours | 1 hour before |
| `critical` | 1 day | 4 hours before |
| `high` | 3 days | 12 hours before |
| `medium` | 10 days | 2 days before |
| `low` | 30 days | 5 days before |

Add, edit, disable or delete tiers freely. Durations are entered as days, hours
and minutes, and the warning must fit inside the deadline — a warning that fires
after the deadline it warns about has nothing to warn anybody about.

**Tier codes come from the definition's resolver, not from case priority.** The
form offers the shipped vocabulary and accepts anything you type, but a tier whose
code the resolver never returns is inert: nothing will ever resolve to it. The
`critical_exploited` tier exists because exploited-in-the-wild is treated as its
own tier rather than as "critical, but sooner".

## Changing a tier does not move a running clock

A clock snapshots its tier and its deadline when it arms. Editing a tier changes
what future clocks get, and leaves every running clock measuring the terms it
started under.

This is why the page never offers to edit a deadline directly. A deadline that
could be changed after the fact is not evidence of anything, and the whole point
of the clock is to be able to say afterwards what was promised and whether it was
met.

## Deleting a tier that clocks are running under is refused

If live clocks were armed from a tier, deleting it is refused with a count, and
the refusal says to disable it instead. Disabling stops the tier being used for
new clocks without erasing the terms the running ones were armed with — which is
what you actually want, and what deleting would silently destroy.
