---
title: "Reachability"
description: "How DefectDojo Pro records whether a Finding's vulnerable code is actually reachable, and how that verdict adjusts priority"
audience: pro
weight: 3
---

A Critical CVE in code your application never calls is not the same risk as
the same CVE on a live request path. **Reachability** captures that
difference: DefectDojo Pro records whether each Finding's vulnerable code can
actually be reached, shows you where that conclusion came from, and feeds it
into the Finding's computed **priority**.

Reachability is a **beta** feature and is **off by default**. A superuser
enables it under **Settings > Feature Flags**. While it is off, no verdicts are
recorded, priority is unaffected, and no reachability UI appears.

## Verdicts

Every verdict is normalized to the same five values, whatever produced it:

| Verdict | Meaning |
|---|---|
| **Reachable (runtime)** | The vulnerable code was observed executing. |
| **Reachable (static)** | A call path to the vulnerable code exists from an application entry point. |
| **Potentially reachable** | Partial evidence — for example the vulnerable package is used, but the specific function could not be confirmed. |
| **Unreachable** | Analysis found no path to the vulnerable code. |
| **Unknown** | No reachability analysis covers this Finding yet. |

Normalizing matters because tools disagree about wording: one scanner's
"no path found" and another's "not in use" mean different things, and
DefectDojo records both as verdicts you can compare rather than flattening
them into a single yes/no.

## The rules reachability follows

These behaviors are deliberate, and they do not change per tool:

- **Unknown never counts against a Finding.** Most instances start with little
  or no reachability coverage. A Finding nothing has analyzed is scored
  exactly as it would be with the feature off.
- **Unreachable lowers priority. It never closes a Finding.** An
  "unreachable" verdict dampens the score so genuinely live issues sort above
  it, but the Finding stays open and visible. Reachability analysis is not
  perfect, and a wrong "unreachable" that silently hid a live Critical would
  be the worst possible failure.
- **Every verdict shows its source.** No verdict appears without the tool that
  produced it, its confidence, and the commit it analyzed where one is known.
- **Verdicts follow deduplication.** When several scanners report the same
  vulnerability and only one of them reports reachability, the verdict applies
  across that duplicate cluster, so you do not lose the signal by importing
  another tool.

## Where verdicts come from

You do not have to adopt a new scanner to get value here — DefectDojo reads
reachability that tools you may already run are producing:

- **Scanners that report it in their output.** Several supported parsers
  carry reachability, either as structured data or in their report text. No
  configuration is required beyond importing the report as usual.
- **Connectors.** A connector that supports reachability sends verdicts for
  the products it syncs, refreshed on its normal schedule.

Coverage is normally partial, and that is expected. Tools that do not report
reachability simply leave their Findings at **Unknown**.

Reachability describes the vulnerable code *inside* your application. For whether the
asset itself can be reached from outside, and whether the code is deployed at all, see
[Asset Exposure](../asset_exposure/). The two are independent and can be used together.

## How reachability changes priority

Reachability is one more input to the priority score described in
[Scoring & Prioritization](../). Reachable verdicts raise a Finding's
priority, unreachable lowers it in proportion to the source's confidence, and
unknown leaves it untouched.

The strength of that adjustment is tunable per prioritization engine, like
every other factor: set the reachability scalar to `0` to record verdicts
without letting them move scores at all, or raise it to weight reachability
more heavily. You can preview the effect with the prioritization simulator
before applying it.

Because enabling reachability shifts scores, review your engine's risk
thresholds after turning it on so Findings land in the buckets you expect.

### Reachability risk rules

That adjustment is proportional to a Finding's severity, which means it cannot
express two things you may want. A Low-severity Finding whose code is confirmed
reachable still gets only a small bump and stays in a low band; a Critical
reported unreachable can still sit at the top of the queue. Two optional rules
on the prioritization engine set a band directly instead:

- **Reachable risk floor** — the minimum Risk band for Findings whose vulnerable
  code is confirmed reachable. It only ever raises a band.
- **Unreachable risk ceiling** — the maximum Risk band for Findings reported
  unreachable. It only ever lowers a band, and it never closes or hides a
  Finding; it just caps where it sorts.

Both are empty by default, so nothing changes until you set them. The ceiling
also has a **minimum confidence**: it applies only when the unreachable verdict
is at least that confident, because capping a band on a low-confidence verdict
is how a live Critical gets buried.

A Finding whose CVE is reported as actively exploited in the wild is never
capped by the ceiling — exploitation evidence takes precedence over an
absence-of-path claim.

## What you see

**On a Finding** — a reachability badge, and a **Reachability Sources** panel
listing every source that reported on it, each source's verdict and
confidence, and which one currently applies. Where a tool supplies a call
path, the supporting evidence is shown with it.

**On the Findings list** — a Reachability column and filter, so you can build
views such as "Critical and reachable" and save them.

**On an asset** — a **Reachability Coverage** panel showing the verdict
breakdown for that asset, how many of its Findings carry any verdict at all,
and how many Criticals reachability has demoted or confirmed. Each figure
links through to the matching Findings. The share still at Unknown is shown
alongside the rest: it tells you how much of the asset reachability can
currently speak to.
