---
title: "Feed Findings"
description: "Triage incoming advisories and read the tri-state answer to 'am I affected?'"
draft: false
weight: 5
pro-feature: true
---

**PSIRT → Feed Findings** is the queue of advisories your enabled feeds have
brought in, and the place each one gets its answer.

## The answer is three-valued, not two

Opening an advisory leads with an explicit answer, and there are four states
rather than a yes/no:

- **Affected** — at least one dependency in your inventory has a version inside
  the advisory's affected range. The panel names the components and the products
  that carry them.
- **Not affected** — every dependency that corresponds to this advisory has a
  version provably outside the affected range.
- **Unknown** — a dependency corresponds, but there is nothing comparable to
  judge on. Usually the inventory records no version, or records something that
  is not a version (`latest`, a branch name, a build tag).
- **No inventory signal** — nothing in your inventory corresponds to this
  advisory at all.

The last two are separate on purpose. "Every version I run is outside the range"
is an answer; "I have no version to check" is not, and reporting the second as
"not affected" would tell you that you are safe on the strength of missing data.
If a component shows as **unknown**, the fix is on your side: record the version,
or supply a CPE for that component.

For the same reason, an advisory whose publisher never stated which versions it
affects can only ever produce **unknown** — there is nothing to compare against.
Those advisories show a version range of "all versions" only when the publisher
actually said so.

## The queue

Each row carries the advisory's identifier and title, its feed, severity and
CVSS, EPSS, whether it is known to be exploited, and how many matches it has
produced — with the verified count shown separately (see below). Filter by feed,
severity, pipeline state, or exploited status; search across identifiers, titles,
and CVE ids; sort by any of the scores or by match count.

Advisories still moving through the pipeline show it: an advisory waiting on
enrichment has not yet been matched, because enrichment is what supplies the
version ranges matching needs.

## Verified and unverified matches

A match tells you a component and an advisory correspond. **Verified** tells you
something stronger: that there is structured, in-range version evidence behind
it.

- A **verified** match exists because a version range actually covered the
  version you run.
- An **unverified** match agreed on a name but had no version evidence to
  confirm — the same package name in a different ecosystem, or a component whose
  version could not be compared.

Unverified matches are shown, not hidden, and ranked below verified ones with the
reason stated. They are leads, not conclusions.

## Retracted matches

Publishers revise advisories. When a revision narrows a range so that a match no
longer holds, PSIRT marks that match **retracted** rather than deleting it: the
record of why it once existed is worth keeping, and a stale match left on the
queue is worse than one withdrawn. Retracted matches are out of the default view
and come back automatically if a later revision re-widens the range.

A match you have confirmed, or exported as a finding, is never retracted
automatically. Once a person has judged it, that judgement stands until a person
changes it.

## Triage actions

- **Review** marks that you have looked at an advisory. It is independent of the
  advisory's pipeline state and never overwrites it.
- **Suppress** hides an advisory from the default queue. Suppressed advisories
  remain viewable so you can audit what was filtered out.
- **Unsuppress** brings one back permanently: a pre-filter rule that hid it once
  will not hide it again. This is deliberate — your decision that an advisory
  matters outlasts the rule that disagreed.
- **Re-match** queues the advisory for another matching pass. Useful after an SBOM
  import or after correcting a component's version.
- On a match: **confirm**, mark **false positive**, or leave notes. Everything
  else on a match is the engine's record of why it exists and is read-only.

## Attribution

An advisory's detail shows the credit its publisher requires. Several feed
licenses require that notice to travel with the content, so it appears wherever
the content is read.
