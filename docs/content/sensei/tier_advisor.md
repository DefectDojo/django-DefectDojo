---
title: "Tier Advisor"
description: "Project how many findings your instance will process in a year, and see which tier covers it."
draft: false
audience: pro
weight: 6
---

**Tier Advisor** estimates how many findings your instance will process over a year and shows
which tier covers that volume. It is meant for an evaluation, where the question "what will
this cost us in production" has to be answered from a few weeks of trial data.

It is part of Sensei Advisor and appears on the Advisor page once DefectDojo enables it for
your instance.

## Why it asks questions

A trial measures one thing well and two things badly.

What it measures well is how many findings each scanner sends per run. That number is stable:
a container scan of the same image set reports about the same amount every time.

What it cannot measure is how often that scan will run once you are in production, and how
much of your estate is connected yet. An evaluator importing scans by hand looks nothing like
the nightly connector that replaces them, and a trial covering three assets says little
about an estate of forty.

So the projection does not simply multiply your trial usage by twelve. It takes the per-run
volume from what it has seen, and takes the frequency and the coverage from you:

```
annual volume = for each scanner: findings per run x runs per year x coverage
```

## What you are asked

**How often will each scanner run in production?** Answered per scanner rather than once for
everything, because most teams run static analysis on every pull request, container scans
nightly and dynamic scans weekly. Each row is pre-filled with a sensible default. If you
choose a per-commit or continuous cadence, you are also asked roughly how many builds or
merges happen a week, because otherwise there is no rate to calculate.

**How much of your estate is connected?** All of it, most of it, or a pilot. If it is a pilot,
you are asked how many assets are connected today and how many you have in total. This is the
question that stops a small pilot being priced as though it were your whole estate, so it
cannot be skipped.

The page uses whichever word your instance is set to, so it reads "products" where that is the
label you use.

**Which scanners will you add?** Any scanner you plan to connect but have not yet is counted
using the median volume of your connected scanners, and the page says so on the card. A
scanner left out entirely would quietly understate your volume.

**How long must closed findings be kept?** Retention is driven by your compliance obligations
rather than by volume, and it is priced separately, so it is asked here while you are already
answering questions.

## What you get back

A range, not a single number. The page shows the expected annual volume with a low and high
estimate around it, a confidence level, and the tier that covers the expected value.

Underneath, the page shows the arithmetic: each scanner, its typical volume per run, the
cadence you gave, and what that contributes to the year. Anything the estimate had to assume
is listed separately, including any opening bulk import that was excluded.

The page also reports what your instance has actually processed so far, and how much of it was
duplicate or unchanged. That figure is measured from your own data rather than quoted from a
case study.

### Headroom

Every tier keeps working past its limit before enforcement applies, which is there so an
account growing into its tier is not interrupted while a renewal is arranged. The advisor uses
that headroom to tell you when you are safely covered, so a projection that lands slightly
over a tier does not push you into a larger one you do not need. When the high end of the
estimate goes past the headroom, the page says so and suggests sizing up.

Headroom is not a planning target. The tier that gets recommended is the one that covers your
expected volume at face value.

### When it declines to answer

The advisor refuses to project when the evidence is too thin to support one. It says what is
missing instead. The common cases are an instance with only a few days of scan history, and a
pilot too narrow to extrapolate from. In both cases the fix is either more trial data or a
conversation with your account team about the volumes you expect.

## What it does not do

The number is an estimate for planning. It is not a quote, and it does not commit DefectDojo
or you to anything. Your account team issues the quote.

The projection is calculated rather than generated. Volumes, tiers and prices come from your
metering data and a fixed price table, not from a language model.

## Availability

Tier Advisor is part of Sensei and requires a Sensei-enabled license. It is enabled per
instance by DefectDojo, separately from the rest of Sensei Advisor.

The projection itself is calculated rather than generated, so it makes no AI model call. An
analysis that includes it still counts as one of your licensed Advisor runs, the same as any
other analysis.
