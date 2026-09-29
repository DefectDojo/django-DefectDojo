---
title: "Components"
description: "The inventory PSIRT matches against, and the judgement you add to it"
draft: false
weight: 4
pro-feature: true
---

Components is the software inventory as PSIRT reads it: one row for each component
in each asset that carries it. The rows come from the SBOMs you import — this page
does not create inventory, it annotates it.

The same library in two assets is two rows on purpose. A library in your payment
path and the same library in a build tool are not the same risk, and the
annotations below are per pair so you can say so.

## What each row tells you

| Column | Meaning |
|---|---|
| Component | Name, with its package type |
| Version | The version recorded in the SBOM. `none` means no version was recorded |
| Asset | Which asset carries this copy |
| PCRSS | Your risk rating for this component here, 1–5 |
| CPE | The CPE you supplied for it, if any |
| Tags | Your labels |
| Matches | How many advisories currently match it, and how many of those verified the version |

A **`none` version is worth noticing.** Version comparison is what turns a
correlation into evidence, so a component with no recorded version can only ever
be answered "unknown" — never "not affected". If a lot of rows say `none`, the
SBOM that produced them is the thing to fix.

## Annotating a component

Select **Annotate** (or **Edit**) on a row. Three fields, all optional, all scoped
to that component in that asset:

**PCRSS (1–5)** — the static risk rating your PSIRT policy assigns this component
in this context. It is copied onto matches produced for the pair, where it feeds
case worthiness, unless an analyst overrides it on the match itself.

**CPE** — the single most useful thing you can add. Advisories are frequently
keyed by CPE, and an SBOM records package URLs, so a component that carries no CPE
cannot correlate on the strongest axis PSIRT has. Supplying one here makes that
axis reachable for this component. An unparseable CPE is refused rather than
stored.

**Tags** — your own labels, lower-cased and de-duplicated.

### An annotation changes future matching, not past matches

Saving a CPE does not rewrite matches that already exist. The matcher reads the
annotation on each advisory's next pass, so the change shows up as advisories are
re-evaluated.

**Re-evaluate matches** on the dialog does not wait for that. It re-queues the
advisories that already matched this component, and reports how many, so you can
see the effect of an annotation you just made rather than wondering whether it
took.

## Filters

**All components / Annotated only** switches between the whole inventory and the
rows somebody has judged. "Annotated only" is the useful view when you are
reviewing your own coverage; the full list is the one to work through when you are
building it.

Keyword search covers component name, namespace and asset name.

## When the list is empty

An empty list means no SBOM has been imported for any asset yet, and PSIRT has
nothing to compare advisories against. **Import SBOM** on the toolbar goes
straight to the [global upload page](../import-sbom/).
