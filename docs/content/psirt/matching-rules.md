---
title: "Matching Rules"
description: "Write your own matching rules, and understand why some of them are refused"
draft: false
weight: 4
pro-feature: true
---

Most matching needs no configuration. When an advisory publishes machine-readable
affected-version ranges, PSIRT compares them against your inventory on its own,
and the match it produces carries that comparison as evidence.

**Matching Rules exist for the advisories that publish nothing.** A vendor
bulletin that names a product in prose, with no CPE and no version range, cannot
be matched structurally — there is nothing to compare. A rule lets you say what
that advisory means for your inventory.

The trade is that a rule matches on what you wrote rather than on evidence, so a
loose rule produces a great deal of output that is not exposure. The authoring
surface is built around limiting that.

## A rule graded "weak" cannot be enabled

Every rule is graded, and the grade is shown while you type:

- **Strong** — the rule correlates against the advisory itself, usually via CPE or
  the advisory's own affected-version ranges. Matches it produces carry evidence.
- **OK** — the rule constrains both what you run *and* which advisories reach you.
  It can run, but a match is a correlation rather than proof.
- **Weak** — the rule has no narrowing signal. **It can be saved as a draft but not
  enabled.**

The refusal is not a warning you can dismiss. A rule saying "tell me about
anything mentioning openssl" fires on every advisory that mentions openssl,
whether or not the version you run is affected, and enabling it is how a triage
queue becomes unusable.

When a rule is refused, the message tells you what the rule actually says and what
is missing. For example:

> This rule is too broad to enable. Matches a component named "docker" in your
> inventory. This keyword/regex rule only constrains the component side. It would
> match every advisory. Pair it with an advisory-side (feed_text) condition.

## Both sides, not one

The most common authoring mistake is gating only the component side. A rule that
says "the component is named libxml2" matches *every* advisory in the store
against every libxml2 you carry, because nothing in the rule says which advisories
are relevant.

A usable keyword rule constrains both halves under AND:

| Condition | Field | What it does |
|---|---|---|
| keyword `libxml2` | Component name | narrows which components |
| keyword `libxml2` | Advisory text | narrows which advisories |

The editor offers to add the missing half for you. Copying a template does it
automatically, so a copy can never start out one-sided.

## Conditions

A rule combines conditions with AND or OR. Ten condition types are available; the
editor describes each one inline as you choose it, including whether it narrows the
component side, the advisory side, or both.

Two are worth knowing about before you start:

- **CPE** is the strongest available signal, because it compares against
  identifiers the advisory itself publishes.
- **Affected version** asks whether the advisory's own ranges cover your installed
  version. It is a *lenient* gate: it passes when an advisory declares no ranges at
  all, which most advisories do. It narrows real exposure without excluding the
  advisories a rule exists to catch.

## Groups, scope, and templates

Rules live in **groups**, and a group is what gets scoped:

- **AND** means every rule in the group must fire — adding a rule *narrows* the
  group, and one disabled rule can silence it entirely.
- **OR** means any one rule suffices — adding a rule *widens* it.

A group applies where you subscribe it: to a product, to a product type, or as a
global default. An **opt-out** exempts one product and beats every other route,
including the global default.

A group with no subscription matches nothing. That is indistinguishable from a
broken group, so the list has an "Applies to" column, and the *resolved* reach —
after opt-out precedence — is available per group rather than left for you to work
out from the subscription rows.

**Templates** are curated groups that are never evaluated directly. Copy one to get
a group you own, which you can then edit, scope and enable. The copy is renamed to
avoid colliding with the template, its loose conditions are paired automatically,
and it starts out applying to every product so it is never born silently inert —
narrow it from the scope control afterwards.

## Deleting a group

Deleting a group does not delete its rules; they survive as standalone rules. A
rule outside a group has no subscription of its own, so it would otherwise keep
matching everywhere. Deleting a group therefore **switches its rules off**, and the
confirmation says how many.

## Where matches go

A rule-produced match appears in
[Feed Findings](../feed-findings/) alongside the structured ones, and is marked with the
rule that produced it. Structured matches outrank rule matches on the same
advisory, so a rule cannot displace evidence.
