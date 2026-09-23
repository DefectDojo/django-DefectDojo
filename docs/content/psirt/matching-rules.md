---
title: "Matching Rules"
description: "Write your own matching rules, and understand why some of them are refused"
draft: false
weight: 6
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

### Start From a Template

**Start From a Template** is the shortest route to a rule that works, and on a new
instance it is the recommended one. The blank rule form invites the shape the trust
layer refuses: "match anything called django" reads like the obvious rule and is
exactly the one-sided keyword that cannot be enabled.

Every template is labelled with what it needs:

- **No SBOM needed** — the rule matches an asset directly from the advisory text.
  These work on any instance, including one that has never imported an SBOM.
- **Needs SBOM** — the rule matches a component in your dependency inventory. With
  no SBOM imported it will not match anything, however well written.

Templates that need no SBOM are listed first, because most instances have no
inventory yet and a dependency rule there is silent rather than wrong.

Each template asks for one term — a vendor, a piece of software, a component, or a
package URL — and fills it in throughout the copy. **A template's rules ship
switched off**, and the copy is only enabled when the term you supplied produces a
rule that clears the same grading a hand-written rule has to clear. Supply a term
too broad to enable (say, a vendor called "linux") and the copy is created stopped,
with the usual explanation of why.

## What to do when you have no SBOM

A dependency-target rule matches a component in your inventory. With no inventory,
it matches nothing — which looks identical to a rule that is simply not working,
and is the most common reason people conclude matching is broken.

Rules targeting an **asset** need no inventory at all. They compare the advisory
text against the asset directly, so "any advisory mentioning Siemens" is expressible
without importing anything. When your instance has no components loaded, the rule
editor starts new rules on the asset target for that reason and says so beneath the
selector.

The three no-SBOM templates cover the usual shapes: an advisory naming a vendor you
run, one naming a piece of software you run, and one carrying a CPE you publish.
The CPE shape is the most precise of the three, because it compares identifiers
rather than prose.

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

## Build rules from your inventory

Rather than authoring rules one at a time, PSIRT can propose one per component in
an asset's [inventory](../components/) and let you keep the ones you want.

Each proposal is generated in a sound shape, never a loose one:

- a component with a **CPE** becomes a single CPE condition;
- a component without one becomes a **two-sided keyword pair** — the component
  name on both the inventory side and the advisory side;
- a component with a **version** additionally gets a version constraint, so the
  rule fires only for advisories whose affected range covers what you run.

Proposals arrive graded and pre-selected, and two kinds arrive **deselected**:
components an in-scope rule already covers (the proposal names the covering
group), and components whose name is a broad platform token like `docker`, where
a rule would pull in far more than your exposure. They are shown rather than
hidden, because "already covered" is worth knowing while you decide.

When you create the group, the conditions are regenerated on the server from the
components you kept. The selection says *what* to cover; it never says what the
rules contain.

## Preview: what would this rule do?

Preview runs a rule against the recent advisory corpus and reports how many
advisories it would match, with samples — **without writing anything**. Matching
itself stays with the background pipeline; a preview that could persist would be a
second way to produce matches, and the two would drift.

Preview works on a rule, on a whole group (composed by the group's operator), and
on conditions you have not saved yet, which is what makes "would this be better?"
answerable while you are still editing. Editing an existing rule also reports the
**before/after** counts, because the new number alone does not tell you whether
your edit widened or narrowed anything.

Two things to read carefully:

- the **corpus size** is how many advisories were evaluated. A rule matching 3 of
  40 means something different from 3 of 4,000, and if the corpus was capped the
  result says so.
- the **heuristic flags** are the same warnings the authoring badge raises: a
  keyword that is too short, a common English word, a broad platform token, an
  unanchored regex, or a one-sided rule.

## Effectiveness: has this rule earned its keep?

Effectiveness reports what a rule has actually produced: lifetime and 30-day match
counts, how many an analyst confirmed, how many were marked false positive, the
resulting false-positive rate, and when it last fired.

From that it derives up to three flags:

- **Noisy** — most of what a reviewer looked at was wrong. Only raised once enough
  matches have been reviewed to mean anything, so a rule with three false
  positives and no confirmations is not condemned on that evidence.
- **Dead** — nothing for 90 days, on a rule old enough to judge.
- **Insufficient data** — never fired, but younger than that window. Deliberately
  distinct from dead: a new rule that has not fired yet has told you nothing, and
  reporting it as dead would invite deleting rules that were simply new.

"Dead" is an age heuristic, not a volume-aware one. A rule with nothing matchable
in the feed during the window is reported dead even though it never had the
chance — worth remembering before deleting on that signal alone.

## Coverage: is anything watching this asset?

Coverage answers the question a list of rule groups does not: for each asset, is
anything actually watching it, and does that cover what the asset carries?

Each asset gets a grade:

- **Covered** — at least one strong group applies, *and* in-scope rules name most
  of the asset's inventory.
- **Partial** — something applies, but it is weaker or narrower than that.
- **None** — nothing applies.

The inventory test is what stops "covered" being earned cheaply. One precise rule
beside a thousand unwatched components is not coverage, so a provisional "covered"
is capped at "partial" when in-scope rules name less than 80% of the inventory. An
asset with no inventory at all is not capped — there is nothing to be
under-covered against, and a product nobody has imported an SBOM for is a
different problem from a real gap.

Organizations are graded weakest-link: covered only when every asset in them is.

One state is called out separately: **rules are scoped here, but all disabled**.
That is a different problem from having authored nothing, and it has a different
fix, so the two do not share a grade.

