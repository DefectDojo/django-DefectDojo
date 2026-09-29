---
title: "Feed Rules"
description: "Score, tag, star and mute advisories from their own text, before anything touches your inventory"
draft: false
weight: 5
pro-feature: true
---

A busy set of feeds produces tens of thousands of advisories, and on a new
instance none of them have matched anything yet. Column filters sort what you can
already describe; they cannot say *"from now on, anything claiming active
exploitation goes to the top"*. Feed Rules is where you say that once.

A feed rule reads the advisory's own text as it arrives — before any comparison
against your inventory — and does one or more of four things:

- **adds points**, which raises the advisory in the triage queue's ranking;
- **adds a tag**, which you can then filter the queue by;
- **marks it a favourite**, which stars the row;
- **suppresses it**, which keeps it out of the active queue entirely.

Because they read only the advisory, feed rules work with no SBOM and no matching
rules. They are usually the first thing worth configuring.

## Start from a starter

The **Starters** button installs a ready-made rule. Each becomes an ordinary rule
afterwards — editable, stoppable, deletable.

| Starter | What it does |
|---|---|
| Exploited in the wild | Scores and stars advisories whose text says exploitation is *happening*, not that it is possible. The highest-signal thing available from text alone. |
| Named in ransomware activity | Tags advisories tying the vulnerability to ransomware operators. |
| Exploit code is public | Scores public proof-of-concept or exploit code — lower than in-the-wild, because they are different claims. |
| A vendor you run | Scores and tags every advisory naming one vendor. Install one per vendor that matters to you. |
| Mute newsletters and event announcements | Suppresses the items a broad feed carries that are not advisories at all. |

Starters are offered, never installed for you. The muting rule in particular is an
editorial decision about what you do not want to see, and that is not a decision to
make on somebody's behalf.

## Writing a rule

A rule is conditions plus actions.

**Conditions** read one advisory field — the title and description together
(*content*), the title alone, the CVE list, or the source URL — with one of four
tests: contains any of, contains all of, contains none of, or matches a regular
expression. Terms are comma-separated.

**Whole word** is on by default and matters more than it looks. Without it, a term
like `SSL` matches inside "assembly" and a scoring rule quietly stops meaning
anything. It does not apply to a regular expression, which can anchor itself.

**Actions** are the four above. A rule that matches and does nothing cannot be
turned on, and neither can a rule with no conditions — both are rules that look
configured and have no effect.

Two settings control how rules interact:

- **Order** — lower numbers run first.
- **Stops after matching** — normally every rule gets a turn, so points from
  several rules add up. A rule that stops the pass ends it, which is how a
  suppressing rule can pre-empt everything after it.

### Preview before you turn it on

**Preview against recent advisories** runs the rule over a window of real
advisories and reports how many it would have caught, listing a sample.

Use it every time. A feed rule is written against a corpus nobody can read, and
the two ways it goes wrong look nothing alike from the form:

- a rule that catches **nothing** is indistinguishable from a rule that is switched
  off;
- a rule that catches **most of the queue** sorts nothing, while looking like it is
  working.

The preview names both cases rather than only reporting a number.

## Scope

A rule applies to **every feed** by default, or to one feed. Per-feed scope is for
rules that only make sense for one publisher — a vendor's own PSIRT feed where
every item is about that vendor, say.

Pre-filtering can also be turned off per feed, on the feed's own settings.

## Re-score recent advisories

Feed rules run as advisories arrive, so a rule written today does not touch
anything already in the queue — while the backlog in front of you is usually the
reason you wrote it. **Re-score Recent** applies the current rules to the most
recent advisories.

Re-scoring recomputes everything from the current rules: scores, tags and stars
are replaced rather than added to, and rule-driven suppression is applied or
lifted to match. Two things it will not touch:

- an advisory **you** suppressed by hand;
- an advisory you **unsuppressed** by hand, which is permanently exempt from rules
  suppressing it again.

## Reading the results in the queue

Feed Findings carries a **Feed Rules** column showing the score, a star where a
rule marked one, and any tags. The column sorts, and the queue filters on minimum
score, favourites, and tag.

That is the payoff: after a few rules, "what should I open next" is answerable by
sorting a column instead of reading titles.

## Deleting a rule

Scores and tags a rule applied stay on advisories already scored until the next
re-score. Deleting a **suppressing** rule lifts its suppression on the next
scoring pass, so advisories it was hiding come back into the queue.
