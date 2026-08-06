---
title: "PSIRT dashboard"
description: "A shared dashboard template that answers \"am I affected?\" first"
draft: false
weight: 8
pro-feature: true
---

PSIRT ships a dashboard template. Add it from **Dashboard → Shared Templates → PSIRT**,
which clones it into your own dashboard so you can rearrange or remove anything.

The template is only offered when the `psirt` feature flag is on. Every widget in it
needs PSIRT, so offering it otherwise would hand you four empty panels and no way to tell
whether the dashboard was broken or you were genuinely unaffected.

## Am I affected?

The lead widget, full width, and the reason the page exists. It counts advisories that
arrived in the window and splits them **four ways**:

| Bucket | Means |
|---|---|
| **Affected** | A component you run has a version inside a published affected range. |
| **Unknown** | A component corresponds, but its recorded version cannot be judged — nothing recorded, or something that is not a version like `latest`. |
| **Not affected** | Matching ran, and every corresponding component is provably outside the range. |
| **No signal** | Nothing in your inventory corresponds — or matching has not run yet. |

**"Not affected" and "no signal" are never merged, and you should not read them as the
same thing.** "Not affected" is an answer: the engine looked and your components are
outside the range. "No signal" is the absence of one. Collapsing them would report
ignorance as safety, which is the single wrong answer a product security team cannot
afford — and a dashboard that did it would be worse than no dashboard, because it would
be trusted.

Below the tiles, the affected advisories are named, with how many components and products
each one touches. Clicking a tile opens Feed Findings filtered to that bucket.

The counts come from stored match rows rather than from re-running the matcher, so they
are a few minutes behind rather than exact to the second. The alternative would make a
dashboard load re-match every advisory in the window.

**Configuration:** window in days (1–90, default 7), and an optional severity floor. Leave
the floor off unless you have another panel covering the rest — it can hide the
low-severity advisory that turns out to matter.

## Is the pipeline healthy?

Two widgets, side by side on purpose.

### Feed health

Which enabled feeds are **failing to poll**, and which have gone **silent** — enabled, but
nothing delivered for two days.

It leads with what is wrong rather than a count of successes, because a feed that stopped
polling produces no advisories, and no advisories looks exactly like a quiet week. A
widget that counted successes would look healthy at precisely the moment it should not.

It also distinguishes a feed that has *never* polled from one that has *stopped*: those
need different actions.

There is no filter on this widget, deliberately. Anything that could hide a silent feed
would remove the only signal separating a broken pipeline from a calm week.

When nothing is wrong it says nothing is wrong with the feeds — not "all clear". Working
feeds are a narrower claim than being unaffected.

### Triage SLA

Live SLA clocks by state, and **breached is counted apart from overdue**:

* **Overdue** — the deadline has passed and the breach scanner has not been round yet.
* **Breached** — the miss is on the record, appears in reporting, and does **not** clear
  when the work is finished.

One combined "late" number would hide which of those you are looking at.

It also shows how many scheduled publishes are armed, and how many **gave up** — a
schedule that exhausted its retries is invisible everywhere else.

Why these two sit together: an SLA that looks perfectly healthy while a feed has silently
stopped polling is the worst combination there is, and it is only visible when both are in
view at once.

## Our advisories

Your own advisories by lifecycle status, plus the ones sitting in review or approved with
**no movement for a fortnight**.

The stalled list is the useful part. A plain status breakdown buries a two-week-old review
among the drafts.

## What is deliberately not here

A chart of advisory volume over time. It looks like insight and answers nothing: a spike
could be a busy week at CISA or a feed that was down and caught up, and the widget cannot
tell you which.

## Adding the widgets individually

All four are in **Add Widget** under Numbers and Lists, prefixed `PSIRT:`. Add them to any
dashboard. The three operational widgets take no configuration beyond a title and a
refresh interval — and they reject unknown configuration rather than ignoring it, so a knob
that did nothing cannot leave you believing the panel is filtered.

## Notifications

Three PSIRT notifications go through your normal notification preferences (email, Slack,
in-app):

* an SLA clock entering **warning**, and again on **breach**;
* a **signoff requested** of you;
* a **material change** on a published advisory.

Advisory **delivery to customers** is not one of these. It uses an explicit recipient list,
never notification preferences, because a preference fan-out would let somebody opt out of
being told about a vulnerability in a product they own.
