---
title: "PSIRT dashboard"
description: "A shared dashboard template that answers \"am I affected?\" first"
draft: false
weight: 10
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

| Answer | Means |
|---|---|
| **Affected** | A component you run has a version inside a published affected range. |
| **Unknown** | A component corresponds, but its recorded version cannot be judged: nothing recorded, or something that is not a version like `latest`. |
| **Not Affected** | Matching ran, and every corresponding component is provably outside the range. |
| **No Signal** | Nothing in your inventory corresponds, or matching has not run yet. |

**"Not affected" and "no signal" are never merged, and you should not read them as the
same thing.** "Not affected" is an answer: the engine looked and your components are
outside the range. "No signal" is the absence of one. Collapsing them would report
ignorance as safety, which is the single wrong answer a product security team cannot
afford, and a dashboard that did it would be worse than no dashboard, because it would
be trusted.

The headline names how many advisories affect you in the window, and how many cannot be
judged yet. Under it, one bar shows the window's advisories by answer, and its legend
carries the four counts. No Signal is drawn hatched and grey, never green, and the widget
says on screen that it is not a safe answer wherever it is the answer. Hover or focus a
legend entry or a bar segment to read its definition. A small tag beside the legend shows
a severity floor when the widget has one.

Below the bar, the affected advisories are named, worst severity first: severity, advisory
id, title, and how many components and assets each one touches. The widget names up to
eight; when more are affected, a last row links to the rest.

Where each link goes:

* **A count** (a legend entry or a bar segment) opens Feed Findings filtered to that
  answer over the same window, and to the floored severities when the widget has a floor,
  so the list total matches the count. **Open Unknown**, **Open No Signal** and the
  "more affected" row open the same lists.
* **An advisory** (its id or title) opens Feed Findings filtered to that advisory.
* **The menu at the start of each row** offers **View in Feed Findings**; **Affected
  Components** when the row names components (PSIRT Components narrowed to the components
  whose version the advisory's range was verified against); and, when a case already holds
  the advisory, **Open Case** (PSIRT Cases narrowed to those cases). Nothing in the menu
  changes data.

Each filtered list shows the filter as a chip above the table; remove the chip to see the
whole list again.

The counts come from stored match rows rather than from re-running the matcher, so they
are a few minutes behind rather than exact to the second. The alternative would make a
dashboard load re-match every advisory in the window.

**Configuration:** window in days (1 to 90, default 7), and an optional severity floor.
Leave the floor off unless you have another panel covering the rest: it can hide the
low-severity advisory that turns out to matter.

## Is the pipeline healthy?

Two widgets, side by side on purpose.

### Feed health

Every feed source is counted in exactly one state, worst first:

| State | Means |
|---|---|
| **Failing** | Enabled, and its last poll failed after its last success. |
| **Silent** | Enabled, but it has delivered nothing for two days, or it has never polled. |
| **Polling** | Enabled and delivering. |
| **Disabled** | Not polled. A source nobody enabled is not a fault. |

The headline leads with what is wrong rather than a count of successes, because a feed
that stopped polling produces no advisories, and no advisories looks exactly like a quiet
week. A widget that counted successes would look healthy at precisely the moment it should
not. When nothing is wrong it says the enabled feeds are polling, not "all clear": working
feeds are a narrower claim than being unaffected.

Under the headline, one bar shows the sources by state, and its legend carries the four
counts. Hover or focus an entry to read its definition. Below the bar, the failing feeds
are listed, then the silent ones: the feed's name, a short error class such as **Timed
Out** or **HTTP 503** (or **Never Polled** and **Silent**), and the date of its last
successful poll. The full error text is in the error class's tooltip (on hover and on
keyboard focus) and on the feed's own page, never in the tile itself. A feed that has
*never* polled is told apart from one that has *stopped*: those need different actions.

Where each link goes:

* **A count** (a legend entry or a bar segment) opens PSIRT Feeds filtered to the sources
  in that state, so the list matches the count.
* **A feed** (its name, or **Open Feed** in the menu at the start of its row) opens PSIRT
  Feeds filtered to that feed.

There is no configuration on this widget, deliberately. Anything that could hide a silent
feed would remove the only signal separating a broken pipeline from a calm week.

### Triage SLA

Live SLA clocks by state, most urgent first, and **breached is counted apart from
overdue**:

* **Breached**: the miss is on the record, appears in reporting, and does **not** clear
  when the work is finished.
* **Overdue**: the deadline has passed and the breach scanner has not been round yet.
* **Due Soon**: inside the warning window before the deadline.
* **Paused**: the count is stopped and the deadline moves with it.
* **On Track**: inside the time the tier allows.

One combined "late" number would hide which of the first two you are looking at.

The headline names the most urgent fact. Under it, one bar shows the clocks by state, and
its legend carries the five counts. Below the bar, up to five clocks that are breached,
overdue or due soon are listed, soonest deadline first: the tier, the case reference and
title (or the advisory's own id and title when no case holds it yet), and the deadline.
Hover or focus the deadline for its state and full date and time. When more clocks need
attention than are listed, a last line says how many.

Where each link goes:

* **A count** opens PSIRT Cases filtered to the cases holding an advisory whose clock is in
  that state. The count is of clocks, the list is of cases: a case holding two overdue
  advisories is one row, and a clock on an in-house advisory or a regulatory report is
  counted but sits in no case.
* **A row** opens what the clock runs on: PSIRT Cases filtered to the cases holding the
  advisory (or Feed Findings filtered to the advisory when no case holds it yet), the
  advisory's workbench for an in-house advisory, or the report for a regulatory stage. The
  menu at the start of the row offers the same, and **View in Feed Findings** for an
  advisory.

It also shows how many scheduled publishes are armed, and how many **gave up**: a schedule
that exhausted its retries is invisible everywhere else. Each opens Advisories filtered to
those advisories.

Why these two sit together: an SLA that looks perfectly healthy while a feed has silently
stopped polling is the worst combination there is, and it is only visible when both are in
view at once.

## Our advisories

Your own advisories by lifecycle status, plus the ones sitting in review or approved with
**no movement for a fortnight**. The template saves this widget with the title "Our
advisories", and a saved title is shown as saved; the widget added on its own is titled
**In-House Advisories**.

The headline counts the stalled advisories. Under it, one bar shows the advisories by
status (a status with none is left out), and its legend carries the counts; only
**Published** is drawn green. A count opens Advisories filtered to that status.

The stalled list is the useful part. A plain status breakdown buries a two-week-old review
among the drafts. Each row shows the advisory id, its title, its status and the date it
last changed (hover or focus for the time), and opens the advisory's workbench. On a narrow
tile the title moves to a second line rather than scrolling sideways.

Each filtered list (PSIRT Cases, PSIRT Feeds, Advisories) shows the dashboard's filter as a
chip above the table; remove the chip to see the whole list again.

## What is deliberately not here

A chart of advisory volume over time. It looks like insight and answers nothing: a spike
could be a busy week at CISA or a feed that was down and caught up, and the widget cannot
tell you which.

## Adding the widgets individually

All four are in **Add Widget** under Numbers and Lists, prefixed `PSIRT:`. Add them to any
dashboard. **Add Widget** offers them only when the license includes the PSIRT Advisory
Engine and you can read PSIRT (the PSIRT View or PSIRT Change permission, a global
Maintainer or Owner role, or superuser), the same access their data needs. A dashboard
that already holds one shows a placeholder in its place for a viewer without that access
("Not Licensed" or "Insufficient Permissions"), rather than an error. The three
operational widgets take no configuration beyond a title and a refresh interval. They
reject unknown configuration rather than ignoring it, so a knob that did nothing cannot
leave you believing the panel is filtered.

## Notifications

Three PSIRT notifications go through your normal notification preferences (email, Slack,
in-app):

* an SLA clock entering **warning**, and again on **breach**;
* a **signoff requested** of you;
* a **material change** on a published advisory.

Advisory **delivery to customers** is not one of these. It uses an explicit recipient list,
never notification preferences, because a preference fan-out would let somebody opt out of
being told about a vulnerability in a product they own.
