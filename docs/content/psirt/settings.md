---
title: "PSIRT Settings"
description: "Case-worthiness calibration, the \"new\" item window, and what counts as a material change"
draft: false
weight: 11
pro-feature: true
---

Three settings that shape how PSIRT scores and re-surfaces work. Each section
saves on its own, and each says who changed it last.

## Case worthiness

Case worthiness is the score the triage queue sorts by — how much an advisory
looks like it deserves attention, from four signals fused together.

**The weights** are points and must sum to exactly 100:

| Weight | What it rewards |
|---|---|
| Specificity | How precisely the match was made — a version-verified structural match over a keyword correlation |
| Pre-filter | Signals your pre-filters asserted, such as known exploitation |
| Severity | CVSS, or an analyst-asserted severity floor |
| Urgency | Exploitation and EPSS |

**The thresholds** are the floors of the risk bands, and must ascend:
low-medium < medium < high < critical.

The page tracks both rules as you type — a running weight total, and a warning
when the thresholds stop ascending — and the save is disabled until they hold. A
half-edited calibration summing to 90 would silently rescale every score.

**A change applies to scores computed from then on.** Already-computed scores keep
their values until the advisory is re-evaluated, so re-calibrating does not
rewrite history. The change reaches the worker you saved it on immediately, and
every other worker within a minute.

If you have never changed anything, the page shows the shipped calibration, which
is what is in force.

## "New" item window

How far back "new" reaches. One of 7, 14, 30 or 90 days.

This window is what the dashboard's **"Am I affected?"** widget counts by default —
the widget and this page always agree on what "new" means, because the widget reads
this setting rather than carrying its own number. A dashboard can still override the
window per-widget in the widget's own settings, and that override wins for that
widget alone.

## Material-change policy

Advisories change after publication. This section decides which of those changes
are *material* — worth stamping a revision and re-opening attention on something
you may already have triaged.

| Setting | Default | What it catches |
|---|---|---|
| Severity tier transitions | on | moves within medium/high/critical, and any escalation into that set from below |
| CVE set changes | on | a CVE joining or leaving an advisory |
| Added to the CISA KEV list | on | a vulnerability now known to be exploited |
| Removed from the CISA KEV list | **off** | de-listing rarely changes what you must do |
| EPSS crossing the high boundary | on | exploitation probability crossing your line |
| Affected-product set changes | on | the publisher adding or removing affected products |
| CVSS v3 delta threshold | 0.5 | how far a score must move to count |
| EPSS high boundary | 0.8 | where "high" starts |
| Severity floor | none | changes below this band are never material |

The defaults are deliberately asymmetric. Being added to KEV is news; being
removed from it usually is not, and treating it as material would re-open triaged
work for a reason nobody needs to act on.

Severity is judged on the tier the feed supplies, so it works even for publishers
that never provide a CVSS score — which is also why an escalation *into*
medium/high/critical counts: a feed that only speaks in tiers must not be able to
raise something to critical without anybody being told. Downgrades out of the set
are not material; nothing needs re-triage because it got less serious.

Turning things **off** here is how a noisy revision stream gets quieter — but
every switch you turn off is a class of upstream change you will no longer be told
about, on advisories you have already decided about.
