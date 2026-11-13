---
title: "PSIRT Settings"
description: "Case-worthiness calibration, the \"new\" item window, what counts as a material change, and the Advisory Site publisher profile"
draft: false
weight: 12
pro-feature: true
---

Three settings that shape how PSIRT scores and re-surfaces work. Each section
saves on its own, and each says who changed it last.

A fourth card, **Advisory Site**, appears when publishing to the advisory site is
turned on for your instance. It holds the publisher profile that readers of your
public advisories see.

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

This window is what the dashboard's **PSIRT: Exposure** widget counts by default:
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

## Advisory Site

The **Advisory Site** card holds your publisher profile: the name, web address and
contact that readers see on every advisory you publish to the
[advisory site](../advisories/#publishing-to-the-advisory-site). Fill it in once,
before the first advisory can go public.

Publishing to the advisory site needs two things beyond PSIRT itself. The
`psirt_advisory_site` feature flag must be on, and DefectDojo turns it on for your
instance, so it is not a switch on the Feature Flags page. Your license must also
include advisory publishing. With the flag on and no such license, the card says
so and nothing can be saved. Contact
[DefectDojo Support](mailto:support@defectdojo.com) for either one.

The profile asks for five things:

| Field | What it is |
|---|---|
| Display name | The publisher name shown on the advisory site and written into every public document. |
| Namespace | An `https` web address that identifies your organization as a publisher, for example `https://www.example.com`. |
| Contact | How a reader reaches your security team, for example `psirt@example.com`. |
| Requested slug | Optional. The short name you would like in your address on the advisory site, for example `acme-corp`. |
| List on CSAF Aggregators | Whether CSAF aggregators, the public directories that collect advisories from many publishers, may list yours. |

Saving needs the **Change PSIRT** permission, and it sends the profile to
DefectDojo. DefectDojo staff review every new publisher and activate it by hand.
Nothing goes public until they have.

The card shows where the publisher stands:

| Status | What it means for publishing |
|---|---|
| Not sent | DefectDojo has no profile from this instance yet. Nothing can be published to the site. |
| Pending | The profile was sent and is waiting for review. Nothing can be published to the site yet. |
| Active | DefectDojo activated the publisher. The card shows your public address on the advisory site, and approved TLP:WHITE advisories can be published there. |
| Suspended | DefectDojo suspended the publisher. The site refuses new advisories and new versions until DefectDojo lifts the suspension. |

If DefectDojo refuses a profile, the card shows the reason. Correct the field it
names and save again.

Once the publisher is active, the display name, the namespace and the slug are
fixed. The card shows them as DefectDojo activated them, and every public document
carries those values. A later save that changes one of them leaves it as it was,
and the card names the fields that were ignored. Only DefectDojo Support can
change them. The contact and the aggregator choice stay yours to edit.

An [airgapped instance](/get_started/pro/onprem/airgapped/) cannot use the
advisory site. The card says that publishing is unavailable, saving is refused,
and nothing is sent to DefectDojo.
