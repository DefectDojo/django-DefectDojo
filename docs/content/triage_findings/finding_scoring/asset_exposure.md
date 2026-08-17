---
title: "Asset Exposure"
description: "How DefectDojo Pro records whether an asset is reachable from outside, whether a Finding is deployed in production, and how both adjust priority"
audience: pro
weight: 4
---

A Critical vulnerability on a service anyone on the internet can reach is not the same
risk as the same vulnerability on an isolated internal system, or on a branch nobody has
deployed. **Asset Exposure** captures both differences: DefectDojo Pro records how
reachable each asset is from outside, whether each Finding's code is actually running in
production, shows you where those conclusions came from, and feeds both into the Finding's
computed **priority**.

Where [Reachability](../reachability/) asks whether the vulnerable code can be reached
*inside* your application, Asset Exposure asks whether the asset can be reached *from
outside*, and whether the code is deployed at all. They are independent and can be used
together.

Asset Exposure is a **beta** feature and is **off by default**. A superuser enables it
under **Settings > Feature Flags**. While it is off, no verdicts are recorded, priority is
unaffected, and no exposure UI appears.

## Exposure verdicts

Every verdict is normalized to the same five values, whatever produced it:

| Verdict | Meaning |
|---|---|
| **Externally exposed** | An unrestricted path from the internet was observed or reported. |
| **Partially exposed** | An internet path exists but is constrained, for example to specific address ranges, ports, or an authenticated audience. |
| **Internally reachable** | No internet path, but the asset is reachable beyond its own network boundary, such as over a VPN or from another network or account. |
| **Isolated** | A source states there is no reachability beyond the local network. |
| **Unknown** | No source has reported on this asset yet. |

Normalizing matters because tools disagree about wording: one vendor says "wide internet
exposure", another says "public", a third reports an observed open service. All three land
on the same verdict here, so a filter or a priority rule means one thing across your whole
estate.

### How conflicting sources are resolved

An asset can carry a verdict from several sources at once. The strongest verdict wins,
and the most recent wins among equals. An *observation* that something is exposed
therefore outranks an *assertion* that it is not, which is the safe direction: if any
source can see the service from outside, it is exposed regardless of what the
configuration says.

### Sources never assert isolation

Automated sources may only report the three positive verdicts (externally exposed,
partially exposed, internally reachable). They are not permitted to assert **Isolated**.

This is deliberate. Several vendors report exposure as a plain true/false field, where an
absent value and a false value look identical on the wire. Treating "the field was
missing" as "this asset is isolated" would quietly reduce the priority of a live,
internet-facing system. A wrong "exposed" verdict is an inconvenience; a wrong "isolated"
verdict is how something reachable gets buried.

A **person** may still set Isolated, using the override described below. A human stating
that an asset is isolated is evidence in a way that an unset field is not.

## Where verdicts come from

Each asset's **Exposure** panel lists every source that has reported on it, with the
verdict, the source's confidence, when it was last seen, and the specific observations
behind it, such as the exposed service, address, or port range. The verdict that won the
rollup is marked.

A verdict that stops being re-reported expires after 30 days and the asset moves back
toward Unknown. This is also how exposure *closure* works for sources that report exposure
but never report it ending: rather than leaving an asset flagged forever on the strength of
one old observation, the claim ages out.

## Overriding exposure

Each asset has an **exposure override**, set on the asset's Exposure panel by anyone with
edit permission on that asset. When set it outranks every automated verdict, everywhere:
the badge, priority, filtering, and SLA tiers.

The override is the single manual control for exposure in DefectDojo Pro. If you
previously ticked the asset's **Internet Accessible** checkbox, that setting is carried
over into the override automatically when you upgrade, and the two are kept consistent
afterwards, so nothing you curated is lost.

Assets where the checkbox was simply never ticked are left with no override. An unticked
checkbox means "nobody has said", not "this asset is isolated", so it is not converted
into a statement.

## Exposure inherited from where an asset runs

An asset can be reachable without anything having scanned it, simply because of what it is
deployed onto. A service nobody has scanned, running on a cluster that answers from the
internet, is reachable.

To record that, link the two assets with a **deploys to** relationship, pointing from the
deployed asset to the thing it runs on. The Exposure panel then shows a second badge, the
**effective exposure**, naming the asset the exposure came from. The strongest verdict
anywhere along the deployment chain wins, so a service deployed onto a cluster in an exposed
account inherits from the account too.

The asset's own verdict is still shown beside it, and the two are deliberately not merged.
"Nothing has scanned this asset" and "this asset is reachable because of where it runs" are
different statements, and collapsing them would read as though a scanner had found the asset
exposed.

Two limits worth knowing:

- **Inherited exposure does not change priority.** Scoring uses the asset's own exposure. The
  inherited verdict is shown so you can see the reachability of what you are looking at; it
  does not silently move scores when somebody edits a relationship elsewhere.
- **You only inherit from assets you can see.** If the asset it is deployed onto is outside
  your permissions, it contributes nothing, so the effective exposure you see may be lower
  than the one somebody with wider access sees.

Only **deploys to** carries exposure. Other relationships do not: an organization that
contains an exposed asset is not itself reachable, so containment deliberately does not
propagate.

## Deployment context

Alongside exposure, each Finding records whether its code is **In production**, **Not in
production**, or **Unknown**.

This is resolved from two settings, in order:

1. **The environment of the Finding's test.** Environments are mapped to production or
   non-production under **Settings**. Production maps to production; Staging, Test,
   Pre-prod and Lab map to non-production.
2. **The asset's production branch.** Set a production branch on the asset's Exposure
   panel and Findings from that branch count as running in production, while Findings from
   other branches do not.

An environment always wins over a branch, because an environment is stated explicitly per
scan while matching a branch name is an inference.

Two cases deliberately resolve to **Unknown** rather than to "not in production":

- **The Development and Default environments are unmapped by default.** A scan imported
  without naming an environment is filed under Development automatically, so on many
  instances most Findings are there without anyone having said anything about them.
  Treating that as "not deployed" would reduce the priority of an entire estate on the
  strength of a default. If you genuinely separate development scans, map those
  environments yourself under **Settings**.
- **A test with no branch recorded**, on an asset that does have a production branch set.
  Plenty of tools never report a branch, and older imports predate branch tracking. Absence
  of a branch is not evidence that something is undeployed.

Unknown always scores neutrally. Missing information never counts against a Finding.

## How exposure and deployment change priority

Both feed the same computed **priority** the rest of the scoring engine produces, and both
are proportional to the Finding's severity, so they re-rank within a severity rather than
flattening severity out.

| Signal | Effect on priority |
|---|---|
| Externally exposed | Raises it the most |
| Partially exposed | Raises it moderately |
| Internally reachable | Raises it slightly |
| Isolated | Lowers it, scaled by the source's confidence |
| In production | Raises it slightly |
| Not in production | Lowers it |
| Unknown (either signal) | No change |

Every weight is tunable per prioritization engine, so you can make exposure count for more
or less than the defaults, or switch it off entirely by setting its scalar to zero.

### Risk floors and ceilings

Proportional weights alone cannot express a rule like "anything internet-facing must never
sort below Urgent", because a proportional bump on a Medium Finding still leaves it a
Medium. Two optional categorical rules cover that:

- An **exposed risk floor** guarantees a minimum risk band for Findings on assets that are
  externally or partially exposed.
- An **isolated risk ceiling** caps the risk band for Findings on assets reported as
  isolated, and only when the verdict meets a minimum confidence you set.

Both are empty by default. Neither closes, hides, or resolves a Finding; the ceiling only
affects where a Finding sorts. A Finding whose vulnerability is known to be exploited in
the wild is always raised back up, even on an asset reported as isolated.

## Using exposure for remediation deadlines

If your SLA configuration uses **Vulnerability Disclosure Report (VDR)** tiers, those tiers
combine exposure with exploitability to set shorter deadlines for Findings that are both
internet-reachable and credibly exploitable.

Historically that required tagging Findings by hand. You can now let the computed exposure
verdict supply the reachability half, by enabling **Use Asset Exposure for VDR Tiering** on
the SLA configuration.

That setting is **off by default and separate from the feature flag**, because it changes
remediation deadlines. Turning on Asset Exposure never shortens an SLA on its own; a
compliance owner has to opt in. When enabled, the tag and the computed verdict are combined
rather than replacing one another, so an existing tag keeps working and enabling the
setting can only tighten a deadline, never loosen one. Both **Externally exposed** and
**Partially exposed** count as internet-reachable for tiering.

## Filtering and reporting

Findings carry **Exposure** and **Deployment** columns, both available on the Findings list
and hidden by default. Add them from the column picker, filter on them, and sort by them
like any other column. Filtering for **Unknown** is supported and is a useful way to find
the assets no source covers yet.
