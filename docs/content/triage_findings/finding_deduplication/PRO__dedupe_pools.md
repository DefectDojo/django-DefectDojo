---
title: "Dedupe Pools"
description: "Group Assets so their Findings deduplicate against each other, per matching kind"
weight: 8
audience: pro
---

By default a Finding only deduplicates against other Findings in **its own Asset**, and an Engagement can narrow that further. A **Dedupe Pool** is the other direction: a named group of Assets whose Findings deduplicate against each other.

Pools are for the case where the same thing is genuinely deployed in several places you model as separate Assets. Three services that all ship the same base image, or a monorepo split into an Asset per component, will each report the same vulnerability separately, and no per-Asset setting can make those Findings meet.

A pool may span Organizations. You only ever see the members you have access to, and a member you cannot read is shown as a placeholder rather than hidden, so a pool never looks smaller than it is.

Find pools at **Settings \> Finding Workflow \> Dedupe Pools** (**Settings \> Pro Settings \> Deduplication Settings \> Dedupe Pools** on instances still using the previous menu layout). Matching Configuration sits beside it in the same group.

## Pools vs. the global algorithms

Pools and the global algorithms solve the same problem at different scales, and they are not alternatives so much as different blast radii.

| | Scope | Matches on | Choose it when |
| --- | --- | --- | --- |
| **Dedupe Pool** | The Assets you put in it | Whatever the tool's normal algorithm already uses | Some Assets should share matching and the rest should not |
| **Global Component** | Every Asset in the instance | Component name and version | Every SCA Finding for a dependency is the same Finding wherever it appears |
| **Global Vulnerability ID** | Every Asset in the instance | A shared vulnerability identifier (CVE, GHSA, and so on) | Every Finding for a given vulnerability is the same Finding wherever it appears |
| **Global Locations** | Every Asset in the instance | Package URL, or URL for DAST Findings | As above, keyed on the full location under the Locations data model |

> **Pooling an Asset narrows a global algorithm rather than leaving it alone.** The two are not
> independent settings at different blast radii. While an Asset is unpooled, Global Component,
> Global Vulnerability ID and Global Locations reach the whole instance as described above. Once that Asset joins a pool for
> the matching kind in question, those algorithms are **bounded to the pool**: its Findings match
> only against the pool's other members, not instance-wide. So creating a pool that happens to
> contain an Asset running Global Component silently narrows matching that was previously
> instance-wide. If you want a tool to keep matching across every Asset, leave its Assets out of
> a pool for that kind.

A pool does not change **how** two Findings are compared. It changes **which** Findings are eligible to be compared at all. How they are compared is set per tool on [Matching Configuration](/triage_findings/finding_deduplication/pro__deduplication_tuning/). Per-pool overrides of that configuration are not yet available; today every member uses the instance default.

## Membership is per matching kind

An Asset joins a pool for one **matching kind** at a time, and can be in at most one pool per kind. The same Asset can therefore share same-tool matching with one group and cross-tool matching with another.

* **Same tool.** Findings from the same scanner deduplicate across the pool's Assets.
* **Cross tool.** Findings from different scanners deduplicate across the pool's Assets.
Membership is offered for these two kinds only. There is no reimport kind to pool for, and that
is deliberate rather than an omission: a reimport matches inside its own Test, so pooling could
never widen what it compares, and the one thing a reimport membership could do (select a
per-pool reimport formula) depends on per-pool overrides, which are not yet available. Offering
the kind would accept a membership that changes nothing.

Pooling still affects reimports, in the way that matters: the Findings a reimport **creates**
are deduplicated like any other new Finding, under same tool and cross tool, and if the Asset is
pooled for those kinds that deduplication reaches across the pool.

If you try to add an Asset that already matches within another pool for that kind, DefectDojo refuses the change and names the pool holding it. Take it out of that pool first if the move is deliberate.

## Creating a pool changes nothing

A new pool has no members, so nothing about deduplication changes until you add some. This is deliberate: creating a pool to look at it is safe.

1. Open **Settings \> Finding Workflow \> Dedupe Pools**.
2. Enter a name under **New pool** and click **Create Pool**.
3. Select the pool, then pick the **Matching kind** you want to configure.

## Adding Assets, and previewing first

Under **Add Assets**, choose the Assets and click **Preview Impact** before **Add to Pool**.

The preview reports how many of the Findings **you can see** would become comparable with the rest of the pool, split by hash and by vendor ID. It is an **upper bound**, not a prediction. It answers an exact question (which Findings share an identity with the rest of the pool) rather than re-running the deduplication engine, because a preview that re-simulated every algorithm, set-matching rule and location predicate would produce confident numbers that were quietly wrong. The real run can only mark fewer.

Adding members applies to **future imports**. Findings already in DefectDojo are untouched until you ask for them to be reprocessed.

## Applying a pool to Findings that already exist

**Apply to existing findings** re-runs deduplication over the Findings already in the pool's Assets. This can mark a large number of Findings as duplicates at once, so it is gated:

1. Click **Preview Re-run**. This reports how many Findings you can see share an identity with a Finding in another Asset in the pool.
2. **Apply Now** stays disabled until that preview has run, and uses the acknowledgement the preview returned.

Apply Now is scoped to one pool and one matching kind: it re-runs deduplication over the pool's members for the kind selected on the page, over the Findings that are not already duplicates. Existing duplicate links are left as they are, so it is not a general re-run of deduplication.

The acknowledgement is derived from the specific change it describes, so the preview you ran for adding Assets does not authorize a re-run, and a re-run preview goes stale if the pool changes underneath it. Preview the thing you are about to do.

Apply Now runs while you wait, so it is capped at 10,000 Findings across the pool. Above that
it refuses and tells you the count rather than running past the request. Narrow the pool, or
contact DefectDojo Support to have the re-run queued in the background.

If deduplication is turned off for the instance, Apply Now reports that nothing was matched and
points you at System Settings rather than reporting a silent zero.

## Where originals collect

**Where originals collect** decides which Finding a pool's duplicates point at.

* **Oldest finding wins.** The default, and what deduplication has always done.
* **Designated asset, then oldest.** Duplicates point at the chosen Asset where it has a matching Finding old enough to be the original (the engine's age check still applies), and at the oldest Finding otherwise. The designated Asset has to be a member of the pool for same-tool or cross-tool matching: add it first, then designate it.

Use the second when one Asset is the place your team actually works, and you want the originals to land there rather than wherever the earliest scan happened to run.

There is deliberately no newest-wins option. It would let an established original change hands, which breaks the guarantee that a Finding your team has already mitigated is not reopened as a duplicate of something newer.

Changing the placement affects **new** matches. Existing duplicates keep their current original until they are re-pointed.

## Removing an Asset from a pool

Removing a member also applies to future imports. Findings already linked **keep their links**, including links to an original in an Asset the removed Asset no longer shares a pool with.

That is the safe default, but it leaves duplicates pointing outside their own Asset. When you want those cleaned up, **Reset External Links** clears exactly those links. Like Apply Now it is preview-gated: **Preview Cleanup** counts the links first and hands back the acknowledgement the reset requires. It never deletes anything: a Finding whose link is cleared goes back to being an ordinary active Finding.

## Pooling from the Asset page

The **Dedupe Pool** panel on an Asset page shows which pool that Asset matches within, per kind, and lets you change it in place. Add it from the page layout editor if it is not already on your Asset pages.

The panel also offers **Pool this asset and everything under it**, which pools the Asset and its descendants for that kind in one action. Two things about it are worth knowing:

* It follows **parent relationships only**. A reference between two Assets is not containment, so an Asset that merely uses another is not pulled in.
* It **skips rather than steals**. A descendant already pooled elsewhere for that kind is reported back as left alone, not moved.
* It pools only what you can read. A descendant you do not have access to is neither pooled nor named; the panel reports how many were left alone for that reason.

A membership created this way is marked **from parent**. **Untoggle subtree** removes only the memberships the toggle created; a membership someone added by hand survives it.

## Pooling automatically with a Rule

The Rules Engine action **Assign to a Dedupe Pool** puts an Asset into a pool, or takes it out of one. Run it on Asset creation and new Assets get pooled the way their siblings are, without anyone remembering to do it.

Like the subtree toggle, it leaves an Asset already pooled elsewhere for that kind unchanged rather than moving it. An Asset's pool is a deliberate decision, and a rule that silently relocated it would change which Findings deduplicate against each other with nothing in the run saying so.

## Permissions

Pools are governed by the **Dedupe Pool** row of the roles editor, four global permissions that take effect only through a global role:

| Dedupe Pool column | Allows |
| --- | --- |
| **View** | See pools, their members, and Matching Configuration |
| **Add** | Create a pool |
| **Edit** | Change membership, placement, matching formulas, and run Apply Now |
| **Delete** | Delete a pool |

Membership lists and every preview are filtered to the Assets you can read, so the numbers a preview reports are the numbers for **your** visibility, not the instance's.

### Custom roles on upgrade

Matching Configuration used to be read through the tuner's **View Tuner** permission and edited through **Edit Tuner**. Neither gates the new pages: reading pools and Matching Configuration needs **Dedupe Pool: View**, and editing a matching formula needs **Dedupe Pool: Edit**. Both are global permissions, so a role scoped to an Asset or Organization grants nothing here.

The upgrade carries existing grants over. A custom role holding **Edit Tuner** receives all four Dedupe Pool permissions; a role holding only **View Tuner** receives **Dedupe Pool: View**, so a view-only tuner role keeps its read access without gaining any write. Built-in roles are re-seeded from the shipped definitions. A custom role that held neither tuner permission receives nothing, and so does a custom role created **after** the upgrade: both need the Dedupe Pool permissions granted explicitly by an administrator.
