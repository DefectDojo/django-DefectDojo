---
title: "Advisories"
description: "Write, review, publish and revise your own security advisories"
draft: false
weight: 9
pro-feature: true
---

Everything else in PSIRT is about what other people published. This page is about what
**you** publish: a security advisory about your own product, written by your team,
reviewed, and sent to the customers it affects.

**PSIRT → Advisories** lists them. Opening one gives you the workbench: the composer,
the review panel, the preflight checklist, and the publishing controls, in the order you
need them.

## The lifecycle

An advisory moves through six states, and the transitions are enforced:

| State | Means |
|---|---|
| Draft | Being written. Nobody outside has seen it. |
| In review | Out with reviewers. |
| Approved | Every reviewer approved. Ready to publish. |
| Published | Sent. Recipients have it. |
| Revised | Published, then materially changed and republished. |
| Superseded | Replaced by a different advisory. |

You cannot skip Approved, and you cannot publish from Draft. That is not procedure for
its own sake: publishing an advisory is irreversible from the recipient's side, and the
review gate is the only thing standing between a draft and a customer's inbox.

## Review, and why editing costs you approvals

Ask for review with **Request review**, naming a reviewer and a role. They approve,
reject with a reason, or recuse themselves.

Here is the part worth understanding before you use it. **An approval is bound to the
exact content that was approved.** Edit the summary, the impact, the remediation, the
recipient list or the remediation milestones after somebody has approved, and their
approval goes stale — the workbench says so, and the advisory drops back to needing
review.

That is deliberate, and it is not a nuisance setting you can turn off. An approval that
survived an edit would mean a reviewer's name is attached to text they never read. The
workbench warns you *before* you save an edit that would do it, so you can decide whether
the change is worth another round.

A **rejection needs a reason**. An advisory rejected without one is a reviewer who has
blocked their colleagues and told them nothing.

**The case list is content too.** The workbench's *Cases covered* section shows which
cases the advisory speaks for — that set decides which findings publishing will file, so
it is part of what a reviewer approves. You can attach and detach cases at any point
before publication, including after approval, because the same binding applies: change
the set and existing approvals go stale exactly as a text edit would. Once published,
the covered set is fixed; changing it means a revision.

## Preflight

**Run preflight** before publishing. Seven checks, and only failures block.

| Check | Fails when |
|---|---|
| Content | A required section is empty. |
| Signoffs | A reviewer has not decided, or an approval has gone stale. |
| Recipients | The advisory resolves to nobody. |
| Comments | An unresolved blocking comment remains. |
| Embargo | The embargo date has not passed. |
| CSAF export | Never. It builds the advisory's CSAF document and validates it, and a problem is reported as a warning. |
| Advisory site | **Publish to the advisory site** is on and one of the [readiness checks](#readiness-checks) fails. |

The last two rows behave differently from the rest. A problem with the CSAF export is a
warning, and a warning never blocks the publish. The advisory site check does block, but
only when the switch is on. With the switch off it has nothing to check and cannot fail.

## Recipients

An advisory reaches:

* every product with a confirmed match on one of its cases (**derived**), plus
* anything you add by hand (**added**), minus
* anything you exclude.

**Exclusions beat both.** If a product is derived *and* excluded, it is excluded — the
narrower, more deliberate instruction wins, because an exclusion is something a person
typed on purpose.

**Preview recipients** before publishing. It names the products, and it names what you
excluded, so a mistake is visible before it is irreversible rather than after.

Retracted matches and matches marked false-positive do not produce recipients.

## Publishing

Publish now, or schedule it.

A **scheduled publish** fires from a background task. When one fails, the failure is
classified, and the three kinds behave differently:

* **Deterministic** — the advisory will never publish as it stands (a preflight failure,
  a missing recipient). It is disarmed, and you are told, because retrying nightly for a
  week would just be a nightly failure.
* **Transient** — a mail server was down. It retries, up to three attempts.
* **Blocked** — PSIRT is switched off, or the licence no longer includes it. This stops
  the whole pass and disarms *nothing*: the advisories are still meant to publish, and
  they will once the block clears.

Delivery states are honest about what did not happen:

* `skipped_not_configured`, shown as Not Configured. No mail server is set up. This is
  not a failure, because nothing was attempted.
* `not_implemented`, shown as Not Built. The channel does not exist yet. It is never
  reported as sent.

Neither counts as a success, and neither counts as a failure. An advisory whose email
was skipped because nothing is configured has not been delivered, and the status says so.

## Publishing to the advisory site

The advisory site is a public website at `advisory.defectdojo.com`, run by DefectDojo.
Each publisher has its own address there, with a page for every advisory, an Atom feed,
and each advisory's CSAF 2.0 document for tools to fetch.

Publishing there is optional and decided per advisory. It needs advisory publishing
turned on for your instance and an active publisher profile. Both are described under
[Advisory Site](../settings/#advisory-site) in PSIRT Settings.

### The switch

The workbench has an **Advisory Site** section with one switch, **Publish to the
advisory site**. It is off on a new advisory, and an advisory with the switch off is
never sent to the site.

The switch is part of what reviewers approve. Turn it on or off after somebody has
approved and their approval goes stale, as it would after any other content change.
Only a TLP:WHITE advisory from an active publisher can go public.

Once the advisory is published, the switch is fixed with the rest of the content.
During a revision of an advisory that is already on the site you cannot turn the switch
off, because the site would go on showing the earlier version.
[Withdraw](#withdraw) the advisory instead.

### Readiness checks

With the switch on, the section shows six checks.

| Check | Fails when | What to do |
|---|---|---|
| Publisher | The publisher profile is not active. | Complete the profile in [PSIRT Settings](../settings/#advisory-site) and wait for DefectDojo to activate it. |
| Document | The public CSAF document cannot be built, or does not validate. | Read the reason the check gives and correct the advisory content. |
| Component name | A component name looks like it carries a URL or credentials. | Correct the component the check names. |
| Publisher match | The publisher in the document is not the active publisher. | Open the Advisory Site card in PSIRT Settings. The document must carry the name and namespace DefectDojo activated. |
| TLP | The advisory is not TLP:WHITE. | Set it to TLP:WHITE if it is meant for the public. Otherwise turn the switch off. |
| Advisory id | The site does not accept the advisory id. | Edit the id. It becomes part of the public address, so it needs letters or digits and cannot be a reserved name. `ACME-SA-2026-0001` is fine. |

The component name check deserves a plain explanation. A component's package name can
hold more than a name: a registry address, a host and port, even a user name and
password. A component whose name looks like it carries any of those is refused.
DefectDojo does not rewrite the name for you. The check names each such component, and
the fix is to correct the component so that its name is only a name.

The same checks run again at the moment you publish. If one fails then, the advisory is
not published.

### What becomes public

The public document is not the advisory as the workbench shows it. It is built from the
advisory's own title, summary, impact and remediation text, your publisher name,
namespace and contact, the names of the affected products (your Assets), the names and
versions of their matched components, public vulnerability identifiers such as CVE and
GHSA ids, and CVSS scores whose source allows redistribution. Where a source reports a
vulnerability as known to be exploited, the document says so without naming the source.
Where you wrote no remediation text, it carries a neutral sentence such as "A fix is
available. Update to a fixed version."

Everything else stays out. That covers case notes, internal identifiers, private
registry addresses, scores that may not be redistributed, and any title, description or
link taken from a third party advisory. A component's package URL keeps its type,
namespace, name and version, and loses anything that could point at a private registry.

The revision history on the public page lists every version of the advisory with its
date, including versions published while the switch was off. Those appear as a version
number only.

Before you publish, the section lists what a reader of the site will see, taken from the
public document itself: the title, each note, each vulnerability's ids and score, each
remediation sentence, and every product and component name that will become public.
**Download** saves the exact document.

### What happens at publish

Publishing with the switch on freezes the public document with that version and sends
it to the site. What the site shows for a version is that frozen document.

The send does not hold up the publish. Recipients get the advisory whether or not the
site answers, and the **Advisory Site** row in the delivery list shows what happened
there. Once the site has the document, the row links to the public page.

The row is held to the same standard as the other delivery states. Its tag reads one of
six things.

| State | Means |
|---|---|
| Not Attempted | Nothing has been sent yet. |
| Sending | A send is under way. |
| Delivered | The site has this version, and the row links to its public page. |
| Failed | The last send did not succeed. The row's message says why, and what happens next. |
| Not Configured | Nothing was sent, because the switch is off or the advisory site is not available to this instance. |
| Withdrawn | You withdrew the advisory. The public page is a withdrawal notice. |

A Failed row covers three different situations, and its message tells them apart.

The first is a temporary failure, such as the site being unreachable or busy. DefectDojo
sends again by itself, and the row shows when the next attempt is due. Waits start at
five minutes, double each time and are capped at six hours, and the site can ask for a
longer wait. It makes up to eight attempts in a row, after which it stops and Re-deliver
starts it again.

The second is a refusal. The row gives the site's reason, and a refusal is not retried,
because the same document would be refused again. Fix the cause first. When the cause is
in the document, that means publishing a revision.

The third is a takedown. The message says that DefectDojo staff took the document down
from the advisory site. Nothing is public, and only DefectDojo Support can restore it.

A temporary failure leaves one thing unknown, which is whether the document reached the
site before the attempt failed. Until that is settled the advisory is treated as
possibly public: it cannot be deleted, and Withdraw is offered.

**Re-deliver** sends the same version again. If the site already has that version,
nothing changes there.

### Revisions on the site

A revision reaches the site the way the first version did. [Revise](#revisions), have
it approved, and publish. The site receives it as the next version and shows it as the
current one. Earlier versions stay readable at their own address.

If an earlier version was still waiting on a retry when the next one is published, only
the newest is sent.

### Withdraw

**Withdraw** takes an advisory off the advisory site. It asks for a reason of up to 500
characters. The public page is replaced by a withdrawal notice at the same address, and
the **Publish to the advisory site** switch is turned off. The reason is recorded with
the withdrawal in DefectDojo. Readers see only that the advisory was withdrawn and when.

Anyone with the **Change PSIRT** permission can withdraw. A withdrawal cannot be undone
from the product. It changes the advisory site only: the advisory stays published in
DefectDojo, and recipients who already have it keep it.

Withdraw is offered whenever the site may hold the document. That includes a send whose
result is not known, and an advisory that DefectDojo staff took down, where withdrawing
turns the switch off.

If the site refuses the withdrawal or cannot be reached, nothing was withdrawn. The
dialog shows the site's answer, the switch stays on, and the row offers **Withdraw
Again**.

An advisory that is live on the site, or may be, cannot be deleted. Withdraw it first.

### Automation

Scripts can read the delivery state and withdraw an advisory through the API, with a
normal API token. This request returns the delivery rows of advisory 42:

```bash
curl -s "https://defectdojo.example.com/api/v2/psirt/advisories-authored/42/delivery_status/" \
  -H "Authorization: Token <your API token>"
```

The Advisory Site row in the answer carries the state and, while the advisory is live,
its public address in `public_url`.

This request withdraws the same advisory. The token's user needs the Change PSIRT
permission, and `reason` is required:

```bash
curl -X POST "https://defectdojo.example.com/api/v2/psirt/advisories-authored/42/withdraw-site/" \
  -H "Authorization: Token <your API token>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Published before the fix was released."}'
```

A `409` answer means the site refused the withdrawal, and a `502` means the site could
not be reached. In both cases nothing was withdrawn.

## Snapshots

Every publish takes a snapshot: the frozen content of that version, exactly as it was
published, and its fingerprint. **Snapshot history** shows them.

A snapshot does not change afterwards. For an advisory published to the advisory site,
it also holds the exact public document that was sent, so the site and the snapshot
always agree on what a version said.

## Revisions

**Revise** starts a new version of a published advisory, carrying the content forward.
The published version stays published. The revision goes back through review, because
the facts changed and the previous approvals were for the previous facts.

A revision is also how a mistake in a published advisory is corrected. Published
content is fixed and cannot be edited in place, so revise, correct the text, have it
approved, and publish the new version.

An advisory and all its revisions share one lineage id, so a reader can follow one story
across supersessions.

## Material change

When the underlying advisory data moves after you publish — a CVSS revision, a new KEV
listing — the advisory is flagged as possibly out of date and you get a notification.

This is separate from the approval question, and it does not invalidate anybody's
approval. It means what the customer was told may no longer be the whole story, which is
a judgement for a human, not a gate.

The workbench shows the flag as a banner naming what moved — the feed's own facts, the
enrichment data, or both. Two honest ways to clear it: **revise** the advisory if the
published text no longer stands, or **acknowledge** if you have read the change and the
text still holds. Acknowledging is a recorded statement that somebody looked — it does
not republish, edit, or touch anybody's approval. If the facts move again later, the
banner comes back.

A material change on published content also arms the **Revision SLA clock**, tiered by
the kind of change (an active-exploitation flip is hours; a severity downgrade is
weeks — see [SLA policies](../sla-policies/)). Either exit stops it: publishing a
revision, or acknowledging. A clock that kept running after a recorded "no revision
needed" would report disagreement as lateness.

Which upstream changes raise the flag at all is yours to tune, in
[Settings](../settings/).

## Locks

Opening the workbench takes an edit lock for 30 minutes so two people do not overwrite
each other. It expires on its own, and you can release it by hand.
