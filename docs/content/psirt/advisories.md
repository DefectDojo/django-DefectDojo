---
title: "Advisories"
description: "Write, review, publish and revise your own security advisories"
draft: false
weight: 8
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

## Preflight

**Run preflight** before publishing. Six checks, and only failures block:

| Check | Fails when |
|---|---|
| Content | A required section is empty. |
| Signoffs | A reviewer has not decided, or an approval has gone stale. |
| Recipients | The advisory resolves to nobody. |
| Comments | An unresolved blocking comment remains. |
| Embargo | The embargo date has not passed. |
| CSAF export | Not implemented — reported as pending, never as a pass. |

The last row matters more than it looks. A check that has not been built reports
**pending**, not success. A green checklist that included un-built checks would tell you
the advisory had been verified in ways it had not.

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

* `skipped_not_configured` — no mail server is set up. Not a failure; nothing was
  attempted.
* `not_implemented` — a channel that does not exist yet. Never reported as sent.

Neither counts as a success, and neither counts as a failure. An advisory whose email
was skipped because nothing is configured has not been delivered, and the status says so.

## Snapshots

Every publish takes a snapshot: the content exactly as sent, its fingerprint, and the
branding in force at the time. **Snapshot history** shows them.

Branding is captured rather than looked up, so a snapshot of a 2024 advisory still
renders with your 2024 logo. Re-rendering it with today's branding would misrepresent
what the customer actually received.

## Revisions and errata

**Revise** starts a new version of a published advisory, carrying the content forward.
The published version stays published; the revision goes back through review, because
the facts changed and the previous approvals were for the previous facts.

**Flag errata** marks a published advisory as containing an error, without waiting for a
revision to be written.

An advisory and all its revisions share one lineage id, so a reader can follow one story
across supersessions.

## Material change

When the underlying advisory data moves after you publish — a CVSS revision, a new KEV
listing — the advisory is flagged as possibly out of date and you get a notification.

This is separate from the approval question, and it does not invalidate anybody's
approval. It means what the customer was told may no longer be the whole story, which is
a judgement for a human, not a gate.

## Locks

Opening the workbench takes an edit lock for 30 minutes so two people do not overwrite
each other. It expires on its own, and you can release it by hand.
