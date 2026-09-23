---
title: "Peer Review & Claiming"
description: "Request a review from specific people, claim a review so others know it is being handled, and control who is eligible to be asked"
audience: pro
weight: 4
---

Peer review lets you ask someone to look at a Finding before it is closed out. In the DefectDojo Pro UI a review can also be **claimed**, so that when several people are eligible, everyone can see who has picked it up.

## Requesting a review

Open a Finding and choose **Request Review** from the Finding menu, or select several Findings in a list and use the [bulk editor](../pro__bulk_edit_findings/).

You can request a review from named users and groups, or tick **Allow Eligible Reviewers** to ask everyone who is eligible on that asset.

Requesting a review sets the Finding to **Under Review** and notifies the reviewers. The message you enter is added to the Finding as a regular note, so the reviewers can read what they are being asked to check.

## Claiming a review

When a review has been requested from several people, any one of them can take it:

* On the Finding, use **Claim Review** in the Finding menu, or the button in the review banner.
* The Finding then shows who holds the review, on the Finding itself, as a **Claimed By** column in Finding lists, and in that person's [My Work](/metrics_reports/dashboards/pro__my_work/) queue.

Once a review is claimed:

* Only the person holding it, the person who requested it, or a superuser can **Clear Review**. Other eligible reviewers are told who holds it instead.
* The holder can hand it back with **Release Review**, which returns it to the pool without ending the review.

If two people claim at the same moment, one succeeds and the other is told who won — the review can only ever be held by one person.

Claims look after themselves in a few situations you would otherwise have to clean up by hand:

* Clearing the review marks the claim **completed**.
* Removing the holder from the reviewer list, or closing or reopening the Finding, **releases** the claim.
* A background job releases claims whose holder is no longer a requested reviewer.

Completed and released are recorded separately, so an abandoned review is distinguishable from a finished one.

Claiming is controlled by the **Review Claiming** [feature flag](/admin/feature_flags/pro__feature_flags/), which is on by default.

## Controlling who can be asked to review

"All eligible reviewers" means everyone holding the **Review Findings** permission on that asset — not everyone who can edit the Finding.

This matters when you want broad visibility but a small reviewer pool. Because **Review Findings** is a separate permission, you can:

1. Create a role — a "Security Reviewer", say — that grants **Review Findings**.
2. Grant it to the handful of people who should actually be asked.
3. Remove **Review Findings** from your broader roles, leaving their finding access untouched.

See [Custom RBAC Roles](/admin/user_management/pro__custom_rbac_roles/) for how to build a role.

On upgrade, every role that could already edit Findings is granted **Review Findings** as well, so "all eligible reviewers" means exactly what it meant before until you change it deliberately.

## Assigning a Finding to a person

Review asks someone to *look*. Assignment makes someone *responsible*, and it does not put the Finding under review.

**Assignees** sits beside **Owners** on the Finding edit form. Owners is a group — the team whose queue this belongs in — while Assignees are individual people.

* Assign from the Finding edit form, or to many Findings at once from the bulk editor.
* In the bulk editor, assignees are **added** to whoever is already assigned. Tick **Replace existing assignees** to make your selection the complete list — which removes anyone not selected, including everyone if you select nobody.
* Findings lists carry an **Assignees** column and an assignee filter, and reports can include an **Assignees** column.
* Each person's assignments appear in their [My Work](/metrics_reports/dashboards/pro__my_work/) queue.

You can only assign a Finding to somebody who can already see it. Assignment does not grant access.

The [Rules Engine](/automation/rules_engine/) can set assignees automatically: choose **Set Users** and the **assignees** field.

Assignment is controlled by the **Work Assignment** [feature flag](/admin/feature_flags/pro__feature_flags/).
