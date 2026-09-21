---
title: "CRA Article 14 Reporting"
description: "Track the 24 hour, 72 hour and final report deadlines the Cyber Resilience Act sets for an actively exploited vulnerability or a severe incident"
audience: pro
weight: 13
---

The Cyber Resilience Act, Article 14, obliges a manufacturer that becomes aware of an actively exploited vulnerability in a product with digital elements to submit an early warning within 24 hours, a vulnerability notification within 72 hours, and a final report within 14 days after a corrective or mitigating measure is available. A severe incident follows the same 24 and 72 hour pattern, with a final report one calendar month after the notification. The clocks start at the moment of awareness, not at confirmation.

DefectDojo tracks those deadlines, builds the submission package for each stage, and keeps an audit trail of every statutory fact. It does not submit anything for you. A person starts a report, records each submission they make on the reporting platform, and remains responsible for the content and the timing. These features record the entity's own determinations and never decide compliance.

This surface is behind the regulatory feature flag. An administrator enables it per instance before it appears.

## Starting a report

There are three ways to start a report, and all of them open the same short form.

On a PSIRT case or an advisory, when a case carries a feed item flagged as exploited and at least one matched component belongs to a product marked in scope for the Cyber Resilience Act, a banner appears: it says an Article 14 early warning is due 24 hours after awareness, and offers a Start button. The moment the banner first appears is written to the case audit trail, because that timestamp is evidence a regulator may ask about. The banner is a suggestion. It never starts a report on its own, and awareness remains a judgment a person makes.

From the same case or advisory, the Start CRA report action opens the form directly, whether or not the banner is showing.

On the reports page, the New severe incident report button starts a report that is not tied to a specific advisory.

The form asks for the regime, an optional title, a sensitivity classification, and the product the report concerns. Awareness defaults to the current time. If the manufacturer became aware earlier, turn on the option to set an earlier awareness time and give a justification. The justification is recorded on the report's audit trail, because a change to a statutory anchor is always audited with a reason. Starting the report arms the stages whose anchor is already known and begins their clocks.

## The three clocks

Each report tracks up to three stages, and each stage shows a live countdown to its statutory deadline.

The early warning is due 24 hours after awareness. It is armed as soon as the report is started.

The notification is due 72 hours after awareness. It is armed as soon as the report is started.

The final report is defined later than the other two. For an actively exploited vulnerability, it is due 14 days after a corrective measure becomes available, so it appears only once you record that a corrective measure is available. For a severe incident, it is due one calendar month after the notification is submitted, so it appears only once the notification is recorded as submitted. Until then the final report reads as not yet defined, which is correct: the deadline does not exist until the event that anchors it has happened.

Editing the awareness time after the fact moves the two awareness stages and re-derives their deadlines. The edit needs a justification and is recorded in the audit trail with the value before, the value after and the reason.

## What each stage contains

Each stage lists the content its submission needs, so nothing is forgotten. An early warning states that the vulnerability is being actively exploited, or that an incident is suspected to be unlawful or malicious, and names the Member States where the product is available. A notification adds product information, the nature of the exploit or incident, any corrective or mitigating measures, and a sensitivity classification. A final report gives a full description of the vulnerability or incident, its severity and impact, information on any malicious actor when known, and the details of the security update or the applied mitigation.

The export buttons on each stage produce the submission package in JSON, Markdown or PDF. The package is assembled from the report's own data and is the document you take to the reporting platform.

## Recording a submission

After you submit a stage on the reporting platform, record it on the stage: enter the reference the platform returned and confirm. The clock for that stage stops, marked as met, unless it had already breached its deadline, in which case it stays marked as breached. If you submitted at a time other than now, set the submission time and give a justification.

Recording a submission also adds a note to each finding the report's advisory produced for the product, and to the engagements those findings belong to, stating the regime, the stage, the submission time and the reference. The notes are a record only. A submission never changes a finding's status.

Submitting a severe incident's notification arms its final report, anchored on that submission.

## The reports page

The reports page lists every report, ordered by the nearest unmet deadline, with the overdue ones first. Each row shows the regime, the product, the next stage due and its state. Open a report to see its clocks, its checklists, its exports and its submission controls.

## Notifications

The statutory clocks reuse the same warning and breach paths as the rest of the SLA framework, so a team that already receives advisory clock alerts receives the statutory ones without configuring anything new.

## Submission is performed by a person

DefectDojo generates the package and records the reference the reporting platform returns. It does not submit to the ENISA Single Reporting Platform on your behalf. Consult ENISA's current guidance for the notification form fields before finalising the content of a package.
