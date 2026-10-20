---
title: "CRA Article 14 Reporting"
description: "Track the 24 hour, 72 hour and final report deadlines the Cyber Resilience Act sets for an actively exploited vulnerability or a severe incident"
audience: pro
weight: 11
aliases:
  - "/psirt/cra-article14-reporting/"
---

The Cyber Resilience Act, Article 14, obliges a manufacturer that becomes aware of an actively exploited vulnerability in a product with digital elements to submit an early warning within 24 hours, a vulnerability notification within 72 hours, and a final report within 14 days after a corrective or mitigating measure is available. A severe incident follows the same 24 and 72 hour pattern, with a final report one calendar month after the notification. The clocks start at the moment of awareness, not at confirmation.

DefectDojo tracks those deadlines, builds the submission package for each stage, and keeps an audit trail of every statutory fact. It does not submit anything for you. A person starts a report, records each submission they make on the reporting platform, and remains responsible for the content and the timing. These features record the entity's own determinations and never decide compliance.

This surface is behind the regulatory feature flag. An administrator enables it per instance before it appears. It does not need PSIRT. The suggestion that a report is due, the deadline alerts and the notes on findings all work on an instance without the PSIRT Advisory Engine. Where PSIRT is enabled, its cases and advisories are one more place to start a report.

An Asset is in scope for the Cyber Resilience Act when its [regulatory profile](../regulatory_profile/) sets a **CRA Product Class** other than **Not Applicable**.

## Starting a report

Every way to start a report opens the same short form.

**From an Asset.** When an in-scope Asset has an open finding marked as known exploited, the **Regulatory** section of the Asset page shows a **CRA Article 14 Early Warning Due** message listing those findings. Each one has a **Start CRA Report** button that fills in the Asset and the finding's vulnerability ID. Once a report names that ID, a link to the report takes the button's place.

**From a finding.** The same finding shows a **CRA Early Warning Due** tag next to its title, or a link to its report once one exists. For anyone who can edit the Asset, the finding's menu has a **Start CRA Report** action that fills in the Asset and the finding's primary vulnerability ID, whether or not the finding is known exploited.

**From the reports page.** The **New CRA Report** button starts a report for any Asset, with the vulnerability ID typed by hand, or none for a severe incident.

**From PSIRT, where it is enabled.** On a PSIRT case or an advisory, when a case carries a feed item flagged as exploited and at least one matched component belongs to an in-scope Asset, a banner offers the same Start button. The case drawer also has a **Start CRA Report** button.

The first time the suggestion appears on a finding or a case, DefectDojo records the moment, because that timestamp is evidence a regulator may ask about. The suggestion never starts a report on its own, and awareness remains a judgment a person makes.

The form asks for the regime, an optional title, a sensitivity classification, the Asset the report concerns and, for an exploited vulnerability, its vulnerability ID in **Advisory Reference**. Awareness defaults to the current time. If the manufacturer became aware earlier, turn on the option to set an earlier awareness time and give a justification. The justification is recorded on the report's audit trail, because a change to a statutory anchor is always audited with a reason. Starting the report arms the stages whose anchor is already known and begins their clocks.

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

Recording a submission also adds a note to each finding the report concerns, and to the engagements those findings belong to, stating the regime, the stage, the submission time and the reference. The findings are the ones on the report's Asset that carry a vulnerability ID named in **Advisory Reference** (separate several IDs with commas or semicolons), plus, where the report was started from a PSIRT advisory, the findings that advisory produced. Duplicates are skipped. The notes are a record only. A submission never changes a finding's status.

Submitting a severe incident's notification arms its final report, anchored on that submission.

## The reports page

The reports page lists every report, ordered by the nearest unmet deadline, with the overdue ones first. Each row shows the regime, the Asset, the next stage due and its state. Open a report to see its clocks, its checklists, its exports and its submission controls.

## Dashboard widget

On Dashboards, the **CRA Article 14 Deadlines** widget counts the pending stages of every report on the Assets you can see, by state: **Breached** (the miss is recorded and stays recorded), **Overdue** (past the deadline, not yet picked up by the scheduled check), **Due Soon** (inside the warning window) and **On Track**. It lists the most urgent stages; select a reference to open that report. The widget takes no configuration, is offered in the widget picker when the regulatory feature flag is on, and does not need PSIRT.

## Notifications

A scheduled check runs every 15 minutes and marks each stage that has entered its warning window or passed its deadline, with or without PSIRT. Each one sends a notification once: **CRA deadline due soon** and **CRA deadline breached**, naming the stage, the report and the Asset. They go to the users who can view the report's Asset, through the channels each has chosen for **Other** events in notification settings, and to superusers; a superuser with no settings of their own receives them through the system defaults.

A breach is recorded and does not clear. A stage submitted after its deadline closes as breached, not as met.

## Submission is performed by a person

DefectDojo generates the package and records the reference the reporting platform returns. It does not submit to the ENISA Single Reporting Platform on your behalf. Consult ENISA's current guidance for the notification form fields before finalising the content of a package.
