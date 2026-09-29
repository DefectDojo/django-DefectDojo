---
title: Scan cadence policies
audience: pro
description: "Measure scan frequency, investigate overdue assets, and export cadence evidence"
weight: 7
---

Scan cadence policies measure how often products receive qualifying Tests. Enable Scan Cadence Assurance in feature flags to expose the page and dashboard widget. A global Maintainer or Owner can create and change policies. Product readers see only the statuses and attestation rows for products they can view.

A policy can cover all products, one product type, a regulation, a business criticality, or one product. Exactly one scope selector is populated. The critical-functions option narrows that scope to products whose regulatory profile says they support a critical or important function. If the critical-function flag is not available, High and Very High business criticality provide the fallback.

To track a weekly scanning policy for DORA critical or important functions, select regulation DORA, enable critical functions only, set an interval of 7 days with no grace, and leave the test types empty. This setting records a scan cadence; it does not establish overall regulatory compliance.

## How status is calculated

The evaluator runs hourly. It reads Tests owned by the product through their Engagement, using target start and falling back to creation time when target start is absent. Future timestamps do not count. When test types are selected, any one of the selected types qualifies. An empty selection accepts any type. Reimports that update an existing Test are represented by that Test's recorded timestamp, not by a separate historical event.

A product is compliant through the end of the interval, due after the interval and through the end of the grace period, and overdue beyond that. No qualifying Test produces never scanned. Never scanned is a separate status and does not send an overdue-transition alert.

When an enabled policy changes a product's status to overdue, one product-scoped alert records the policy, last scan date, interval, and grace period. Repeated evaluations do not repeat that alert. A new qualifying Test clears the overdue timestamp. A later overdue transition can send another alert. The overdue timestamp records when the evaluator first observed the transition, while the widget's days overdue measures elapsed time since the scan deadline.

Operators can recompute immediately with `python manage.py evaluate_scan_cadence`. Disabled policies and products leaving a policy's scope have their computed status rows removed at the next evaluation.

## Export an attestation

Select a policy and start and end dates, then download XLSX or CSV. Dates are inclusive UTC calendar dates. For today, the export ends at generation time. Future dates are rejected.

Each product row records policy, interval, product name, criticality, critical-function flag, qualifying Test count, first and last qualifying Test timestamps, longest gap, whether that gap exceeds the interval, and current status. The longest gap includes both window boundaries and is clipped to the reporting window. No scans during a 90-day window produces a 90-day gap. The comparison uses the required interval without grace. Current status is calculated at generation time, independently of the historical reporting window.

The headers identify the requesting user, generation time, exact window boundaries, complete policy definition, and method. The export includes all currently in-scope products visible to that user, including those without scans. It uses the current policy and current Test records; it cannot reconstruct deleted Tests or past policy revisions. It is a dated export and is not digitally signed.
