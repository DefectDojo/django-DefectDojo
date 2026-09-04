---
title: "Posture Score"
description: "DefectDojo Pro's published, versioned security posture score: the scale, every weight, every formula, and the counterfactual semantics"
draft: false
audience: pro
weight: 12
slug: posture-score
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: the Posture Score ships with the DefectDojo Pro <b>Command Center</b> (beta). See <a href="../command-center/">Command Center</a> for enabling it.</span>

Most security scores are opaque: a number with no published scale, no published weights, and no way to check it. DefectDojo's posture score makes the opposite commitment. The formula below is the formula; the same descriptor is served machine-readable at `GET /api/v2/dashboards/widget_data/posture_formula/`; every input is stored in the daily snapshot ledger, so any historical score can be recomputed and audited; and formula changes are versioned events drawn on the trend line, never silent rewrites of history.

## The scale

0 to 1000, higher is better. Bands: **strong** at 800 and above, **needs attention** at 600 to 799, **at risk** below 600. A score is computed over the viewer's authorized assets, so two users with different access correctly see different scores; instance-wide scores require a global view permission.

## The formula (version 1)

The score is the weighted sum of five components. Each component is normalized to a 0 to 1 value by a monotone function of raw inputs, then multiplied by its weight. Weights sum to exactly 1000.

| Component | Weight | Normalized value |
|---|---|---|
| Open severity burden | 300 | `1 / (1 + density / 25)` where `density` is severity-weighted open findings (Critical 10, High 5, Medium 2, Low 1, Info 0) divided by assessed assets |
| SLA posture | 200 | `1 - (breached / SLA-tracked open)`; neutral 1.0 when nothing is SLA-tracked, flagged as such |
| Coverage confidence | 200 | assets scanned in the last 90 days / all assets |
| Exploit pressure | 150 | `0.5 ^ (open KEV findings / 4)`, multiplied by `1 - 0.5 x EPSS p90` of the open backlog |
| Automation health | 150 | rule actions / (rule actions + manual closures) over the window; neutral 0.5 when there was no triage activity, flagged as such |

Design commitments, stated so they can be challenged:

* **Ratios, not raw counts**, wherever growth would otherwise punish scope: burden is a per-assessed-asset density, SLA and coverage are shares. Growing your inventory without scanning it lowers the score through coverage, which is the honest direction.
* **KEV is deliberately absolute.** A known-exploited vulnerability open anywhere is an emergency regardless of estate size, so it is an exponential penalty, not a ratio. It saturates, so it cannot zero the score alone.
* **Priority bands are excluded** from the score because their thresholds are per-instance configuration; a published formula must not change meaning when an admin edits a threshold.
* **Neutral rules are visible.** Where a component has nothing to measure (no SLA tracking, no triage activity, no EPSS data), the why panel says so instead of hiding a default.

## The why panel and the counterfactual

The score widget's why panel decomposes the number into the five components (weight, value, contribution, and a plain sentence each), shows the raw stored inputs (the receipt), and ranks the **levers**: exact counterfactuals computed by substituting one input and re-running the same formula. "Fix the 12 known-exploited findings: at least +84 points." Deltas are lower bounds where levers overlap in reality, which is why every lever says "at least".

## Versioning

Formula versions are immutable once shipped. Changing a weight or a normalization means publishing a new version; the daily snapshot records both the score as published that day and the full input vector, so trends can be rendered two ways: recomputed under the current formula (the default, so a formula release never masquerades as a posture change) or as published at the time, with version-change markers on the chart. The version history is part of the formula endpoint's response.
