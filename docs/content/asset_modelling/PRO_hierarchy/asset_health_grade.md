---
title: "Asset Health Grade"
description: "How DefectDojo calculates an Asset Health Grade"
aliases:
  - /en/working_with_findings/organizing_engagements_tests/product_health_grade
  - /asset_modelling/pro_hierarchy/product_health_grade/
  - /en/asset_modelling/pro_hierarchy/product_health_grade/
---
DefectDojo can calculate a grade for your Assets based on the amount of Findings contained within. Grades are ranked from A \- F.

Note that only Active \& Verified Findings contribute to an Asset Grade \- unverified Findings will not have an impact.

## Asset Grade Calculation

Every Asset Grade starts at 100 (with no Findings).

Grade calculation starts by looking at the highest **Severity** level of a Finding in an Asset, and reducing the Asset Health to a base level.

| **Highest Severity Level of a Finding** | **Maximum Grade** |
| --- | --- |
| **Critical** | **40** |
| **High** | **60** |
| **Medium** | **80** |
| **Low** | **95** |

Further points are then deducted from the Grade for each additional Finding:

| **Severity Level of an additional Finding** | **Grade Reduced by** |
| --- | --- |
| **Critical** | **5** |
| **High** | **3** |
| **Medium** | **2** |
| **Low** | **1** |
