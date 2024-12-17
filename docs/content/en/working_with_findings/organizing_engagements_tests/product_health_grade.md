---
title: "Product Health Grade"
description: "How DefectDojo calculates a Product Health Grade"
---

DefectDojo can calculate a grade for your Products based on the amount of Findings contained within. Grades are ranked from A \- F.



Note that only Active \& Verified Findings contribute to a Product Grade \- unverified Findings will not have an impact.




# Product Grade Calculation


Every Product Grade starts at 100 (with no Findings).



Grade calculation starts by looking at the highest **Severity** level of a Finding in a Product, and reducing the Product Health to a base level.




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

