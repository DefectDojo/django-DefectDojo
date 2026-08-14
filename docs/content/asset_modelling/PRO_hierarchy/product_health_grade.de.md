---
title: Product Health Grade
description: Wie DefectDojo eine Product Health Grade berechnet
aliases:
- /de/en/working_with_findings/organizing_engagements_tests/product_health_grade
---

DefectDojo kann für Ihre Produkte eine Note basierend auf der Anzahl der darin enthaltenen Befunde berechnen. Die Noten reichen von A \- F.

Beachten Sie, dass nur Aktive \& Verifizierte Befunde zu einer Product Grade beitragen \- nicht verifizierte Befunde haben keinen Einfluss.

## Berechnung der Product Grade

Jede Product Grade beginnt bei 100 (ohne Befunde).

Die Berechnung der Grade beginnt damit, den höchsten **Schweregrad** eines Befunds in einem Produkt zu betrachten und die Product Health auf ein Grundniveau zu reduzieren.

| **Höchster Schweregrad eines Befunds** | **Maximale Grade** |
| --- | --- |
| **Kritisch** | **40** |
| **Hoch** | **60** |
| **Mittel** | **80** |
| **Niedrig** | **95** |

Für jeden weiteren Befund werden anschließend zusätzliche Punkte von der Grade abgezogen:

| **Schweregrad eines weiteren Befunds** | **Grade reduziert um** |
| --- | --- |
| **Kritisch** | **5** |
| **Hoch** | **3** |
| **Mittel** | **2** |
| **Niedrig** | **1** |
