---
title: Asset-Zustandsbewertung
description: Wie DefectDojo eine Asset-Zustandsbewertung berechnet
weight: 7
audience: opensource
aliases:
- /asset_modelling/os_hierarchy/product_health_grade/
- /en/asset_modelling/os_hierarchy/product_health_grade/
---

DefectDojo kann für Ihre Assets eine Bewertung anhand der Anzahl der darin enthaltenen Befunde berechnen. Die Bewertungen reichen von A \- F.

Beachten Sie, dass nur aktive \& verifizierte Befunde zu einer Asset-Bewertung beitragen \- nicht verifizierte Befunde wirken sich nicht aus.

*Die Zustandsbewertung (A \- F) jedes Assets wird neben seinem Namen in der Asset-Liste angezeigt.*

![Asset-Zustandsbewertungen neben jedem Asset in der Asset-Liste](images/asset-health-grade.png)

## Berechnung der Asset-Bewertung

Jede Asset-Bewertung beginnt bei 100 (ohne Befunde).

Die Berechnung der Bewertung beginnt damit, den höchsten **Schweregrad** eines Befunds in einem Asset zu betrachten und den Asset-Zustand auf ein Grundniveau zu reduzieren.

| **Höchster Schweregrad eines Befunds** | **Maximale Bewertung** |
| --- | --- |
| **Kritisch** | **40** |
| **Hoch** | **60** |
| **Mittel** | **80** |
| **Niedrig** | **95** |

Anschließend werden für jeden weiteren Befund zusätzliche Punkte von der Bewertung abgezogen:

| **Schweregrad eines weiteren Befunds** | **Bewertung reduziert um** |
| --- | --- |
| **Kritisch** | **5** |
| **Hoch** | **3** |
| **Mittel** | **2** |
| **Niedrig** | **1** |
