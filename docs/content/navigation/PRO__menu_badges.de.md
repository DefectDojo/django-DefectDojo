---
title: Menü-Badges
description: Was die Tags BETA, NEW, LEGACY und DEPRECATED in der Seitenleiste von
  DefectDojo Pro bedeuten und was sie jeweils von Ihnen verlangen
weight: 7
audience: pro
---

Einträge in der Seitenleiste von DefectDojo Pro können ein kleines farbiges Tag tragen. Jedes beantwortet eine andere Frage zu der Funktion, neben der es steht, und zwei davon sind Links.

| Badge | Farbe | Bedeutung | Was von Ihnen erwartet wird |
| --- | --- | --- | --- |
| `NEW` | Grün | Kürzlich veröffentlicht | Nichts — es ist nur dazu da, dass Sie die Funktion bemerken |
| `BETA` | Orange | Funktioniert, wird aber noch fertiggestellt; das Verhalten kann sich zwischen Releases ändern | Probieren Sie es aus und rechnen Sie mit Unebenheiten |
| `LEGACY` | Rot | Durch eine neuere Funktion abgelöst, ohne angekündigtes Entfernungsdatum | Bevorzugen Sie für neue Arbeiten den Ersatz |
| `DEPRECATED` | Rot | Zur Entfernung in einem genannten Release vorgesehen | Migrieren Sie vor diesem Release |

![Das LEGACY-Badge beim Jira-Menüeintrag](images/menu_badge_legacy.png)

## LEGACY und DEPRECATED sind nicht dasselbe

Die Unterscheidung ist beabsichtigt, da die beiden Zustände unterschiedliche Reaktionen erfordern.

**`DEPRECATED`** bedeutet, dass eine Entfernung angekündigt wurde. Wenn Sie mit der Maus über das Badge fahren, erfahren Sie, in welchem Release die Funktion entfällt; ein Klick öffnet den Deprecation-Hinweis:

> \<Feature\> is deprecated and will be removed by \<release\>. Click for the deprecation notice.

**`LEGACY`** bedeutet, dass die Funktion abgelöst wurde, aber keine Entfernung geplant ist. Im Hover-Text steht bewusst kein Datum, da ein erfundenes Datum schlimmer wäre, als gar keines zu nennen. Stattdessen wird der Ersatz genannt und auf dessen Dokumentation verlinkt:

> \<Feature\> is superseded by \<replacement\> and will not receive new development. Click for its documentation.

Eine `LEGACY`-Funktion funktioniert weiterhin und erhält weiterhin Fehlerbehebungen. Sie erhält lediglich keine neuen Fähigkeiten mehr, weshalb alles, was Sie jetzt aufbauen, besser auf dem Ersatz basiert.

Beide Badges sind Links, da sich ein Tooltip schließt, sobald der Mauszeiger ihn verlässt, und er daher keinen anklickbaren Link enthalten kann. Ein Klick auf eines der Badges öffnet den zugehörigen Hinweis in einem neuen Tab; der darunterliegende Menüeintrag wird dabei nicht aufgerufen.

## Was aktuell ein Badge trägt

**`LEGACY`**

* **Connect > Jira** — die ursprüngliche produktbezogene Jira-Integration, abgelöst durch den Downstream-Connector für Jira. Siehe [Pro-Integrationen](/connectors/downstream/about/).

**`DEPRECATED`**

* **Settings > Configuration > Tool Types**
* **Settings > Configuration > Tool Configurations**

Beide werden in **3.5.0** entfernt, zusammen mit den API-basierten (Pull-)Parsern, die sie konfigurieren. Die [Upgrade-Hinweise zu 3.2](/releases/os_upgrading/3.2/) erläutern, worauf und bis wann migriert werden muss.

![DEPRECATED-Badges unter Settings > Configuration](images/menu_badge_deprecated.png)

Wenn ein Label und sein Badge nicht nebeneinander in die Seitenleiste passen, bricht das Badge in eine eigene Zeile unterhalb des Labels um, anstatt abgeschnitten zu werden.

## Verwandte Themen

* [Upgrade-Hinweise zu 3.2](/releases/os_upgrading/3.2/) — die aktuellen Deprecations und ihr Entfernungs-Release
* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — optionale Funktionen, einschließlich Beta-Funktionen, ein- und ausschalten
