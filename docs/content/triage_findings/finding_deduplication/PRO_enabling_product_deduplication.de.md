---
title: Deduplizierung aktivieren
description: So aktivieren Sie die Deduplizierung auf Produkt- oder Engagement-Ebene
weight: 2
audience: pro
aliases:
- /en/working_with_findings/finding_deduplication/enabling_product_deduplication
---

Die Deduplizierung kann produktweit angewendet oder enger auf ein einzelnes Engagement beschränkt werden.

## Deduplizierung für Produkte

1. Navigieren Sie zur Seite Systemeinstellungen: **Settings > System > ⚙️ System Settings** in der Seitenleiste (**Settings > Pro Settings > System Settings** bei Instanzen, die noch das vorherige Menülayout verwenden).

![image](images/enabling_product-level_deduplication.png)

2. Die Karte **Deduplication and Finding Settings** befindet sich oben auf der Seite **System Settings**.

![image](images/enabling_product-level_deduplication_2.png)

### Befund-Deduplizierung aktivieren

**Enable Finding Deduplication** aktiviert den Deduplizierungsalgorithmus für alle Befunde. Nach der Aktivierung läuft die Deduplizierung bei jedem nachfolgenden Import — DefectDojo vergleicht importierte Befunde mit vorhandenen Befunden im Zielprodukt und markiert Duplikate gemäß Ihrer Konfiguration.

### Doppelte Befunde löschen

**Delete Duplicate Findings** begrenzt zusammen mit dem Feld **Maximum Duplicates**, wie viele doppelte Befunde DefectDojo aufbewahrt. Ist diese Option aktiviert, entfernt ein Hintergrundjob regelmäßig überzählige Duplikate, sodass jeder ursprüngliche Befund nicht mehr als die konfigurierte Anzahl unter **Maximum Duplicates** behält. Die ältesten Duplikate werden zuerst entfernt.

## Deduplizierung für Engagements

Anstatt produktweit zu deduplizieren, können Sie die Deduplizierung auf ein einzelnes Engagement beschränken.

### Das Engagement-Formular öffnen

* **Für ein neues Engagement:** Öffnen Sie das Untermenü **📥 Engagements** in der Seitenleiste und klicken Sie auf **+ New Engagement**.

![image](images/enabling_deduplication_within_an_engagement.png)

* **Für ein bestehendes Engagement (von der Seite „Alle Engagements“):** Öffnen Sie das Menü **⋮** für das Engagement und wählen Sie **Edit Engagement**.

![image](images/enabling_deduplication_within_an_engagement_2.png)

* **Für ein bestehendes Engagement (von der Engagement-Seite):** Öffnen Sie das Menü **⚙️ Gear** oben rechts auf der Seite und wählen Sie **Edit Engagement**.

![image](images/enabling_deduplication_within_an_engagement_3.png)

### Das Engagement-Formular ausfüllen

1. Suchen Sie im Engagement-Formular das Kontrollkästchen ☐ **Isolate Deduplication from Other Engagements**. Es erscheint über dem Bereich **Optional Fields +**.
2. Aktivieren Sie das Kontrollkästchen, um die Deduplizierung auf dieses Engagement zu beschränken.
3. Senden Sie das Formular ab.

Wenn diese Option aktiviert ist, werden Befunde in diesem Engagement nur mit anderen Befunden innerhalb desselben Engagements dedupliziert. Befunde in anderen Engagements desselben Produkts werden vom Deduplizierungsalgorithmus ignoriert.

![image](images/enabling_deduplication_within_an_engagement_4.png)
