---
title: Objekte mit Tags versehen
description: Nutzen Sie Tags, um eine neue Sicht auf Ihr Datenmodell zu erstellen
draft: false
weight: 2
exclude_search: false
audience: pro
aliases:
- /en/working_with_findings/organizing_engagements_tests/tagging_objects
---

Tags eignen sich hervorragend, um Objekte so zu gruppieren, dass sie sich in kleinere, leichter überschaubare Abschnitte filtern lassen. Sie können verwendet werden, um einen Status zu kennzeichnen oder um benutzerdefinierte Gruppen aus Produkttyp, Produkten, Engagements oder Findings über das gesamte Datenmodell hinweg zu erstellen.

In DefectDojo sind Tags ein zentrales Konzept und gelten als die treibende Kraft der Organisation auf jeder Ebene des Datenmodells.

Hier ist ein Beispiel für ein Produkt mit zwei Tags und vier Findings, die jeweils ein einzelnes Tag haben:

![Übersichtsbeispiel für die Verwendung von Tags](images/tags-high-level-example.png)

### Tag-Formate

Tags können in einem der folgenden Formate geschrieben werden:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Tag-Verwaltung (Pro UI)

### Hinzufügen und Entfernen

Tags können auf folgende Weise verwaltet werden:

1. **Neue Objekte erstellen oder bearbeiten**

   Wenn ein neues Objekt über die Benutzeroberfläche oder die API erstellt oder bearbeitet wird, gibt es ein Feld, in dem die für dieses Objekt festzulegenden Tags angegeben werden können.

   ![tag](images/tags_product.png)

2. **Beim Importieren/Reimportieren von Findings**

  Tags stehen auf dem Import-/Reimport-Formular sowohl in der Benutzeroberfläche als auch über die API zur Verfügung. Wenn dieses Formular abgeschickt wird, wird der **Test** mit `[tag]` und `[daily-import]` getaggt. Wenn "Apply Tags to Findings" oder "Apply Tags to Endpoints" ausgewählt ist, werden auch diese Objekte getaggt. Tags bieten die Möglichkeit, Details zum Automatisierungslauf und Tool-Informationen zu ergänzen, die nicht direkt im Test- oder Finding-Objekt erfasst werden.

   ![tag](images/tags_importscan.png)

3. **Über Bulk Edit**

  Wenn in einer Tabelle mehrere Findings ausgewählt werden, können Sie über das Menü Bulk Edit die zugehörigen Tags für viele Findings gleichzeitig ändern. Beachten Sie, dass dadurch alle Tags auf Finding-Ebene durch die angegebenen Tags ersetzt werden; vorhandene Finding-Tags werden überschrieben.

  ![Massenbearbeitung von Findings](images/Bulk_Editing_Findings.png)


## Tag-Verwaltung (Classic UI / Open Source)

### Hinzufügen und Entfernen

Tags können auf folgende Weise verwaltet werden:

1. Neue Objekte erstellen oder bearbeiten

   Wenn ein neues Objekt über die Benutzeroberfläche oder die API erstellt oder bearbeitet wird, gibt es ein Feld, in dem die für dieses Objekt festzulegenden Tags angegeben werden können. Dieses Feld ist ein Mehrfachauswahlfeld, das außerdem über eine Autovervollständigung verfügt, mit der sich vorhandene Tags mühelos suchen und hinzufügen lassen. So sieht das Feld beim Produkt aus dem Screenshot im vorherigen Abschnitt aus:

   ![Tag-Verwaltung an einem Objekt](images/tags-management-on-object.png)

2. Import und Reimport

    Tags können einem bestimmten Test auch zum Zeitpunkt des Imports oder Reimports zugewiesen werden. Das ist ein sehr nützlicher Anwendungsfall beim Importieren über die API mit Automatisierung, da es die Möglichkeit bietet, Details zum Automatisierungslauf und Tool-Informationen zu ergänzen, die nicht direkt im Test- oder Finding-Objekt erfasst werden.

    Das Feld sieht genauso aus und verhält sich genauso wie bei einem einzelnen Objekt

3. Menü Bulk Edit (nur Findings)

    Wenn viele Findings mit demselben Tag-Satz aktualisiert werden müssen, kann das Bulk-Edit-Menü die Arbeit erleichtern.

    Nehmen wir im folgenden Beispiel an, ich möchte die Tags der beiden Findings mit dem Tag "tag-group-alpha" durch eine neue Tag-Liste wie diese ["tag-group-charlie", "tag-group-delta"] ersetzen.
    Zuerst wähle ich die zu aktualisierenden Findings aus:

    ![Auswahl von Findings für die Bulk-Edit-Tag-Aktualisierung](images/tags-select-findings-for-bulk-edit.png)

    Sobald ein Finding ausgewählt ist, erscheint eine neue Schaltfläche mit der Bezeichnung "Bulk Edit". Ein Klick auf diese Schaltfläche öffnet ein Dropdown-Menü mit vielen Optionen; hier konzentrieren wir uns jedoch nur auf die Tags. Aktualisieren Sie das Feld wie folgt mit der gewünschten Tag-Liste, und klicken Sie auf Absenden

    ![Änderungen für die Bulk-Edit-Tag-Aktualisierung übernehmen](images/tags-bulk-edit-submit.png)

    Die Tags der ausgewählten Findings werden auf die im Tags-Feld des Bulk-Edit-Menüs angegebenen Werte aktualisiert

    ![Abgeschlossene Bulk-Edit-Tag-Aktualisierung](images/tags-bulk-edit-complete.png)

## Tag-Vererbung

**Hinweis zur Pro-UI: Obwohl die Tag-Vererbung über die Pro-UI konfiguriert werden kann, lassen sich vererbte Tags derzeit nur über die Classic UI oder die API einsehen und filtern.**

Wenn die Tag-Vererbung aktiviert ist, werden Tags, die einem bestimmten Produkt zugewiesen wurden, automatisch auf alle Objekte unterhalb der Produkte in der [Produkthierarchie](/asset_modelling/os_hierarchy/product_hierarchy/) angewendet.

### Konfiguration

Die Tag-Vererbung kann auf den folgenden Geltungsbereichen aktiviert werden:
- Globaler Geltungsbereich
  - Jedes Produkt im gesamten System beginnt, Tags auf alle untergeordneten Objekte (Engagements, Tests und Findings) anzuwenden
  - Dies wird in den System Settings festgelegt
- Produkt-Geltungsbereich
  - Nur das ausgewählte Produkt beginnt, Tags auf alle untergeordneten Objekte (Engagements, Tests und Findings) anzuwenden
  - Dies wird auf der Seite zum Erstellen/Bearbeiten des Produkts festgelegt

### Verhalten

Wenn die Tag-Vererbung aktiviert ist, können normale Tags weiterhin auf die übliche Weise zu Objekten hinzugefügt und von ihnen entfernt werden.
Vererbte Tags können jedoch nicht von einem untergeordneten Objekt entfernt werden, ohne sie auch vom übergeordneten Objekt zu entfernen
Sehen Sie sich das folgende Beispiel an, bei dem ein Tag "test_only_tag" zum Test-Objekt und ein Tag "engagement_only_tag" zum Engagement hinzugefügt wird.

![Beispiel für vererbte Tags](images/tags-inherit-exmaple.png)

Wenn die Tag-Liste eines Produkts aktualisiert wird, werden dieselben Änderungen asynchron auf alle Objekte innerhalb des Produkts angewendet. Die Dauer dieser Aufgabe hängt direkt von der Anzahl der in einem Finding enthaltenen Objekte ab.

**Open Source:** Wenn Tag-Änderungen nicht innerhalb eines angemessenen Zeitraums sichtbar werden, prüfen Sie die Celery-Worker-Logs, um mögliche Fehlerursachen zu identifizieren.


### Nach Tags filtern (Classic UI)

Tags können sowohl über die Benutzeroberfläche als auch über die API auf viele Arten gefiltert werden. Hier sehen Sie beispielsweise einen Ausschnitt
der Finding-Filter:

![Ausschnitt der Finding-Filter](images/tags-finding-filter-snippet.png)

Es gibt zehn Felder, die sich auf Tags beziehen:

 - Tags: Filtert nach allen Tags, die einem bestimmten Finding zugeordnet sind
   - Beispiele:
     - Das Finding wird zurückgegeben
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "B"
     - Das Finding wird *nicht* zurückgegeben
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "F"
 - Not Tags: Filtert nach allen Tags, die einem bestimmten Finding *nicht* zugeordnet sind
   - Beispiele:
     - Das Finding wird zurückgegeben
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "F"
     - Das Finding wird *nicht* zurückgegeben
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "B"
 - Tag Name Contains: Filtert nach allen Tags im gegebenen Finding, die die Suchanfrage ganz oder teilweise enthalten
   - Beispiele:
     - Das Finding wird zurückgegeben
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "et" (Teil von "Beta")
     - Das Finding wird *nicht* zurückgegeben
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "meg" (Teil von "Omega")
 - Not Tags: Filtert nach allen Tags im gegebenen Finding, die die Suchanfrage *nicht* ganz oder teilweise enthalten
   - Beispiele:
     - Das Finding wird zurückgegeben
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "meg" (Teil von "Omega")
     - Das Finding wird *nicht* zurückgegeben
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "et" (Teil von "Beta")

Für die übrigen sechs Tag-Filter gelten dieselben Regeln wie oben für "Tags" und "Not Tags",
jedoch auf unterschiedlichen Ebenen des Datenmodells:

 - Tags (Test): Filtert nach allen Tags, die dem Test eines bestimmten Findings zugeordnet sind
 - Not Tags (Test): Filtert nach allen Tags, die dem Test eines bestimmten Findings *nicht* zugeordnet sind
 - Tags (Engagement): Filtert nach allen Tags, die dem Engagement eines bestimmten Findings zugeordnet sind
 - Not Tags (Engagement): Filtert nach allen Tags, die dem Engagement eines bestimmten Findings *nicht* zugeordnet sind
 - Tags (Product): Filtert nach allen Tags, die dem Produkt eines bestimmten Findings zugeordnet sind
 - Not Tags (Product): Filtert nach allen Tags, die dem Produkt eines bestimmten Findings *nicht* zugeordnet sind
