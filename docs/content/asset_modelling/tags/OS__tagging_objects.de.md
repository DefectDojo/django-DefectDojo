---
title: Objekte taggen
description: Verwenden Sie Tags, um eine neue Sicht auf Ihr Datenmodell zu erstellen
draft: false
weight: 2
exclude_search: false
audience: opensource
---

Tags eignen sich hervorragend, um Objekte so zu gruppieren, dass sie sich in kleinere, besser überschaubare Abschnitte filtern lassen.  Sie können verwendet werden, um einen Status zu kennzeichnen oder um benutzerdefinierte Gruppen von Organisationen, Assets, Engagements oder Befunden über das gesamte Datenmodell hinweg zu bilden.

In DefectDojo sind Tags ein zentrales Konzept und gelten als das Mittel zur Organisation
auf jeder Ebene des Datenmodells.

Hier ein Beispiel mit einem Asset mit zwei Tags und vier Befunden mit jeweils einem Tag:

![Übersichtsbeispiel für die Verwendung von Tags](images/tags-high-level-example.png)

### Tag-Formate

Tags können in jedem der folgenden Formate geschrieben werden:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Tag-Verwaltung

### Hinzufügen und Entfernen

Tags lassen sich auf folgende Weise verwalten:

1. Neue Objekte erstellen oder bearbeiten

   Wenn ein neues Objekt über die UI oder die API erstellt oder bearbeitet wird, gibt es ein Feld
   zur Angabe der Tags, die für dieses Objekt gesetzt werden sollen. Dieses Feld ist ein Mehrfachauswahlfeld
   mit Autovervollständigung, wodurch sich vorhandene Tags mühelos suchen und hinzufügen lassen. So sieht
   das Feld beim Asset aus dem Screenshot im vorherigen Abschnitt aus:

   ![Tag-Verwaltung an einem Objekt](images/tags-management-on-object.png)

2. Import und Reimport

    Tags können einem Test auch beim Import oder Reimport zugewiesen werden. Das ist besonders nützlich,
    wenn der Import per Automatisierung über die API erfolgt, da sich so Details zum Automatisierungslauf
    und Tool-Informationen ergänzen lassen, die im Test- oder Befundobjekt selbst nicht direkt erfasst
    werden.

    Das Feld sieht genauso aus und verhält sich genauso wie bei einem einzelnen Objekt

3. Menü „Massenbearbeitung" (nur Befunde)

    Wenn viele Befunde mit demselben Satz von Tags aktualisiert werden müssen, kann das Menü zur
    Massenbearbeitung diese Arbeit erleichtern.

    Nehmen wir im folgenden Beispiel an, ich möchte die Tags der beiden Befunde mit dem Tag "tag-group-alpha" auf eine neue Tag-Liste wie diese ["tag-group-charlie", "tag-group-delta"] aktualisieren.
    Zunächst wähle ich die zu aktualisierenden Befunde aus:

    ![Befunde für die Massenbearbeitung der Tags auswählen](images/tags-select-findings-for-bulk-edit.png)

    Sobald ein Befund ausgewählt ist, erscheint eine neue Schaltfläche mit dem Namen "Bulk Edit". Ein Klick
    auf diese Schaltfläche öffnet ein Dropdown-Menü mit vielen Optionen, wobei der Fokus hier nur auf den
    Tags liegt. Aktualisieren Sie das Feld mit der gewünschten Tag-Liste wie folgt und klicken Sie auf
    "Absenden"

    ![Änderungen für die Massenbearbeitung der Tags übernehmen](images/tags-bulk-edit-submit.png)

    Die Tags der ausgewählten Befunde werden auf das aktualisiert, was im Tags-Feld des Menüs zur
    Massenbearbeitung angegeben wurde

    ![Abgeschlossene Massenbearbeitung der Tags](images/tags-bulk-edit-complete.png)

## Tag-Vererbung

Wenn die Tag-Vererbung aktiviert ist, werden Tags, die einem bestimmten Asset zugewiesen sind, automatisch auf alle Objekte unterhalb der Assets in der [Asset-Hierarchie](/asset_modelling/os_hierarchy/os__asset_hierarchy/) angewendet.

### Konfiguration

Die Tag-Vererbung kann auf folgenden Geltungsbereichen aktiviert werden:
- Globaler Geltungsbereich
  - Jedes Asset im gesamten System beginnt, Tags auf alle untergeordneten Objekte (Engagements, Tests und Befunde) anzuwenden
  - Dies wird in den Systemeinstellungen festgelegt
- Asset-Geltungsbereich
  - Nur das ausgewählte Asset beginnt, Tags auf alle untergeordneten Objekte (Engagements, Tests und Befunde) anzuwenden
  - Dies wird auf der Erstellungs-/Bearbeitungsseite des Assets festgelegt

### Verhalten

Wenn die Tag-Vererbung aktiviert ist, können normale Tags wie gewohnt zu Objekten hinzugefügt und von ihnen entfernt werden.
Vererbte Tags lassen sich jedoch nicht von einem untergeordneten Objekt entfernen, ohne sie auch vom übergeordneten Objekt zu entfernen.
Sehen Sie sich das folgende Beispiel an, bei dem ein Tag "test_only_tag" zum Test-Objekt und ein Tag "engagement_only_tag" zum Engagement hinzugefügt wird.

![Beispiel für vererbte Tags](images/tags-inherit-exmaple.png)

Wenn die Tag-Liste eines Assets aktualisiert wird, werden dieselben Änderungen asynchron auf alle Objekte innerhalb des Assets angewendet. Die Dauer dieser Aufgabe hängt direkt von der Anzahl der in einem Befund enthaltenen Objekte ab.

**Open Source:** Wenn Tag-Änderungen nicht innerhalb eines angemessenen Zeitraums sichtbar werden, prüfen Sie die Celery-Worker-Logs, um mögliche Ursachen zu identifizieren.


### Filtern nach Tags (klassische UI)

Tags lassen sich sowohl über die UI als auch über die API auf vielfältige Weise filtern. Hier zum Beispiel
ein Ausschnitt der Befundfilter:

![Ausschnitt der Befundfilter](images/tags-finding-filter-snippet.png)

Es gibt zehn Felder im Zusammenhang mit Tags:

 - Tags: filtert nach allen Tags, die einem bestimmten Befund zugeordnet sind
   - Beispiele:
     - Befund wird zurückgegeben
       - Befund-Tags: ["A", "B", "C"]
       - Filterabfrage: "B"
     - Befund wird *nicht* zurückgegeben
       - Befund-Tags: ["A", "B", "C"]
       - Filterabfrage: "F"
 - Not Tags: filtert nach allen Tags, die einem bestimmten Befund *nicht* zugeordnet sind
   - Beispiele:
     - Befund wird zurückgegeben
       - Befund-Tags: ["A", "B", "C"]
       - Filterabfrage: "F"
     - Befund wird *nicht* zurückgegeben
       - Befund-Tags: ["A", "B", "C"]
       - Filterabfrage: "B"
 - Tag Name Contains: filtert nach allen Tags eines Befunds, die die Abfrage ganz oder teilweise enthalten
   - Beispiele:
     - Befund wird zurückgegeben
       - Befund-Tags: ["Alpha", "Beta", "Charlie"]
       - Filterabfrage: "et" (Teil von "Beta")
     - Befund wird *nicht* zurückgegeben
       - Befund-Tags: ["Alpha", "Beta", "Charlie"]
       - Filterabfrage: "meg" (Teil von "Omega")
 - Not Tags: filtert nach allen Tags eines Befunds, die die Abfrage ganz oder teilweise *nicht* enthalten
   - Beispiele:
     - Befund wird zurückgegeben
       - Befund-Tags: ["Alpha", "Beta", "Charlie"]
       - Filterabfrage: "meg" (Teil von "Omega")
     - Befund wird *nicht* zurückgegeben
       - Befund-Tags: ["Alpha", "Beta", "Charlie"]
       - Filterabfrage: "et" (Teil von "Beta")

Die übrigen sechs Tag-Filter folgen denselben Regeln wie "Tags" und "Not Tags" oben,
gelten jedoch für andere Ebenen des Datenmodells:

 - Tags (Test): filtert nach allen Tags, die dem Test eines bestimmten Befunds zugeordnet sind
 - Not Tags (Test): filtert nach allen Tags, die dem Test eines bestimmten Befunds *nicht* zugeordnet sind
 - Tags (Engagement): filtert nach allen Tags, die dem Engagement eines bestimmten Befunds zugeordnet sind
 - Not Tags (Engagement): filtert nach allen Tags, die dem Engagement eines bestimmten Befunds *nicht* zugeordnet sind
 - Tags (Asset): filtert nach allen Tags, die dem Asset eines bestimmten Befunds zugeordnet sind
 - Not Tags (Asset): filtert nach allen Tags, die dem Asset eines bestimmten Befunds *nicht* zugeordnet sind
