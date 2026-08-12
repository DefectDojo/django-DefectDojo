---
title: Operationen verwalten
description: Den Status der Discover- und Sync-Operationen Ihres Connectors prüfen
aliases:
- /import_data/pro/connectors/manage_operations/
- /en/connecting_your_tools/connectors/manage_operations
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Upstream-Connectors sind eine reine DefectDojo-Pro-Funktion.</span>

Sobald ein Upstream-Connector eingerichtet ist, führt er wiederkehrend zwei Operationen aus:

* **Discover** lernt die Struktur des verbundenen Tools kennen und legt in DefectDojo Records für alle noch nicht zugeordneten Daten an;
* **Sync** importiert anhand Ihrer Zuordnungen neue Befunde aus dem Tool.

Beide Operationen werden auf der Operations-Seite eines Connectors verwaltet. Die Tabelle erfasst außerdem vergangene Ausführungen dieser Operationen, sodass Sie sicherstellen können, dass Ihr Connector auf dem neuesten Stand ist.

Um die Operations-Seite eines Connectors zu öffnen, öffnen Sie **Manage Records & Operations** für den gewünschten Connector und wechseln Sie dann zum Tab **</\> Operations From (tool)**.

![image](images/operations_discover.png)

Die Seite **Manage Records & Operations** kann auch verwendet werden, um Records zu verwalten; die einzelnen Produktzuordnungen Ihres verbundenen Tools.  Weitere Informationen finden Sie unter [Records verwalten](../manage_records).

## Die Operations-Seite

![image](images/operations_page.png)

Jeder Eintrag in der Tabelle der Operations-Seite ist die Aufzeichnung eines Operationsereignisses mit folgenden Merkmalen:

* **Type** gibt an, ob es sich bei dem Ereignis um eine **Sync**- oder eine **Discover**-Operation handelte.
* **Status** gibt an, ob das Ereignis erfolgreich ausgeführt wurde.
* **Trigger** beschreibt, wie das Ereignis ausgelöst wurde \- handelte es sich um eine **Scheduled**-Operation, die automatisch ablief, oder um eine **Manual**-Operation, die von einem DefectDojo-Benutzer ausgelöst wurde?
* Hier werden **Start \& End Time** jeder Operation sowie die **Duration** erfasst.

## Discover-Operationen

Der erste Schritt, den ein DefectDojo-Connector ausführen muss, ist ein **Discover**-Vorgang für die Umgebung Ihres Tools, um zu sehen, wie Sie Ihre Scan-Daten organisieren.

Nehmen wir an, Sie haben ein BurpSuite-Tool, das so eingerichtet ist, dass es fünf verschiedene Repositories auf Schwachstellen scannt. Ihr Connector nimmt diese Organisationsstruktur zur Kenntnis und richtet **Records** ein, die Ihnen helfen, diese einzelnen Repositories in die Produkt-/Engagement-/Test-Hierarchie von DefectDojo zu übertragen.

### Neue Records erstellen

Jedes Mal, wenn Ihr Connector eine **Discover**-Operation ausführt, sucht er nach neuen **Vendor-Equivalent-Products (VEPs)**. DefectDojo betrachtet, wie das Vendor-Tool eingerichtet ist, und erstellt **Records** von VEPs basierend darauf, wie Ihr Tool organisiert ist.

![image](images/operations_discover_2.png)

### Discover manuell ausführen

**Discover**-Operationen werden automatisch in regelmäßigen Abständen ausgeführt, können aber auch manuell gestartet werden. Wenn Sie diesen Connector zum ersten Mal einrichten, können Sie auf die Schaltfläche **Discover** neben der Überschrift **Unmapped Records** klicken. Nach dem Neuladen der Seite sehen Sie Ihre erste Liste von **Records**.

![image](images/operations_discover_3.png)

Weitere Informationen zur Arbeit mit Records und zum Einrichten von Zuordnungen zu Produkten finden Sie in unserem Leitfaden [Records verwalten](../manage_records).

## Sync-Operationen

Täglich prüft DefectDojo jeden **Mapped Record** auf neue Scan-Daten. DefectDojo führt dann einen **Reimport** durch, bei dem der Zustand vorhandener Scan-Daten mit einem eingehenden Bericht verglichen wird.

### Wo werden Schwachstellendaten gespeichert?

* DefectDojo erstellt ein **Engagement** unterhalb des im **Record Mapping** angegebenen Produkts. Dieses Engagement heißt **Global Connectors**.
* Das Engagement **Global Connectors** erfasst jeden einzelnen mit dem Produkt verknüpften Connector als **Test**.
* Bei diesem und jedem weiteren Sync speichert der **Test** jede vom Tool gefundene Schwachstelle als **Befund**.

### Wie Sync mit neuen Schwachstellendaten umgeht

Jedes Mal, wenn Sync ausgeführt wird, vergleicht es die neuesten Scan-Daten mit der bestehenden Liste von Befunden, um Änderungen zu erkennen.

* Werden neue Befunde erkannt, werden sie dem Test als neue Befunde hinzugefügt.
* Befunde, die im neuesten Scan nicht erkannt werden, werden im Test als Inaktiv markiert.

Weitere Informationen zu Produkten, Engagements, Tests und Befunden finden Sie in unserer [Übersicht zur Produkthierarchie](/asset_modelling/os_hierarchy/product_hierarchy/).

### Sync manuell ausführen

Damit DefectDojo eine Sync-Operation außerplanmäßig ausführt:

1. Navigieren Sie zur Seite **Manage Records \& Operations** für den gewünschten Connector. Klicken Sie auf der Seite **Upstream Connectors** beim gewünschten Connector auf das Dropdown-Menü **Manage Configuration** und wählen Sie **Manage Records \& Operations**.
​
2. Klicken Sie auf dieser Seite auf die Schaltfläche **Sync**. Diese Schaltfläche befindet sich neben der Überschrift **Mapped Records**.

![image](images/operations_sync.png)