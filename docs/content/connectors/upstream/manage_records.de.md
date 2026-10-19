---
title: Datensätze verwalten
description: Steuern Sie den Datenfluss von Ihrem Tool zu DefectDojo
aliases:
- /import_data/pro/connectors/manage_records/
- /en/connecting_your_tools/connectors/manage_records
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Upstream-Connectors sind eine Funktion, die nur in DefectDojo Pro verfügbar ist.</span>

Nachdem Sie Ihren ersten Discover-Vorgang ausgeführt haben, sollten Sie auf der Seite **Manage Records and Operations** eine Liste der zugeordneten oder nicht zugeordneten Datensätze sehen.

## Was ist ein Datensatz?

Ein Datensatz ist eine Verbindung zwischen einem DefectDojo-**Produkt** und einem **Vendor\-Equivalent\-Product**. Über Ihre Datensatzliste können Sie steuern, wie Daten zwischen Ihrem Tool und DefectDojo fließen.

Datensätze werden während des **[Discover](../manage_operations/#discover-operations)**-Vorgangs erstellt und aktualisiert, den DefectDojo täglich ausführt, um nach neuen Vendor\-Equivalent Products zu suchen.

![image](images/manage_records.png)

Datensätze verfügen über verschiedene Attribute, darunter:

* Der **Status** des Datensatzes
* Das **Produkt**, in das der Datensatz Daten importiert
* Wann der Datensatz zuerst und zuletzt vom Discover-Vorgang **erkannt** wurde
* Wann die Zuordnung des Datensatzes von einem Benutzer **finalisiert** wurde
* Ein Link zum DefectDojo-**Produkt**

## Wie Datensätze zugeordnet werden

Jedem Datensatz muss eine Zuordnung zugewiesen werden. Die Zuordnung teilt DefectDojo mit, wo die Scan-Daten aus dem Tool gespeichert werden sollen. Ein zugeordneter Datensatz verknüpft das Vendor-Equivalent Product mit einem DefectDojo-Produkt und weist den Connector an, Scan-Daten an diesen Ort zu importieren (als Engagements und Tests).

Sie können Zuordnungen selbst vornehmen oder sie von DefectDojo automatisch zuweisen lassen.

### Auto-Mapping

Wenn **Auto-Mapping** aktiviert ist, werden neue Datensätze automatisch Produkten zugeordnet. Jedes Mal, wenn DefectDojo einen neuen Datensatz **entdeckt**, wird für jeden Datensatz automatisch ein passendes DefectDojo-Produkt erstellt. Dieser Datensatz wird dann unter den zugeordneten Datensätzen gespeichert, um anzuzeigen, dass er bereit ist, Daten in DefectDojo zu importieren.

Wenn Auto-Mapping nicht aktiviert ist, können Sie selbst entscheiden, wohin die Daten fließen sollen. Jedes Mal, wenn der Connector ein neues Vendor-Equivalent Product findet (über **Discover**), fügt er Ihrer Liste der nicht zugeordneten Datensätze einen neuen Datensatz hinzu. Sie können diesen Datensatz dann manuell einem neuen oder bestehenden Produkt in DefectDojo zuordnen.

#### Zuordnung – Beispiel-Workflow:

David hat gerade die Einrichtung eines Connectors für sein BurpSuite-Tool abgeschlossen und führt einen Discover-Vorgang aus. David hat Burp so konfiguriert, dass 4 verschiedene „Sites“ gescannt werden, und DefectDojo erstellt für jede dieser Sites einen neuen Datensatz.

* Wenn David sich für Auto-Mapping entscheidet, erstellt DefectDojo für jede Site ein neues Produkt. Ab sofort importiert der Connector bei jedem Sync-Vorgang von DefectDojo die Scan-Daten direkt von der Site in das Produkt (über die Datensatzzuordnung)
​
* Wenn David Auto-Mapping deaktiviert lässt, entdeckt DefectDojo weiterhin die 4 Sites und erstellt Datensätze, importiert jedoch keine Daten, bis David die Zuordnungen selbst vornimmt.
​
* David kann die Einrichtung dieser Zuordnungen jederzeit später ändern. Vielleicht möchte er die Ausgabe mehrerer verschiedener Burp-Sites in einem einzigen Produkt zusammenführen. Oder er möchte ein Produkt haben, das Scan-Daten aus mehreren verschiedenen Tools erfasst – einschließlich Burp. David kann leicht ändern, wo Burp-Scan-Daten in DefectDojo gespeichert werden, indem er die Zuordnung dieser Datensätze ändert.

## Wie Datensätze mit Produkten zusammenwirken

Sobald ein Datensatz zugeordnet ist, ist DefectDojo bereit, die Scans Ihres Tools über einen Sync-Vorgang zu importieren. Connectors können parallel zu anderen DefectDojo-Importprozessen oder interaktiven Tests arbeiten.

* Datensatzzuordnungen sind so konzipiert, dass sie nicht invasiv sind. Wenn Sie ein Produkt einem Datensatz zuordnen, der bereits vorhandene Engagements oder Findings enthält, werden diese vorhandenen Engagements und Findings durch den Daten-Sync-Prozess nicht beeinträchtigt oder überschrieben.
​
* Alle über einen Connector erstellten Daten werden unter einem einzigen Engagement namens **Global Connectors** gespeichert. Dieses Engagement erstellt für jeden dem Produkt zugeordneten Connector einen separaten Test.

![image](images/manage_records_2.jpg)

Dadurch ist es möglich, Scan-Daten von mehreren Connectors an dasselbe Produkt zu senden. Alle Daten werden im selben Engagement gespeichert, aber jeder Connector speichert seine Daten in einem separaten Test.

Weitere Informationen zu Produkten, Engagements und Tests finden Sie in unserer [Übersicht der Produkthierarchie](/asset_modelling/os_hierarchy/product_hierarchy/).

## Datensatzstatus – Glossar

Jeder Datensatz hat einen zugehörigen Status, der angibt, wie der Datensatz funktioniert.

Die vollständige Datensatzliste eines Connectors erreichen Sie, indem Sie den Connector über **Connect \> Upstream** öffnen – die Seite trägt den Titel **All \<Connector\> Records**. Trotz des Namens listet sie alle Datensätze auf, die zu **diesem einen Connector** gehören, nicht alle Datensätze der Instanz.

Diese Liste kann über die Spalte **Status** **nach Status gefiltert** werden, wobei mehrere Status gleichzeitig ausgewählt werden können. Dies ist der schnellste Weg, um bei einer großen Connector-Flotte die am häufigsten auftretenden Fragen zu beantworten – *Was wartet noch auf meine Zuordnung?* (**Neu**) und *Was hat aufgehört, Daten zu melden?* (**Fehlend** oder **Fehler**) – ohne jeden einzelnen Datensatz durchsehen zu müssen.

Nicht jeder Status gilt für jeden Connector. **Veraltet** wird von der Findings-Import-Pipeline gesetzt und tritt daher nur bei Connectors auf, die Findings importieren; **Asset Connectors** nehmen diesen Status nie an, weshalb er für sie auch nicht als Filteroption angeboten wird.

### Neu

Ein Datensatz mit dem Status Neu ist ein nicht zugeordneter Datensatz, den DefectDojo entdeckt hat. Er kann einem Produkt zugeordnet oder ignoriert werden. Informationen zum Zuordnen eines neuen Datensatzes zu einem Produkt finden Sie in unserem Leitfaden [Datensätze bearbeiten]().

### Gut

„Gut“ zeigt an, dass ein Datensatz zugeordnet ist und korrekt funktioniert. Künftige Discover-Vorgänge prüfen, ob das zugrunde liegende Vendor-Equivalent Product noch existiert, um sicherzustellen, dass der Sync-Vorgang korrekt ausgeführt wird.

### Ignoriert

Datensätze mit dem Status „Ignoriert“ wurden erfolgreich entdeckt, aber ein DefectDojo-Benutzer hat entschieden, die Daten keinem Produkt zuzuordnen.

## Warnstatus: Veraltet oder Fehlend

Wenn sich die Verbindung zwischen dem Tool und DefectDojo ändert, ändert sich auch der Status eines Datensatzes, um Sie darüber zu informieren.

### Veraltet

Eine Zuordnung wechselt in den Status „Veraltet“, wenn ein zugehöriges Produkt, Engagement oder Test aus DefectDojo gelöscht wurde. Die Zuordnung besteht weiterhin, aber es gibt in DefectDojo keinen Ort mehr, an den die Daten des Tools importiert werden können.

Veraltete Datensätze können einem bestehenden Produkt neu zugeordnet oder ignoriert werden, wenn die Scan-Daten nicht mehr relevant sind.

### Fehlend

Wenn ein Datensatz zugeordnet wurde, die Quelldaten (oder das Vendor\-Equivalent Product) von DefectDojo jedoch nicht erkannt werden, wird der Datensatz als **Fehlend** gekennzeichnet.

DefectDojo-Connectors passen sich an Namensänderungen, Verzeichnisänderungen und andere Datenverschiebungen an. Möglicherweise wurde das zugehörige Vendor\-Equivalent Product daher aus dem von Ihnen verwendeten Tool gelöscht.

Wenn Sie beabsichtigt haben, das Vendor Equivalent Product aus Ihrem Tool zu entfernen, können Sie einen fehlenden Datensatz löschen. Andernfalls müssen Sie das Problem innerhalb des Tools beheben, damit die Quelldaten korrekt entdeckt werden können.

### Fehler

**Fehler** zeigt an, dass DefectDojo den Datensatz nicht verarbeiten konnte. Dieser Status ist bei jedem Connector-Typ verfügbar und kann im **Status**-Filter zusammen mit den oben genannten Status ausgewählt werden. So lässt sich nach einem Lauf am schnellsten prüfen, ob bei einem Connector etwas Aufmerksamkeit erfordert.

## Datensätze bearbeiten: Neu zuordnen, ignorieren oder löschen

Datensätze können auf der Seite **Manage Records \& Operations** bearbeitet, ignoriert oder gelöscht werden.

Obwohl sich zugeordnete und nicht zugeordnete Datensätze in getrennten Tabellen befinden, können beide auf die gleiche Weise bearbeitet werden.

Klicken Sie in der Datensatztabelle bei einem bestimmten Datensatz auf den blauen ▼-Pfeil neben der Spalte Status. Von dort aus können Sie **Datensatz bearbeiten** oder **Datensatz löschen** auswählen.

![image](images/edit_ignore_delete_records.png)

### Die Zuordnung eines Datensatzes ändern

Wenn Sie auf **Datensatz bearbeiten** klicken, öffnet sich ein Fenster, in dem Sie das Zielprodukt in DefectDojo ändern können. Sie können entweder ein bestehendes Produkt aus dem Dropdown-Menü auswählen oder den Namen eines neuen Produkts eingeben, das Sie erstellen möchten.

![image](images/edit_ignore_delete_records_2.png)

Indem Sie die Zuordnung ändern, können Sie die mit einem Datensatz verknüpften Scan-Daten in ein anderes Produkt umleiten.

Wählen Sie im Dropdown-Menü rechts ein Produkt aus, oder geben Sie den Namen eines neuen Produkts ein.

#### Den Status eines Datensatzes bearbeiten

Auch der Status eines Datensatzes kann über dieses Menü geändert werden. Datensätze können über die **Status**-Dropdown-Liste von Gut zu Ignoriert (oder umgekehrt) gewechselt werden.

### Einen Datensatz ignorieren

Wenn Sie einen der Datensätze „abschalten“ oder die Daten, die er an DefectDojo sendet, ignorieren möchten, können Sie den Datensatz auf „Ignoriert“ setzen. Ein Datensatz mit dem Status „Ignoriert“ wandert in die Liste der nicht zugeordneten Datensätze und überträgt keine neuen Daten mehr an DefectDojo.

Sie können sowohl einen zugeordneten Datensatz ignorieren (wodurch die Zuordnung entfernt wird) als auch einen neuen Datensatz (aus der Liste der nicht zugeordneten Datensätze).

#### Einen ignorierten Datensatz wiederherstellen

Wenn Sie den Status „Ignoriert“ von einem Datensatz entfernen möchten, können Sie ihn über dasselbe Status-Dropdown-Menü wieder auf „Neu“ setzen.

* Wenn die automatische Zuordnung aktiviert ist, kehrt der Datensatz zu seiner ursprünglichen Zuordnung zurück, sobald der Discover-Vorgang erneut ausgeführt wird.
* Wenn die automatische Zuordnung nicht aktiviert ist, stellt DefectDojo eine frühere Zuordnung nicht automatisch wieder her. Sie müssen die Zuordnung für diesen Datensatz dann erneut einrichten.

### Einen Datensatz löschen

Sie können Datensätze auch löschen, wodurch sie aus der Tabelle der nicht zugeordneten oder zugeordneten Datensätze entfernt werden.

Beachten Sie, dass die Discover-Funktion immer alle Datensätze eines Tools importiert – das bedeutet, dass ein Datensatz, selbst wenn er aus DefectDojo gelöscht wird, später erneut entdeckt wird (und wieder in der Liste der zuzuordnenden Datensätze erscheint).

* Wenn Sie planen, das zugrunde liegende Vendor\-Equivalent\-Product aus Ihrem Scan-Tool zu entfernen, ist das Löschen des Datensatzes eine gute Option. Andernfalls stellt der nächste Discover-Vorgang fest, dass die zugehörigen Daten fehlen, und der Status dieses Datensatzes wechselt zu „Fehlend“.
​
* Wenn das zugrunde liegende Vendor\-Equivalent\-Product jedoch weiterhin existiert, wird es bei einem künftigen Discover-Vorgang erneut entdeckt. Um dies zu verhindern, können Sie den Datensatz stattdessen ignorieren.

#### Wirkt sich das auf bereits importierte Daten aus?

Nein. Alle Findings, Tests und Engagements, die durch einen Sync-Datensatz erstellt wurden, verbleiben auch nach dem Löschen des Datensatzes in DefectDojo. Das Löschen eines Datensatzes oder einer Konfiguration entfernt nur den Datenfluss-Prozess und löscht keine Schwachstellendaten aus DefectDojo oder Ihrem Tool.
