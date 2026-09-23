---
title: Infrastruktur-Scans / Smart Upload
description: Eingehende Befunde automatisch dem richtigen Produkt zuordnen
weight: 3
audience: pro
aliases:
- /de/en/connecting_your_tools/import_scan_files/smart_upload
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Smart Upload ist nur in DefectDojo Pro verfügbar.</span>

Smart Upload ist ein spezialisierter Importer, der Berichte von **Tools für Infrastruktur-Scans** verarbeitet, darunter:

* Nexpose
* NMap
* OpenVas
* Qualys
* Tenable

Smart Upload ist insofern besonders, als es Befunde aus einer Scan-Datei auf verschiedene Produkte aufteilen kann. Das ist im Kontext von Infrastruktur-Scans relevant, wo die Befunde viele unterschiedliche Teams betreffen, unterschiedliche implizite SLAs haben oder je nach Fundort in Ihrer Infrastruktur in getrennte Berichte aufgenommen werden müssen.

Smart Upload löst das, indem eingehende Befunde anhand der im Scan gefundenen Endpunkte sortiert werden. Zunächst müssen diese Befunde manuell zugewiesen oder aus einer Liste nicht zugewiesener Befunde in das richtige Produkt geleitet werden. Sobald ein Befund einem Produkt zugewiesen wurde, werden jedoch alle nachfolgenden Befunde, die denselben Endpunkt oder Host haben, an dasselbe Produkt gesendet. Wenn dieser Host mit mehr als einem Produkt verknüpft ist, wird der Befund an jedes davon gesendet (siehe unten).

## Menüoptionen von Smart Upload

Das Smart-Upload-Menü befindet sich in einem einklappbaren Bereich der Seitenleiste.

* **Mit „Befunde hinzufügen“ können Sie eine neue Scan-Datei importieren, ähnlich wie mit der Methode „Scan importieren“ von DefectDojo**
* **„Nicht zugewiesene Befunde“ listet alle Befunde aus Smart Upload auf, die noch keinem Produkt zugewiesen wurden.**

![image](images/smart_upload.png)

### Das Smart-Upload-Formular

Das Formular „Scan importieren“ von Smart Upload entspricht im Wesentlichen dem allgemeinen Formular „Scan importieren“. Weitere Details finden Sie in unseren Hinweisen zum **Formular „Scan importieren“**.

![image](images/smart_upload_2.png)

## Nicht zugewiesene Befunde

Sobald ein Smart Upload abgeschlossen ist, werden alle Befunde, die nicht automatisch (anhand ihres Endpunkts) einem Produkt zugewiesen werden, in die Liste **Nicht zugewiesene Befunde** aufgenommen. Beim ersten Smart Upload für ein bestimmtes Tool gibt es noch keine Möglichkeit, Befunde zuzuweisen, daher wird jeder Befund aus dieser Datei zum Sortieren auf diese Seite geleitet.

Nicht zugewiesene Befunde sind nicht Teil der Produkthierarchie und erscheinen erst nach ihrer Zuweisung in Berichten, Filtern oder Metriken.

### Arbeiten mit nicht zugewiesenen Befunden

![image](images/smart_upload_3.png)

Sie können über die Checkbox einen oder mehrere nicht zugewiesene Befunde zum Sortieren auswählen und eine der folgenden Aktionen ausführen:

* **„Einem neuen Produkt zuweisen“ erstellt ein neues Produkt**
* **„Einem bestehenden Produkt zuweisen“ verschiebt den Befund in ein bestehendes Produkt**
* **Ausgewählte Befunde verwerfen**, wodurch der Befund aus der Liste entfernt wird

Immer wenn ein Befund einem neuen oder bestehenden Produkt zugewiesen wird, wird er in ein eigenes Engagement mit dem Namen „Smart Upload“ eingefügt. Dieses Engagement enthält einen Test, der nach dem Scan-Typ benannt ist (z. B. Tenable Scan). Nachfolgende über Smart Upload hochgeladene Befunde, die zu diesen Endpunkten passen, werden unter diesem Engagement \> Test abgelegt.

### Verworfene Befunde

Wenn ein Befund verworfen wird, wird er aus der Liste der nicht zugewiesenen Befunde entfernt. Der Befund wird jedoch nicht dauerhaft gespeichert, sodass er bei nachfolgenden Scan-Uploads erneut in der Liste der nicht zugewiesenen Befunde erscheinen kann.

## Befunde, die zu mehr als einem Produkt passen

Ein einzelner Host oder Endpunkt kann zu mehr als einem Produkt gehören, zum Beispiel ein gemeinsam genutzter Load Balancer oder ein Host, den zwei Teams verfolgen. Wenn Smart Upload den Host eines eingehenden Befunds mehreren Produkten zuordnet, wählt es nicht eines aus: Es erstellt in **jedem** passenden Produkt eine Kopie des Befunds und legt jede Kopie im eigenen Smart-Upload-Engagement und -Test dieses Produkts ab.

Das ist beabsichtigt. Jedes Produkt behält ein vollständiges Bild der Schwachstellen, die die von ihm verwalteten Hosts betreffen, und Berichte, SLAs und Metriken bleiben für jedes Produkt unabhängig.

Die Zuordnung erfolgt anhand des im Scan gefundenen Host-Werts (der vollständig qualifizierte Domänenname, ersatzweise die IP-Adresse), sodass jedes Produkt, das diesen Host bereits besitzt, eine Kopie des Befunds erhält.
