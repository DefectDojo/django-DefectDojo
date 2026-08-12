---
title: Reimport
description: Erfahren Sie, wie Sie Daten manuell, über die API oder per Connector
  importieren
weight: 2
aliases:
- /en/connecting_your_tools/import_scan_files/using_reimport
---

Wenn in DefectDojo ein Test erstellt wird (entweder im Voraus oder durch den Import einer Scan-Datei), kann der Test um neue Befunddaten erweitert werden.

Nehmen wir zum Beispiel an, Sie haben eine CI/CD-Pipeline, die so konzipiert ist, dass sie täglich einen neuen Bericht an DefectDojo sendet. Anstatt für jeden „Lauf“ der Pipeline einen neuen Test oder ein neues Engagement zu erstellen, können Sie jeden Bericht mithilfe von **Reimport** in denselben Test einfließen lassen.

## Reimport: Zusammenfassung des Ablaufs

Das erneute Importieren von Daten ersetzt keine alten Daten im Test, sondern vergleicht die eingehende Scan-Datei mit den vorhandenen Scan-Daten in einem Test, um fundierte Entscheidungen zu treffen:

* Welche Schwachstellen sind laut der neuesten Datei noch vorhanden?
* Welche Schwachstellen sind nicht mehr vorhanden?
* Welche Schwachstellen wurden zuvor behoben, sind aber inzwischen wieder aufgetreten?

Der Test verfolgt und trennt jede Scan-Version über die **Import History,** sodass Sie die Änderungen der Befunde in Ihrem Test im Zeitverlauf nachvollziehen können.

![Bild](images/using_reimport.png)

## Reimport-Logik: Erstellen, Ignorieren, Schließen oder Wiedereröffnen

Bei Verwendung von Reimport vergleicht DefectDojo die eingehenden Scan-Daten mit den vorhandenen Scan-Daten und wendet dann wie folgt Änderungen auf die im Test enthaltenen Befunde an:

### Befunde erstellen

Alle Schwachstellen, die im vorherigen Import nicht enthalten waren, werden dem Test automatisch als neue Befunde hinzugefügt.

### Bestehende Befunde ignorieren

Wenn eingehende Befunde mit bereits vorhandenen Befunden übereinstimmen, werden die eingehenden Befunde verworfen, statt als Duplikate erfasst zu werden. Diese Befunde wurden bereits erfasst \- es muss kein neues Befund-Objekt hinzugefügt werden. Die Testseite zeigt diese Befunde als **Left Untouched** an.

### Felder fix_available und fix_version

Wenn eingehende Befunde mit bereits vorhandenen Befunden übereinstimmen, wird beim eingehenden Befund geprüft, ob sich die Felder `fix_available` und `fix_version` unterscheiden, und sie werden gegebenenfalls aktualisiert. Diese Befunde wurden bereits erfasst \- es muss kein neues Befund-Objekt hinzugefügt werden. Die Testseite zeigt diese Befunde als **Left Untouched** an.

### Befunde schließen

Wenn im Test bereits Befunde vorhanden sind, die im eingehenden Bericht nicht enthalten sind, können Sie diese Befunde automatisch auf Inaktiv und Behoben setzen lassen (unter der Annahme, dass diese Schwachstellen seit dem vorherigen Import behoben wurden). Die Testseite zeigt diese Befunde als **Closed** an.

Wenn Sie **nicht** möchten, dass alte Befunde geschlossen werden, können Sie dieses Verhalten bei Reimport deaktivieren:

* Deaktivieren Sie das Kontrollkästchen **Close Old Findings**, wenn Sie die UI verwenden
* Setzen Sie `close_old_findings` auf `False`, wenn Sie die API verwenden (bei diesem Endpunkt ist `close_old_findings` standardmäßig `True`)

**Hinweis zum Geltungsbereich:** Anders als beim Import kann Reimport beim Schließen von Befunden nie andere Tests im Engagement berücksichtigen. Der Geltungsbereich für das Schließen von Befunden ist stets auf den Ziel-Test beschränkt.

Die Funktion `close_old_findings` berücksichtigt außerdem das Feld `service`: Nur Befunde mit identischem `service`-Wert (oder ohne `service`-Wert, falls keiner angegeben wurde) kommen für die Schließung infrage.

### Befunde wiedereröffnen

* Wenn geschlossene Befunde in einem Reimport erneut auftauchen, werden sie automatisch wiedereröffnet. Es wird angenommen, dass diese Schwachstellen trotz vorheriger Behebung erneut aufgetreten sind. Die Testseite verfolgt diese Befunde als **Reactivated**.

Wenn Sie einen Scanner ohne Triage verwenden oder aus anderen Gründen nicht möchten, dass geschlossene Befunde reaktiviert werden, können Sie dieses Verhalten bei Reimport deaktivieren:

* Setzen Sie **do\_not\_reactivate** auf **True**, wenn Sie die API verwenden
* Aktivieren Sie das Kontrollkästchen **Do Not Reactivate**, wenn Sie die UI verwenden

### Verhalten von Force Active und Force Verified

Wenn Sie bei einem Reimport `active=true` (UI: **Force Active**) oder `verified=true` (UI: **Force Verified**) setzen, wird der entsprechende Status bei jedem übereinstimmenden Befund gesetzt, **einschließlich Befunden, die andernfalls aufgrund einer Behebung inaktiv wären**. Das ist dasselbe oben beschriebene Reaktivierungsverhalten, nur bei jedem eingehenden Befund explizit gemacht.

Force Active und Force Verified überschreiben **nicht** Status, die eine ausdrückliche Entscheidung eines Benutzers oder Systems darüber darstellen, warum ein Befund nicht aktiv sein sollte:

| Status | Does Force Active reactivate it? | Why |
|---|---|---|
| Mitigated / Closed | Ja | Wie beim Standard-Reaktivierungsverhalten |
| Risk Accepted | Nein | Der Befund ist inaktiv, weil ein Benutzer das Risiko ausdrücklich akzeptiert hat; Reimport darf diese Entscheidung nicht stillschweigend aufheben |
| Duplicate | Nein | Der Befund ist inaktiv, weil die Deduplizierung ihn als Duplikat eines anderen Befunds markiert hat; aktiv sein sollte der ursprüngliche Befund, nicht das Duplikat |
| False Positive | Nein | Dieselbe Begründung wie bei Risk Accepted — eine ausdrückliche Triage-Entscheidung |
| Out of Scope | Nein | Dieselbe Begründung wie bei Risk Accepted — eine ausdrückliche Triage-Entscheidung |

Wenn ein Befund mit dem Status Risk Accepted oder Duplicate wieder aktiv werden soll, müssen Sie zuerst die Risikoakzeptanz oder die Duplikat-Markierung entfernen. Force Active allein genügt dafür nicht.

## Das Reimport-Formular öffnen

Das Formular **Re\-Import Findings** ist auf jeder Testseite über das Dropdown-Menü **⚙️Gear** erreichbar.

![Bild](images/using_reimport_2.png) 

Das Formular **Re\-import Findings** erlaubt es **nicht**, einen anderen Scan-Typ zu importieren oder das Ziel der Befunde zu ändern, die Sie hochladen möchten. Wenn Sie eines dieser Dinge tun möchten, benötigen Sie das **Import Scan Form**.

## Mit der Import History arbeiten

Die Import History für einen bestimmten Test wird unter der Überschrift **Test Overview** auf der Seite **Test** angezeigt.

Diese Tabelle zeigt jeden Import oder Reimport als einzelne Zeile mit einem **Timestamp**, sowie den Spalten **Branch Tag, Build ID, Commit Hash** und **Version**, sofern diese angegeben wurden.

![Bild](images/using_reimport_3.png)

### Aktionen

Diese Überschrift zeigt die Aktionen an, die durch einen Import/Reimport ausgeführt wurden.

* **\# created gibt die Anzahl der neuen Befunde an, die zum Zeitpunkt des Import/Reimport erstellt wurden**
* **\# closed zeigt die Anzahl der Befunde, die durch einen Reimport geschlossen wurden (weil sie im eingehenden Bericht nicht mehr vorhanden waren).**
* **\# left untouched zeigt die Anzahl offener Befunde, die durch einen Reimport unverändert blieben (weil sie auch im eingehenden Bericht vorhanden waren).**
* **\#** **reactivated** zeigt geschlossene Befunde, die durch einen eingehenden Reimport wiedereröffnet wurden.

## Reimport-Deduplizierung

Reimport entscheidet mithilfe der Einstellungen für **[Reimport Deduplication](/triage_findings/finding_deduplication/about_deduplication/)**, ob ein eingehendes Element mit einem vorhandenen Befund übereinstimmt. Das ist etwas anderes als „Same Tool Deduplication“ und „Cross Tool Deduplication“, die erst greifen, nachdem Befunde bereits existieren.

Wenn Sie feststellen, dass Reimport alte Befunde schließt und neue Befunde erstellt, obwohl sich nur ein untergeordnetes Attribut geändert hat (zum Beispiel eine verschobene Zeilennummer), stellen Sie die **Reimport Deduplication** für dieses Tool so ein, dass stabile Kennungen verwendet werden, die diese Attribute ignorieren (zum Beispiel Unique ID From Tool).

**DefectDojo Pro** kann dieses Problem für Tools ohne verlässliche eindeutige IDs direkt lösen: Durch Aktivieren von **[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/)** erkennt Reimport einen Befund, dessen Fundort sich verschoben hat — eine verschobene Zeile, eine Dateiumbenennung, eine verschobene URL oder eine Abhängigkeits-Versionsanhebung — als *denselben* Befund, aktualisiert ihn direkt und bewahrt seinen Standortverlauf.

## Reimport über die API - besonderer Hinweis

Beachten Sie, dass der API-Endpunkt /reimport sowohl **einen bestehenden Test erweitern** kann (Anwendung der in diesem Artikel beschriebenen Methode) **als auch einen neuen Test** mit neuen Daten erstellen kann \- ein anfänglicher Aufruf von `/import` oder das vorherige Einrichten eines Tests ist nicht erforderlich.

Um mehr darüber zu erfahren, wie Sie mit DefectDojo eine automatisierte CI/CD-Pipeline erstellen, lesen Sie unseren Leitfaden [hier](/automation/api/api-v2-docs/).
