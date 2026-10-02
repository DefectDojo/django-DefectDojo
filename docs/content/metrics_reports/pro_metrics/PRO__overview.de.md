---
title: Übersicht der Pro-Metriken
description: So nutzen Sie Metriken in DefectDojo Pro
audience: pro
weight: 2
---

Die DefectDojo Pro UI bietet verschiedene Metriken-Dashboards, um Ihre aktuelle Sicherheitslage zu visualisieren. Jedes Dashboard ermöglicht es Stakeholdern auf unterschiedlichen Ebenen der Organisation, fundierte Entscheidungen zu treffen, ohne Rohdaten interpretieren oder einzelne Befunde durchsuchen zu müssen. Zu diesen Dashboards gehören:
* [Executive Insights](/metrics_reports/pro_metrics/pro__executive_insights/#main-content)
* [Priority Insights](/metrics_reports/pro_metrics/pro__priority_insights/#main-content)
* [Program Insights](/metrics_reports/pro_metrics/pro__program_insights/#main-content)
* [Remediation Insights](/metrics_reports/pro_metrics/pro__remediation_insights/#main-content)
* [Tool Insights](/metrics_reports/pro_metrics/pro__tool_insights/#main-content)

![Metriken-Übersicht](images/metrics_image1.png)

## Metriken-Funktionen

Bevor wir auf die einzelnen Dashboards näher eingehen, lohnt sich ein Blick auf einige Gemeinsamkeiten, die allen Dashboards gemein sind.

### Filtern

Alle Metriken können nach Zeitraum, Organisation, Asset und Tag gefiltert werden. Nachdem Sie den Filter wie gewünscht angepasst haben, müssen Sie auf Apply Filter klicken, damit der Filter wirksam wird. Wenn Sie ein PDF aller Diagramme, Tabellen und Grafiken auf dem Dashboard mit der aktuell angewendeten Filterung exportieren möchten, klicken Sie auf Export as PDF. 

Der Filterzeitraum ist auf das vergangene Jahr begrenzt, kann aber ansonsten auf die vergangenen 7, 14, 30, 90 oder 180 Tage eingestellt werden.

Beachten Sie, dass die Filterparameter in der URL abgebildet werden, sodass Sie mehrere Seiten mit unterschiedlichen Filterparametern als Lesezeichen speichern können.  Das ist nützlich für schnellen Zugriff oder um durchgängig eine bestimmte Art von Bericht zu erzeugen.

### Untermenüs 

Jedes Diagramm verfügt oben rechts über ein ⋮-Kebab-Menü mit folgenden Funktionen:
* Force Refresh — Aktualisiert manuell, um neue Änderungen in den Daten zu übernehmen. 
* Expand Plot — Öffnet dasselbe Diagramm in einem größeren Pop-up-Fenster.
* Download Plot as SVG — Lädt das Diagramm als SVG-Datei herunter.
* View as Table — Zeigt die Daten des Diagramms in Tabellenform an.
    * Jede Spalte der Tabelle kann per Klick auf- oder absteigend sortiert werden. Sie können auch jede Tabelle herunterladen.

![Inhalt des Kebab-Menüs](images/metrics_image2.png)

### Zugriff

Der Bereich Metriken zeigt nur Daten aus den Organisationen und Assets an, für die der jeweilige Benutzer über die entsprechenden Berechtigungen verfügt. Ein Benutzer mit auf ein einzelnes Asset beschränktem Zugriff sieht nur Metriken für dieses Asset; hat er keinen Zugriff auf die anderen Assets innerhalb der übergeordneten Organisation, werden Daten aus diesen anderen Assets nicht in den Metriken angezeigt. 

### Daten in Diagrammen anzeigen

Die X-Achse von Liniendiagrammen bildet stets den aktuellen Zeitraumfilter ab. Wenn Sie den Cursor über ein Liniendiagramm bewegen, erscheint ein Fenster mit der Anzahl der Werte auf der Y-Achse zu diesem Zeitpunkt. 

![Pop-up-Fenster des Diagramms](images/metrics_image3.png)

### Ergebnisse ein-/ausblenden

Benutzer können bestimmte Kategorien von Befunden im Diagramm ein- oder ausblenden, indem sie auf die jeweilige Farbe/den jeweiligen Namen oben im Diagramm klicken. 

Wenn Sie zum Beispiel im folgenden Diagramm Active Findings by Severity nur Befunde mit dem Schweregrad Hoch oder Kritisch sehen möchten, klicken Sie oben auf Mittel, Niedrig und Info, um diese Ergebnisse aus dem Diagramm zu entfernen. Ein erneuter Klick auf Mittel, Niedrig und Info lässt diese Ergebnisse wieder erscheinen. 

![Animation zum Ein-/Ausblenden von Diagrammergebnissen](images/metrics_image4.gif)
