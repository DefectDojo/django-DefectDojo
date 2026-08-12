---
title: 🎨 Änderungen an der Pro-UI
description: Arbeiten mit unterschiedlichen Benutzeroberflächen in DefectDojo
draft: 'false'
weight: 5
audience: pro
aliases:
- /en/about_defectdojo/ui_pro_vs_os
---

In late 2023, DefectDojo, Inc. veröffentlichte eine neue Benutzeroberfläche für DefectDojo Pro, die inzwischen die Standardoberfläche dieser Edition ist.

Die Pro-UI bringt DefectDojo folgende Verbesserungen:

- Modernes und schlankes Design mit Vue.js.
- Optimierte Datenübertragung und Ladezeiten, besonders bei großen Datenmengen.
- Zugriff auf neue Pro-Funktionen, einschließlich [Upstream Connectors](/connectors/upstream/about/), [Universal Importer](/import_data/pro/specialized_import/external_tools/) und [Pro-Metriken](/metrics_reports/pro_metrics/pro__overview/)-Ansichten.
- Verbesserte UI-Workflows: bessere Filterung, Dashboards und Navigation.

## Wechsel zur Pro-UI

Um auf die Pro-UI zuzugreifen, öffnen Sie Ihr Benutzeroptionen-Menü oben rechts.  Über dasselbe Menü können Sie auch zur klassischen UI zurückwechseln.

![image](images/beta-classic-uis.png)

## Navigationsänderungen

![image](images/pro_ui_overview.png)

1. Die **Seitenleiste** wurde in vier übergeordnete Kategorien neu gegliedert: Dashboards, Import, Manage und Settings.

2. Die Homepage, die [KI-gestützten nativen API-Verbindungsfunktionen](/metrics_reports/ai/mcp_server_pro/), Pro-Metriken und die Kalenderansicht sind alle unter Dashboards zugänglich.

4. Importmethoden finden Sie im Bereich Import: Richten Sie [Connectors](/connectors/about/) ein, um Befunde aus Ihren Scannern abzurufen (Upstream) oder sie an Issue-Tracker weiterzugeben (Downstream), verwenden Sie das Formular [Add Findings](/import_data/import_scan_files/pro__import_scan_ui/), um Befunde hinzuzufügen, nutzen Sie [Smart Upload](/import_data/pro/specialized_import/smart_upload/) für Infrastruktur-Scanning-Tools, oder verwenden Sie unsere externen Tools—[Universal Importer und DefectDojo CLI](/import_data/pro/specialized_import/external_tools/)—um sowohl den Import- als auch den Reimport-Prozess von Befunden und zugehörigen Objekten zu vereinfachen.

5. Im Bereich **Manage** können Sie verschiedene Objekte in der [Produkthierarchie](/asset_modelling/os_hierarchy/product_hierarchy/) einsehen, mit Ansichten für Produkttypen, Produkte, Engagements, Tests, Befunde, Risikoakzeptanzen, Endpunkte und Komponenten.  Es gibt zusätzliche Bereiche zum Erstellen von Berichten (Report Builder), zur Nutzung von Umfragen (Surveys) sowie eine [Rules Engine](/automation/rules_engine/about/). 

5. Im Bereich **Settings** können Sie Ihre DefectDojo-Instanz konfigurieren, einschließlich Lizenz, Cloud-Einstellungen, Benutzer, Feature-Konfiguration und administrativen Enterprise-Einstellungen. (Integrationen wurden nach **Import > Connectors > Downstream Connectors** verschoben.)

6. Der Bereich **Settings** enthält die administrativen Seiten, gruppiert als System, Users & Permissions, Finding Workflow, Configuration, Notifications, Operations und License & Support, sowie eine Seite **All Settings**, die alle auflistet und durchsuchbar macht. Siehe [Das Settings-Menü](/navigation/pro__settings_menu/).

7. Die Pro-UI verfügt außerdem über ein **neues Tabellenformat**, das in der [Produkthierarchie](/asset_modelling/os_hierarchy/product_hierarchy/) zur besseren Navigation eingesetzt wird.  Jede Spalte kann angeklickt werden, um einen entsprechenden Filter anzuwenden, und Spalten können neu angeordnet werden, um Daten so darzustellen, wie Sie es möchten.

8. Die Tabelle verfügt außerdem über ein Menü **„Toggle Columns“**, mit dem Spalten zur Tabelle hinzugefügt oder daraus entfernt werden können.

## Filtern der Tabelle

In diesem Screenshot filtern wir nach allen Befunden, die sich in „Sams Awesome Product“ befinden. Sobald wir auf Apply klicken, wird der Inhalt dieser Befundliste entsprechend dem gewählten Filter aktualisiert.

![image](images/pro_ui_sams_filter.png)

## Neue Dashboards

Neue Metrik-Visualisierungen sind in der Pro-UI enthalten. Alle diese Berichte können gefiltert und als PDF exportiert werden, um sie mit einem größeren Publikum zu teilen.

![image](images/program_insights.png)

- Das Dashboard **Executive Insights** zeigt den aktuellen Status Ihrer Produkte und Produkttypen.
- **Priority Insights** zeigt die kritischsten Befunde mit der Möglichkeit, nach verschiedenen Zeiträumen, Produkttypen, Produkten und Tags zu filtern.
- Das Dashboard **Program Insights** zeigt die Effektivität Ihres Sicherheitsteams sowie die Kosteneinsparungen, die sich aus der Trennung von Duplikaten und Falsch-positiven von verwertbaren Befunden ergeben.
- **Remediation Insights** zeigt, wie effektiv Ihr Team Befunde behebt.
- **Tool Insights** zeigt, wie effektiv Ihre Toolsammlung (und die Upstream-Connector-Pipelines) Sicherheitslücken erkennt und meldet.
