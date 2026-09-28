---
title: DefectDojo-Hauptdashboard
description: Arbeiten mit der Startseite von DefectDojo
weight: 1
audience: opensource
aliases:
- /de/en/customize_dojo/dashboards/Introduction_dashboard
- /de/en/customize_dojo/dashboards/pro_dashboards
---

Das Dashboard ist wahrscheinlich die erste Seite, die Sie sehen, wenn Sie DefectDojo öffnen. Es fasst die Leistung Ihres Teams zusammen und bietet Tracking-Tools, mit denen Sie bestimmte Bereiche Ihrer Schwachstellenverfolgung überwachen können.

<div class="version-opensource">

![Bild](images/dashboard.png)

</div>
<div class="version-pro">

> **💡 DefectDojo Pro:** In DefectDojo Pro ist die Startseite ein vollständig **anpassbares Dashboard** — Sie bauen es aus Widgets auf und ordnen diese selbst an, statt das unten beschriebene feste Layout zu verwenden. Die Konzepte und eine Anleitung durch die UI finden Sie unter **[Customizable Dashboards](../custom-dashboards/)**. Der Rest dieser Seite beschreibt das Open-Source-Hauptdashboard.

</div>

<div class="version-opensource">

## Dashboard-Komponenten

Das Open-Source-Dashboard bietet mit den folgenden integrierten Komponenten einen Überblick über Ihre Sicherheitslage:

### Zusammenfassungskarten

Die obere Zeile des Dashboards zeigt vier Zusammenfassungskarten, die Ihnen auf einen Blick einen Überblick über die Aktivität geben:

* **Active Engagements** — Gesamtzahl der aktuell offenen Engagements über alle Produkte hinweg.
* **Findings Last 7 Days** — neue Befunde, die in der vergangenen Woche erstellt wurden.
* **Closed in Last 7 Days** — Befunde, die kürzlich behoben wurden.
* **Accepted in Last 7 Days** — Befunde, deren Risiko kürzlich akzeptiert wurde.

Jede Karte verlinkt direkt auf die entsprechende gefilterte Liste, sodass Sie mit einem Klick tiefer einsteigen können.

### Historical Finding Severity

Dieses Kreisdiagramm schlüsselt alle jemals in DefectDojo erstellten Befunde nach Schweregrad auf (Kritisch, Hoch, Mittel, Niedrig, Info) und gibt Ihnen so einen schnellen Überblick über die Gesamtverteilung der Schwachstellen in Ihrer Umgebung.

### Reported Finding Severity by Month

Dieses Liniendiagramm stellt Volumen und Schweregrad eingehender Befunde im Monatsvergleich dar und hilft Ihnen, Trends zu erkennen, etwa Spitzen nach der Integration eines neuen Scanners oder eine anhaltende Verbesserung durch Behebungsmaßnahmen.

### Dashboard-Konfiguration

Superuser können festlegen, welche Diagramme auf dem Dashboard angezeigt werden. Navigieren Sie zum Zahnradmenü oben rechts und wählen Sie **Edit Dashboard Configuration**, um Folgendes ein- oder auszublenden:

* **Display Graphs** — steuert die Diagramme Historical Finding Severity und Reported Finding Severity.
* **Display Surveys** — steuert die Tabelle Unassigned Answered Engagement Questionnaires.
* **Display Data Tables** — steuert die Tabellen Top 10 / Bottom 10 Graded Products.

Wählen Sie **Reset Dashboard Configuration** aus demselben Menü, um die Standardeinstellungen wiederherzustellen.

</div>
