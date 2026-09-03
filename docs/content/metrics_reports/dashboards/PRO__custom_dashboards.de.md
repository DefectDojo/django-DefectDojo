---
title: Anpassbare Dashboards
description: Erstellen Sie in DefectDojo Pro personalisierte Dashboards aus Widgets,
  die Sie per Drag-and-Drop auf einem Raster anordnen
draft: false
audience: pro
weight: 10
slug: custom-dashboards
aliases:
- /de/en/customize_dojo/dashboards/about_custom_dashboard_tiles
- /de/metrics_reports/dashboards/about_custom_dashboard_tiles
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Anpassbare Dashboards (Layouts, Widgets und der Widget-Katalog) sind eine DefectDojo-Pro-Funktion. Sie sind standardmäßig deaktiviert — ein Superuser kann sie unter **Settings > Feature Flags** sowohl auf Cloud- als auch auf On-Premise-Instanzen aktivieren.</span>

Mit den anpassbaren Dashboards von DefectDojo Pro kann jeder Benutzer seine eigene Startseite aus **Widgets** zusammenstellen — Zählern, Diagrammen, Bestenlisten, Feeds und Notizen —, die per Drag-and-Drop auf einem Raster angeordnet werden. Anstelle eines einzigen festen Dashboards für alle erstellen Sie die **Layouts**, die für Sie relevant sind: eine Management-Übersicht, eine Triage-Warteschlange, ein Board zur Behebungsgeschwindigkeit, eine Ansicht zur Scanner-Effektivität. Sie können Layouts privat halten, sie für Ihr gesamtes Team veröffentlichen, eines als Standard-Startseite festlegen und jedes Layout (Ihr eigenes oder eine gemeinsame Vorlage) als Ausgangspunkt klonen.

![A DefectDojo Pro customizable dashboard — the Default Dashboard layout.](images/pro_dashboard_v2_default.png)

## Vergleich mit Open Source

Open-Source-DefectDojo verfügt über ein einziges, integriertes [Haupt-Dashboard](../introduction_dashboard/) mit einem festen Satz an Übersichtskarten und Diagrammen, die ein Superuser ein- oder ausblenden kann. Es ist für jeden Benutzer gleich.

DefectDojo Pro ersetzt diese feste Seite durch **benutzerindividuelle, anpassbare Dashboards**. Sie legen fest, welche Widgets angezeigt werden, wie sie gefiltert werden und wo sie im Raster platziert sind. Sie können beliebig viele benannte Layouts erstellen, zwischen ihnen wechseln, sie mit Ihrem Team teilen und das gesamte System über die [REST-API](../custom-dashboards-api/) oder ein [LLM](../custom-dashboards-llm/) steuern.

> **💡 Tipp:** In DefectDojo Pro wurden **Assets** früher **Produkte** und **Organisationen** früher **Produkttypen** genannt. Die Benutzeroberfläche verwendet die neue Terminologie, aber einige zugrunde liegende Widget-Einstellungen verwenden weiterhin die alten Namen — beispielsweise erwarten die meisten Widgets ein `model` mit dem Wert `finding`, `product`, `engagement` oder `test`. Wo dies relevant ist, wird es unten erläutert.

## Anpassbare Dashboards aktivieren

Anpassbare Dashboards sind standardmäßig deaktiviert. Ein Superuser kann sie unter **Settings > Feature Flags** aktivieren, sowohl auf Cloud- als auch auf On-Premise-Instanzen. Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Sobald die Funktion aktiviert ist, zeigt die Seite **🏠 Home** Ihr anpassbares Dashboard an, und die [Dashboards-REST-API](../custom-dashboards-api/) wird verfügbar.

> **🔑 Wichtig:** Solange die Funktion deaktiviert ist, behält die Startseite das bisherige Dashboard bei, und jeder `/api/v2/dashboards/`-Endpunkt gibt `403 Dashboards 2.0 is not enabled.` zurück. Das Aktivieren ändert **nicht** den Datenzugriff eines Benutzers — jedes Widget respektiert weiterhin die rollenbasierte Zugriffskontrolle von DefectDojo, sodass jeder Benutzer stets nur die Befunde, Assets und anderen Datensätze sieht, für die er berechtigt ist.

## Grundkonzepte

Ein anpassbares Dashboard besteht aus wenigen einfachen Bausteinen.

### Layouts

Ein **Layout** ist ein benanntes Dashboard: eine Sammlung von Widgets und ihren Positionen im Raster. Jedes Layout gehört Ihnen, und Sie können beliebig viele davon anlegen — zum Beispiel ein Board »Daily Triage« und ein separates »Exec Overview«. Ein Layout speichert drei Dinge:

- **widgets** — die geordnete Liste der enthaltenen Widgets, jedes mit eigenem Typ, Titel und Konfiguration.
- **layout** — wo jedes Widget sitzt und wie groß es im Raster ist.
- **settings** — Anzeigeoptionen auf Layout-Ebene.

Wenn Sie die anpassbaren Dashboards zum ersten Mal öffnen, erhalten Sie von DefectDojo eine persönliche Kopie der Startvorlage **Default Dashboard**, damit Sie nie vor einer leeren Seite stehen.

### Widgets

Ein **Widget** ist ein einzelnes Panel im Dashboard. Jedes Widget ist eine Instanz eines **Typs** aus dem Katalog (ein Zähler, ein Diagramm, eine Top-N-Bestenliste usw.) und trägt seine eigene **Konfiguration**: welches Daten**modell** es liest (`finding`, `product`, `engagement` oder `test`), welche **Filter** es eingrenzen, und typspezifische Anzeigeoptionen wie Diagrammtyp, Farben oder Gruppierung. Zwei Widgets desselben Typs mit unterschiedlichen Filtern sind vollständig unabhängig voneinander.

Jedes Widget verfügt außerdem über ein optionales **Auto-Refresh-Intervall** (aus, 30 Sekunden, 1 Minute, 5 Minuten oder 15 Minuten) und einen bearbeitbaren **Titel**.

### Der Widget-Katalog

Der **Katalog** ist das feste Menü der von der Plattform unterstützten Widget-Typen, gegliedert in vier Kategorien — **Numbers**, **Charts**, **Lists & Feeds** und **Static & Utility**. Wenn Sie ein Widget hinzufügen, wählen Sie dessen Typ aus dem Katalog. Der Katalog ist auch über die [API](../custom-dashboards-api/) verfügbar, sodass Skripte und LLMs die verfügbaren Widget-Typen und eine bewährte Startkonfiguration für jeden Typ ermitteln können. Die vollständige Liste finden Sie unten unter [Der Widget-Katalog](#the-widget-catalog-1).

### Das Raster

Widgets werden auf einem **12-spaltigen Raster** platziert. Im Bearbeitungsmodus ziehen Sie Widgets, um sie zu verschieben, und ziehen die untere rechte Ecke, um sie in der Größe zu ändern; das Raster verdichtet sich nach oben, um Lücken zu füllen. Jeder Widget-Typ hat sinnvolle Mindest- und Höchstgrößen, damit Diagramme und Tabellen lesbar bleiben.

### Teilen, Klonen und Standardeinstellungen

- **Standard** — eines Ihrer Layouts ist Ihr **Standard**: dasjenige, das beim Öffnen der Startseite geladen wird. Sie können jederzeit ändern, welches Layout Ihr Standard ist.
- **Klonen** — kopieren Sie ein beliebiges Layout (eines Ihrer eigenen oder eine gemeinsame Vorlage) als neuen, unabhängigen Ausgangspunkt in Ihren eigenen Bereich. Beim Klonen erhält die Kopie eigene Widgets, sodass das Bearbeiten des Klons das Original nie beeinflusst.
- **Teilen** — veröffentlichen Sie eines Ihrer Layouts als **gemeinsames Layout** für das gesamte Team. Andere Benutzer können es sehen und klonen, aber nur ein **Maintainer** des Teams kann ein gemeinsames Layout veröffentlichen, bearbeiten oder die Freigabe aufheben. Das Teilen eines Layouts teilt nur dessen *Design* — jeder Betrachter sieht weiterhin nur die Daten, die seine eigenen Berechtigungen zulassen.
- **Start- und gemeinsame Vorlagen** — DefectDojo liefert eine Reihe kuratierter **gemeinsamer Vorlagen**, die Sie als Ausgangspunkt klonen können (siehe [Gemeinsame Vorlagen](#shared-templates) unten). Das **Default Dashboard** ist die spezielle »Start«-Vorlage, die neue Benutzer automatisch erhalten.

## Ein Dashboard in der Benutzeroberfläche erstellen

### Die Dashboard-Symbolleiste

Über die Symbolleiste am oberen Rand der Startseite wechseln und verwalten Sie Layouts. Sie enthält eine **Layout-Auswahl** (mit Badges, die Ihr Standardlayout und alle gemeinsamen Layouts/Vorlagen kennzeichnen) sowie Schaltflächen zum Erstellen eines **New Layout**, zum Öffnen von **Manage Layouts**, zum **Refresh** aller Widgets und zum Umschalten des **Edit**-Modus.

![The dashboard toolbar (highlighted): the layout picker, plus New Layout, Manage Layouts, Refresh, and Edit](images/pro_dashboard_v2_home.png)

### Schritt 1: Bearbeitungsmodus aufrufen

Klicken Sie auf **Edit**, um das Dashboard zu entsperren. Das Raster wird zieh- und größenveränderbar, und eine Schaltfläche **Add Widget** erscheint. Klicken Sie auf **Done**, wenn Sie fertig sind — der Bearbeitungsmodus wird auch automatisch deaktiviert, wenn Sie das Layout wechseln.

![A dashboard in edit mode, showing drag and resize handles](images/pro_dashboard_v2_edit_grid.png)

### Schritt 2: Ein Widget hinzufügen

Klicken Sie im Bearbeitungsmodus auf **Add Widget**, um die Auswahl zu öffnen. Sie hat zwei Reiter:

- **By Type** — durchsuchen Sie den Katalog nach Kategorie (Numbers, Charts, Lists & Feeds, Static & Utility). Jede Karte zeigt den Namen des Widgets und eine kurze Beschreibung. Die Auswahl eines Widgets fügt es dem Raster hinzu und öffnet dessen Konfigurationsdialog.
- **From Catalog** — starten Sie mit einem vorkonfigurierten Widget aus einer der gemeinsamen Vorlagen (zum Beispiel dem Diagramm »Findings by Severity« aus dem Default Dashboard). Diese sind bereits fertig konfiguriert und werden direkt auf das Raster gelegt.

![The Add Widget dialog, By Type tab](images/pro_dashboard_v2_add_widget.png)

### Schritt 3: Das Widget konfigurieren

Jedes Widget öffnet einen auf seinen Typ zugeschnittenen Konfigurationsdialog. Zu den gängigen Einstellungen gehören:

- **Title** — die im Widget angezeigte Überschrift.
- **Model** — welche Datensätze das Widget liest (Finding, Asset, Engagement oder Test), sofern zutreffend.
- **Filters** — eine eingebettete Listenansicht-Filteroberfläche, die das Widget genau auf die gewünschten Datensätze eingrenzt (zum Beispiel aktive Befunde mit Schweregrad Kritisch). Die hier gewählten Filter sind dieselben, die Sie auch auf der Listenseite des jeweiligen Objekts verwenden würden.
- **Refresh interval** — wie oft sich das Widget selbstständig neu lädt.
- **Type-specific options** — zum Beispiel Diagrammtyp und Gruppierungsdimension für ein Graph-Widget, Schwellenwerte für ein Gauge-Widget oder die Kennzahl für eine Top-N-Bestenliste.

![Configuring a Graph widget](images/pro_dashboard_v2_widget_config.png)

> **💡 Tipp:** Die Daten eines Widgets respektieren stets Ihre Berechtigungen. Enthält ein gemeinsames Layout ein Widget »My Work«, sieht jeder Betrachter *seine eigenen* Zuweisungen und Erwähnungen — nicht die des Layout-Autors.

### Schritt 4: Anordnen und speichern

Ziehen Sie Widgets, um sie neu anzuordnen, und ziehen Sie eine Ecke, um die Größe zu ändern. Verwenden Sie das Zahnrad-Symbol an einem Widget, um es neu zu konfigurieren, und das Papierkorb-Symbol, um es zu entfernen. Positions- und Größenänderungen werden automatisch laufend gespeichert. Klicken Sie auf **Done**, um den Bearbeitungsmodus zu verlassen.

### Layouts verwalten

Der Dialog **Manage Layouts** (die Zahnrad-Schaltfläche in der Symbolleiste) ist die zentrale Anlaufstelle für alles auf Layout-Ebene:

- **Your Layouts** — jedes Layout, das Ihnen gehört, umbenennen, als Standard festlegen, teilen/Freigabe aufheben, klonen oder löschen.
- **Create New** — ein neues, leeres Layout beginnen, um von Grund auf zu erstellen.
- **Shared Templates** — kuratierte und vom Team veröffentlichte Layouts nach Kategorie gruppiert durchsuchen und auf **Use Layout** klicken, um eines in Ihren eigenen Bereich zu klonen.

![The Manage Layouts dialog](images/pro_dashboard_v2_manage_layouts.png)

### Gemeinsame Vorlagen

DefectDojo liefert vier einsatzbereite gemeinsame Vorlagen, die Sie als Ausgangspunkt klonen können:

| Vorlage | Zweck |
|----------|---------|
| **Default Dashboard** | Die klassische Startansicht — 12 Zähler auf einen Blick, Schweregrad-Diagramme sowie Assets mit der besten/schlechtesten Bewertung. Dies ist die Startvorlage, die jeder neue Benutzer automatisch erhält. |
| **Priority Layout** | Ein auf Triage ausgerichtetes Board rund um Befund-Priorität und -Risiko. |
| **Mitigation Layout** | Ein Board zur Behebungsgeschwindigkeit (Schließungstrends, MTTR/MTTD, Alterung). |
| **Tool Layout** | Ein Board zur Scanner-Effektivität rund um Testtypen und aktuelle Scan-Aktivität. |

> **💡 Tipp:** Das Klonen einer Vorlage erstellt eine unabhängige Kopie. Passen Sie den Klon frei an — Sie beeinflussen weder die Vorlage noch andere Benutzer, die sie ebenfalls klonen.

### Der Leerzustand

Ein brandneues Layout ohne Widgets zeigt die Aufforderung **»Build Your First Dashboard«**. Klicken Sie auf **Add Your First Widget**, um direkt in den Bearbeitungsmodus zu gelangen und mit der Auswahl von Widgets zu beginnen.

![The empty-layout state](images/pro_dashboard_v2_empty_state.png)

## Der Widget-Katalog

Die anpassbaren Dashboards liefern die folgenden Widget-Typen, gegliedert in vier Kategorien. Die meisten Widgets lesen eines von vier Modellen — `finding`, `product` (Assets), `engagement` oder `test` — und werden durch von Ihnen gewählte Filter eingegrenzt. Die vollständig detaillierten Konfigurationsoptionen für jedes Widget sind im [API-Leitfaden](../custom-dashboards-api/) dokumentiert.

### Numbers

Kennzahlen auf einen Blick — Zähler, KPIs und Anzeigeinstrumente.

| Widget | Was es zeigt |
|--------|---------------|
| **Count** | Eine einzelne Zahl aus einer gefilterten Abfrage — z. B. »Open Critical Findings« oder »Active Engagements«. Funktioniert mit finding / asset / engagement / test. |
| **KPI / Trend** | Eine Hauptkennzahl plus deren Veränderung gegenüber der Vorperiode, mit optionalem Sparkline-Diagramm. |
| **Gauge** | Ein als Bogenanzeige dargestelltes Verhältnis — ein »universe«-Filter als Nenner und ein »pass«-Filter als Zähler. Geeignet für SLA-Einhaltung, Behebungsrate oder Scan-Abdeckung, mit konfigurierbaren Warn-/OK-Schwellenwerten. |
| **License Usage** | Der Lizenznutzungsstatus Ihres Kontos mit einer Aufschlüsselung nach Einzelwerten (Datenbankgröße, wöchentliches Befundvolumen usw.). *Erfordert die Rolle Maintainer.* |
| **Scan Coverage** | Welcher Anteil der Assets innerhalb von 30 / 90 / 180 / 365 Tagen gescannt wurde, als mehrfenstrige Zusammenfassung. |

### Charts

Zeitreihen- und Verteilungsvisualisierungen.

| Widget | Was es zeigt |
|--------|---------------|
| **Graph** | Ein universelles Diagramm über ein beliebiges Modell und eine Gruppierungsdimension — Balken, Linie, Fläche, Kreis oder Ring. Z. B. Findings by Severity, Findings by Month. |
| **Sankey** | Ein Flussdiagramm von einer Quelldimension zu einer Zieldimension — z. B. Severity → Status. |
| **Sunburst** | Eine ein- oder zweistufige radiale Aufschlüsselung — z. B. Severity, dann Test Type innerhalb jedes Schweregrads. |
| **Risk Matrix** | Eine EPSS-Wahrscheinlichkeit-×-Risiko-Heatmap der Befunde — unten links sicher, oben rechts gefährlich. |
| **Priority Histogram** | Die Verteilung der **Priority**-Werte der Befunde aus der Priorisierungs-Engine, automatisch gruppiert. |
| **Rate by Category** | Ein Verhältnis pro Kategorie (Zähler / Nenner) — z. B. False-Positive-Rate nach Tool oder Behebungsrate nach Asset. |
| **Finding Velocity** | Erstellte im Vergleich zu geschlossenen Befunden im Zeitverlauf, zeigt, ob der Rückstand wächst oder schrumpft. |
| **MTTR / MTTD** | Mean Time to Remediate und Mean Time to Detect, als gepaarte Zeitreihen. |
| **Vulnerability Aging** | Offene Befunde nach Altersgruppe (0–30 Tage / 30–90 Tage / 90–180 Tage / 180+ Tage), gestapelt nach Schweregrad. |
| **Activity Heatmap** | Ein Kalender im GitHub-Stil mit täglicher Aktivität über ein gleitendes Zeitfenster. |
| **Portfolio Treemap** | Verschachtelte Rechtecke für eine Portfolio-Zusammenfassung (Organisation → Asset), nach Anzahl skaliert und nach Schweregrad eingefärbt. |

### Lists & Feeds

Rangierte Listen, Feeds und eingebettete Tabellen.

| Widget | Was es zeigt |
|--------|---------------|
| **Top-N Leaderboard** | Eine Rangliste in einem von zwei Modi: *aggregate* (Top-Dimensionsgruppen nach Anzahl, z. B. Top 10 CWEs) oder *records* (einzelne Top-Datensätze nach einer Kennzahl, z. B. Top 10 Assets nach Grade). |
| **Embedded Table** | Eine vollständige Listenansicht (Findings, Assets, Engagements, Tests, Risk Acceptances, Organizations oder Test Types) mit vordefinierten Filtern und Sortierung — inklusive Paginierung, Sortierung und CSV-Export. |
| **Recent Activity** | Ein scrollbarer Feed der zuletzt aktualisierten Datensätze, anklickbar zu den Detailseiten. |
| **SLA Burndown** | Befunde, die einer SLA-Überschreitung nahekommen, sortiert nach verbleibenden Tagen, mit Countdown-Badges. |
| **My Work** | Ihre persönliche Warteschlange — Zuweisungen, Erwähnungen und ausstehende Risikoakzeptanz-Prüfungen. Immer auf den Betrachter eingegrenzt. |
| **Saved Reports** | Ein-Klick-Zugriff auf Ihre gespeicherten Berichtsvorlagen. *Erfordert die Reporting-Funktion.* |

### Static & Utility

Notizen, Verknüpfungen und Struktur.

| Widget | Was es zeigt |
|--------|---------------|
| **Favorites** | Von Benutzern kuratierte Schnellzugriffe auf bestimmte Seiten in der Anwendung. |
| **Section Break** | Ein beschrifteter Trenner zur Gruppierung verwandter Widgets unter einer Überschrift. |
| **Markdown / Notes** | Ein eingebettetes Rich-Text-Panel für Überschriften, Kontextnotizen oder Referenzlinks. |
| **Quick Actions** | Ein-Klick-Aktionsschaltflächen, die zu einer gewählten Seite navigieren. |

## Nächste Schritte

- **[Dashboards mit der API automatisieren](../custom-dashboards-api/)** — entdecken Sie den Widget-Katalog, erstellen und aktualisieren Sie Layouts, und rendern Sie Widget-Daten über die REST-API, mit einem vollständigen Skript.
- **[Dashboards mit einem LLM erstellen](../custom-dashboards-llm/)** — lassen Sie ein LLM Dashboards für Sie entwerfen und erstellen (die Dashboards-API wurde mit Blick auf KI-Agenten entwickelt).
