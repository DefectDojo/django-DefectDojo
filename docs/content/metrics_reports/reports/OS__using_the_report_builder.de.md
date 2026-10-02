---
title: Verwendung des Report Builders
description: Einen benutzerdefinierten Bericht in Open-Source-DefectDojo erstellen,
  ausführen und abrufen
draft: false
audience: opensource
weight: 24
slug: using-the-report-builder
aliases:
- /de/en/share_your_findings/pro_reports/working_with_generated_reports
- /de/metrics_reports/reports/working_with_generated_reports
---

Mit dem Report Builder von DefectDojo können Sie einen benutzerdefinierten Bericht aus einer Reihe von Inhalts-Widgets zusammenstellen, ihn ausführen und das Ergebnis exportieren (zum Beispiel durch Drucken als PDF). Benutzerdefinierte Berichte können die Befunde oder Endpunkte zusammenfassen, die Sie mit einem externen Publikum teilen möchten, und können Branding sowie Standardtext enthalten.

> **Hinweis:** In Open-Source-DefectDojo erstellen Sie einen Bericht, führen ihn aus und rufen seine Ausgabe als einmaligen Vorgang ab. Berichtslayouts (Vorlagen) und die erzeugte Berichtsausgabe werden in der Open-Source-Version **nicht gespeichert**. Um ein Layout wiederzuverwenden, erstellen Sie es im Report Builder neu. Um wiederverwendbare Themes, Blocks und Templates zu speichern und einen dauerhaften Verlauf erzeugter Berichte zu führen, siehe den [Report Builder](../report-builder/) von DefectDojo Pro.

## Öffnen des Report Builders

Der Report Builder lässt sich über die Seite **📄 Berichte** in der Seitenleiste öffnen.

![image](images/Using_the_Report_Builder.png)

Die Seite des Report Builders ist in zwei Spalten aufgeteilt. In der linken Spalte **Report Format** gestalten Sie Ihren Bericht mithilfe von Widgets aus der rechten Spalte **Available Widgets**.

![image](images/Using_the_Report_Builder_2.png)

## Schritt 1: Berichtsoptionen festlegen

![image](images/Using_the_Report_Builder_3.png)

Im Bereich Report Options können Sie folgende Aktionen durchführen:

* Einen **Report Name** für den Bericht festlegen
* Benutzererstellte **Finding Notes** in den Bericht aufnehmen
* **Finding Images** in den Bericht aufnehmen
* Ein Kopfzeilen-**Image** für den Bericht hochladen

### Ein Kopfzeilenbild für Ihren Bericht auswählen

Um ein Bild am Anfang Ihres Berichts hinzuzufügen, klicken Sie auf die Schaltfläche **Choose File** und laden Sie ein Bild in DefectDojo hoch.

Das Bild wird automatisch an das Dokument angepasst und direkt oberhalb Ihres **Report Name** dargestellt.

![image](images/Using_the_Report_Builder_4.png)

## Schritt 2: Inhalte mit Widgets hinzufügen

Nachdem Sie Ihre Berichtsoptionen festgelegt haben, können Sie damit beginnen, Ihren Bericht mithilfe der Widgets von DefectDojo zu gestalten.

Widgets sind Inhaltselemente eines Berichts, die Sie per Drag-and-Drop in die Spalte **Report Format** einfügen. Der endgültige Bericht wird basierend auf der Position jedes Widgets erzeugt, wobei **Report Name** und **Header Image** oben dargestellt werden.

* Die Elemente Ihres Berichts können neu angeordnet werden, indem Sie Ihre Widgets per Drag-and-Drop in eine neue Reihenfolge bringen.
* Um ein Widget aus einem Bericht zu entfernen, klicken Sie es an und ziehen Sie es zurück in die rechte Spalte.
* Widgets können außerdem durch Klicken auf die graue Kopfzeile eingeklappt werden, um die Navigation durch den Report Builder zu erleichtern.
* Das Findings-Widget, das WYSIWYG-Widget und das Endpoints-Widget können jeweils mehrfach verwendet werden.

Weitere Informationen zu Berichts-Widgets finden Sie im [Widget-Verzeichnis für Berichte](./#report-widget-index).

## Schritt 3: Bericht ausführen und anzeigen

Sobald Sie die Erstellung Ihres Berichts abgeschlossen haben, können Sie ihn erzeugen, indem Sie unten im Bereich **Report Format** auf die grüne Schaltfläche **Run** klicken.

DefectDojo erzeugt den Bericht aus den von Ihnen zusammengestellten Widgets. Sobald die Erzeugung abgeschlossen ist, können Sie den resultierenden HTML-Bericht in Ihrem Browser anzeigen.

![image](images/Using_the_Report_Builder_14.png)

Ein erzeugter Bericht ist eine Momentaufnahme: Er spiegelt die Daten in DefectDojo zum Zeitpunkt der Ausführung wider und aktualisiert sich nicht automatisch, wenn sich Ihre Daten ändern.

## Schritt 4: Bericht exportieren

Berichte sind so aufgebaut, dass sie sich leicht exportieren oder drucken lassen.

Die einfachste Methode ist der Druck als PDF. Öffnen Sie bei geöffnetem HTML-Bericht in Ihrem Browser einen **Print**-Dialog und legen Sie **Save to PDF** als **Print Destination** fest.

![image](images/Using_the_Report_Builder_15.png)

## Vorschläge zur Berichtsformatierung

* WYSIWYG-Abschnitte können verwendet werden, um Finding-Listen zu kontextualisieren oder zusammenzufassen. Erwägen Sie, dieses Widget an mehreren Stellen in Ihrem Bericht einzusetzen, etwa zwischen Findings- oder Vulnerable-Endpoints-Widgets.

## Widget-Verzeichnis für Berichte

### Cover Page-Widget

Mit dem Cover Page-Widget können Sie eine Überschrift, eine Unterüberschrift und zusätzliche Metadaten für Ihren Bericht festlegen. Sie können pro Bericht nur eine einzige Cover Page verwenden.

![image](images/Using_the_Report_Builder_5.png)

### Executive Summary-Widget

Das Executive Summary-Widget dient dazu, Ihren Bericht auf einen Blick zusammenzufassen. Es enthält eine Überschrift (standardmäßig Executive Summary) sowie ein Textfeld, das beliebige Informationen enthalten kann, die Sie zur Zusammenfassung des Berichts für erforderlich halten.

![image](images/Using_the_Report_Builder_6.png)

Sie können in Ihrer Executive Summary auch **Include SLAs** aktivieren. Um Bilder, Markup-Formatierung oder alles über reinen Text hinaus hinzuzufügen, sollten Sie direkt nach der Executive Summary ein **WYSIWYG Content-Widget** einfügen.

* Sie können pro Bericht nur eine einzige Executive Summary verwenden.
* Wenn Ihr Bericht mehrere SLA-Konfigurationen enthält (zum Beispiel, weil Sie Befunde aus unterschiedlichen Produkten haben, die jeweils eigene SLA-Standards besitzen), wird jede SLA-Konfiguration in der Executive Summary als eigene Zeile aufgeführt.

### Severities-Widget

Da jede Organisation unterschiedliche Definitionen für die einzelnen Schweregrade hat, können Sie mit dem Severities-Widget die in Ihrem Bericht verwendeten Schweregrade zum besseren Verständnis definieren.

![image](images/Using_the_Report_Builder_7.png)

### Table of Contents-Widget

Das Table of Contents-Widget erstellt eine Liste aller Befunde in Ihrem Bericht für einen schnelleren Zugriff auf bestimmte Befunde. Das Inhaltsverzeichnis erstellt für jeden im Bericht enthaltenen Schweregrad eine eigene Überschrift. Jeder im Inhaltsverzeichnis aufgeführte Befund verfügt über einen Anker-Link, mit dem Sie schnell zum jeweiligen Befund im Bericht springen können.

![image](images/Using_the_Report_Builder_8.png)

* Sie können einen Abschnitt mit **Custom Content** hinzufügen, der Text unterhalb der Überschrift einfügt.
* Sie können ein Bild zum Table of Contents hinzufügen, indem Sie auf die Schaltfläche **Choose File** neben der Zeile **Image** klicken. Das hochgeladene Bild wird direkt oberhalb der ausgewählten Überschrift dargestellt. Bilder werden an das Dokument angepasst.

### WYSIWYG Content-Widget

Das WYSIWYG-Widget (What You See Is What You Get) kann verwendet werden, um Ihrem Bericht einen Abschnitt mit Text und Bildern hinzuzufügen. Sie können mehrere Kopien dieses Widgets hinzufügen, um andere Abschnitte Ihres Berichts mit Kontext zu versehen.

![image](images/Using_the_Report_Builder_9.png)

* WYSIWYG Content kann eine optionale Überschrift enthalten.
* Bilder können zu einem WYSIWYG-Widget hinzugefügt werden, indem Sie sie per Drag-and-Drop direkt in das Feld **Content** ziehen. In das Content-Feld eingefügte Bilder werden in voller Auflösung dargestellt.
* Sie können einem Bericht mehrere WYSIWYG-Widgets hinzufügen.

### Findings-Widget

Das Findings-Widget liefert eine Liste und Zusammenfassung jedes Befunds, den Sie in Ihren Bericht aufnehmen möchten. Mit Filtern können Sie den Umfang der einzuschließenden Befunde festlegen.

Das Findings-Widget ist in zwei Abschnitte unterteilt. Der obere Abschnitt enthält eine Liste von Filtern, mit denen Sie festlegen können, welche Befunde eingeschlossen werden sollen, und der untere Abschnitt enthält die resultierende Liste der Befunde nach Anwendung der Filter.

Um Filter auf Ihr Findings-Widget anzuwenden, legen Sie die Filterparameter fest und klicken Sie unten auf die Schaltfläche **Apply Filter**. Sie können die Ergebnisse Ihres Filters in der Befundeliste unterhalb des Filterbereichs überprüfen.

![image](images/Using_the_Report_Builder_10.png)

* Wie bei Widgets kann der Filterbereich durch Klicken auf die graue Filters-Überschrift ein- und ausgeklappt werden.
* Sie können Ihrem Bericht mehrere separate Findings-Widgets mit unterschiedlichen Filterparametern hinzufügen, wenn der Bericht mehr als eine Liste von Befunden enthalten soll.
* In diesen Listen werden gemäß der rollenbasierten Zugriffskontrolle nur die Befunde aufgeführt, für die Sie eine Zugriffsberechtigung haben.

#### Beispiel für eine gerenderte Befundeliste

![image](images/Using_the_Report_Builder_11.png)

### Vulnerable Endpoints-Widget

Das Vulnerable Endpoints-Widget ähnelt dem Findings-Widget. Mit diesem Widget können Sie alle Befunde für bestimmte Endpunkte auflisten und die Befundeliste nach Endpunkt statt nach Schweregrad sortieren.

Das Widget **Vulnerable Endpoints** listet jeden aktiven Befund für die ausgewählten Endpunkte auf. Anstatt eine einzige unsortierte Liste von Befunden zu erstellen, unterteilt diese Funktion sie nach ihrem jeweiligen Endpunktkontext.

Wie beim Findings-Widget ist auch das Vulnerable Endpoints-Widget in einen Filterbereich und eine Liste der aus den Filterparametern resultierenden Endpunkte unterteilt.

![image](images/Using_the_Report_Builder_12.png)

Legen Sie hier die Parameter für die einzuschließenden Endpunkte fest und klicken Sie unten auf die Schaltfläche **Apply Findings**. Sie können die Ergebnisse Ihres Filters in der Endpunktliste unterhalb des Filterbereichs überprüfen.

* Sie können Ihrem Bericht mehrere separate Vulnerable Endpoints-Widgets mit unterschiedlichen Filterparametern hinzufügen, wenn der Bericht mehr als eine Liste enthalten soll.
* In diesen Listen werden gemäß der rollenbasierten Zugriffskontrolle nur die Befunde aufgeführt, für die Sie eine Zugriffsberechtigung haben.

### ---- (Trennlinie)-Widget

Dieses Widget stellt eine hellgraue horizontale Linie dar, um Abschnitte voneinander zu trennen.

![image](images/Using_the_Report_Builder_13.png)
