---
title: Report Builder
description: Erstellen Sie benutzerdefinierte, wiederverwendbare Berichte in DefectDojo
  Pro mit Themes, Blocks und Templates
draft: false
audience: pro
weight: 20
slug: report-builder
aliases:
- /en/share_your_findings/pro_reports/using_the_report_builder
- /metrics_reports/reports/using_the_report_builder
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Der wiederverwendbare Report Builder (Themes, Blocks, Templates und gespeicherte Generated Reports) ist eine DefectDojo Pro-Funktion, die sich derzeit in der Beta-Phase befindet.</span>

Mit dem DefectDojo Pro Report Builder können Sie ansprechende Berichte aus wiederverwendbaren Teilen zusammenstellen, sodass Sie die Bausteine einmal erstellen und überall wiederverwenden können, anstatt einen Bericht jedes Mal von Grund auf neu aufzubauen. Sie erreichen ihn über den Bereich **📄 Berichte** in der Seitenleiste.

## Vergleich mit Open Source

Die Open-Source-Version von DefectDojo kann einen Bericht erstellen, ausführen und Ihnen die Ausgabe zur Verfügung stellen, speichert jedoch **keine** Berichtsvorlagen und persistiert die erzeugten Berichte nicht dauerhaft. Jeder Bericht ist ein einmaliger Vorgang.

DefectDojo Pro macht aus dem Reporting wiederverwendbare Bausteine. Sie speichern **Themes**, **Blocks** und **Templates**, die Sie beliebig kombinieren, austauschen und wiederverwenden können, und jeder ausgeführte Bericht wird als **Generated Report** gespeichert, den Sie später herunterladen oder erneut ausführen können. Pro stellt den gesamten Workflow außerdem über eine vollständige REST-API bereit und unterstützt LLM-gestützte Erstellung, sodass Berichte programmgesteuert erstellt und ausgeführt werden können.

> **💡 Tipp:** Wenn Sie die Open-Source-Version von DefectDojo verwenden, lesen Sie stattdessen den Abschnitt zum [Open-Source-Report-Builder](../using-the-report-builder/).

## Grundlegende Konzepte

Der Report Builder besteht aus vier Teilen, die jeweils als REST-Ressource unter `/api/v2/` verfügbar sind: `report_themes`, `report_blocks`, `report_templates` und `generated_reports`. Zu verstehen, wie diese zusammenspielen, ist der Schlüssel zum effizienten Erstellen von Berichten.

### Themes

Ein **Theme** steuert den visuellen Stil und das Branding eines Berichts: die Farben, die Bilder in Kopf- und Fußzeile sowie den Fußzeilentext. Indem Sie ein Theme einmal definieren, können Sie ein einheitliches Unternehmens-Branding auf jeden von Ihnen erstellten Bericht anwenden.

Ein Theme verfügt über die folgenden Einstellungen:

| Einstellung | Zweck | Standard |
|---------|---------|---------|
| Name | Eine Bezeichnung für das Theme | — |
| Primärfarbe | Haupt-Markenfarbe | `#1e3a5f` |
| Sekundärfarbe | Unterstützende Markenfarbe | `#4a90a4` |
| Akzentfarbe | Hervorhebungsfarbe | `#e67e22` |
| Textfarbe | Farbe des Fließtexts | `#333333` |
| Hintergrundfarbe | Hintergrundfarbe der Seite | `#ffffff` |
| Fußzeilentext | Im Seitenfuß angezeigter Text | — |
| Seitenzahlen anzeigen | Ob Seitenzahlen gedruckt werden | An |
| Kopfzeilenbild | In der Kopfzeile angezeigtes Bild | — |
| Fußzeilenbild | In der Fußzeile angezeigtes Bild | — |

> **💡 Tipp:** Alle fünf Farben werden als 7-stellige Hex-Werte angegeben (zum Beispiel `#1e3a5f`), sodass Sie die exakte Markenpalette Ihrer Organisation abbilden können.

Sie können dies in der Benutzeroberfläche erstellen (siehe unten) oder mit der [API](../report-builder-api/) automatisieren.

### Blocks

Ein **Block** ist eine wiederverwendbare Inhaltseinheit. Sie erstellen einen Block einmal, konfigurieren, was er anzeigt, und fügen ihn anschließend in beliebig viele Templates ein. Es gibt vier Blocktypen:

| Blocktyp | Was er erzeugt |
|------------|------------------|
| **Stock** | Nicht-datengebundener Inhalt wie eine Titelseite, ein Inhaltsverzeichnis, ein Seitenumbruch, ein Bild oder ein Textblock. |
| **Tabular** | Eine Tabelle mit Datensätzen aus einer einzelnen Entität. |
| **Detail** | Ein Layout pro Datensatz, ideal für Langtextfelder, die als Markdown gerendert werden (zum Beispiel description, impact, mitigation und references). |
| **Chart** | Visuelle Diagramme. *Demnächst verfügbar* — dieser Blocktyp ist im Datenmodell definiert, aber noch nicht in der API oder Benutzeroberfläche verfügbar. |

Ein **Stock**-Block wird konfiguriert, indem Sie einen von fünf Stock-Typen auswählen, zusammen mit einem Titel, Untertitel, Textinhalt oder Bild, je nachdem, was zutrifft:

- **Titelseite**
- **Inhaltsverzeichnis**
- **Seitenumbruch**
- **Bild**
- **Textblock**

**Tabular**- und **Detail**-Blocks beziehen beide Live-Datensätze aus einer Entität. Sie wählen die Entität über eine Modellauswahl aus und legen dann fest, welche Felder eingeschlossen werden und wie die Datensätze sortiert werden. Die Modellauswahl ist genau eine der folgenden sieben Entitäten:

- **Organization**
- **Asset**
- **Engagement**
- **Test**
- **Befund**
- **Testtyp**
- **Risikoakzeptanz**

> **💡 Tipp:** In DefectDojo Pro hießen **Assets** früher **Produkte**, und **Organizations** hießen früher **Produkttypen**. In einigen zugrunde liegenden Feld- und Filternamen kann Ihnen die alte Bezeichnung noch begegnen.

Der Unterschied liegt in der Darstellung: Ein **Tabular**-Block ordnet die Datensätze als Spaltentabelle an, was sich ideal für Zusammenfassungen und Inventare eignet, während ein **Detail**-Block jeweils einen Datensatz in einem Langform-Layout darstellt, das am besten für markdown-reiche Felder wie description, impact, mitigation und references geeignet ist.

> **💡 Tipp:** Filter gehören zum Block, nicht zum Template. Ein Block bringt seine eigenen Filter mit, sodass die Wiederverwendung eines Blocks überall, wo er erscheint, dieselben Filter übernimmt. Wenn Sie denselben Inhalt mit einem anderen Filter benötigen, duplizieren Sie den Block und passen Sie die Kopie an.

Sie können dies in der Benutzeroberfläche erstellen (siehe unten) oder mit der [API](../report-builder-api/) automatisieren.

### Templates

Ein **Template** ist eine geordnete Liste von Blocks, die an ein einzelnes Theme gebunden ist. Das Template legt fest, was im Bericht erscheint und in welcher Reihenfolge, während das zugehörige Theme bestimmt, wie es aussieht.

Da ein Template Blocks durch Einbindung referenziert, kann derselbe Block mehrfach in einem Template vorkommen. Ein wiederverwendbarer Seitenumbruch-Block kann beispielsweise zwischen mehrere Abschnitte desselben Berichts eingefügt werden.

Sie können dies in der Benutzeroberfläche erstellen (siehe unten) oder mit der [API](../report-builder-api/) automatisieren.

### Generated Reports

Das Ausführen eines Templates erzeugt einen **Generated Report**: eine gespeicherte PDF- oder HTML-Datei, die Sie herunterladen und bei Bedarf erneut ausführen können. Jeder Generated Report ist **zeitlich eingefroren** — er erfasst Ihre DefectDojo-Daten zum Zeitpunkt der Erstellung und wird **nicht** automatisch aktualisiert, wenn sich die zugrunde liegenden Daten später ändern. Um eine aktuelle Momentaufnahme zu erhalten, führen Sie das Template erneut aus.

Ein Generated Report durchläuft während der Erstellung die folgenden Status:

| Status | Bedeutung |
|--------|---------|
| Pending | Der Bericht wurde angefordert und wartet in der Warteschlange. |
| Processing | Der Bericht wird zusammengestellt. |
| Completed | Der Bericht steht zum Download bereit. |
| Failed | Der Bericht konnte nicht erstellt werden. |

> **🔑 Wichtig:** Reporting ist standardmäßig aktiviert. Ein Superuser kann es unter **Settings > Feature Flags** ein- oder ausschalten (siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/)). Beim Anzeigen wird die rollenbasierte Zugriffskontrolle (RBAC) von DefectDojo berücksichtigt — Benutzer sehen auch innerhalb eines Berichts stets nur die Daten, für die sie berechtigt sind.

Sie können dies in der Benutzeroberfläche erstellen (siehe unten) oder mit der [API](../report-builder-api/) automatisieren.

## Einen Bericht in der Benutzeroberfläche erstellen

Die folgenden Schritte führen Sie durch die vollständige Erstellung eines Berichts: Erstellen eines Themes, Erstellen der Blocks, die Ihren Inhalt enthalten, Zusammenstellen dieser zu einem Template und Generieren des endgültigen Berichts.

### Schritt 1: Ein Theme erstellen

Beginnen Sie im Themes-Bereich. Die Themes-Liste zeigt alle von Ihnen definierten Themes und ermöglicht es Ihnen, ein neues zu erstellen.

![Themes-Liste](images/pro_report_themes_list.png)

Öffnen Sie ein neues Theme, um dessen Branding festzulegen. Das Theme-Formular bietet die fünf Farben, ein optionales Kopf- und Fußzeilenbild, den Fußzeilentext und den Schalter für Seitenzahlen. Wählen Sie Farben, die zur Marke Ihrer Organisation passen, damit jeder von Ihnen erstellte Bericht einheitlich aussieht.

![Theme-Bearbeitungsformular](images/pro_report_theme_new.png)

### Schritt 2: Blocks erstellen

Erstellen Sie als Nächstes die Inhalts-Blocks. Die Blocks-Liste zeigt alle Ihre Blocks über sämtliche Typen hinweg.

![Blocks-Liste](images/pro_report_blocks_list.png)

Um einen datengetriebenen Block zu erstellen, wählen Sie dessen Typ aus und konfigurieren ihn. Das folgende Beispiel ist ein **Tabular**-Block, benannt für offene Befunde: Der Block-Typ ist auf Tabular gesetzt, eine Überschrift wird angegeben, das Modell ist **Befund**, die ausgewählten Felder sind Schweregrad, Titel, Produkt, Alter (Tage) und Verbleibende SLA-Tage, und die Datensätze werden nach Numerischem Schweregrad absteigend sortiert. Da Filter zum Block gehören, legen die **Filtereinträge** hier genau fest, welche Datensätze dieser Block überall dort abruft, wo er verwendet wird.

![Tabular-Block-Konfiguration](images/pro_report_block_new_tabular.png)

Sie können einen Block in der **Preview** ansehen, um zu sehen, wie er mit einem angewendeten Theme gerendert wird, bevor Sie ihn einem Template hinzufügen. Die folgende Vorschau zeigt eine gestaltete Titelseite ("DefectDojo Security Report"), die die Farben und das Branding des Themes übernimmt.

![Gerenderte Blockvorschau](images/pro_report_block_preview.png)

> **💡 Tipp:** Verwenden Sie **Duplicate**, um einen bestehenden Block zu kopieren, wenn Sie dasselbe Layout mit einem anderen Filter benötigen. Da Filter mit dem Block wandern, ist das Duplizieren der richtige Weg, um beispielsweise aus demselben Spaltenlayout eine Tabelle „Kritische Befunde" und eine Tabelle „Hohe Befunde" zu erzeugen.

### Schritt 3: Ein Template zusammenstellen

Sobald Ihre Blocks bereit sind, erstellen Sie ein Template. Die Templates-Liste zeigt Ihre gespeicherten Templates.

![Templates-Liste](images/pro_report_templates_list.png)

Im Template-Editor wählen Sie ein Theme aus und ordnen die Blocks in der Reihenfolge an, in der sie erscheinen sollen. Das folgende Beispiel reiht Cover Page → Executive Intro → Open Findings → KEV → Page Break → Asset Inventory aneinander. Verwenden Sie **Add Existing Block**, um einen bereits erstellten Block wiederzuverwenden, oder **Add New Block**, um spontan einen neuen zu erstellen, und nutzen Sie die Ziehpunkte zum Umsortieren. Denken Sie daran, dass derselbe Block mehr als einmal erscheinen kann — ein einzelner Seitenumbruch-Block kann zwischen mehrere Abschnitte eingefügt werden.

![Template-Editor](images/pro_report_template_new.png)

### Schritt 4: Generieren und herunterladen

Sobald das Template bereit ist, generieren Sie den Bericht. Der Generierungsdialog bestätigt das Template und lässt Sie das Ausgabeformat wählen — **HTML** oder **PDF**.

![Dialog zum Generieren eines Berichts](images/pro_generate_report_dialog.png)

Generierte Berichte werden in der Generated-Reports-Liste gesammelt, die für jeden Bericht den Status, das Dateiformat, den Zeitpunkt der Anforderung und Fertigstellung sowie einen Download-Link anzeigt.

![Liste der generierten Berichte](images/pro_generated_reports_list.png)

Sie können ein Template jederzeit erneut ausführen, um einen aktuellen Bericht zu erzeugen. Denken Sie daran, dass jeder Generated Report zeitlich eingefroren ist — er spiegelt Ihre Daten zum Zeitpunkt der Erstellung wider und ändert sich nicht, wenn sich die DefectDojo-Daten später ändern. Führen Sie das Template daher erneut aus, wann immer Sie eine aktuelle Momentaufnahme benötigen.

## Umstieg von der klassischen Reporting-Engine

Die klassische Reporting-Engine — die Seiten **Report Builder**, **Report Templates** und **Generated
Reports**, die in der Seitenleiste unter *Classic Report Engine* aufgeführt sind — wird in
**3.3.0 (8. September 2026)** entfernt. Bis dahin zeigen diese Seiten ein Banner, das Sie an das
Datum erinnert, und sowohl sie als auch dieser Report Builder bieten eine Ein-Klick-Migration.

### Ihre gespeicherten Templates migrieren

Verwenden Sie **Migrate to the new engine** auf einer beliebigen klassischen Seite, oder **Import from Classic Engine**
hier unter *All Report Templates*. Beide führen dieselbe Konvertierung durch, sodass es keine Rolle spielt, womit
Sie beginnen, und beide können gefahrlos mehrfach ausgeführt werden: Ein klassisches Template, dessen Name
hier bereits existiert, wird als *bereits migriert* gemeldet, statt dupliziert zu werden.

Jedes klassische Widget wird zu einem Block:

| Klassisches Widget | Wird zu |
|----------------|---------|
| Cover Page | Cover Page Stock-Block |
| Table Of Contents | Table of Contents Stock-Block |
| Page Break | Page Break Stock-Block |
| Custom Content / WYSIWYG | Text Block |
| Findings | Tabular-Block über Befunde, unter Beibehaltung der Filter des Widgets |
| Vulnerable Endpoints | Tabular-Block über URLs |
| Severities | Chart-Block „Active Findings by Severity" |

Zwei werden nicht übertragen, und die Migration weist dies pro Template aus, anstatt sie in etwas
Angenähertes umzuwandeln:

- **Executive Summary** — die klassische Engine leitete dies aus den Findings-Widgets ab, die
  sich im selben Bericht befanden. Es gibt keinen entsprechenden aggregierten Block; bauen Sie
  ihn bei Bedarf als Text Block neu auf.
- **Report Options** — kein Block. Der *Report name* wird zum Namen des neuen Templates.
  Finding-Notizen, Finding-Bilder und Seitenumbrüche pro Widget sind in der neuen Engine
  Einstellungen auf Theme-Ebene.

### Was mit bereits ausgeführten Berichten geschieht

Nichts. Von der klassischen Engine erzeugte Generated Reports sind fertige Dateien, es gibt also
nichts zu konvertieren. Sie bleiben aufgelistet und herunterladbar, bis die Engine entfernt wird —
sichern Sie alles, was Sie über 3.3.0 hinaus behalten möchten.

### Wenn der Report Builder deaktiviert ist

Die Migration funktioniert auch, wenn das Feature-Flag **Reporting** deaktiviert ist. Die konvertierten
Templates erscheinen einfach erst wieder, wenn das Flag erneut aktiviert wird, sodass Sie Ihre
Templates nach Ihrem eigenen Zeitplan übertragen können.

## Nächste Schritte

- **[Report Builder API](../report-builder-api/)** — skripten Sie den gesamten Workflow (Themes, Blocks, Templates und Generated Reports) für wiederholbares, automatisiertes Reporting.
- **[Report Builder mit einem LLM](../report-builder-llm/)** — nutzen Sie LLM-gestützte Erstellung, um Berichte im Dialog zu entwerfen und zu bauen.
