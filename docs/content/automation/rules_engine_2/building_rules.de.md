---
title: Regeln erstellen
description: Der Grafikeditor, Trigger, Geltungsbereich, Bedingungen und Nachrichtenvorlagen
weight: 2
audience: pro
aliases:
- /de/automation/rules_engine_v2/building_rules/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

Eine Regel wird auf einer Zeichenfläche (Canvas) erstellt. Sie ziehen Knoten aus einer Palette, verbinden sie miteinander und konfigurieren jeden davon in einem Seitenpanel. Diese Seite behandelt die Teile dieses Prozesses, die unabhängig von den verwendeten Knoten gleich sind. Die Knoten selbst finden Sie in der [Node-Referenz](../node_reference/).

## Der Editor

Öffnen Sie **Rules Engine 2.0 > All Rules** und wählen Sie **New Rule**, oder öffnen Sie eine bestehende Regel zur Bearbeitung.

Die Palette ist in vier Kategorien gegliedert, was auch der Reihenfolge entspricht, in der Elemente einen typischen Graphen durchlaufen:

| Category | What the nodes do |
|----------|-------------------|
| **Triggers** | Entscheiden, wann die Regel aktiviert wird und welche Befunde sie durchlaufen. Genau einer pro Graph. |
| **Logic** | Leiten, begrenzen und deduplizieren die durchlaufenden Elemente. |
| **Findings** | Ändern die Befunde. |
| **Egress** | Senden etwas nach außen: ein Ticket, eine Nachricht, einen Bericht. |

Die Palette wird direkt aus der Engine generiert, sodass das, was Sie im Editor sehen, immer genau dem entspricht, was die Engine ausführen kann.

### Graph-Regeln

Ein Graph wird beim Speichern und erneut vor jedem Lauf überprüft. Er muss alle folgenden Bedingungen erfüllen:

* Er hat mindestens einen Knoten.
* Er hat **genau einen** Trigger-Knoten.
* Jeder Knoten hat eine eindeutige, nicht leere ID mit maximal 100 Zeichen.
* Jeder Knoten ist von einem Typ, den die Engine kennt.
* Jede Kante verbindet zwei existierende Knoten.
* Er enthält keinen Zyklus.

Ein Knoten, in den nichts eingespeist wird, ist zulässig. Er läuft mit einer leeren Eingabeliste, was in der Regel bedeutet, dass er nichts tut.

Ein Knoten mit mehreren eingehenden Kanten erhält alle deren Ausgaben zusammengeführt.

### Vorschau vor dem Speichern

**Preview** führt den Graphen, den Sie aktuell auf der Zeichenfläche haben, testweise aus (Dry-Run) und zeigt Ihnen den Trace pro Knoten, den er erzeugen würde: wie viele Elemente in jeden Knoten eingegangen sind, wie viele über welchen Ausgang verlassen wurden und was jeder Knoten geändert hätte.

Preview führt die echte Engine aus, nicht eine Simulation davon, und macht anschließend alles rückgängig. Es wird nichts geschrieben, kein Lauf wird aufgezeichnet, und der Egress wird gezwungen, zu simulieren, was auch immer der Modus der Regel vorgibt. Es ist der schnellste Weg zu prüfen, ob Ihre Bedingungen das treffen, was Sie erwartet haben.

Preview ist die einzige Ausführung, die begrenzt, wie viele Befunde betrachtet werden, damit sie schnell bleibt. Wenn gekürzt wird, wird dies im Trace vermerkt. Ein echter Lauf kennt keine solche Grenze.

## Trigger und Geltungsbereich

Jeder Graph beginnt mit einem von drei Triggern.

* **On Finding Event** aktiviert die Regel, wenn Befunde erstellt, aktualisiert, geschlossen oder wieder geöffnet werden. Wählen Sie in der **Event**-Einstellung des Knotens aus, welche davon gelten sollen, oder `any` für alle vier.
* **On a Schedule** durchsucht Befunde nach einem wiederkehrenden Zeitplan.
* **Manual Run** durchsucht Befunde, wenn Sie auf der Regel auf **Run** klicken.

### Geltungsbereich

Alle drei Trigger nehmen einen **Scope** (Geltungsbereich) entgegen, und mit dem Geltungsbereich grenzen Sie ein, was die Regel berücksichtigt. Es handelt sich um dasselbe Filtervokabular, das die ursprüngliche Rules Engine verwendet, rund sechzig Filter, die Befunde und die sie umgebenden Objekte abdecken. Ein Filter, den Sie dort bereits zu schreiben wissen, bedeutet also hier dasselbe.

Zwei Dinge zum Geltungsbereich sollten Sie verstehen:

* **Der Geltungsbereich wird zusätzlich zur Autorisierung angewendet, niemals anstelle davon.** Die Regel läuft als ihr Eigentümer, sodass der Geltungsbereich eine bereits autorisierte Menge von Befunden einschränkt. Einen leeren Geltungsbereich zu lassen bedeutet nicht „jeder Befund in der Instanz“, sondern „jeder Befund, den der Regeleigentümer sehen kann“.
* **Ein ungültiger Geltungsbereich lässt den Lauf fehlschlagen, statt ihn zu erweitern.** Existiert ein Filterschlüssel nicht, oder ist ein Wert einer, den der Filter stillschweigend verwerfen würde, bricht der Lauf mit einem Fehler ab. Eine Regel, die nichts tut, ist wiederherstellbar. Eine Regel, die stillschweigend jeden Befund in der Instanz bearbeitet, ist es nicht.

Bei einem Event-Trigger fungiert der Geltungsbereich als zweites Tor: Die im Event genannten Befunde werden gegen ihn abgeglichen, und nur die, die ihn passieren, gelangen in den Graphen.

### Zeitplanung

Eine Regel, deren Trigger **On a Schedule** ist, wird direkt aus der Regel heraus geplant. Das Festlegen des Zeitplans erfordert Rule Edit, dieselbe Berechtigung wie das Bearbeiten der Regel, denn eine zeitplan-ausgelöste Regel tut überhaupt nichts, solange sie keinen hat.

Zeitpläne sind auf Viertelstundenmarken beschränkt. Das Minutenfeld eines Cron-Ausdrucks muss `0`, `15`, `30` oder `45` sein.

Gültige Beispiele:

```
0 * * * *     every hour, on the hour
15 9 * * *    every day at 09:15
0 15 * * 1    every Monday at 15:00
30 2 * * *    every day at 02:30
```

## Auf Befunddaten verweisen

An zwei Stellen liest eine Regel Werte aus dem durchlaufenden Element aus: **Conditions** (Bedingungen) und **Templates** (Vorlagen). Beide verwenden dieselben Punktpfade.

```
finding.severity
finding.title
finding.vulnerability_ids.0
product.name
product_type.name
test.scan_type
ctx.rule_name
```

Ein Pfad, der sich nicht auflösen lässt, ergibt keinen Wert statt eines Fehlers.

### Verfügbare Felder

Jedes Element trägt einen festen Satz von Befundfeldern. Diese Liste ist ein Vertrag und ändert sich daher nur bewusst.

| Group | Fields |
|-------|--------|
| Identität | `id`, `title`, `hash_code`, `unique_id_from_tool` |
| Schweregrad und Bewertung | `severity`, `numerical_severity`, `cvssv3`, `cvssv3_score`, `epss_score`, `epss_percentile`, `priority`, `risk`, `risk_score` |
| Text | `description`, `mitigation`, `impact` |
| Status | `active`, `verified`, `false_p`, `duplicate`, `is_mitigated`, `out_of_scope`, `risk_accepted`, `under_review` |
| Daten | `date`, `mitigated`, `last_status_update`, `sla_expiration_date` |
| Ort | `file_path`, `line`, `component_name`, `component_version`, `service` |
| Klassifizierung | `cwe`, `vulnerability_ids`, `tags` |

Neben `finding` trägt jedes Element `test` (`id`, `title`, `scan_type`), `engagement` (`id`, `name`), `product` (`id`, `name`), `product_type` (`id`, `name`) und `ctx`.

Daten sind ISO-8601-Zeichenketten. Das ist beabsichtigt: Es bedeutet, dass `gt` und `lt` sie als Text korrekt ordnen, sodass `2026-07-28` korrekt größer ist als `2026-01-01`.

`priority`, `risk` und `risk_score` stammen aus der Priorisierung von Pro. Ein Befund, der noch nicht bewertet wurde, trägt für sie keinen Wert.

### Bedingungen

Ein **If / Filter**-Knoten enthält eine Liste von Bedingungszeilen. Jede Zeile besteht aus einem Pfad, einem Operator und einem Wert. **Match** entscheidet, ob jede Zeile zutreffen muss (`all`) oder nur eine davon (`any`).

| Operator | Meaning |
|----------|---------|
| `eq` | ist gleich |
| `neq` | ist ungleich |
| `contains` | enthält |
| `not_contains` | enthält nicht |
| `in` | ist eines von |
| `not_in` | ist keines von |
| `gt` | ist größer als |
| `gte` | ist größer als oder gleich |
| `lt` | ist kleiner als |
| `lte` | ist kleiner als oder gleich |
| `startswith` | beginnt mit |
| `endswith` | endet mit |
| `exists` | ist gesetzt |
| `not_exists` | ist nicht gesetzt |

Vergleiche sind **tolerant**. Zunächst wird eine Zahl versucht, und wenn das fehlschlägt, werden die Werte als getrimmter, Groß-/Kleinschreibung ignorierender Text verglichen. Eine Bedingung wie `finding.severity eq high` trifft daher auf einen Befund mit dem Schweregrad `High` zu, was fast immer das ist, was der Verfasser gemeint hat.

#### Transformationen

Eine Bedingungszeile kann den gelesenen Wert vor dem Vergleich nachbearbeiten.

| Transform | Effect |
|-----------|--------|
| `int` | Ganzzahl |
| `float` | Dezimalzahl |
| `str` | Text |
| `first` | erster Eintrag einer Liste |
| `list` | als Liste |
| `join` | mit Kommas verbunden |
| `upper` | GROSSBUCHSTABEN |
| `lower` | Kleinbuchstaben |
| `strip` | getrimmt |
| `cwe_int` | CWE-Nummer |
| `severity` | normalisierter Schweregrad, sodass Werte im Stil von `critical`, `error` und `warning` aus verschiedenen Scannern auf die fünf Stufen von DefectDojo abgebildet werden |
| `numerical_severity` | sortierbarer Schweregrad-Code, für Vergleiche zur Reihenfolge |

### Vorlagen

Jede Einstellung, die als Nachricht, Notiz, Titel oder Wert bezeichnet ist, akzeptiert `{{ path }}`-Platzhalter, die pro Element aufgelöst werden:

```
{{finding.severity}}: {{finding.title}} ({{product.name}})
```

Ein Pfad ohne Wert wird als leere Zeichenkette dargestellt. Eine Liste wird durch Kommas getrennt dargestellt.

Vorlagen sehen außerdem einen `ctx`-Block mit Details zum Lauf selbst. Welche Schlüssel verfügbar sind, hängt vom Knoten ab, aber die gängigen sind:

| Placeholder | Meaning |
|-------------|---------|
| `{{ctx.rule_name}}` | Der Name der Regel |
| `{{ctx.count}}` | Wie viele Befunde die Nachricht umfasst |
| `{{ctx.trigger}}` | Das Event, das den Lauf gestartet hat |
| `{{ctx.findings_html}}` | Die gerenderte Befundliste, im E-Mail-Knoten |
| `{{ctx.report_url}}` | Der Download-Link, im Berichts-Knoten |
| `{{ctx.template_name}}` | Der Name der Berichtsvorlage, im Berichts-Knoten |

Vorlagen sind reine Textersetzung. Es gibt keine Auswertung von Ausdrücken, keine Codeausführung und keinen Attributzugriff auf Objekte irgendwo in einer Regelkonfiguration.

## Eine Regel sicher testen

Die empfohlene Reihenfolge für eine Regel, die irgendetwas sendet:

1. Erstellen Sie den Graphen und verwenden Sie **Preview**, bis die Elementzahlen stimmen.
2. Speichern Sie ihn. Neue Regeln werden deaktiviert erstellt.
3. Belassen Sie den Modus auf **Simulate** und aktivieren Sie die Regel.
4. Lassen Sie sie laufen, lesen Sie dann **Deliveries** und prüfen Sie, ob die aufgezeichneten Payloads das sind, was Sie beabsichtigt haben.
5. Stellen Sie den Modus auf **Live** um.

Simulate ist kein Teillauf. Jede Befundänderung im Graphen erfolgt im Simulationsmodus tatsächlich. Nur die ausgehenden Sendungen werden zurückgehalten.
