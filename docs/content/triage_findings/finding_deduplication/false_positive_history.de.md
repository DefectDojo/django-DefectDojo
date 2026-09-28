---
title: False Positive History
description: Markiert neue Befunde automatisch als Falsch-positiv, wenn ein übereinstimmender
  Befund bereits so eingestuft wurde
weight: 7
---

**False Positive History** erspart Ihrem Team, denselben Falsch-positiv-Befund immer wieder erneut zu triagieren. Wenn die Funktion aktiviert ist und ein Befund importiert wird, sucht DefectDojo nach vorhandenen Befunden im selben Produkt, die damit übereinstimmen. Ist einer davon bereits als **Falsch-positiv** markiert, wird auch der eingehende Befund als Falsch-positiv markiert.

> **Diese Funktion ist im Produkt als EXPERIMENTAL gekennzeichnet** und **kann nicht gleichzeitig mit der Deduplizierung verwendet werden.** Lesen Sie [Wann Sie sie verwenden können](#when-you-can-use-it), bevor Sie sie aktivieren.

## Was die Funktion bewirkt

Angenommen, ein Scanner meldet einen Befund, den Ihr Team untersucht und als Falsch-positiv markiert. Bei jedem späteren Scan taucht derselbe Befund wieder auf. Normalerweise muss ihn jemand jedes Mal erneut abweisen. Mit aktivierter False Positive History erkennt DefectDojo den wiederkehrenden Befund und markiert ihn automatisch als Falsch-positiv.

Auf diese Weise markierte Befunde werden zudem auf **inaktiv** und **unverifiziert** gesetzt, nicht nur auf Falsch-positiv. Das ist beabsichtigt — der Befund fällt vollständig aus Ihrer aktiven Warteschlange heraus —, überrascht aber Personen, die erwarten, dass sich nur das Falsch-positiv-Flag ändert.

Die Regel, die DefectDojo dabei einhält, lautet: *Innerhalb eines Produkts gilt: Ist ein Befund Falsch-positiv, sind es alle übereinstimmenden Befunde auch.*

### Rückwirkender Modus

**Retroactive False Positive History** wendet dieselbe Regel rückwirkend an. Wenn Sie einen Befund als Falsch-positiv markieren, wird jeder andere übereinstimmende **aktive** Befund in diesem Produkt ebenfalls als Falsch-positiv markiert.

Dies überschreibt vorhandene Daten. Es gibt keine Vorschau und keine Bestätigungsabfrage — die Änderung erfolgt einfach produktweit. Aktivieren Sie diese Option bewusst.

## Wann Sie sie verwenden können

**False Positive History und Deduplizierung schließen sich gegenseitig aus.** Beide lösen sich überschneidende Probleme, weshalb DefectDojo nicht zulässt, beide gleichzeitig zu verwenden: In den System Settings wird beim Aktivieren der einen die andere ausgegraut, und das Aktivieren der Deduplizierung setzt die Einstellungen von False Positive History zurück.

Das ist der wichtigste Punkt, den man über diese Funktion verstehen muss. Die meisten Instanzen verwenden die Deduplizierung, und für diese ist False Positive History nicht verfügbar. Sie ist für Instanzen gedacht, die sich bewusst gegen die Deduplizierung entschieden haben.

## Aktivieren

Beide Einstellungen befinden sich in den **System Settings**, im Deduplizierungsblock, und sind standardmäßig **deaktiviert**:

| Einstellung | Wirkung |
| --- | --- |
| **Enable False Positive History** | Aktiviert die Funktion für die Instanz. |
| **Enable Retroactive False Positive History** | Wendet die Regel zusätzlich rückwirkend an, wie oben beschrieben. Setzt die obige Einstellung voraus. |

Diese Einstellungen gelten **instanzweit**. Es gibt keine Möglichkeit, sie pro Produkt oder pro Tool zu überschreiben — die Aktivierung wirkt sich auf jedes Produkt der Instanz aus.

## Was als Übereinstimmung zählt

False Positive History entscheidet mithilfe **des für das meldende Tool konfigurierten Deduplizierungsalgorithmus**, ob zwei Befunde „dieselben“ sind — auch wenn die Deduplizierungsfunktion selbst deaktiviert sein muss.

| Deduplizierungsalgorithmus des Tools | Befunde stimmen überein, wenn sie gemeinsam haben |
| --- | --- |
| **Hash Code** | denselben Hash-Code, gebildet aus den für dieses Tool konfigurierten Hash Code Fields |
| **Unique ID From Tool** | dieselbe eindeutige ID des Tools |
| **Unique ID From Tool or Hash Code** | eines von beidem |
| **Legacy** | denselben Titel (ohne Berücksichtigung der Groß-/Kleinschreibung) und denselben Schweregrad |

Die Genauigkeit dieser Funktion hängt somit vollständig davon ab, wie gut die Deduplizierung dieses Tools konfiguriert ist. **Passen Sie den Algorithmus und die Hash-Felder des Tools an, bevor Sie False Positive History aktivieren** — siehe [Deduplication Tuning](/triage_findings/finding_deduplication/pro__deduplication_tuning/) (Pro) oder [Deduplication Tuning](/triage_findings/finding_deduplication/os__deduplication_tuning/) (Open Source).

Der Abgleich ist **auf ein Produkt beschränkt**. Er reicht nie über Produkte hinweg und gilt nie instanzweit.

### Mengenbasierter Abgleich (Pro)

In DefectDojo Pro berücksichtigt der Abgleich außerdem die **mengenbasierten Hash Code Fields** — die Schwachstellen-ID- und CWE-Abgleicher (`vulnerability_ids_partial`, `vulnerability_ids_subset`, `cwes_partial`, `cwes_subset`, sowie deren exakte Übereinstimmungsformen) mit derselben Bedeutung wie bei der Deduplizierung.

Dadurch ist der Abgleich in Pro **enger** gefasst als in Open Source, und genau das ist der Zweck: Ohne diese Verfeinerung könnte False Positive History einen Falsch-positiv-Status auf Befunde übertragen, die die Same-Tool-Deduplizierung überhaupt nicht als Duplikate betrachtet hätte. Die Verfeinerung kann die Menge der markierten Befunde immer nur verringern — Pro führt niemals dazu, dass *mehr* Befunde automatisch markiert werden.

In Open Source basiert der Abgleich allein auf dem Hash-Code und ist damit breiter gefasst. Beachten Sie dies bei der Konfiguration.

## Risiken, die Sie vor der Aktivierung kennen sollten

Diese Funktion markiert Befunde als Falsch-positiv, ohne dass ein Mensch sie sich ansieht. Ihr Wirkungsbereich wird durch Ihre Deduplizierungskonfiguration bestimmt, weshalb eine zu lockere Konfiguration gefährlich ist.

* **Ein zu locker gefasster Abgleichsschlüssel kann unbemerkt nicht zusammengehörige Befunde abweisen.** Der Algorithmus **Legacy** gleicht nur anhand von Titel und Schweregrad ab — eine einzige Falsch-positiv-Einstufung könnte also jeden Befund mit demselben Titel und Schweregrad im Produkt als Falsch-positiv markieren, einschließlich echter Befunde. Dasselbe gilt für einen zu breit gefassten Satz von Hash Code Fields. Verschärfen Sie zuerst den Algorithmus.
* **Der rückwirkende Modus überschreibt vorhandene Befunde**, ohne Vorschau, ohne Abfrage und ohne Zusammenfassung der vorgenommenen Änderungen.
* **Befunde werden deaktiviert und als unverifiziert markiert**, nicht nur gekennzeichnet.
* **Das Massen-Update umgeht die übliche Verarbeitung beim Speichern**, sodass Automatisierungen, die auf Aktualisierungen von Befunden reagieren, bei so geänderten Befunden möglicherweise nicht ausgelöst werden.
* **Sie ist in DefectDojo selbst weiterhin als EXPERIMENTAL gekennzeichnet.**

Für die meisten Teams ist es sicherer, die Deduplizierung aktiviert zu lassen und Duplikate den Status ihres Original-Befunds übernehmen zu lassen, anstatt auf False Positive History umzustellen. Siehe [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/).
