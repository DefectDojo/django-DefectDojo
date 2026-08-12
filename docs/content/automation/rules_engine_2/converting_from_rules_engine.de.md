---
title: Migration von der Rules Engine
description: Bestehende Rules-Engine-Regeln in Rules-Engine-2.0-Graphen überführen
weight: 6
audience: pro
aliases:
- /automation/rules_engine_v2/converting_from_rules_engine/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

Beide Engines laufen nebeneinander. Das Aktivieren von Rules Engine 2.0 ändert nichts an Ihren bestehenden [Rules Engine](/automation/rules_engine/about/)-Regeln, und es gibt keine Frist, bis zu der Sie diese migrieren müssen.

Wenn Sie sie migrieren möchten, gibt es dafür einen Konverter. Er übersetzt eine Rules-Engine-Regel (ein Filter plus eine geordnete Liste von Aktionen) in einen gleichwertigen Rules-Engine-2.0-Graphen.

## Was der Konverter garantiert

**Eine Regel wird entweder sauber konvertiert oder überhaupt nicht.** Jede Konvertierung meldet zwei Arten von Ergebnissen:

* **Problems** bedeuten, dass die Regel nicht geschrieben wurde. Es wird nichts Unvollständiges gespeichert.
* **Warnings** bedeuten, dass die Regel konvertiert wurde, sich aber etwas daran verändert hat und Sie es sich ansehen sollten.

Es wird nichts stillschweigend angenähert. Der ganze Wert des Konverters liegt darin, dass Sie einer Regel vertrauen können, die ohne Anmerkung konvertiert wurde, und eine, bei der das nicht der Fall war, von Hand prüfen.

**Konvertierte Regeln werden immer deaktiviert erstellt.** Beide Engines laufen, und zwei Regeln, die dasselbe mit denselben Befunden tun, sind das eine Ergebnis, das ein Konverter niemals von sich aus erzeugen darf. Prüfen Sie jede konvertierte Regel und aktivieren Sie sie bewusst.

**Eine Regel wird nur einmal konvertiert.** Jede konvertierte Regel merkt sich, aus welcher Regel sie stammt, sodass ein zweiter Lauf des Konverters überspringt, was bereits erledigt wurde, statt Duplikate zu erzeugen. Verwenden Sie die Overwrite-Option, um einen zuvor konvertierten Graphen bewusst zu ersetzen.

## Den Konverter ausführen

### Über die Benutzeroberfläche

Die Regelliste bietet eine Konvertierungsaktion an, die pro Regel meldet, was konvertiert wurde, was übersprungen wurde und was fehlgeschlagen ist.

### Über die Kommandozeile

```bash
python manage.py convert_rules_to_v2
```

| Option | Effect |
|--------|--------|
| `--dry-run` | Gibt den Graphen aus, den jede Regel erzeugen würde, und schreibt nichts. |
| `--rule-ids 1,2,3` | Konvertiert nur diese Regeln. Konvertiert alle Regeln, wenn weggelassen. |
| `--overwrite` | Ersetzt den Graphen einer bereits konvertierten Regel und erhöht ihre Version, statt sie zu überspringen. |
| `--activate-schedules` | Kopiert außerdem jeden Zeitplan auf die konvertierte Regel. Standardmäßig aus. |
| `--drop-invalid-filters` | Verwirft Geltungsbereichsfilter, die das Filterset nicht mehr erkennt, und warnt, statt die Regel fehlschlagen zu lassen. |
| `--json` | Gibt den Bericht als JSON statt als Text aus. |

Der Befehl gibt nur dann einen Exit-Code ungleich null zurück, wenn eine Regel nicht konvertiert werden kann. Übersprungene Regeln werden gemeldet, gelten aber nicht als Fehlschläge.

Beginnen Sie mit `--dry-run` auf der gesamten Menge, um zu sehen, worauf Sie sich einlassen, und konvertieren Sie dann tatsächlich.

## Was die Konvertierung erzeugt

| Rules Engine concept | Becomes |
|----------------------|---------|
| Der Filter der Regel | Der **Scope** am Trigger-Knoten. |
| Eine Regel mit Zeitplan | Ein **On a Schedule**-Trigger. |
| Eine Regel ohne Zeitplan | Ein **Manual Run**-Trigger. |
| Jede Aktion, in Reihenfolge | Ein Knoten, in derselben Reihenfolge verkettet. |
| Eine durch eine Bedingung geschützte Aktion | Ein **If / Filter**-Knoten vor diesem Knoten. |

Das Filtervokabular wird von beiden Engines gemeinsam genutzt, sodass ein Geltungsbereich ohne Übersetzung konvertiert wird. Das ist beabsichtigt: Es ist derselbe Filtersatz, mit einer Implementierung.

Konvertierte Graphen werden auf dieselbe Weise validiert wie ein von Hand erstellter Graph, einschließlich der Konfiguration pro Knoten und der zulässigen Werte jedes Dropdowns. Eine Regel mit einem Schweregrad- oder Risikowert, von dem sich das Produkt inzwischen entfernt hat, wird bei der Konvertierung erkannt statt erst zur Laufzeit.

## Was nicht übernommen wird

Vier Dinge, auf die Sie sich einstellen sollten. Der Konverter meldet diese als Hinweise bei jedem Lauf.

* **Der Lauf-Verlauf bleibt, wo er ist.** Der bestehende Lauf-Verlauf sowie die betroffenen und übersprungenen Datensätze verbleiben in der Rules-Engine-Benutzeroberfläche. Sie werden nicht kopiert.
* **Zeitpläne werden standardmäßig nicht aktiviert.** Eine zeitplan-ausgelöste Regel wird konvertiert, aber ihr Zeitplan wird nur kopiert, wenn Sie `--activate-schedules` übergeben. Dadurch bleibt die alleinige Verantwortung für aktive Zeitpläne bei der ursprünglichen Engine, solange beide laufen, sodass eine konvertierte Regel nicht heimlich zu feuern beginnen kann. Wenn Sie einen Zeitplan tatsächlich kopieren, erhält die Kopie einen eigenen Namen, damit sie nicht mit dem Original kollidiert.
* **Das Nebenläufigkeitsmodell ist unterschiedlich.** Rules Engine hat eine instanzweite Laufsperre. Rules Engine 2.0 serialisiert pro Regel, sodass unterschiedliche Regeln gleichzeitig laufen. Eine Gruppe von Regeln, die sich früher abgewechselt hat, überlappt sich nun.
* **Eine Aktion hat keine Entsprechung.** Eine Aktion „Falsch-positiv auf false setzen“ kann nicht als Rules-Engine-2.0-Knoten ausgedrückt werden und muss von Hand konvertiert werden.

Eine Regel, deren Eigentümer nicht gesetzt ist, wird mit einer Warnung konvertiert. Denken Sie daran, dass eine Regel ohne Eigentümer keine Befunde sieht, weisen Sie also einen zu, bevor Sie sie aktivieren.

## Eine vorgeschlagene Reihenfolge

1. Aktivieren Sie Rules Engine 2.0 und lassen Sie Ihre bestehenden Regeln weiterlaufen.
2. Führen Sie den Konverter mit `--dry-run` aus und lesen Sie den Bericht.
3. Konvertieren Sie. Alles landet deaktiviert.
4. Öffnen Sie jede konvertierte Regel, prüfen Sie den Graphen und belassen Sie den Modus auf **Simulate**.
5. Aktivieren Sie die konvertierte Regel und lassen Sie sie eine Weile parallel zum Original laufen. Simulate bedeutet, dass sie Befunde ändert, aber nichts sendet, sodass Sie ihre Läufe mit denen des Originals vergleichen können.
6. Wenn Sie zufrieden sind, deaktivieren Sie die ursprüngliche Regel und stellen Sie die konvertierte auf **Live** um.
7. Kopieren Sie den Zeitplan zuletzt, sobald die alte Regel nicht mehr läuft.

Schritt 5 ist der, den Sie nicht überspringen sollten. Dass beide Engines dieselben Befunde bearbeiten, ist zum Beobachten unproblematisch, aber Sie möchten selbst entscheiden, wann die Sendungen beginnen.
