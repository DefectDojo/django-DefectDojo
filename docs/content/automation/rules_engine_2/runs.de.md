---
title: Läufe
description: Wie eine Regel ausgeführt wird, was ein Lauf aufzeichnet und wie die
  Kaskadierung begrenzt wird
weight: 4
audience: pro
aliases:
- /automation/rules_engine_v2/runs/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Rules Engine 2.0 ist eine reine DefectDojo-Pro-Funktion.</span>

Ein **Lauf** ist eine Ausführung einer Regel. Jeder Lauf wird aufgezeichnet, unabhängig davon, ob er erfolgreich war oder fehlgeschlagen ist, und jeder Knoten darin hinterlässt eine Spur. **Rules Engine 2.0 > Läufe** listet sie auf.

## Was ein Lauf aufzeichnet

| Feld | Bedeutung |
|-------|---------|
| **Regel** | Die Regel, die ausgeführt wurde. |
| **Auslöser** | Das Ereignis, das den Lauf gestartet hat, zum Beispiel `finding.created`, `schedule` oder `manual`. |
| **Ausgelöst von** | Die Person, die den Lauf gestartet hat, sofern es eine Person war: wer auf Run geklickt hat, oder wer den Befund gespeichert hat, der den Lauf ausgelöst hat. Leer bei einem Zeitplan und bei einer Änderung, bei der niemand anwesend war, etwa ein Import oder ein API-Aufruf ohne Benutzer. Dies unterscheidet sich vom Eigentümer der Regel, der angibt, **als wer** der Lauf ausgeführt wurde. |
| **Status** | `Running`, `Success` oder `Error`. |
| **Gestartet** und **Beendet** | Wann der Lauf ausgeführt wurde. Beendet ist nur leer, solange der Lauf noch läuft. |
| **Fehler** | Der Fehler, der den Lauf beendet hat, falls er fehlgeschlagen ist. |
| **Statistiken** | Summen pro Knoten, kaskadierte Ereignisse und aufgeschobene Arbeit. |
| **Tiefe** | Wie viele Kaskadierungsschritte dieser Lauf vom auslösenden Ereignis entfernt ist. |
| **Quell-Lauf** | Der Lauf, dessen ausgelöstes Ereignis diesen Lauf bei einem kaskadierten Lauf gestartet hat. |

### Die Knoten-Spur

Innerhalb eines Laufs zeichnet jeder Knoten seine eigene Zeile auf:

| Feld | Bedeutung |
|-------|---------|
| **Reihenfolge** | Wo der Knoten in der Ausführungsreihenfolge stand. |
| **Knoten** | Seine ID, sein Typ und, falls vergeben, seine Bezeichnung. |
| **Status** | Ob der Knoten erfolgreich abgeschlossen wurde oder einen Fehler ausgelöst hat. |
| **Eingehende Elemente** | Wie viele Elemente eingegangen sind. |
| **Ausgehende Elemente** | Wie viele Elemente den Knoten verlassen haben, aufgeschlüsselt nach Ausgabe-Handle, sodass ein If/Filter-Knoten seine True- und False-Zähler getrennt anzeigt. |
| **Zusammenfassung** | Welche Zähler der Knoten gemeldet hat, zum Beispiel wie viele Befunde er geändert hat. |
| **Fehler** | Der Fehler, den er ausgelöst hat, falls er fehlgeschlagen ist. |

Die Spur ist das, was Sie lesen, wenn eine Regel nicht das getan hat, was Sie erwartet haben. Ein If/Filter-Knoten, der 400 eingehende Elemente und 0 im True-Zweig meldet, zeigt Ihnen, dass die Bedingungen falsch sind, ohne dass Sie raten müssen.

## Ausführungsmodell

Knoten werden in topologischer Reihenfolge ausgeführt: Ein Knoten läuft erst, wenn alles, was in ihn einfließt, bereits gelaufen ist. Ein Knoten mit mehreren eingehenden Kanten erhält alle deren Ausgaben zusammengeführt. Ein Knoten, in den nichts einfließt, läuft trotzdem, mit einer leeren Eingabeliste.

### Ein fehlgeschlagener Lauf ändert nichts

Ein Lauf ist atomar. Wenn ein Knoten einen Fehler auslöst, wird jede Befundänderung, die der Lauf vorgenommen hat, zurückgerollt.

Die Spur wird dabei nicht zurückgerollt. Die Knotenzeilen und der `Error`-Status werden im Nachhinein geschrieben, sodass ein fehlgeschlagener Lauf Ihnen genau zeigt, welcher Knoten kaputt war, ohne halb angewendete Änderungen zu hinterlassen. Das ist die wichtigste Garantie, die Sie beim Lesen der Läufe-Seite im Hinterkopf behalten sollten: Ein fehlerhafter Lauf ist ein Lauf, der nichts bewirkt hat.

Der Egress folgt derselben Regel. Zustellungen werden innerhalb der Transaktion des Laufs aufgezeichnet und erst nach deren Commit versendet, sodass ein Lauf, der zurückgerollt wird, nichts versendet.

### Immer nur ein Lauf pro Regel

Eine Regel kann immer nur einen laufenden Lauf haben. Ein zweiter Auslöser für dieselbe Regel, während sie noch läuft, tritt nicht in Konkurrenz dazu. Er wartet und versucht es erneut.

Unterschiedliche Regeln laufen vollständig parallel, sodass eine langsame Regel ihre Geschwisterregeln nie aufhält.

Wenn ein Lauf auf irgendeine Weise verwaist, zum Beispiel weil der ausführende Worker beendet wurde, wird seine Sperre nach einem Stillstandsfenster (standardmäßig 30 Minuten) freigegeben, damit die Regel nicht für immer blockiert bleibt. Ein Lauf, der sich diesem Fenster nähert, stoppt sich zuerst selbst und wickelt sich sauber ab, sodass ein lediglich langsamer Lauf niemals gleichzeitig mit seinem eigenen Ersatz laufen kann.

## Kaskadierung

Eine Regel, die einen Befund ändert, erzeugt genau die Art von Ereignis, auf das eine andere Regel reagieren kann. Rules Engine 2.0 erlaubt das, sodass Ketten wie `A -> B -> C` funktionieren, und begrenzt dies auf zwei unabhängige Arten:

* **Tiefe.** Ein Ereignis darf höchstens **3** Kaskadierungsschritte von der Änderung entfernt zurücklegen, die es ausgelöst hat.
* **Ketten-Zugehörigkeit.** Jedes Ereignis trägt die Liste der Regeln, die in seiner Kette bereits durchlaufen wurden, und eine Regel läuft nie zweimal in derselben Kette. Eine Regel kann sich also nicht selbst erneut auslösen, und zwei Regeln können nicht hin- und herspielen.

Die Felder **Tiefe** und **Quell-Lauf** eines Laufs erlauben es Ihnen, eine Kette bis zu der Änderung zurückzuverfolgen, die sie gestartet hat. **Ausgelöst von** wird durch die gesamte Kette weitergegeben, sodass eine Kaskade, die eine Person ausgelöst hat, bei jedem Schritt dieser Person zuordenbar bleibt.

Änderungen, die *von* einer laufenden Regel vorgenommen werden, werden der eigenen Kaskade dieser Regel zugeordnet, statt wie neue Benutzeraktivität auszusehen, sodass eine Regel, die Arbeit intern delegiert, die Kette nicht aufbläht.

## Umfang und Grenzwerte

**Ein Lauf ist nicht begrenzt.** Eine Regel verarbeitet alles, worauf ihr Geltungsbereich zutrifft, egal wie groß das ist. Eine Regel, die bei den ersten N Befunden stillschweigend anhält, wäre eine Regel, der Sie nicht vertrauen könnten.

Stattdessen wird ein Lauf in **Chunks** verarbeitet, standardmäßig 1.000 Befunde auf einmal. Nur der Chunk wird im Speicher gehalten, sodass ein Durchlauf über einen sehr großen Geltungsbereich im Speicherverbrauch begrenzt ist, nicht in der Abdeckung. Die einzige Ausnahme ist die **Vorschau**, die tatsächlich begrenzt ist und dies in ihrer Spur angibt, wenn sie kürzt.

Zwei weitere Zahlen bestimmen, wie die Arbeit aufgeteilt wird:

* **Befunde pro Ereignis**, standardmäßig 500. Eine Massenänderung wird auf mehrere Ereignisse aufgeteilt, von denen jedes zu einem eigenen Lauf wird. Der praktische Effekt bei einem großen Import ist eine überschaubare Anzahl von Läufen statt eines Laufs pro Befund.
* **Sendeobergrenze pro Befund**, standardmäßig 1.000. Ein Egress-Knoten, der so eingestellt ist, dass er eine Nachricht pro Befund sendet, hält bei dieser Anzahl in einem einzelnen Lauf an und protokolliert ein sichtbares Überspringen mit der Anzahl der nicht gesendeten Nachrichten. Dies begrenzt Zustellungszeilen und wartende Aufgaben, was ein in Chunks verarbeiteter Lauf allein nicht mehr begrenzt.

Alle drei sind Deployment-Einstellungen, dokumentiert unter [Configuration](../configuration/).

### Wie lange ein Lauf dauern darf

Ein Lauf setzt nach jedem Chunk einen **Heartbeat**. Die Stillstandserkennung liest diesen Heartbeat statt der Startzeit, sodass ein langer Durchlauf, der noch Fortschritte macht, niemals mit einem abgestürzten Worker verwechselt wird.

Zwei Zeitfenster gelten, beide konfigurierbar:

* Ein Lauf, der 30 Minuten ohne Heartbeat bleibt, wird als verwaist behandelt, auf Fehler gesetzt, und seine Sperre wird freigegeben.
* Ein Lauf wird nach sechs Stunden zwangsweise beendet, als Schutz gegen einen Lauf, der niemals fertig würde.

## Aufbewahrung

Läufe werden standardmäßig **180 Tage** lang aufbewahrt, zusammen mit ihren Zeilen pro Knoten und ihrer Befund-Herkunft. Zustellungen werden separat 180 Tage lang aufbewahrt.

Das Produkt teilt Ihnen dies mit, statt es implizit zu lassen: Die Detailansicht eines Laufs zeigt das Aufbewahrungsfenster und das Datum, an dem der Lauf gelöscht wird. Ein Lauf, der noch Zustellungen enthält, wird aufbewahrt, bis diese bereinigt sind.

Beide Zeitfenster sind konfigurierbar, und beide können so eingestellt werden, dass Datensätze unbegrenzt aufbewahrt werden. Siehe [Configuration](../configuration/#retention).

## Eine Regel manuell ausführen

Eine Regel, deren Auslöser **Manueller Lauf** ist, wird über die Aktion **Ausführen** in der Regelliste gestartet. Regeln mit anderen Auslösern laufen, wenn ihr Auslöser eintritt.

**Vorschau**, im Editor, ist die andere Möglichkeit, einen Graphen auszuführen. Sie führt die echte Engine aus und rollt anschließend alles zurück, zeichnet keinen Lauf auf und zwingt den Egress zur Simulation. Nutzen Sie die Vorschau während der Erstellung und Läufe, um zu sehen, was tatsächlich passiert ist.

## Herkunft an einem Befund

Läufe beantworten die Frage „Was hat diese Regel getan?“. Herkunft beantwortet die entgegengesetzte Frage: „Warum hat sich dieser Befund geändert?“.

Jede Änderung, die eine Regel vornimmt, wird am Befund zusammen mit der verantwortlichen Regel, dem Lauf und dem Knoten aufgezeichnet und erscheint als Zeitleiste am Befund selbst. Die aufgezeichneten Aktionen sind:

| Aktion | Bedeutung |
|--------|---------|
| `created`, `updated`, `closed`, `reopened` | Der Lebenszyklus des Befunds hat sich geändert. |
| `duplicate`, `status_change` | Seine Duplikat- oder Status-Flags haben sich geändert. |
| `notified` | Eine Benachrichtigung wurde dazu versendet. |
| `delivered` | Eine ausgehende Zustellung hat ihn abgedeckt. |

Feldbearbeitungen zeichnen auf, was sich geändert hat, einschließlich des Werts jedes Feldes vor und nach der Änderung. Sehr lange Werte werden im Datensatz gekürzt, sodass die Zeitleiste ein Protokoll der Änderung bleibt und keine zweite Kopie des Befunds.

Benachrichtigungen und Zustellungen werden ebenfalls hier aufgezeichnet. Das ist beabsichtigt: Eine Regel, die eine Nachricht gesendet, aber kein Feld geändert hat, würde sonst überhaupt keine Spur am Befund hinterlassen.

Die Herkunft überdauert die Regel. Das Löschen einer Regel oder eines Laufs behält die Zeitleisteneinträge bei und verknüpft sie lediglich neu, sodass der Verlauf nicht verschwindet, wenn jemand aufräumt.

## Regeln mit Verlauf löschen

Eine Regel, die Zustellungen erzeugt hat, kann nicht gelöscht werden, solange diese noch bestehen. Löschen Sie zuerst die Zustellungen, oder behalten Sie die Regel und deaktivieren Sie sie. Dies ist beabsichtigt: Zustellungen enthalten das Protokoll dessen, was tatsächlich an externe Systeme gesendet wurde, und ein kaskadierendes Löschen würde laufende Sendungen mit sich reißen.
