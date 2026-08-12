---
title: Zustellungen
description: Das Protokoll aller ausgehenden Sendungen von Regeln sowie der Funktionsweise
  von Wiederholungsversuchen und erneutem Senden
weight: 5
audience: pro
aliases:
- /de/automation/rules_engine_v2/deliveries/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Rules Engine 2.0 ist eine Funktion, die nur in DefectDojo Pro verfügbar ist.</span>

Jeder ausgehende Nebeneffekt, den eine Regel erzeugt, ist eine Zeile im Zustellungsprotokoll. **Rules Engine 2.0 > Deliveries** listet sie auf.

Die Zeile wird geschrieben, **bevor** ein Netzwerkaufruf stattfindet, und sie enthält genau das, was gesendet werden würde oder wurde. Das macht ausgehenden Datenverkehr überprüfbar, statt sich auf eine Logzeile zu verlassen, in der Hoffnung, dass sie jemand aufbewahrt hat, und deshalb ist Simulieren kein eigener Codepfad: Ein simulierter Versand ist dieselbe Zeile, nur ohne den Versandschritt.

## Was eine Zustellung erfasst

| Feld | Bedeutung |
|-------|---------|
| **Ausführung** und **Knoten** | Welche Ausführung und welcher Egress-Knoten sie erzeugt hat. |
| **Finding** | Der Befund, um den es bei einem Versand pro Befund geht. Sammelversände erfassen stattdessen die Gruppe. |
| **Channel** | Um welche Art von Versand es sich handelt. |
| **Target** | Das aufgelöste Ziel: ein JIRA-Projektschlüssel, ein Kanal, eine URL, eine Adresse. |
| **Title** | Eine einzeilige Beschreibung des Versands. |
| **Payload** | Genau das, was gesendet werden würde oder wurde. |
| **Mode** | `simulate` oder `live`. |
| **Status** | Wie weit die Zustellung gekommen ist. |
| **Attempts** | Wie viele Versandversuche bereits unternommen wurden, gemessen am zulässigen Maximum. |
| **Last error** | Warum der letzte Versuch fehlgeschlagen ist, oder warum die Zustellung übersprungen wurde. |
| **Response** | Was das Ziel zurückgemeldet hat. |
| **External reference** und **URL** | Der Ticketschlüssel, die Nachrichten-ID oder der Dateipfad, den das Ziel zurückgegeben hat, sowie ein Link dazu, falls vorhanden. |

## Kanäle

| Kanal | Erzeugt von |
|---------|-------------|
| **JIRA** | Ein JIRA-Issue erstellen |
| **Downstream connector** | Ein Downstream-Ticket erstellen |
| **Slack** | Eine Slack-Nachricht senden, sowie Berichtsankündigungen, die an Slack gesendet werden |
| **Microsoft Teams** | Eine Microsoft-Teams-Nachricht senden |
| **Email** | Eine E-Mail senden, sowie Berichtsankündigungen, die per E-Mail gesendet werden |
| **Webhook** | Einen Webhook aufrufen |
| **Report** | Einen Bericht erstellen |
| **In-app alert** | Eine In-App-Benachrichtigung auslösen |

## Status-Werte

| Status | Bedeutung |
|--------|---------|
| `simulated` | Die Regel befand sich im Simulationsmodus. Es wurde nichts gesendet, und es wird auch nie etwas gesendet werden. |
| `skipped` | Etwas anderes deckte diesen Versand bereits ab, oder eine Gating-Prüfung hat ihn abgelehnt. Der Grund steht im Feld „Last error“. |
| `pending` | Im Live-Modus erfasst, wartet auf ihre Zustellungsaufgabe. |
| `dispatched` | An den Integrationsdienst übergeben, wartet auf Bestätigung. |
| `sent` | Zustellung bestätigt. |
| `failed` | Endgültig abgelehnt, zum Beispiel durch einen 4xx-Fehler oder einen Fehler des Anbieters. Kann wiederholt werden. |
| `dead` | Wiederholungsversuche ausgeschöpft, oder es kam nie eine Bestätigung an. Kann wiederholt werden. |

`skipped` verdient eine genauere Betrachtung. Übersprungene Versände werden erfasst statt stillschweigend übergangen, denn „die Regel hat nichts getan“ und „die Regel hat nichts getan, weil dieser Befund bereits ein Ticket hatte“ sind unterschiedliche Antworten, und nur eine davon ist ein Problem.

Es gibt drei häufige Gründe für ein Überspringen, und das Feld „Last error“ nennt immer den jeweiligen:

* **Idempotenz.** Etwas anderes deckte diesen Versand bereits ab.
* **Der Kanal ist ausgeschaltet.** Eine Regel mit einem Slack-Knoten auf einer Instanz, auf der Slack deaktiviert ist, erfasst ein Überspringen mit entsprechender Erklärung, anstatt fehlzuschlagen. Eine Regel, die gespeichert wurde, während ein Kanal aktiv war, soll nicht plötzlich Fehler werfen, wenn ihn jemand abschaltet. Siehe [Verfügbarkeit von Knoten](../node_reference/#when-a-channel-is-unavailable).
* **Die Obergrenze für Versände pro Befund wurde erreicht.** Ein Knoten, der eine Nachricht pro Befund sendet, stoppt standardmäßig nach 1.000 Nachrichten in einer einzelnen Ausführung und erfasst, für wie viele weitere Befunde nichts gesendet wurde.

### Payload-Genauigkeit

Das Protokoll gibt ehrlich an, wie nah die erfasste Payload der tatsächlich übertragenen Nutzlast kommt, denn das ist je nach Kanal unterschiedlich.

| Genauigkeit | Bedeutung |
|----------|---------|
| `exact` | Byte-identisch mit dem, was gesendet wurde. |
| `rendered` | Von den echten Hilfsfunktionen gerendert, aber ein Gating zum Zeitpunkt des Versands kann sie noch kürzen. |
| `dojo request` | Die exakte Anfrage, die an den Integrationsdienst übergeben wurde. Die anbieterspezifische Payload wird nachgelagert zusammengesetzt. |
| `summary` | Eine Beschreibung des Versands statt einer Reproduktion davon. Ein generierter Bericht ist das Beispiel dafür: Die Datei wird zum Zeitpunkt des Versands aus Live-Daten erstellt, sodass eine gespeicherte Kopie davon in dem Moment falsch wäre, in dem sich irgendetwas ändert. |

## Der Schutz vor doppeltem Versand

Pro Idempotenzschlüssel kann nur eine **aktive** Zustellung existieren, durchgesetzt in der Datenbank und nicht nur per Konvention. Aktiv bedeutet `pending`, `dispatched` oder `sent`.

Ein zweiter Versand, der mit einem aktiven kollidieren würde, wird zu einer `skipped`-Zeile mit erfasstem Grund. Es ist niemals ein stiller No-Op, und es ist niemals ein doppeltes Ticket.

Da Zeilen mit `simulated`, `skipped`, `failed` und `dead` keinen Anspruch belegen, kann eine fehlgeschlagene Zustellung an Ort und Stelle wiederholt werden, ohne dass eine zweite Zeile um denselben Schlüssel konkurriert.

## Wiederholungsversuche

Eine Live-Zustellung wird automatisch wiederholt. Jede Zeile führt ihren eigenen Versuchszähler und ihre eigene Obergrenze, standardmäßig sechs Versuche, sodass ein fehlschlagendes Ziel nicht auch die anderen mit sich reißen kann. Zwischen den Versuchen liegt eine Verzögerung, die mit jedem Versuch wächst.

Wenn der letzte Wiederholungsversuch verbraucht ist, wird die Zeile als `dead` markiert, statt bei `pending` liegen zu bleiben. Erschöpfung ist sichtbar, nicht stillschweigend.

Wird ein Worker mitten im Versand beendet, wird die Nachricht erneut zugestellt. Die Zeile wird gesperrt und ihr Status erneut geprüft, bevor irgendetwas erneut gesendet wird, sodass eine erneute Zustellung nicht zu einem doppelten Versand werden kann.

Zustellungen, die an den Integrationsdienst übergeben wurden, wechseln zu `dispatched` und warten auf einen Bestätigungs-Callback. Trifft innerhalb von sechs Stunden kein Callback ein, wird die Zeile als `dead` markiert, damit sie wiederholt werden kann. Dieses Zeitfenster ist bewusst großzügig bemessen: Dass sich eine nachgelagerte Warteschlange eine Stunde lang staut, ist normal, und eine Zeile zu früh für tot zu erklären, würde aus einer Wiederholung ein doppeltes Ticket machen.

## Eine Zustellung wiederholen

Eine `failed`- oder `dead`-Zustellung kann von der Deliveries-Seite aus erneut gesendet werden. Das Protokoll erfasst, wann und von wem sie wiederholt wurde.

Für das Wiederholen ist **Regel bearbeiten** erforderlich.

Beim Wiederholen wird die erfasste Payload erneut gesendet. Bei einem Bericht bedeutet das, dass der Bericht aus den aktuellen Daten neu erzeugt wird, denn die Payload ist eine Beschreibung dessen, was erzeugt werden soll, und nicht die Datei selbst.

## Simulieren

Im Simulationsmodus schreibt jeder Egress-Knoten seine Zustellungszeile mit dem Status `simulated`, der vollständigen Payload und dem aufgelösten Ziel, und stoppt dann. Es wird kein Versand registriert, sodass später nichts gesendet werden kann, wie auch immer die Ausführung endet. Die Vorschau verhält sich genauso und fügt die Zeilen nicht einmal ein.

Das ist der vorgesehene Weg, um eine Regel zu prüfen, bevor man sie freigibt: im Simulationsmodus aktivieren, gegen echte Befunde laufen lassen, und dann die erfassten Payloads lesen.

Bedenken Sie, dass der Simulationsmodus **nur** die ausgehenden Versände zurückhält. Befunde-Knoten verändern Befunde weiterhin.

## Aufbewahrung

Zustellungen werden standardmäßig **180 Tage** aufbewahrt, danach entfernt ein Aufbewahrungsjob sie.

Das ist die am schnellsten wachsende Tabelle in dieser Funktion, denn ein Knoten, der eine Nachricht pro Befund sendet, schreibt eine Zeile pro Befund, sowohl im Simulationsmodus als auch im Live-Modus. Der Standardwert ist ein echtes Zeitfenster statt „alles behalten“, damit das Wachstum nicht unbemerkt zu Ihrem Problem wird.

Sie werden darüber informiert, statt es selbst entdecken zu müssen. Die Detailansicht einer Zustellung zeigt das Aufbewahrungsfenster und das Datum, an dem diese Zeile gelöscht wird, und das Datum wird bei jedem Lesevorgang neu berechnet, sodass eine Änderung des Zeitfensters sofort wirksam wird.

Stellen Sie das Zeitfenster länger ein, wenn Sie eine längere Nachweiskette für ausgehende Sendungen benötigen, oder auf `0`, um alles zu behalten. Siehe [Konfiguration](../configuration/#retention).
