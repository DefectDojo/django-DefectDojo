---
title: Knotenreferenz
description: Jeder Knoten, den Rules Engine 2.0 mitbringt, und was er jeweils tut
weight: 3
audience: pro
aliases:
- /de/automation/rules_engine_v2/node_reference/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Rules Engine 2.0 ist eine Funktion, die nur in DefectDojo Pro verfügbar ist.</span>

Rules Engine 2.0 bringt 25 Knoten in vier Kategorien mit. Diese Seite dokumentiert sie alle.

Sofern nicht anders angegeben, nimmt ein Knoten eine Eingabe entgegen, erzeugt eine Ausgabe namens `out` und gibt jedes empfangene Element an diese Ausgabe weiter. Das ist wichtig, wenn Sie Knoten verketten: Ein Befunde-Knoten verändert den Befund und reicht das Element dann weiter, sodass mehrere davon hintereinander alle wirksam werden.

## Trigger

Jeder Graph hat genau einen Trigger, und nur ein Trigger kann eine Ausführung starten. Alle drei erzeugen Befund-Elemente, und alle drei verwenden einen **Geltungsbereich**, der eingrenzt, welche Befunde sie erzeugen. Wie der Geltungsbereich funktioniert, erfahren Sie unter [Regeln erstellen](../building_rules/).

### Bei einem Befund-Ereignis

`trigger.finding`

Läuft, wenn Befunde erstellt, aktualisiert, geschlossen oder wieder geöffnet werden.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Ereignis** | `created` | Welche Befund-Änderung diese Regel weckt: `created`, `updated`, `closed`, `reopened`, oder `any` für alle vier. |
| **Geltungsbereich** | leer | Welche Befunde diese Regel berücksichtigt. Leer bedeutet jeden Befund, den der Regel-Eigentümer sehen kann. |

Von dem Ereignis benannte Befunde werden vor dem Eintritt in den Graphen mit dem Geltungsbereich abgeglichen, sodass das Ereignis entscheidet, *wann*, und der Geltungsbereich entscheidet, *welche*.

### Nach Zeitplan

`trigger.schedule`

Durchsucht nach einem Zeitplan alle Befunde im Geltungsbereich. Der Zeitplan wird an der Regel konfiguriert und ist auf Viertelstundenmarken beschränkt.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Geltungsbereich** | leer | Welche Befunde diese Regel berücksichtigt. |

### Manuelle Ausführung

`trigger.manual`

Durchsucht alle Befunde im Geltungsbereich, wenn Sie bei der Regel auf **Ausführen** klicken.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Geltungsbereich** | leer | Welche Befunde diese Regel berücksichtigt. |

## Logik

### Wenn / Filter

`filter.if`

Leitet jedes Element anhand von Bedingungen in den **true**- oder den **false**-Zweig. Das ist der einzige Knoten mit zwei Ausgängen, und so verzweigt sich ein Graph.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Bedingungen** | leer | Jede Zeile besteht aus einem Pfad, einem Operator und einem Wert. Siehe [Bedingungen](../building_rules/#conditions). |
| **Übereinstimmung** | `all` | Ob jede Bedingung erfüllt sein muss (`all`) oder nur eine davon (`any`). |

Eine leere Bedingungsliste lässt alles in den true-Zweig durch. Beide Zweige sind optional: Wird der false-Zweig nicht verbunden, werden die nicht zutreffenden Elemente einfach verworfen.

### Begrenzung

`flow.limit`

Lässt die ersten N Elemente durch und verwirft den Rest. Nützlich als Sicherheitsventil beim Testen einer Regel und um zu begrenzen, wie viele Tickets oder Nachrichten eine einzelne Ausführung erzeugen kann.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Erste behalten** | `100` | Wie viele Elemente weitergegeben werden. |

### Innerhalb der Ausführung deduplizieren

`flow.dedupe_batch`

Behält das erste Element pro Schlüssel und verwirft spätere Elemente mit demselben Schlüssel. Auf die Ausführung beschränkt, sodass innerhalb einer Ausführung dedupliziert wird, nicht über mehrere Ausführungen hinweg.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Schlüsselpfad** | `finding.hash_code` | Der Element-Pfad, dessen Wert ein Duplikat identifiziert. |

Ein gängiger Anwendungsfall ist `finding.component_name`, um einmal pro betroffener Komponente statt einmal pro Befund zu benachrichtigen.

## Befunde

Diese Knoten verändern Befunde. Jede Änderung wird der Regel, der Ausführung und dem Knoten zugeordnet, die sie vorgenommen haben, und erscheint in der Herkunfts-Zeitleiste des Befunds.

### Schweregrad festlegen

`finding.set_severity`

Legt den Schweregrad fest und berechnet dabei das SLA-Datum und die Priorität neu.

| Einstellung | Optionen |
|---------|---------|
| **Schweregrad** | `Critical`, `High`, `Medium`, `Low`, `Info` |

### Ein Feld festlegen

`finding.set_field`

Legt ein Textfeld fest, hängt daran an oder stellt ihm etwas voran.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Feld** | keiner | Eines von `component_name`, `component_version`, `cvssv3`, `cwe`, `description`, `file_path`, `impact`, `mitigation`, `service`, `title`. |
| **Modus** | `set` | `set`, `append` oder `prepend`. Ein CVSSv3-Vektor kann nur ersetzt werden. |
| **Wert** | keiner | Der zu schreibende Text. Unterstützt Platzhalter im Stil von `{{finding.title}}`. |

### Status festlegen

`finding.set_status`

Versetzt den Befund in einen Status.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Status** | keiner | `active`, `inactive`, `verified`, `unverified`, `false_positive`, `mitigated`, `reopen`. |
| **Notiz** | leer | Eine optionale Notiz, die zusammen mit der Statusänderung erfasst wird. |

### Tags hinzufügen

`finding.add_tags`

Fügt dem Befund Tags hinzu. Vorhandene Tags bleiben erhalten.

| Einstellung | Hinweise |
|---------|-------|
| **Tags** | Durch Kommas getrennt. Unterstützt Platzhalter im Stil von `{{product.name}}`, sodass Sie mit Daten aus dem Befund taggen können. |

### Eine Notiz hinzufügen

`finding.add_note`

Fügt dem Befund eine Notiz hinzu.

| Einstellung | Hinweise |
|---------|-------|
| **Notiz** | Der Notiztext. Unterstützt Platzhalter. |

### Eigentümer festlegen

`finding.set_owners`

Macht eine Gruppe für den Befund verantwortlich.

| Einstellung | Hinweise |
|---------|-------|
| **Gruppe** | Die Gruppe, der diese Befunde gehören. |

### Prüfer festlegen

`finding.set_reviewers`

Stellt den Befund zur Prüfung durch die ausgewählten Benutzer.

| Einstellung | Hinweise |
|---------|-------|
| **Prüfer** | Ein oder mehrere Benutzer, die diese Befunde prüfen sollen. |

### Risiko akzeptieren

`finding.risk_accept`

Akzeptiert den Befund per einfacher Risikoakzeptanz oder fügt ihn einem Risikoakzeptanz-Datensatz hinzu.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Wie** | `simple` | `simple` setzt eine einfache Risikoakzeptanz auf den Befund. `acceptance` fügt ihn einem Risikoakzeptanz-Datensatz hinzu. |
| **Akzeptiert** | ein | Wird bei `simple` angezeigt. Ausschalten, um die Risikoakzeptanz rückgängig zu machen. |
| **Risikoakzeptanz** | keine | Wird bei `acceptance` angezeigt. Zu welcher Risikoakzeptanz diese Befunde hinzugefügt werden. |

### Behebungsrichtlinie festlegen

`finding.set_mitigation_policy`

Legt die Behebungsrichtlinie fest, unter der der Befund behoben wird.

| Einstellung | Hinweise |
|---------|-------|
| **Behebungsrichtlinie** | Die anzuwendende Richtlinie. |

### Priorität ändern

`finding.set_priority`

Legt die Priorität fest oder passt sie rechnerisch an. Das überschreibt die berechnete Priorität.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Operation** | `set` | `set`, `add`, `subtract`, `multiply`, `divide`. |
| **Wert** | keiner | Die zu setzende Priorität, oder der Betrag, um den angepasst wird. |

### Risiko festlegen

`finding.set_risk`

Legt das Risiko fest und überschreibt damit das berechnete.

| Einstellung | Optionen |
|---------|---------|
| **Risiko** | `Low`, `Medium`, `Needs Action`, `Urgent` |

## Egress

Egress-Knoten sind die Knoten, die DefectDojo verlassen. Jeder von ihnen erfasst eine [Zustellung](../deliveries/), bevor irgendetwas gesendet wird, und jeder von ihnen beachtet den **Simulate**- oder **Live**-Modus der Regel.

Mehrere von ihnen bieten dieselbe Option **Eine Nachricht pro Befund**. Ausgeschaltet sendet der Knoten eine Nachricht, die den gesamten Batch beschreibt, mit einer Aufschlüsselung nach Schweregrad und einer begrenzten Liste von Befunden. Eingeschaltet sendet er eine Nachricht pro Befund.

Ein Knoten, der eine Nachricht pro Befund sendet, stoppt standardmäßig nach 1.000 Versänden in einer einzelnen Ausführung und erfasst ein sichtbares Überspringen, das angibt, für wie viele Befunde nichts gesendet wurde. Siehe [Konfiguration](../configuration/#per-finding-send-ceiling).

### Wenn ein Kanal nicht verfügbar ist

Ein Egress-Knoten hängt von etwas außerhalb der Regel ab: einem Slack-Token, einem Microsoft-Teams-Webhook, einer JIRA-Konfiguration, einem lizenzierten Connector. Fehlt das oder ist es abgeschaltet, kann der Knoten nicht arbeiten, und Rules Engine 2.0 macht das an drei verschiedenen Stellen deutlich, statt still zu scheitern:

* **In der Palette** wird ein nicht verfügbarer Knoten als solcher markiert, mit Angabe des Grundes, bevor Sie ihn auf die Zeichenfläche ziehen.
* **Beim Speichern** wird ein Graph, der einen nicht verfügbaren Knoten enthält, abgelehnt. Das ist der Moment, in dem jemand anwesend ist, um einen anderen auszuwählen.
* **Zur Laufzeit** wird die Zustellung mit angehängtem Grund **übersprungen**, nicht als fehlgeschlagen markiert. Eine Regel, die gespeichert wurde, während Slack aktiv war, soll nicht plötzlich Fehler werfen, sobald jemand Slack abschaltet. Der ehrliche Eintrag ist eine übersprungene Zustellung, die besagt, dass Slack abgeschaltet ist.

### Ein JIRA-Issue erstellen

`ticket.jira`

Erstellt oder aktualisiert das JIRA-Issue für den Befund.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Befunde überspringen, die bereits ein Issue haben** | ein | Lässt Befunde unangetastet, die bereits ein JIRA-Issue haben. |
| **Vorhandenes Issue aktualisieren** | aus | Wird angezeigt, wenn die obige Option ausgeschaltet ist. Übermittelt Befunde, die bereits ein Issue haben, sodass JIRA aktualisiert wird. |

Zusammenfassung, Beschreibung und Priorität stammen aus der JIRA-Konfiguration des Produkts, nicht aus diesem Knoten. Ein von einer Regel erstelltes Ticket ist daher identisch mit einem, das durch „Alle Issues übermitteln" erstellt wurde.

### Ein Downstream-Ticket erstellen

`ticket.downstream`

Erstellt oder aktualisiert ein Ticket über einen [Downstream-Connector](/connectors/downstream/about/).

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Issue-Tracker** | `auto` | `auto` verwendet die Issue-Tracker, die dem Engagement oder Produkt zugewiesen sind. `mapping` zielt auf ein bestimmtes Mapping. |
| **Issue-Tracker-Mapping** | keines | Wird bei `mapping` angezeigt. An welches Mapping übermittelt wird. |
| **Operation** | `create` | `create` erzeugt ein Ticket, oder `update` aktualisiert das vorhandene. Ein Update ohne vorhandenes Ticket erstellt es. |
| **Befunde überspringen, die bereits ein Ticket haben** | ein | Lässt Befunde unangetastet, die im Ziel-Mapping bereits ein Ticket haben. |

Die Regel ersetzt die automatischen Übermittlungseinstellungen der Zuweisung: Schweregrad- und „nur aktiv"-Filter werden hier nicht ein zweites Mal angewendet. Ein Befund, dessen Ticket bereits existiert, wird übersprungen, unabhängig davon, wie dieses Ticket erstellt wurde.

### Eine Slack-Nachricht senden

`notify.slack`

Postet über einen Messaging-Connector in einen Slack-Kanal. Die Verbindung führt das Bot-Token; die instanzweiten Slack-Einstellungen unter **Systemeinstellungen** werden nicht verwendet und dienen nicht als Fallback.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Verbindung** | keine | Ein [Messaging-Connector](/issue_tracking/pro_integration/messaging_connectors/) dieses Typs. Erforderlich. |
| **Ziel** | leer | Wird angezeigt, sobald eine Connection ausgewählt ist. Die Felder hängen vom Anbieter der Connection ab. |
| **Eine Nachricht pro Befund** | aus | Ausgeschaltet sendet eine Nachricht über den gesamten Batch. |
| **Nachricht** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Wird pro Befund gerendert. |
| **In der Zusammenfassung aufgeführte Befunde** | `10` | Wird bei Sammelnachrichten angezeigt. Wie viele Befunde die Nachricht auflistet, bevor sie angibt, wie viele weitere es gab. |

### Eine Microsoft-Teams-Nachricht senden

`notify.msteams`

Postet eine Karte über einen Messaging-Connector. Die Verbindung führt die Power-Automate-Workflow-URL; der instanzweite Teams-Webhook unter **Systemeinstellungen** wird nicht verwendet und dient nicht als Fallback.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Verbindung** | keine | Ein [Messaging-Connector](/issue_tracking/pro_integration/messaging_connectors/) dieses Typs. Erforderlich. |
| **Ziel** | leer | Wird angezeigt, sobald eine Connection ausgewählt ist. Die Felder hängen vom Anbieter der Connection ab. |
| **Eine Nachricht pro Befund** | aus | Ausgeschaltet sendet eine Karte über den gesamten Batch. |
| **Nachricht** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Wird pro Befund gerendert. |
| **In der Zusammenfassung aufgeführte Befunde** | `10` | Wird bei Sammelnachrichten angezeigt. |

### Eine E-Mail senden

`notify.email`

Verschickt E-Mails an eine feste Liste von Adressen über einen Messaging-Connector. Die Empfänger sind das Ziel der Connection.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Verbindung** | keine | Ein [Messaging-Connector](/issue_tracking/pro_integration/messaging_connectors/) dieses Typs. Erforderlich. |
| **Ziel** | leer | Wird angezeigt, sobald eine Connection ausgewählt ist. Die Felder hängen vom Anbieter der Connection ab. |

| **Betreff** | `[DefectDojo] {{ctx.count}} finding(s) from rule {{ctx.rule_name}}` | Wird einmal pro Nachricht gerendert. |
| **Inhalt** | ein HTML-Body, der `{{ctx.findings_html}}` enthält | HTML. `{{ctx.findings_html}}` rendert die Befundliste. |
| **Eine Nachricht pro Befund** | aus | Ausgeschaltet sendet eine E-Mail über den gesamten Batch. |
| **Im Inhalt aufgeführte Befunde** | `25` | Wie viele Befunde `{{ctx.findings_html}}` auflistet, bevor angegeben wird, wie viele weitere es gab. |

### Einen Webhook aufrufen

`notify.webhook`

Sendet JSON per POST an einen Webhook-Endpunkt.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Webhook-Endpunkt** | keiner | Ein konfigurierter [Benachrichtigungs-Webhook](/automation/api/notification_webhooks/). Sein benutzerdefinierter Header wird mit der Anfrage gesendet. |
| **URL** | leer | Wird angezeigt, wenn kein Endpunkt ausgewählt ist. Wohin per POST gesendet wird. |
| | | Eine der beiden oben genannten Optionen ist erforderlich. |
| **Signaturschlüssel** | leer | Signiert den Body als `X-DefectDojo-Signature: sha256=HMAC`. |
| **Eine Nachricht pro Befund** | aus | Ausgeschaltet postet den gesamten Batch in einer einzigen Anfrage. |

Zwei Dinge sind wichtig zu wissen. Ein hier eingegebenes Signing Secret wird zusammen mit der Regel gespeichert. Bevorzugen Sie daher für alles Sensible einen konfigurierten Endpunkt mit eigenem Header. Und ein von einer Regel aufgerufener Webhook ändert niemals den eigenen Health-Status dieses Endpunkts, sodass eine Regel Ihre Benachrichtigungs-Webhooks nicht durch Fehlschlagen deaktivieren kann.

Frei eingegebene URLs werden beim Speichern validiert. Siehe [Konfiguration](../configuration/#outbound-destination-validation) für Informationen dazu, was abgelehnt wird und wie private Adressen zugelassen werden können.

### Eine In-App-Benachrichtigung auslösen

`notify.alert`

Erstellt eine In-App-Benachrichtigung über den Batch.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Titel** | `Rules Engine 2.0: {{ctx.rule_name}}` | Wird einmal für den gesamten Batch gerendert. |
| **Beschreibung** | `{{ctx.count}} finding(s) matched the rule {{ctx.rule_name}}.` | Wird einmal für den gesamten Batch gerendert. |
| **Empfänger** | leer | Benutzernamen, durch Kommas getrennt. Leer benachrichtigt die Administratoren. |

Empfänger steuern dies weiterhin über ihre eigene Benachrichtigungseinstellung **Rules Engine Match**, sodass eine Benachrichtigung die Benachrichtigungspräferenzen eines Benutzers nicht umgehen kann.

### Einen Bericht erstellen

`report.generate`

Erzeugt einen Bericht aus einer Vorlage, beschränkt auf die Befunde, die diesen Knoten erreicht haben, und kann den Download-Link ankündigen.

| Einstellung | Standard | Hinweise |
|---------|---------|-------|
| **Berichtsvorlage** | keine | Aus welcher Vorlage erzeugt wird. Erforderlich. |
| **Format** | `pdf` | `pdf` oder `html`. |
| **Enthaltene Befunde** | `batch_findings` | `batch_findings` beschränkt den Bericht auf die Befunde, die diesen Knoten erreicht haben. `template_default` lässt die Vorlage ihre eigenen Filter verwenden. |
| **Ankündigen über** | keine | Ein [Messaging-Connector](/issue_tracking/pro_integration/messaging_connectors/), über den der Download-Link gepostet wird, sobald der Bericht erzeugt wurde. Leer lassen, um nicht anzukündigen. |
| **Ankündigen an** | leer | Wird angezeigt, sobald eine Connection ausgewählt ist. Wohin diese Connection sendet: eine Slack-Kanal-ID, E-Mail-Adressen und so weiter. |
| **Ankündigung** | `Report ready: {{ctx.report_url}}` | Wird bei einer Ankündigung angezeigt. `{{ctx.report_url}}` ist der Download-Link. |

`batch_findings` ist das, was eine Regel kann und ein geplanter Bericht nicht: genau über die Befunde berichten, die gerade zugetroffen haben.

Die Ankündigung wird als eigene Zustellung erfasst, getrennt von der Berichtserstellung, sodass Sie sehen können, dass der Bericht erfolgreich war, während die Ankündigung unabhängig davon fehlschlägt.
