---
title: Messaging-Connectors
description: Senden Sie Warnungen von DefectDojo an Slack, Microsoft Teams, E-Mail
  oder Amazon SNS.
weight: 4
audience: pro
---

**Verfügbarkeit:** Messaging-Connectors sind eine Beta-Funktion. Aktivieren Sie **Messaging Connectors** auf der Seite „Feature Flags“. Da Warnungen über Regeln weitergeleitet werden, muss außerdem **Rules Engine 2.0** aktiviert sein.

Messaging-Connectors senden Warnungen von DefectDojo an einen Chatdienst, an eine E-Mail-Adresse oder an ein Amazon-SNS-Topic. Sie stehen neben den Ticketing- und Incident-Management-Connectors auf derselben Seite **Downstream Connectors** und werden auf dieselbe Weise konfiguriert: Sie erstellen einmal eine Verbindung und legen dann fest, was darüber gesendet werden soll.

Ticketing-Connectors und Messaging-Connectors beantworten unterschiedliche Fragen. Ein Ticketing-Connector erstellt und aktualisiert ein Ticket, das einen Befund über die Zeit verfolgt. Ein Messaging-Connector veröffentlicht eine Nachricht über etwas, das gerade passiert ist, zum Beispiel einen Import, der neue Befunde mit dem Schweregrad Hoch und Kritisch eingebracht hat. Eine Nachricht hat keinen Status, der sich ändern könnte, und kein Ticket, das synchron gehalten werden muss. Daher werden beide getrennt konfiguriert und beeinflussen sich nicht gegenseitig.

## Was Sie senden können

Warnungen werden über die Rules Engine 2.0 weitergeleitet. Eine Regel legt fest, **wann** gesendet wird (ein Trigger), **welche** Befunde infrage kommen (Bedingungen) und **wohin** die Nachricht geht (ein Notify-Knoten, der Ihre Verbindung und Ihren Kanal adressiert).

Das bedeutet, dass einer Warnung dieselben Filter zur Verfügung stehen wie einer Regel: Schweregrad, Geltungsbereich, Tags, Status und alles andere, was eine Regelbedingung ausdrücken kann. Mehrere unterschiedliche Warnungen an mehrere unterschiedliche Kanäle sind schlicht mehrere Regeln.

## Die vier Anbieter

| Anbieter | Was Sie bereitstellen | Wie viele Ziele pro Verbindung |
| --- | --- | --- |
| Slack | Ein Bot-Token aus einer Slack-App | Viele. Jedes Ziel nennt eine Kanal-ID. |
| Microsoft Teams | Eine Power-Automate-Workflow-URL | Eines. Die URL bestimmt den Kanal. |
| E-Mail | Nichts. Es wird der Mailserver der Instanz verwendet. | Viele. Jedes Ziel nennt Empfänger. |
| Amazon SNS | Ein AWS-Zugriffsschlüssel mit Veröffentlichungsrecht | Viele. Jedes Ziel nennt ein Topic-ARN. |

Jeder wird auf dieselbe Weise eingerichtet: Fügen Sie die Verbindung unter **Connect > Downstream** hinzu und erstellen Sie anschließend eine Warnung,
die sie adressiert.

## Eine Slack-Verbindung einrichten

Sie benötigen eine Slack-App mit einem Bot-Token. Wenn Ihr Workspace bereits eine für DefectDojo hat, können Sie diese wiederverwenden.

### 1. Eine Slack-App erstellen

1. Rufen Sie [https://api.slack.com/apps](https://api.slack.com/apps) auf und wählen Sie **Create New App**, dann **From scratch**.
2. Benennen Sie die App (zum Beispiel DefectDojo) und wählen Sie den Workspace aus, in den sie posten soll.
3. Öffnen Sie **OAuth & Permissions** und fügen Sie diese **Bot Token Scopes** hinzu:
   - `chat:write` (erforderlich): erlaubt der App, Nachrichten zu posten.
   - `chat:write.public` (optional): erlaubt der App, in jeden öffentlichen Kanal zu posten, ohne vorher dazu eingeladen zu werden. Ohne diesen Scope müssen Sie den Bot zu jedem Kanal einladen, den Sie verwenden möchten.
4. Wählen Sie **Install to Workspace** und genehmigen Sie die App.
5. Kopieren Sie das **Bot User OAuth Token**. Es beginnt mit `xoxb-`.

### 2. Die Verbindung in DefectDojo hinzufügen

1. Gehen Sie zu **Connect > Downstream**.
2. Suchen Sie im Bereich **Messaging** die Slack-Kachel und wählen Sie **Add Configuration**.
3. Geben Sie Folgendes ein:
   - **Location**: die URL Ihres Slack-Workspace, zum Beispiel `https://your-workspace.slack.com`. Dies dient nur der Anzeige und für Links.
   - **Identifier**: eine Bezeichnung, die diese Verbindung von anderen unterscheidet, zum Beispiel `Security workspace`.
   - **Bot Token**: das kopierte `xoxb-`-Token.
4. Speichern Sie. DefectDojo validiert das Token sofort bei Slack, sodass ein falsches oder widerrufenes Token bereits hier gemeldet wird und nicht erst, wenn eine Warnung ausgelöst wird.

Sie können so viele Slack-Verbindungen hinzufügen, wie Sie benötigen. Über getrennte Verbindungen erreichen Sie mehr als einen Workspace.

### 3. Die Kanal-ID finden

Slack-Ziele verwenden eine Kanal-**ID**, keinen Kanalnamen.

1. Öffnen Sie in Slack den Kanal und wählen Sie oben seinen Namen aus.
2. Scrollen Sie im Tab **About** nach unten.
3. Kopieren Sie die **Channel ID**. Sie sieht etwa so aus: `C0123456789`.

Wenn die App nicht über den Scope `chat:write.public` verfügt, laden Sie sie zusätzlich in den Kanal ein: Geben Sie im Kanal `/invite @your-app-name` ein.

## Eine Microsoft-Teams-Verbindung einrichten

Teams verwendet eine **Power-Automate-Workflow-URL**. Klassische Office-365-Connectors wurden abgeschaltet, und dieser Weg
benötigt weder eine App-Registrierung noch eine Zustimmung des Tenant-Administrators: Jemand mit Rechten für den Kanal
erstellt den Flow und fügt die zurückgegebene URL ein.

**Eine Verbindung postet in einen Kanal.** Die Workflow-URL entscheidet, wohin die Nachricht geht. Ein
zweiter Kanal bedeutet daher eine zweite Verbindung und nicht ein zweites Ziel.

### 1. Den Workflow erstellen

1. Öffnen Sie in Teams den Kanal, in den gepostet werden soll, wählen Sie das Menü **...** neben dem Kanalnamen und dann **Workflows**.
2. Wählen Sie die Vorlage **Post to a channel when a webhook request is received**.
3. Bestätigen Sie Team und Kanal und wählen Sie dann **Add workflow**.
4. Kopieren Sie die URL, die der Workflow liefert. Es handelt sich um eine lange `https://`-Adresse auf einem Microsoft-Power-Automate-Host.

Behandeln Sie diese URL wie ein Passwort. Jeder, der sie besitzt, kann in diesen Kanal posten.

### 2. Die Verbindung in DefectDojo hinzufügen

1. Gehen Sie zu **Connect > Downstream**.
2. Suchen Sie im Bereich **Messaging** die Kachel für Microsoft Teams und wählen Sie **Add Configuration**.
3. Geben Sie Folgendes ein:
   - **Location**: Ihre Teams- oder Microsoft-365-URL. Dies dient nur der Anzeige und für Links.
   - **Instance Label**: eine Bezeichnung, die den Kanal benennt, den diese Verbindung erreicht, zum Beispiel `Security / Alerts`.
   - **Workflow URL**: die kopierte URL.
4. Speichern Sie.

DefectDojo prüft beim Speichern die Form der URL (sie muss `https://` verwenden und auf einem Microsoft-Workflow-Host liegen), postet aber nicht dorthin. Eine Workflow-URL lässt sich nur durch das Senden einer Nachricht testen, und eine überraschende Nachricht in einem Kanal beim Speichern wäre schlimmer, als es später zu erfahren. Verwenden Sie **Send test message**, wenn Sie so weit sind.

Ein Teams-Ziel hat ein optionales Feld, eine Kanalbezeichnung, die lediglich den Zustellungsdatensatz beschriftet. Die Workflow-URL bestimmt bereits das Ziel.

## Eine E-Mail-Verbindung einrichten

E-Mail benötigt keine Zugangsdaten. DefectDojo sendet über den Mailserver, den diese Instanz bereits für Benachrichtigungen verwendet, sodass es nichts Neues zu konfigurieren gibt und keine zweite Stelle, an der SMTP falsch eingestellt sein könnte.

1. Gehen Sie zu **Connect > Downstream**.
2. Suchen Sie im Bereich **Messaging** die E-Mail-Kachel und wählen Sie **Add Configuration**.
3. Geben Sie Folgendes ein:
   - **Location**: die anzuzeigende Absenderidentität, zum Beispiel `mailto:defectdojo@example.com`.
   - **Instance Label**: eine Bezeichnung, die diese Verbindung von anderen unterscheidet.
4. Speichern Sie.

Das Speichern schlägt fehl, wenn für diese Instanz kein Mailserver oder keine Absenderadresse konfiguriert ist, da über die Verbindung nichts das Haus verlassen würde. Konfigurieren Sie SMTP zuerst unter **Settings > System Settings**.

Empfänger werden bei der Warnung festgelegt, nicht bei der Verbindung, sodass eine E-Mail-Verbindung für alle Warnungen ausreicht. Ein E-Mail-Ziel akzeptiert bis zu 50 Adressen; darüber hinaus verwenden Sie eine Verteileradresse.

## Eine Amazon-SNS-Verbindung einrichten

SNS unterscheidet sich grundsätzlich von den anderen drei: DefectDojo veröffentlicht eine Nachricht in einem Topic, und AWS
verteilt sie an alles, was abonniert ist – das können E-Mail-Adressen, SMS-Nummern, eine Lambda-Funktion,
ein HTTPS-Endpunkt oder eine SQS-Warteschlange sein. DefectDojo weiß nicht, was davon zutrifft, und muss es auch nicht wissen.

### 1. Einen Zugriffsschlüssel mit Veröffentlichungsrecht erstellen

1. Erstellen (oder wählen) Sie in der AWS-Konsole einen IAM-Benutzer oder eine Rolle für DefectDojo.
2. Fügen Sie eine Policy hinzu, die `sns:Publish` für die vorgesehenen Topics erlaubt. Es ist besser, die Topic-ARNs explizit zu benennen, als alle zu erlauben.
3. Erstellen Sie dafür einen Zugriffsschlüssel und kopieren Sie beide Hälften. AWS zeigt den Secret Access Key nur einmal an.

Wenn das Topic mit einem KMS-Schlüssel verschlüsselt ist, benötigt derselbe Principal für diesen Schlüssel außerdem `kms:GenerateDataKey` und `kms:Decrypt`, andernfalls wird jede Veröffentlichung verweigert.

### 2. Die Verbindung in DefectDojo hinzufügen

1. Gehen Sie zu **Connect > Downstream**.
2. Suchen Sie im Bereich **Messaging** die Amazon-SNS-Kachel und wählen Sie **Add Configuration**.
3. Geben Sie Folgendes ein:
   - **Location**: eine URL nur für Anzeige und Links, zum Beispiel die URL Ihrer AWS-Konsole.
   - **Instance Label**: eine Bezeichnung, die diese Verbindung von anderen unterscheidet, zum Beispiel `Production AWS account`.
   - **Access Key ID**: die Schlüssel-ID, die etwa so aussieht: `AKIAIOSFODNN7EXAMPLE`.
   - **Secret Access Key**: die geheime Hälfte.
4. Speichern Sie.

DefectDojo prüft die Zugangsdaten sofort bei AWS, sodass ein falscher oder gelöschter Schlüssel bereits hier gemeldet wird und nicht erst, wenn eine Warnung ausgelöst wird. Diese Prüfung bestätigt lediglich, dass die Zugangsdaten gültig sind; ob damit in ein bestimmtes Topic veröffentlicht werden darf, wird geprüft, wenn Sie das Ziel festlegen.

**Es gibt kein Regionsfeld.** Die Region ist Teil des Topic-ARN, sodass eine Verbindung in Topics mehrerer Regionen veröffentlichen kann und es keine zweite Einstellung gibt, die dem ARN widersprechen könnte.

### 3. Das Topic-ARN finden

Ein SNS-Ziel verwendet das ARN des Topics.

1. Öffnen Sie in der SNS-Konsole das Topic.
2. Kopieren Sie das **ARN** oben auf der Seite. Es sieht etwa so aus: `arn:aws:sns:us-east-1:123456789012:security-alerts`.

Anders als eine Teams-Workflow-URL ist ein ARN kein Geheimnis: Es benennt lediglich ein Topic, und für das Veröffentlichen ist die Zugangsberechtigung der Verbindung erforderlich. Deshalb kann eine SNS-Verbindung viele Topics bedienen.

FIFO-Topics (ein ARN, das auf `.fifo` endet) werden nicht unterstützt. Sie benötigen eine Nachrichtengruppe und eine Deduplizierungs-ID – Reihenfolgeregeln, die eine Warnung nicht liefern kann. Verwenden Sie ein Standard-Topic.

## Eine Testnachricht senden

Überall dort, wo ein Messaging-Ziel konfiguriert ist, sendet **Send test message** eine kurze Nachricht genau über den Weg, den auch eine echte Warnung nutzt, und meldet die Antwort des Anbieters.

Nutzen Sie sie, um die Dinge zu bestätigen, bei denen leicht Fehler passieren: bei Slack, dass die Kanal-ID stimmt und der Bot dort posten kann; bei Teams, dass die Workflow-URL noch funktioniert; bei E-Mail, dass die Adresse zustellbar ist; bei SNS, dass der Schlüssel in dieses Topic veröffentlichen darf. Die Antwort des Anbieters wird unverändert durchgereicht, sodass eine fehlende Slack-Einladung als Hinweis erscheint, den Bot einzuladen, statt als allgemeiner Fehler.

Ein erfolgreicher Test hebt außerdem eine automatisch deaktivierte Verbindung wieder auf (siehe [Wenn eine Verbindung nicht mehr funktioniert](#when-a-connection-stops-working)).

## Eine Warnung erstellen

Es gibt zwei Wege dorthin. Beide führen zum selben Ergebnis: einer Regel der Rules Engine 2.0.

### Die Seite „Warnungen“

Der kurze Weg für den häufigen Fall, neue Befunde aus einem Import bekanntzugeben.

1. Gehen Sie zu **Connect > Downstream** und wählen Sie bei einer Messaging-Verbindung **Create Alert**, oder öffnen Sie direkt **Messaging Alerts**.
2. Wählen Sie **New Alert** und füllen Sie aus:
   - **Name**: wofür diese Warnung dient, zum Beispiel `New highs to the security channel`.
   - **Alert**: worum es geht. **New findings from an import** ist derzeit die einzige Option.
   - **Send over**: die Messaging-Verbindung.
   - **Where it delivers**: das jeweilige Zielfeld des Anbieters, also eine Slack-Kanal-ID, eine optionale Teams-Kanalbezeichnung, eine Liste von E-Mail-Adressen oder ein SNS-Topic-ARN.
   - **Severity**: die Untergrenze, von **Critical only** bis **Every severity**.
   - **Mode**: **Simulate** protokolliert, was gesendet worden wäre, ohne es zu senden; **Live** sendet tatsächlich.
3. Wählen Sie **Create Alert**.

Die Seite listet die erstellten Warnungen mit Trigger, Schweregrad-Untergrenze und einem Schalter zum Aktivieren oder Deaktivieren jeder einzelnen auf.

Beginnen Sie mit **Simulate**, wenn Sie sehen möchten, was eine Warnung erfasst hätte, bevor irgendein Kanal davon erfährt. Die Regel läuft, die Zustellungen werden protokolliert, und es wird nichts gesendet.

Warnungen sind Regeln und lassen sich daher aus derselben Liste auch im Regeleditor öffnen. Sobald eine Regel zu etwas bearbeitet wurde, das das Formular nicht abbilden kann, etwa einem zweiten Zweig oder einer zweiten Nachricht, bietet die Liste statt des Formulars den Regeleditor an, anstatt die zusätzliche Arbeit stillschweigend zu verwerfen.

### Der Regeleditor

Der vollständige Weg für alles, was das Formular nicht abdeckt.

1. Gehen Sie zu **Automation > Rules Engine 2.0** und erstellen Sie eine Regel.
2. Fügen Sie einen Trigger hinzu. Für Warnungen zu neu importierten Befunden verwenden Sie den Finding-Ereignis-Trigger bei **created**. Importe werden gebündelt, sodass ein Import eine Warnung erzeugt statt einer pro Befund.
3. Fügen Sie Bedingungen dafür hinzu, was infrage kommen soll, zum Beispiel einen Mindest-Schweregrad von Hoch.
4. Fügen Sie einen Nachrichtenknoten für den gewünschten Anbieter hinzu (**Send a Slack Message**, **Send a Microsoft Teams Message**, **Send an Email** oder **Publish to an SNS Topic**) und legen Sie fest:
   - **Connection**: die von Ihnen erstellte Messaging-Verbindung.
   - **Destination**: das Ziel des Anbieters, also eine Kanal-ID für Slack, eine optionale Kanalbezeichnung für Teams, Empfänger für E-Mail oder ein Topic-ARN für SNS.
5. Speichern Sie die Regel und aktivieren Sie sie.

Es wird nichts gesendet, wenn keine Befunde den Bedingungen entsprechen. Eine Regel, die auf Hoch und darüber gefiltert ist, bleibt daher bei einem Import stumm, der nur Befunde mit dem Schweregrad Niedrig eingebracht hat.

### Regeln, die vor den Messaging-Connectors erstellt wurden

Ein Nachrichtenknoten sendet über eine Verbindung, und nur über eine Verbindung. Die Slack-, Teams- und E-Mail-Knoten griffen zuvor auf die instanzweiten Einstellungen unter **Settings > Notifications** zurück, wenn keine Verbindung ausgewählt war. Das tun sie nicht mehr.

Eine so geschriebene Regel läuft weiter, und ihr Nachrichtenknoten protokolliert eine übersprungene Zustellung mit dem Hinweis, dass keine Verbindung genannt ist. Um das zu beheben, öffnen Sie die Regel, wählen am Knoten eine Verbindung und ein Ziel aus und speichern. Eine bereits protokollierte Zustellung lässt sich aus der Zustellungsliste erneut auslösen, sobald der Knoten eine Verbindung nennt.

Die Verbindung ist bei jedem Nachrichtenknoten ein Pflichtfeld, sodass der Regeleditor eine solche verlangt, bevor die Regel gespeichert werden kann.

## Wenn eine Verbindung nicht mehr funktioniert

Ein widerrufenes Bot-Token, ein gelöschter Workflow oder ein gelöschter AWS-Zugriffsschlüssel lässt jede Warnung fehlschlagen, die darüber läuft. Anstatt denselben Fehler für jedes Ereignis zu protokollieren, zählt DefectDojo aufeinanderfolgende Zugangsdatenfehler pro Ziel und stellt nach einigen davon das Senden ein. Die Verbindung meldet, welches Ziel deaktiviert wurde und warum.

Zur Wiederherstellung: Korrigieren Sie die Zugangsdaten (installieren Sie die Slack-App neu und fügen Sie das neue Token ein, erstellen Sie den Teams-Workflow neu und fügen Sie die neue URL ein, oder erstellen Sie einen neuen AWS-Zugriffsschlüssel), und senden Sie dann entweder eine Testnachricht an dieses Ziel, wodurch es bei Erfolg wieder aktiviert wird, oder verwenden Sie direkt die Aktion zum erneuten Aktivieren.

Nur Zugangsdatenfehler lösen dies aus. Eine Nachricht, die abgelehnt wird, weil eine Slack-Kanal-ID falsch ist, der Bot nicht eingeladen wurde, eine E-Mail-Adresse nicht existiert oder eine IAM-Policy das Veröffentlichen in ein Topic nicht erlaubt, deaktiviert nichts, da die Zugangsdaten in Ordnung sind und die Korrektur des Ziels oder der Policy sofort funktionieren sollte.

## Warnungen und Benachrichtigungen zusammen

Messaging-Connectors ersetzen keine Benachrichtigungen. Die instanzweiten Slack-, Teams- und E-Mail-Einstellungen unter **Settings > Notifications**, persönliche Benachrichtigungen und die Benachrichtigungsmatrix funktionieren weiterhin genau wie konfiguriert. Sie kündigen DefectDojos eigene Ereignisse an; ein Messaging-Connector ist das, worüber eine von Ihnen geschriebene Regel sendet.

Ein Punkt, auf den Sie achten sollten: Wenn eine Warnung an denselben Kanal oder dieselbe Adresse postet, die die instanzweite Einstellung bereits bedient, erhält dieses Ziel beide Nachrichten. Konfigurieren Sie für ein bestimmtes Ziel nur eines von beidem.

## Einschränkungen

- Der Nachrichtentext lässt sich noch nicht anpassen. Warnungen verwenden den integrierten Wortlaut von DefectDojo.
- Nachrichten sind Einwegkommunikation. DefectDojo liest keine Antworten, und die Nachricht enthält keine Schaltflächen oder interaktiven Elemente.
- Threads, das Bearbeiten von Nachrichten und Direktnachrichten an einzelne Benutzer werden nicht unterstützt. Persönliche Benachrichtigungen nutzen weiterhin das bestehende Benachrichtigungssystem.
- Eine Teams-Verbindung erreicht einen Kanal, da die Workflow-URL den Kanal adressiert.
- SNS-Nachrichten sind reiner Text. Ein Topic kann gleichzeitig an E-Mail-, SMS-, Lambda- und HTTPS-Abonnenten verteilen, sodass es kein einzelnes Format gibt, das für alle passt, und keine protokollspezifische Variante veröffentlicht wird.
- SNS-FIFO-Topics werden nicht unterstützt.
- Berichte und andere Anhänge können noch nicht gesendet werden. Warnungen sind Nachrichten mit Links zurück zu DefectDojo.
- Die Seite „Warnungen“ deckt neue Befunde aus einem Import ab. Alles andere wird im Regeleditor erstellt.
