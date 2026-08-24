---
title: "Opsgenie"
description: "Einrichtung des Opsgenie Downstream-Connectors für DefectDojo"
weight: 99
audience: pro
---
Die Opsgenie-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als Opsgenie-Alerts zu übertragen, die optional an ein Opsgenie-Team als Responder geleitet werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.opsgenie.com` gesetzt werden.  Wird Ihr Opsgenie-Konto in der EU-Serviceregion gehostet, verwenden Sie stattdessen `https://api.eu.opsgenie.com`.  Liegen Ihre Alerts in Jira Service Management Operations (Atlassian überführt Opsgenie in JSM), verwenden Sie `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** sollte auf einen Opsgenie-**API-Integrations**-Key gesetzt werden.  Ein Kontoadministrator kann einen solchen in der Opsgenie-Web-App unter **Settings > Integrations** erstellen: Fügen Sie eine Integration des Typs **API** hinzu und erteilen Sie ihr *Create and Update Access* (sowie *Read Access*, damit DefectDojo die Verbindung prüfen kann).  Beachten Sie, dass dies ein Integrations-Key und kein persönlicher API-Key ist - DefectDojo authentifiziert sich mit `GenieKey`-Autorisierung, die nur Integrations-Keys unterstützen.

### Issue-Tracker-Zuordnung

- **Team Name** *(optional)* sollte der Name des Opsgenie-Teams sein, das erstellten Alerts als Responder hinzugefügt wird.  Sie können das Feld leer lassen: Ist der API-Integrations-Key teambezogen, werden Alerts automatisch an dieses Team geleitet, andernfalls entscheiden die Routing-Regeln Ihres Kontos über die Responder.

### Details zur Schweregrad-Zuordnung

Schweregrade werden dem Opsgenie-Alert-Feld **Priority** zugeordnet, das die feste Opsgenie-Skala von `P1` (kritisch) bis `P5` (informativ) verwendet:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `P5`
- **Niedrig-Zuordnung**: `P4`
- **Mittel-Zuordnung**: `P3`
- **Hoch-Zuordnung**: `P2`
- **Kritisch-Zuordnung**: `P1`

Ist ein Schweregrad einem unbekannten Wert zugeordnet, wird die Priorität weggelassen und Opsgenie wendet seinen eigenen Standard (`P3`) an.

### Details zur Status-Zuordnung

Opsgenie-Alerts sind `open` oder `closed`, und ein offener Alert kann zusätzlich `acknowledged` sein:

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `open`
- **Geschlossen-Zuordnung**: `closed`
- **Falsch-positiv-Zuordnung**: `closed`
- **Risiko-akzeptiert-Zuordnung**: `acknowledged`

Beachten Sie, dass `closed` in Opsgenie ein endgültiger Status ist - ein geschlossener Alert kann nicht wieder geöffnet werden, und sein Alias wird freigegeben.  Anders als manche anderen Tools erlaubt Opsgenie Inhaltsänderungen nach dem Erstellen, sodass beim Übertragen eines aktualisierten Befunds neben dem Status auch Nachricht, Beschreibung und Priorität synchronisiert werden.

DefectDojo setzt den **Alias** jedes Alerts auf einen stabilen Schlüssel, der vom Befund oder von der Befundgruppe abgeleitet ist, und Opsgenie dedupliziert offene Alerts anhand des Alias - ein erneutes Übertragen desselben Befunds aktualisiert daher den bestehenden offenen Alert, anstatt ein Duplikat zu erzeugen.
