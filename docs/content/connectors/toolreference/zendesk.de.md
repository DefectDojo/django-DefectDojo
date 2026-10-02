---
title: "Zendesk"
description: "Einrichtung des Zendesk Downstream-Connectors für DefectDojo"
weight: 144
audience: pro
---
Die Zendesk-Integration ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als Zendesk-Tickets zu übertragen, die einer Zendesk-Gruppe Ihrer Wahl zugewiesen werden.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres Zendesk-Kontos gesetzt werden, zum Beispiel `https://your-subdomain.zendesk.com`.
- **Email** sollte die E-Mail-Adresse des Zendesk-Agenten sein, zu dem das API-Token gehört.
- **API Token** sollte auf ein Zendesk-API-Token gesetzt werden.  Ein Administrator kann eines im Zendesk Admin Center unter **Apps and integrations > APIs > Zendesk API** erstellen (der Token-Zugriff muss aktiviert sein).

### Issue-Tracker-Zuordnung

- **Group ID** sollte die numerische ID der Zendesk-Gruppe sein, der Tickets zugewiesen werden.  Sie finden sie im Admin Center unter **People > Team > Groups** oder in der URL, während Sie die Gruppe ansehen.

### Details zur Schweregrad-Zuordnung

Dies wird dem Zendesk-Ticketfeld **Priority** zugeordnet, das `low`, `normal`, `high` und `urgent` akzeptiert:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `low`
- **Niedrig-Zuordnung**: `low`
- **Mittel-Zuordnung**: `normal`
- **Hoch-Zuordnung**: `high`
- **Kritisch-Zuordnung**: `urgent`

### Details zur Status-Zuordnung

Zendesk-Tickets unterstützen die Status `new`, `open`, `pending`, `hold`, `solved` und `closed`.  Beachten Sie, dass `hold` in Ihrem Konto aktiviert sein muss, bevor es verwendet werden kann.

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `new`
- **Geschlossen-Zuordnung**: `solved`
- **Falsch-positiv-Zuordnung**: `solved`
- **Risiko-akzeptiert-Zuordnung**: `pending`

Einige Zendesk-spezifische Verhaltensweisen, die Sie kennen sollten:

- Die Ticketbeschreibung ist in Zendesk der erste Kommentar und kann nach dem Erstellen nicht bearbeitet werden; beim Übertragen eines aktualisierten Befunds werden daher Betreff, Priorität und Status des Tickets synchronisiert, Änderungen der Beschreibung jedoch nicht.
- Tickets werden als `solved` markiert und nicht gelöscht, wenn ein Befund entfernt wird; Zendesk schließt gelöste Tickets nach einer bestimmten Zeit automatisch.
- `closed` ist ein endgültiger Status - geschlossene Tickets können überhaupt nicht mehr aktualisiert werden, und das Übertragen eines Befunds, dessen Ticket geschlossen ist, meldet einen Fehler.
