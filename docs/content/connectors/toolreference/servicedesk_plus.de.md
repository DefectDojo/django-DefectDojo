---
title: "ServiceDesk Plus"
description: "Einrichtung des ServiceDesk Plus Downstream-Connectors für DefectDojo"
weight: 119
audience: pro
---
Die Integration mit ManageEngine ServiceDesk Plus ermöglicht es Ihnen, DefectDojo-Befunde und Befundgruppen als ServiceDesk-Plus-Requests zu übertragen, die einer Support-Gruppe Ihrer Wahl zugewiesen werden.  Sowohl die **Cloud**-Edition (ServiceDesk Plus OnDemand) als auch die **On-Premises**-Edition werden von derselben Integration unterstützt - die Anmeldedaten, die Sie angeben, bestimmen, welcher Modus verwendet wird.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf Ihre ServiceDesk-Plus-URL gesetzt werden: `https://sdpondemand.manageengine.com` für die Cloud-Edition (oder Ihr regionales Äquivalent) beziehungsweise die Adresse Ihres Servers bei On-Premises-Installationen.

Geben Sie dann **einen** der beiden Anmeldedatensätze an:

#### On-Premises: Technician Key

- **Technician Key** sollte ein API-Key sein, der für einen Techniker auf Ihrem Server unter **Admin > General Settings > API** generiert wurde.  Lassen Sie die Zoho-OAuth-Felder leer.

#### Cloud: Zoho OAuth

Die Cloud-Edition authentifiziert sich über Zoho Accounts OAuth:

1. Öffnen Sie die [Zoho API Console](https://api-console.zoho.com/) und erstellen Sie einen **Self Client**.
2. Notieren Sie sich die **Client ID** und das **Client Secret**.
3. Geben Sie im Tab „Generate Code“ des Self Client den Scope `SDPOnDemand.requests.ALL` ein, wählen Sie eine Dauer und generieren Sie den Code.
4. Tauschen Sie den Code gegen ein Refresh-Token:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Geben Sie die **Client ID**, das **Client Secret** und das zurückgegebene **Refresh Token** im Instanzformular ein.  Wird Ihr Konto außerhalb des US-Rechenzentrums gehostet, setzen Sie die **Token URL** auf Ihren regionalen Zoho-Accounts-Endpunkt (zum Beispiel `https://accounts.zoho.eu/oauth/v2/token`).

### Issue-Tracker-Zuordnung

- **Group Name** sollte der Name der ServiceDesk-Plus-Support-Gruppe sein, der Requests zugewiesen werden, genau so, wie er unter **Admin > Users > Support Groups** erscheint.

### Details zur Schweregrad-Zuordnung

Dies wird dem ServiceDesk-Plus-Request-Feld **Priority** anhand des Namens zugeordnet, unter Verwendung der Prioritätsnamen Ihres Kontos:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `Low`
- **Niedrig-Zuordnung**: `Normal`
- **Mittel-Zuordnung**: `Medium`
- **Hoch-Zuordnung**: `High`
- **Kritisch-Zuordnung**: `High`

### Details zur Status-Zuordnung

Dies wird dem Request-Feld **Status** anhand des Namens zugeordnet.  Die Standardwerte verwenden die integrierten Status:

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `Open`
- **Geschlossen-Zuordnung**: `Closed`
- **Falsch-positiv-Zuordnung**: `Closed`
- **Risiko-akzeptiert-Zuordnung**: `On Hold`

Einige ServiceDesk-Plus-spezifische Verhaltensweisen, die Sie kennen sollten:

- Aktualisierungen synchronisieren den vollständigen Request-Inhalt - anders als die meisten Tracker erlaubt ServiceDesk Plus es, Betreff und Beschreibung nach dem Erstellen zu bearbeiten.
- Requests werden geschlossen und nicht gelöscht, wenn ein Befund entfernt wird; Requests, die bereits Closed oder Resolved sind, bleiben unberührt.
- Macht Ihr Konto beim Schließen Felder zwingend erforderlich (zum Beispiel eine Lösung), kann ein von DefectDojo angestoßenes Schließen von diesen Regeln abgewiesen werden und erscheint dann in der Fehlertabelle der Integration.
