---
title: "ServiceNow"
description: "Einrichtung des ServiceNow Downstream-Connectors für DefectDojo"
weight: 120
audience: pro
---
Die ServiceNow-Integration ermöglicht es Ihnen, DefectDojo-Befunde als ServiceNow-Incidents zu übertragen.

### Instanz-Einrichtung

DefectDojo authentifiziert sich bei ServiceNow über OAuth 2.0. Wie Sie die OAuth-Anmeldedaten erstellen, hängt von Ihrem ServiceNow-Release ab – neuere Releases (Zurich und später) verwenden einen Client-Credentials-Grant, frühere Releases ein Refresh-Token.

#### ServiceNow Zurich und später (Client Credentials)

In neueren ServiceNow-Releases wurde die klassische Option „Create an OAuth API endpoint for external clients“ zugunsten der **New Inbound Integration Experience** abgekündigt, die einen an ein Servicekonto gebundenen OAuth-**Client-Credentials**-Grant ausgibt:

1. Suchen Sie in der linken Navigationsleiste nach „Application Registry“ und wählen Sie den Eintrag aus.
2. Klicken Sie auf **New** und wählen Sie dann **New Inbound Integration Experience**.
3. Wählen Sie **New Integration → OAuth - Client credentials grant**.
4. Setzen Sie den **OAuth Application User** auf das Servicekonto, das die Incidents erstellen wird. Die Rollen dieses Kontos bestimmen, was DefectDojo schreiben darf.
5. Speichern Sie die Registrierung. ServiceNow generiert **Client ID** und **Client Secret** automatisch (lassen Sie diese Felder beim Erstellen der Registrierung leer).

Anschließend in DefectDojo:

- **Instance Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres ServiceNow-Servers gesetzt werden, zum Beispiel `https://your-organization.service-now.com/`.
- **Client ID** sollte die Client ID aus der OAuth-Registrierung sein.
- **Client Secret** sollte das Client Secret aus der OAuth-Registrierung sein.

Lassen Sie die Felder Refresh Token, Username und Password leer – DefectDojo fordert für jede Synchronisierung ein frisches Client-Credentials-Token an.

#### Frühere ServiceNow-Releases (Refresh-Token)

Bei Releases, die noch die klassische Registrierung anbieten, benötigen Sie ein Refresh-Token, das dem Benutzer- oder Servicekonto zugeordnet ist, das Incidents an ServiceNow überträgt:

1. Suchen Sie in der linken Navigationsleiste nach „Application Registry“ und wählen Sie den Eintrag aus.
2. Klicken Sie auf „New“.
3. Wählen Sie „Create an OAuth API endpoint for external clients“.
4. Füllen Sie die erforderlichen Felder aus:
    * Name: Geben Sie Ihrer Anwendung einen sinnvollen Namen (z. B. Vulnerability Integration Client).
    * (Optional) Passen Sie die Token-Lebensdauer an:
    * Access Token Lifespan: Standard sind 1800 Sekunden (30 Minuten).
    * Refresh Token Lifespan: Standard sind 8640000 Sekunden (etwa 100 Tage).
5. Klicken Sie auf „Submit“, um den Anwendungsdatensatz zu erstellen.
6. Wählen Sie die Anwendung nach dem Absenden aus der Liste aus und notieren Sie sich die Felder **Client ID und Client Secret**.

Anschließend müssen Sie mit dieser Registrierung ein Refresh-Token beziehen, was nur über die ServiceNow-API möglich ist.  Öffnen Sie ein Terminalfenster und fügen Sie Folgendes ein (ersetzen Sie dabei die in `{{}}` eingeschlossenen Variablen durch die tatsächlichen Angaben Ihres Benutzers)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Wenn Ihre ServiceNow-Anmeldedaten korrekt sind und Zugriff auf Administratorebene in ServiceNow erlauben, sollten Sie eine Antwort mit einem RefreshToken erhalten.  Dieses Token benötigen Sie, um die Integration mit DefectDojo abzuschließen.

- **Instance Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres ServiceNow-Servers gesetzt werden, zum Beispiel `https://your-organization.service-now.com/`.
- **Refresh Token** ist das Feld, in das das Refresh-Token eingetragen wird.
- **Client ID** sollte die in der OAuth-App-Registrierung festgelegte Client ID sein.
- **Client Secret** sollte das in der OAuth-App-Registrierung festgelegte Client Secret sein.

### Details zur Schweregrad-Zuordnung

Dies wird dem ServiceNow-Feld „Impact“ zugeordnet.
- **Info-Zuordnung**: `1`
- **Niedrig-Zuordnung**: `1`
- **Mittel-Zuordnung**: `2`
- **Hoch-Zuordnung**: `3`
- **Kritisch-Zuordnung**: `3`

### Details zur Status-Zuordnung

- **Name des Status-Felds**: `State`
- **Aktiv-Zuordnung**: `New`
- **Geschlossen-Zuordnung**: `Closed`
- **Falsch-positiv-Zuordnung**: `Resolved`
- **Risiko-akzeptiert-Zuordnung**: `Resolved`

Jede Zuordnung akzeptiert eine Standard-Statusbezeichnung (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) oder einen numerischen Statuswert. Auf Instanzen mit angepassten Incident-Status – oder wenn eine andere Tabelle als `incident` das Ziel ist – verwenden Sie den numerischen **Statuswert** aus der Auswahlliste Ihrer Instanz; ein numerischer Wert außerhalb des Standardsatzes wird genau so an ServiceNow gesendet, wie er konfiguriert ist. Der integrierte Standardwert für den Resolution-Code begleitet nur die Standardstatus „resolved“/„closed“; kombinieren Sie benutzerdefinierte Statuswerte daher mit den unten beschriebenen Zuordnungen für Abschluss- und Resolution-Felder.

### Abschluss- und Resolution-Felder

Manche ServiceNow-Instanzen erzwingen eine Data Policy, die Felder wie den **Resolution code** (`close_code`) zwingend erforderlich macht, sobald ein Incident in einen aufgelösten oder geschlossenen Status wechselt. Schließt DefectDojo einen Incident ohne diese Felder, weist ServiceNow den Schreibvorgang mit HTTP 403 *„Data Policy Exception“* zurück, und der Grund wird in der Fehleransicht der Integration festgehalten.

Hängen Sie die erforderlichen Felder mit **Custom Field Mappings** an den Statuswechsel an und setzen Sie **Apply On** auf die Disposition, die sie tragen soll:

- **Transition to Closed** – wird gesendet, wenn ein Befund behoben/geschlossen wird.
- **Transition to False Positive** – wird gesendet, wenn ein Befund als Falsch-positiv markiert wird.
- **Transition to Risk Accepted** – wird gesendet, wenn für einen Befund das Risiko akzeptiert wird.

Um zum Beispiel einen zwingend erforderlichen Resolution code zu erfüllen:

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Hinweise:

- Field Name ist der ServiceNow-Spaltenname – `close_code`, `close_notes` oder ein benutzerdefiniertes `u_...`-Feld.
- Übergangszuordnungen greifen, wenn sich der Status des Datensatzes tatsächlich ändert: bei einem Befund, der beim ersten Übertragen bereits geschlossen ist, bei einer Aktualisierung, die den Datensatz schließt oder wieder öffnet, und beim erzwungenen Schließen, wenn eine Ticket-Verknüpfung gelöscht wird. Sie werden bei routinemäßigen Aktualisierungen eines unveränderten Datensatzes nicht erneut gesendet, sodass Journalfelder wie `work_notes` pro Übergang einen Eintrag erhalten.
- Referenzfelder wie `assignment_group` und `assigned_to` erwarten eine **sys_id** und keinen Anzeigenamen.
- Werte, die als JSON interpretierbar sind, werden typisiert gesendet: `true`, `42`, `[...]`, `{...}` – und `null`, wodurch das Feld geleert wird. Um solchen Text als wörtliche Zeichenkette zu senden, schließen Sie ihn in doppelte Anführungszeichen ein (z. B. `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` und `priority` gehören zur Beschreibungsvorlage und zu den Schweregrad-/Status-Zuordnungen und können daher nicht über eine Zuordnung benutzerdefinierter Felder gesetzt werden.
- Auf anderen Tabellen als `incident` werden Statuswerte, die dem Standardsatz für Incidents entsprechen (`1`, `2`, `3`, `6`, `7`, `8`), weiterhin mit Incident-Semantik interpretiert – einschließlich des automatischen Standard-Resolution-Codes bei `6`/`7`/`8`. Bevorzugen Sie auf benutzerdefinierten Tabellen Statuswerte außerhalb dieses Bereichs, oder geben Sie die Abschlussfelder wie oben beschrieben explizit an.
