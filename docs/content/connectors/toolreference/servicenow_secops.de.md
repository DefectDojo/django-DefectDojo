---
title: "ServiceNow SecOps"
description: "Einrichtung des ServiceNow SecOps Downstream-Connectors für DefectDojo"
weight: 122
audience: pro
---
Die ServiceNow-SecOps-Integration (auch bekannt als **ServiceNow SecOps / Vulnerability Response**) überträgt DefectDojo-Befunde und Befundgruppen in eine ServiceNow-Sicherheitstabelle – einen **Security Incident** (`sn_si_incident`) oder ein **Vulnerable Item** (`sn_vul_vulnerable_item`) – und hält den Datensatz synchron, während sich der Befund ändert (Erstellen, Aktualisieren und Auflösen/Schließen). Sie ist das Security-Operations-Gegenstück zur oben beschriebenen ServiceNow-Issue-Tracker-Integration; verwenden Sie ServiceNow SecOps, wenn Sie die Anwendungen Security Incident Response (SIR) oder Vulnerability Response (VR) einsetzen.

### Instanz-Einrichtung

- **Instance Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres ServiceNow-Servers gesetzt werden, zum Beispiel `https://your-organization.service-now.com/`.

ServiceNow SecOps unterstützt drei Authentifizierungsmethoden; geben Sie **eine** davon an:

- **OAuth 2.0** – geben Sie eine **Client ID**, ein **Client Secret** und ein **Refresh Token** ein. Sie erhalten diese genau so, wie im Abschnitt [ServiceNow](/connectors/toolreference/servicenow/) oben beschrieben (erstellen Sie einen OAuth-API-Endpunkt in der Application Registry und tauschen Sie Ihre Anmeldedaten dann unter `/oauth_token.do` gegen ein Refresh-Token). Alternativ können Sie **Client ID** und **Client Secret** zusammen mit einem **Username** und **Password** angeben, um anstelle eines Refresh-Tokens den OAuth-Password-Grant zu verwenden.
- **API Key** – geben Sie einen **API Key** ein, der als Header `x-sn-apikey` gesendet wird. Der Key authentifiziert nichts, solange auf der Instanz kein Inbound Authentication Profile und keine REST API Access Policy daran angehängt sind.
- **HTTP Basic** – geben Sie **Username** und **Password** des Servicekontos ein.

Das Servicekonto (oder der OAuth-Client) benötigt Schreibzugriff auf die Zieltabelle.

### Issue-Tracker-Zuordnung

- **Target Table** legt die ServiceNow-Tabelle fest, in die Datensätze geschrieben werden: **Security Incident** (`sn_si_incident`, der Standard) oder **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Details zur Schweregrad-Zuordnung

Bei einem Security Incident wird dies dem Feld **Impact** zugeordnet; ServiceNow leitet die Incident-Priorität aus Impact und Urgency ab, sodass Urgency dem zugeordneten Impact folgt, sofern Sie sie nicht selbst zuordnen. Bei einem Vulnerable Item ordnen Sie den Schweregrad dem Risikofeld zu, das Ihre Instanz verwendet. Die Standardwerte unten entsprechen der Standard-SIR-Impact-Skala (`1` Hoch, `2` Mittel, `3` Niedrig) und sind bearbeitbar.

- **Name des Schweregrad-Felds**: `impact`
- **Info-Zuordnung**: `3`
- **Niedrig-Zuordnung**: `3`
- **Mittel-Zuordnung**: `2`
- **Hoch-Zuordnung**: `1`
- **Kritisch-Zuordnung**: `1`

### Details zur Status-Zuordnung

Dies wird dem Feld **State** des Datensatzes zugeordnet. Statuswerte sind numerische Codes, die sich zwischen den Tabellen Security Incident und Vulnerable Item unterscheiden und pro Instanz angepasst werden können; prüfen Sie sie daher gegen Ihre eigene Konfiguration. Die Standardwerte unten verwenden die Standard-SIR-Statuscodes (`16` Analysis, `3` Closed).

- **Name des Status-Felds**: `state`
- **Aktiv-Zuordnung**: `16`
- **Geschlossen-Zuordnung**: `3`
- **Falsch-positiv-Zuordnung**: `3`
- **Risiko-akzeptiert-Zuordnung**: `3`

Wird ein Datensatz geschlossen, setzt DefectDojo zusätzlich den ServiceNow-**Close Code** und die **Close Notes** (`Resolved` für geschlossene Befunde, `False positive` und `Risk accepted` für die entsprechenden Status).

### Verhalten speziell bei ServiceNow SecOps

- **Deduplizierung** – jeder Datensatz wird in seinem Feld `correlation_id` mit dem DefectDojo-Identifikator des Befunds oder der Befundgruppe gekennzeichnet. Bevor DefectDojo einen Datensatz erstellt, sucht es per `correlation_id` nach einem vorhandenen; ein Treffer wird übernommen und aktualisiert statt dupliziert, sodass erneute Synchronisierungen idempotent sind.
- **Aktualisierungen** werden im Journal **Work notes** des Datensatzes eingetragen (intern), niemals in kundenseitig sichtbaren Comments.
- **Auflösen beim Löschen** – das Löschen eines Befunds in DefectDojo löst bzw. schließt den ServiceNow-Datensatz (State + Close Code), anstatt ihn zu löschen; Datensätze werden niemals endgültig gelöscht.
- **Referenzfelder** – die optionalen Werte `cmdb_ci`, `assignment_group` und `assigned_to` dürfen als Anzeigenamen angegeben werden; DefectDojo löst jeden in seine `sys_id` auf. Ein Name, der nicht auflösbar ist, wird mit einer Warnung verworfen, anstatt die Übertragung fehlschlagen zu lassen.
