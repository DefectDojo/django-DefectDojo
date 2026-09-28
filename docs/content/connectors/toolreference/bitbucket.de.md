---
title: "Bitbucket"
description: "Einrichtung der Upstream- und Downstream-Connectors für Bitbucket"
weight: 25
audience: pro
---
## Upstream-Connector

Der Bitbucket-Connector ist ein **Asset-Connector**: Er zählt die Repositories in den von Ihnen benannten Bitbucket-Cloud-Workspaces auf und erstellt für jedes Repository ein DefectDojo-Asset, gruppiert in Organisationen nach Bitbucket-Projekt. Es werden keine Befunde importiert.

#### Voraussetzungen

Bitbucket Cloud erfordert ein **scoped** Atlassian-API-Token — klassische (nicht-scoped) Atlassian-API-Tokens werden von Bitbucket mit dem Fehler „API Token provided has no Bitbucket scopes" abgelehnt.

1. Gehen Sie zu [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) und wählen Sie **Create API token with scopes**.
2. Wählen Sie die **Bitbucket**-App und gewähren Sie dann die Lese-Scopes: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` und `read:project:bitbucket`.

Nur Bitbucket Cloud (bitbucket.org) wird unterstützt. Bitbucket Server hat 2024 das Ende seiner Lebensdauer erreicht, und Bitbucket Data Center wird nicht unterstützt.

#### Connector-Zuordnungen

1. Geben Sie `https://bitbucket.org` in das Feld **Location** ein.
2. Geben Sie die Atlassian-Konto-E-Mail-Adresse, zu der das Token gehört, in das Feld **Email** ein.
3. Geben Sie das scoped API-Token in das Feld **Secret** ein.
4. Geben Sie einen oder mehrere Workspace-Slugs (kommagetrennt) in das Feld **Workspace Slugs** ein. Dieses Feld ist erforderlich: Die scoped API-Tokens von Bitbucket können Workspaces nicht automatisch auflisten, daher muss DefectDojo mitgeteilt werden, welche Workspaces gelesen werden sollen.

Jedes Repository wird zu einem nach dem Repository benannten Eintrag, gruppiert nach seinem Bitbucket-**Projekt**.

## Downstream-Connector

Die Bitbucket-Integration ermöglicht es Ihnen, Issues in den [Issue-Tracker](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) eines Bitbucket-Cloud-Repositorys zu übertragen.

Der Issue-Tracker ist in Bitbucket optional und muss im Repository aktiviert werden, bevor DefectDojo dort Issues erstellen kann. Öffnen Sie zum Aktivieren das Repository in Bitbucket, wählen Sie **Repository settings** und aktivieren Sie den Issue-Tracker anschließend unter **Features**.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://bitbucket.org` gesetzt werden.
- **Email** sollte die E-Mail-Adresse des Atlassian-Kontos sein, zu dem das API-Token gehört.
- **API Token** sollte auf ein Atlassian-API-Token mit Scopes gesetzt werden.

Bitbucket-App-Passwörter wurden von Atlassian abgekündigt und funktionieren mit dieser Integration nicht. So erstellen Sie ein API-Token:

1. Öffnen Sie die [Atlassian-Kontoeinstellungen](https://id.atlassian.com/manage-profile/security/api-tokens) und wählen Sie **Security** und dann **Create and manage API tokens**.
2. Wählen Sie **Create API token with scopes**, benennen Sie das Token und legen Sie ein Ablaufdatum fest.
3. Wählen Sie **Bitbucket** als App aus.
4. Erteilen Sie dem Token die Berechtigung, Repositorys zu lesen sowie Issues zu lesen und zu schreiben.

### Issue-Tracker-Zuordnung

- **Workspace** sollte der Slug des Workspace sein, der das Repository enthält, so wie er in bitbucket.org-URLs erscheint.
- **Repository Slug** sollte der Slug des Repositorys sein, in dem Sie Issues erstellen möchten.

### Details zur Schweregrad-Zuordnung

Dies wird dem Bitbucket-Feld „Priority“ eines Issues zugeordnet. Die Attribute im Formular sind als Standardwerte vorbelegt, und jeder Wert muss eine der Bitbucket-Prioritäten sein: `trivial`, `minor`, `major`, `critical` oder `blocker`.

- **Name des Schweregrad-Felds**: `priority`
- **Info-Zuordnung**: `trivial`
- **Niedrig-Zuordnung**: `minor`
- **Mittel-Zuordnung**: `major`
- **Hoch-Zuordnung**: `critical`
- **Kritisch-Zuordnung**: `blocker`

### Details zur Status-Zuordnung

Dies wird dem Bitbucket-Feld „State“ eines Issues zugeordnet. Jeder Wert muss einer der Bitbucket-Issue-Status sein: `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` oder `closed`.

- **Name des Status-Felds**: `state`
- **Aktiv-Zuordnung**: `new`
- **Geschlossen-Zuordnung**: `resolved`
- **Falsch-positiv-Zuordnung**: `invalid`
- **Risiko-akzeptiert-Zuordnung**: `wontfix`
