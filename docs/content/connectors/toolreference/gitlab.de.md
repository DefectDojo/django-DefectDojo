---
title: "GitLab"
description: "Einrichtung der Upstream- und Downstream-Connectors für GitLab"
weight: 65
audience: pro
---
## Upstream-Connector

Der GitLab-Connector ist ein **Asset-Connector**: Er zählt jedes Projekt (Repository) auf, auf das Ihr Token zugreifen kann, und erstellt für jedes ein DefectDojo-Asset, gruppiert in Organisationen nach GitLab-Namespace (Gruppe oder Benutzer). Es werden keine Befunde importiert.

#### Voraussetzungen

Sie benötigen ein Personal Access Token mit dem Scope **read_api**. Wir empfehlen, das Token von einem dedizierten Service-Konto aus zu erstellen; der Connector listet die Projekte auf, in denen dieses Konto Mitglied ist.

#### Connector-Zuordnungen

1. Geben Sie Ihre GitLab-URL in das Feld **Location** ein: `https://gitlab.com`, oder die Basis-URL Ihrer selbstgehosteten Instanz.
2. Geben Sie das Personal Access Token in das Feld **Secret** ein.

Jedes Projekt wird zu einem nach dem Projekt benannten Eintrag, gruppiert nach seinem **Namespace**. Projekte, die in GitLab zur Löschung vorgesehen sind (von einem Benutzer gelöscht, aber noch nicht durch den Hintergrundjob von GitLab endgültig entfernt), werden automatisch ausgeschlossen; das Löschen eines Projekts markiert seinen Eintrag daher beim nächsten Sync als `MISSING`, statt ein umbenanntes Geister-Asset zu hinterlassen.

## Downstream-Connector

Die GitLab-Integration ermöglicht es Ihnen, Issues zu einem [GitLab-Projekt](https://docs.gitlab.com/ee/user/project/) hinzuzufügen.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf den Link zu Ihrem GitLab-Server gesetzt werden, zum Beispiel `https://gitlab.com/`.
- **Token** sollte auf ein persönliches Zugriffstoken aus GitLab gesetzt werden. Das Token muss API-Scopes besitzen. Siehe [GitLabs Anleitung zum Erstellen eines persönlichen Zugriffstokens](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Issue-Tracker-Zuordnung

- **Project Name**: Der Name des Projekts in GitLab, an das Sie Issues senden möchten.

### Details zur Schweregrad-Zuordnung

Dies wird dem GitLab-Feld „Priority“ zugeordnet.
- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `1`
- **Niedrig-Zuordnung**: `2`
- **Mittel-Zuordnung**: `3`
- **Hoch-Zuordnung**: `4`
- **Kritisch-Zuordnung**: `5`

### Details zur Status-Zuordnung

Standardmäßig kennt GitLab die Status „opened“ und „closed“.  Zusätzliche Status-Labels können hinzugefügt werden, wenn Sie den Status Falsch-positiv oder Risiko akzeptiert nachverfolgen möchten.  Details finden Sie in den [GitLab-Docs](https://docs.gitlab.com/user/work_items/status/).

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `opened`
- **Geschlossen-Zuordnung**: `closed`
- **Falsch-positiv-Zuordnung**: `closed`
- **Risiko-akzeptiert-Zuordnung**: `closed`
