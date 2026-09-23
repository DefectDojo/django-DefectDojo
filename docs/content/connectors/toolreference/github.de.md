---
title: "GitHub"
description: "Einrichtung der Upstream- und Downstream-Connectors für GitHub"
weight: 63
audience: pro
---
## Upstream-Connector

Der GitHub-Connector ist ein **Asset-Connector**: Er zählt die Repositories auf, auf die Ihr Token zugreifen kann, und erstellt für jedes ein DefectDojo-Asset, gruppiert in Organisationen nach GitHub-Owner (Organisation oder Benutzer). Es werden keine Befunde importiert.

**Bitte beachten Sie:** Dieser Connector importiert nur Ihr Repository-**Inventar**. Um GitHub-Sicherheitswarnungen — Code Scanning, Dependabot und Secret Scanning — als Befunde zu importieren, verwenden Sie den separaten **GitHub-Advanced-Security**-Connector weiter unten. Beide sind unabhängig voneinander und können gemeinsam betrieben werden.

#### Voraussetzungen

Der Connector authentifiziert sich mit einem GitHub-**Personal Access Token** und liest nur Repository-**Metadaten** (Name, Beschreibung, URL und Owner) — er greift nicht auf Ihren Code, Ihre Issues oder Sicherheitswarnungen zu. Er importiert jedes Repository, das dem Konto des Tokens gehört, an dem es mitarbeitet oder dessen Organisation es angehört; stellen Sie daher sicher, dass das Konto des Tokens die zu spiegelnden Repositories sehen kann. Wir empfehlen ein dediziertes Service-Konto.

Das Token benötigt nur lesenden Zugriff auf Repository-Metadaten:

- Ein *fein-granulares* Token benötigt **Repository permissions → Metadata: Read-only**, gewährt für die zu importierenden Repositories (oder die gesamte Organisation).
- Ein *klassisches* Token benötigt den Scope **`repo`**, um private Repositories einzuschließen (verwenden Sie **`public_repo`**, wenn Sie nur öffentliche benötigen), sowie **`read:org`**, damit organisationseigene Repositories aufgelöst werden.

Nur GitHub.com (einschließlich GitHub Enterprise Cloud) wird unterstützt. GitHub Enterprise **Server** wird von diesem Connector derzeit nicht unterstützt.

#### Connector-Zuordnungen

1. Geben Sie `https://api.github.com` in das Feld **Location** ein.
2. Geben Sie das Personal Access Token in das Feld **Secret** ein.

Es muss keine Organisations- oder Repository-Liste eingegeben werden — DefectDojo importiert jedes Repository, das das Token sehen kann. Jedes Repository wird zu einem nach dem Repository benannten Eintrag, gruppiert nach seinem GitHub-**Owner** (Organisation oder Benutzer). Wird ein Repository später gelöscht oder verliert das Token den Zugriff darauf, wird sein zugeordneter Eintrag beim nächsten Sync als `MISSING` markiert statt entfernt — DefectDojo löscht niemals stillschweigend ein Produkt.

## Downstream-Connector

Die GitHub-Integration ermöglicht es Ihnen, Issues zu einem [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects) hinzuzufügen, wodurch außerdem Issues in einem zugehörigen Repo geöffnet werden.  Diese Repos/Projects können entweder mit einer GitHub-Organisation oder mit einem persönlichen GitHub-Konto verknüpft sein.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf die URL Ihres GitHub-Benutzers oder Ihrer GitHub-Organisation gesetzt werden, je nachdem, wo Sie Issues erstellen möchten, zum Beispiel `https://github.com/{your-organization}`
- **Token** sollte auf ein persönliches Zugriffstoken aus GitHub gesetzt werden.

Persönliche Zugriffstoken für GitHub können unter https://github.com/settings/tokens erstellt werden.  Das Token muss die Scopes „Repo“ und „Project“ besitzen.

### Issue-Tracker-Zuordnung

- **Issue Tracker Mapping Label** sollte so gesetzt werden, dass es das Project oder Repo identifiziert, in dem Sie Issues erstellen möchten.
- **Project Number** sollte die ID eines GitHub-Projects sein, an das Sie Elemente senden möchten.  Sie finden sie in der URL, während Sie ein Project ansehen, zum Beispiel `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** sollte der Name eines Repos sein, das Ihrer Organisation (oder Ihrem Benutzer) zugeordnet ist und in das Sie Issues übertragen möchten.


### Details zur Schweregrad-Zuordnung

**Damit die Integration eingerichtet werden kann, MUSS im Project ein benutzerdefiniertes Feld für die Issue-Priorität angelegt sein, andernfalls wird der Schweregrad nicht korrekt zugeordnet und Issues werden nicht an GitHub übertragen.**

Folgen Sie dieser Anleitung, um ein [benutzerdefiniertes Feld](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority) zu erstellen.
Für jeden Schweregrad muss eine entsprechende Single-Select-Option verfügbar sein.  Standardmäßig schlägt DefectDojo zum Beispiel P0, P1, P2, P3, P4 als mögliche Prioritätswerte vor, und jeder dieser Werte muss dem benutzerdefinierten Feld „Priority“ hinzugefügt werden.

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `P0`
- **Niedrig-Zuordnung**: `P1`
- **Mittel-Zuordnung**: `P2`
- **Hoch-Zuordnung**: `P3`
- **Kritisch-Zuordnung**: `P4`

### Details zur Status-Zuordnung

Standardmäßig haben neue GitHub Projects für Issues die Status „In Progress“ und „Done“.  Dem Project können weitere Status hinzugefügt werden, um bei Bedarf den Status Falsch-positiv oder Risiko akzeptiert nachzuverfolgen.  Eine Möglichkeit dafür ist, dem Project-Board eine neue Statusspalte hinzuzufügen.

- **Name des Status-Felds**: `Status`
- **Aktiv-Zuordnung**: `In Progress`
- **Geschlossen-Zuordnung**: `Done`
- **Falsch-positiv-Zuordnung**: `Done`
- **Risiko-akzeptiert-Zuordnung**: `Done`
