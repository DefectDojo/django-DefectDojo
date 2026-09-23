---
title: "Azure DevOps Boards"
description: "Einrichtung des Azure DevOps Boards Downstream-Connectors für DefectDojo"
weight: 21
audience: pro
---
### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf Ihre Azure-URL gesetzt werden, zum Beispiel `https://dev.azure.com/{your organization}`
- **Token** sollte auf ein persönliches Zugriffstoken aus Azure gesetzt werden.

Die Authentifizierung bei Azure DevOps erfordert ein [persönliches Zugriffstoken](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
mit der Berechtigung „Read, Write and Manage“ für „Work Items“ im Azure-Projekt, mit dem Sie arbeiten möchten.

### Issue-Tracker-Zuordnung

Diese Angaben legen fest, wie DefectDojo Attribute von Befunden oder Befundgruppen einem bestimmten Projekt in Azure DevOps zuordnet:

#### Details zur Issue-Tracker-Zuordnung

Das Feld `Project ID` entspricht dem Namen oder der ID des Projekts in Azure.

#### Details zur Schweregrad-Zuordnung

Die Attribute im Formular sind als Standardwerte vorbelegt und lauten wie folgt:

- **Name des Schweregrad-Felds**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info-Zuordnung**: `4`
- **Niedrig-Zuordnung**: `4`
- **Mittel-Zuordnung**: `3`
- **Hoch-Zuordnung**: `2`
- **Kritisch-Zuordnung**: `1`

#### Details zur Status-Zuordnung

Die Attribute im Formular sind als Standardwerte vorbelegt und lauten wie folgt:

- **Name des Status-Felds**: `/fields/System.State`
- **Aktiv-Zuordnung**: `To Do`
- **Geschlossen-Zuordnung**: `Done`
- **Falsch-positiv-Zuordnung**: `Done`
- **Risiko-akzeptiert-Zuordnung**: `Done`
