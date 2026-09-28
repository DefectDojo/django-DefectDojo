---
title: "Shortcut"
description: "Einrichtung des Shortcut Downstream-Connectors für DefectDojo"
weight: 124
audience: pro
---
Die Shortcut-Integration ermöglicht es Ihnen, DefectDojo-Befunde als [Shortcut](https://www.shortcut.com/)-Stories zu übertragen. Stories werden mit dem Story-Typ „Bug“ erstellt und einem Team in Ihrem Shortcut-Workspace zugewiesen.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.app.shortcut.com` gesetzt werden.
- **API Token** sollte auf ein Shortcut-API-Token gesetzt werden. Token können in Shortcut unter „Settings“, dann „Your Account“, dann [API Tokens](https://app.shortcut.com/settings/account/api-tokens) generiert werden.

### Issue-Tracker-Zuordnung

- **Team (Group) ID** sollte auf die UUID des Shortcut-Teams gesetzt werden, für das Stories erstellt werden. Sie finden diese UUID, indem Sie die Team-Seite in Shortcut öffnen und den Identifikator aus der URL kopieren, oder indem Sie die Shortcut-API aufrufen:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Details zur Schweregrad-Zuordnung

Jeder Schweregradwert wird der Story als Label zugewiesen. Labels werden in Shortcut automatisch erstellt, falls sie noch nicht existieren; die Standardwerte unten können also unverändert übernommen oder durch Labelnamen Ihrer Wahl ersetzt werden. Ändert sich der Schweregrad eines Befunds, wird das alte Schweregrad-Label von der Story entfernt und das neue hinzugefügt.

- **Name des Schweregrad-Felds**: `Label`
- **Info-Zuordnung**: `sev-info`
- **Niedrig-Zuordnung**: `sev-low`
- **Mittel-Zuordnung**: `sev-medium`
- **Hoch-Zuordnung**: `sev-high`
- **Kritisch-Zuordnung**: `sev-critical`

### Details zur Status-Zuordnung

Jeder Statuswert muss auf die numerische ID eines Workflow-States in Ihrem Shortcut-Workspace gesetzt werden. Workflow-State-IDs sind je Workspace eindeutig, daher gibt es keine Standardwerte. Sie können die Workflow-States und ihre IDs auflisten, indem Sie die Shortcut-API aufrufen:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Name des Status-Felds**: `Workflow State ID`
- **Aktiv-Zuordnung**: die ID des States für offene Arbeit, zum Beispiel ein Backlog- oder To-Do-State.
- **Geschlossen-Zuordnung**: die ID eines States vom Typ „Done“. Wenn ein Befund in DefectDojo gelöscht wird, wird seine Story in diesen State verschoben.
- **Falsch-positiv-Zuordnung**: die ID des States, der für Falsch-positiv-Befunde verwendet wird.
- **Risiko-akzeptiert-Zuordnung**: die ID des States, der für Befunde mit akzeptiertem Risiko verwendet wird.
