---
title: "Linear"
description: "Einrichtung des Linear Downstream-Connectors für DefectDojo"
weight: 87
audience: pro
---
Die Linear-Integration ermöglicht es Ihnen, DefectDojo-Befunde als [Linear](https://linear.app/)-Issues zu übertragen. Issues werden in einem Team in Ihrem Linear-Workspace erstellt.

### Instanz-Einrichtung

- **Label** sollte die Bezeichnung sein, mit der Sie diese Integration identifizieren möchten.
- **Location** sollte auf `https://api.linear.app/graphql` gesetzt werden.
- **API Key** sollte auf einen persönlichen Linear-API-Key gesetzt werden. Keys können in Linear unter „Settings“, dann „Security & access“, dann [API](https://linear.app/settings/account/security) generiert werden. Der Key wird im Header `Authorization` an die GraphQL-API von Linear gesendet.

### Issue-Tracker-Zuordnung

- **Team (Group) ID** sollte auf die ID des Linear-Teams gesetzt werden, für das Issues erstellt werden. Sie können Ihre Teams und deren IDs auflisten, indem Sie die Linear-GraphQL-API aufrufen:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Details zur Schweregrad-Zuordnung

Ein Linear-Issue trägt eine numerische **Priorität** anstelle eines Schweregrad-Felds. Jeder DefectDojo-Schweregrad wird einer Linear-Priorität zugeordnet, wobei `1` „Urgent“ und `4` „Low“ bedeutet:

- **Name des Schweregrad-Felds**: `Priority`
- **Info-Zuordnung**: `4`
- **Niedrig-Zuordnung**: `4`
- **Mittel-Zuordnung**: `3`
- **Hoch-Zuordnung**: `2`
- **Kritisch-Zuordnung**: `1`

### Details zur Status-Zuordnung

Jeder Statuswert muss auf die ID eines Workflow-States in Ihrem Linear-Team gesetzt werden. Workflow-State-IDs sind je Workspace eindeutig, daher gibt es keine Standardwerte. Sie können die Workflow-States und ihre IDs auflisten, indem Sie die Linear-GraphQL-API aufrufen:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Name des Status-Felds**: `Workflow State ID`
- **Aktiv-Zuordnung**: die ID eines gestarteten oder noch nicht gestarteten States, zum Beispiel `Todo` oder `In Progress`.
- **Geschlossen-Zuordnung**: die ID eines abgeschlossenen States, zum Beispiel `Done`. Wenn ein Befund in DefectDojo gelöscht wird, wird sein Issue in diesen State verschoben.
