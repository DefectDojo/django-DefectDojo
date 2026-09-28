---
title: "Linear"
description: "Cómo configurar el Conector Downstream de Linear para DefectDojo"
weight: 87
audience: pro
---
La integración de Linear le permite enviar los Hallazgos de DefectDojo como incidencias de [Linear](https://linear.app/). Las incidencias se crean en un equipo (Team) de su espacio de trabajo de Linear.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://api.linear.app/graphql`.
- **API Key** debe establecerse en una clave de API personal de Linear. Las claves pueden generarse en Linear en Settings, luego Security & access, luego [API](https://linear.app/settings/account/security). La clave se envía a la API GraphQL de Linear en el encabezado `Authorization`.

### Mapeo del Issue Tracker

- **Team (Group) ID** debe establecerse en el ID del equipo de Linear para el que se crearán las incidencias. Puede listar sus equipos y sus ID llamando a la API GraphQL de Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Detalles del mapeo de severidad

Una incidencia de Linear lleva una **priority** numérica en lugar de un campo de severidad. Cada severidad de DefectDojo se mapea a una prioridad de Linear, donde `1` es Urgent y `4` es Low:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

### Detalles del mapeo de estado

Cada valor de estado debe establecerse en el ID de un estado de flujo de trabajo (Workflow State) en su equipo de Linear. Los ID de estado de flujo de trabajo son únicos para cada espacio de trabajo, por lo que no hay valores predeterminados. Puede listar los estados de flujo de trabajo y sus ID llamando a la API GraphQL de Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping**: el ID de un estado started o unstarted, por ejemplo `Todo` o `In Progress`.
- **Closed Mapping**: el ID de un estado completed, por ejemplo `Done`. Cuando se elimina un Hallazgo en DefectDojo, su incidencia se mueve a este estado.
