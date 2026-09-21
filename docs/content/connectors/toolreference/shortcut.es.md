---
title: "Shortcut"
description: "Cómo configurar el Conector Downstream de Shortcut para DefectDojo"
weight: 124
audience: pro
---
La integración con Shortcut le permite enviar los Hallazgos de DefectDojo como Stories de [Shortcut](https://www.shortcut.com/). Las Stories se crean con el tipo de story Bug y se asignan a un Team de su espacio de trabajo de Shortcut.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse como `https://api.app.shortcut.com`.
- **API Token** debe configurarse con un token de API de Shortcut. Los tokens pueden generarse en Shortcut en Settings, luego Your Account, luego [API Tokens](https://app.shortcut.com/settings/account/api-tokens).

### Mapeo del sistema de tickets

- **Team (Group) ID** debe configurarse con el UUID del Team de Shortcut para el que se crearán las Stories. Puede encontrar este UUID abriendo la página del Team en Shortcut y copiando el identificador de la URL, o llamando a la API de Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Detalles del mapeo de severidad

Cada valor de severidad se aplica a la Story como una etiqueta. Las etiquetas se crean automáticamente en Shortcut si aún no existen, por lo que los valores predeterminados a continuación pueden usarse tal cual, o sustituirse por nombres de etiqueta de su elección. Cuando cambia la severidad de un Hallazgo, la etiqueta de severidad anterior se elimina de la Story y se añade la nueva.

- **Nombre del campo de severidad**: `Label`
- **Mapeo de Informativa**: `sev-info`
- **Mapeo de Baja**: `sev-low`
- **Mapeo de Media**: `sev-medium`
- **Mapeo de Alta**: `sev-high`
- **Mapeo de Crítica**: `sev-critical`

### Detalles del mapeo de estado

Cada valor de estado debe configurarse con el ID numérico de un Workflow State en su espacio de trabajo de Shortcut. Los ID de Workflow State son únicos para cada espacio de trabajo, por lo que no hay valores predeterminados. Puede listar los Workflow States y sus ID llamando a la API de Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Nombre del campo de estado**: `Workflow State ID`
- **Mapeo de Activo**: el ID del estado para trabajo abierto, por ejemplo un estado de Backlog o To Do.
- **Mapeo de Cerrado**: el ID de un estado de tipo Done. Cuando se elimina un Hallazgo en DefectDojo, su Story se mueve a este estado.
- **Mapeo de Falso positivo**: el ID del estado que se usará para los Hallazgos marcados como Falso positivo.
- **Mapeo de Riesgo aceptado**: el ID del estado que se usará para los Hallazgos con Riesgo aceptado.
