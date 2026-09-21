---
title: "Zendesk"
description: "Cómo configurar el Conector Downstream de Zendesk para DefectDojo"
weight: 144
audience: pro
---
La integración con Zendesk le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como tickets de Zendesk, asignados a un Group de Zendesk de su elección.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su cuenta de Zendesk, por ejemplo `https://your-subdomain.zendesk.com`.
- **Email** debe ser la dirección de correo del agente de Zendesk al que pertenece el token de API.
- **API Token** debe configurarse con un token de API de Zendesk. Un administrador puede crear uno en el Zendesk Admin Center, en **Apps and integrations > APIs > Zendesk API** (debe habilitarse el acceso por token).

### Mapeo del sistema de tickets

- **Group ID** debe ser el ID numérico del Group de Zendesk al que se asignarán los tickets. Puede encontrarlo en el Admin Center, en **People > Team > Groups**, o en la URL al ver el grupo.

### Detalles del mapeo de severidad

Esto se corresponde con el campo **Priority** del ticket de Zendesk, que acepta `low`, `normal`, `high` y `urgent`:

- **Nombre del campo de severidad**: `Priority`
- **Mapeo de Informativa**: `low`
- **Mapeo de Baja**: `low`
- **Mapeo de Media**: `normal`
- **Mapeo de Alta**: `high`
- **Mapeo de Crítica**: `urgent`

### Detalles del mapeo de estado

Los tickets de Zendesk admiten los estados `new`, `open`, `pending`, `hold` y `closed`, así como `solved`. Tenga en cuenta que `hold` debe estar habilitado en su cuenta antes de poder usarse.

- **Nombre del campo de estado**: `Status`
- **Mapeo de Activo**: `new`
- **Mapeo de Cerrado**: `solved`
- **Mapeo de Falso positivo**: `solved`
- **Mapeo de Riesgo aceptado**: `pending`

Algunos comportamientos específicos de Zendesk que debe tener en cuenta:

- La descripción del ticket es el primer comentario en Zendesk y no se puede editar después de la creación, por lo que enviar un Hallazgo actualizado sincronizará el asunto, la prioridad y el estado del ticket, pero no los cambios de descripción.
- Los tickets se marcan como `solved` en lugar de eliminarse cuando se elimina un Hallazgo; Zendesk cierra automáticamente los tickets resueltos después de un período de tiempo.
- `closed` es un estado final: los tickets cerrados no se pueden actualizar en absoluto, y enviar un Hallazgo cuyo ticket esté cerrado generará un error.
