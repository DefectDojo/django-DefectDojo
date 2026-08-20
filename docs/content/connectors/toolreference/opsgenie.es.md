---
title: "Opsgenie"
description: "Cómo configurar el Conector Downstream de Opsgenie para DefectDojo"
weight: 99
audience: pro
---
La integración de Opsgenie le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como alertas de Opsgenie, opcionalmente enrutadas a un equipo de Opsgenie como responsable.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://api.opsgenie.com`. Si su cuenta de Opsgenie está alojada en la región de servicio de la UE, use `https://api.eu.opsgenie.com` en su lugar. Si sus alertas residen en Jira Service Management Operations (Atlassian está integrando Opsgenie en JSM), use `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** debe establecerse en una clave de **integración API** de Opsgenie. Un administrador de la cuenta puede crear una en la aplicación web de Opsgenie en **Settings > Integrations**: añada una integración de tipo **API** y otórguele *Create and Update Access* (y *Read Access* para que DefectDojo pueda verificar la conexión). Tenga en cuenta que esto es una clave de integración, no una clave de API personal - DefectDojo se autentica con autorización `GenieKey`, que solo admiten las claves de integración.

### Mapeo del Issue Tracker

- **Team Name** *(opcional)* debe ser el nombre del equipo de Opsgenie que se añadirá como responsable en las alertas creadas. Puede dejarlo vacío: si la clave de integración de la API tiene alcance de equipo, las alertas se enrutan automáticamente a ese equipo, y en caso contrario las propias reglas de enrutamiento de su cuenta deciden los responsables.

### Detalles del mapeo de severidad

Las severidades se mapean al campo **Priority** de la alerta de Opsgenie, que usa la escala fija de Opsgenie de `P1` (crítica) a `P5` (informativa):

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P5`
- **Low Mapping**: `P4`
- **Medium Mapping**: `P3`
- **High Mapping**: `P2`
- **Critical Mapping**: `P1`

Si una severidad se mapea a un valor no reconocido, se omite la prioridad y Opsgenie aplica su propio valor predeterminado (`P3`).

### Detalles del mapeo de estado

Las alertas de Opsgenie son `open` o `closed`, y una alerta abierta puede además estar `acknowledged`:

- **Status Field Name**: `Status`
- **Active Mapping**: `open`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `acknowledged`

Tenga en cuenta que `closed` es un estado final en Opsgenie - una alerta cerrada no se puede reabrir, y su alias queda liberado. A diferencia de otras herramientas, Opsgenie sí permite editar el contenido después de la creación, así que enviar un Hallazgo actualizado sincroniza su mensaje, descripción y prioridad junto con el estado.

DefectDojo establece el **alias** de cada alerta con una clave estable derivada del Hallazgo o Grupo de Hallazgos, y Opsgenie deduplica las alertas abiertas por alias - así que reenviar el mismo Hallazgo actualiza la alerta abierta existente en lugar de crear un duplicado.
