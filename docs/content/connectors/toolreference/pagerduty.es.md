---
title: "PagerDuty"
description: "Cómo configurar el Conector Downstream de PagerDuty para DefectDojo"
weight: 102
audience: pro
---
La integración de PagerDuty le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como incidentes de PagerDuty, abiertos en un servicio de PagerDuty de su elección.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://api.pagerduty.com`. Si su cuenta de PagerDuty está alojada en la región de servicio de la UE, use `https://api.eu.pagerduty.com` en su lugar.
- **API Token** debe establecerse en una clave de la API REST de PagerDuty. Un administrador de la cuenta puede crear una en la aplicación web de PagerDuty en **Integrations > API Access Keys > Create New API Key**. Deje sin marcar "Read-only" - DefectDojo necesita crear y actualizar incidentes.
- **From Email** debe ser la dirección de correo electrónico de un usuario válido de su cuenta de PagerDuty. PagerDuty requiere esta dirección al crear o actualizar incidentes, y se mostrará como el solicitante del incidente.

### Mapeo del Issue Tracker

- **Service ID** debe ser el ID del servicio de PagerDuty en el que se abrirán los incidentes. Puede encontrarlo al final de la URL al ver el servicio en PagerDuty, por ejemplo `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Detalles del mapeo de severidad

De forma predeterminada, esto se mapea al campo **Urgency** del incidente de PagerDuty, que solo acepta `high` o `low`:

- **Severity Field Name**: `Urgency`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `low`
- **High Mapping**: `high`
- **Critical Mapping**: `high`

Alternativamente, si su cuenta de PagerDuty tiene habilitadas las [Priorities](https://support.pagerduty.com/main/docs/incident-priority), puede mapear las severidades a nombres de Priority en su lugar. Establezca **Severity Field Name** en `Priority` y use los nombres de Priority de su cuenta (por ejemplo `P1` a `P5`) como valores de mapeo. Al mapear a Priority, la Urgency del incidente queda a cargo de las propias reglas de urgencia de su servicio.

### Detalles del mapeo de estado

Los incidentes de PagerDuty tienen tres estados: `triggered`, `acknowledged` y `resolved`.

- **Status Field Name**: `Status`
- **Active Mapping**: `triggered`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `resolved`
- **Risk Accepted Mapping**: `acknowledged`

Tenga en cuenta que `resolved` es un estado final en PagerDuty - un incidente resuelto no se puede reabrir. Tenga en cuenta también que PagerDuty no permite editar el título o la descripción de un incidente después de su creación, así que enviar un Hallazgo actualizado sincronizará su estado, urgencia y prioridad, pero no los cambios de contenido.
