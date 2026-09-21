---
title: Integración de seguimiento de incidencias
description: Sincronice los hallazgos de DefectDojo con su sistema de seguimiento
  de incidencias para agilizar la remediación y la rendición de cuentas.
weight: 6
aliases:
- /es/issue_tracking/
- /es/issue_tracking/intro/
- /es/issue_tracking/intro/intro/
---

## Descripción general

Las integraciones de seguimiento de incidencias de DefectDojo conectan sus flujos de trabajo de gestión de vulnerabilidades con su sistema de seguimiento de incidencias existente. Al crear y actualizar automáticamente incidencias a partir de los hallazgos de seguridad, DefectDojo ayuda a garantizar que las vulnerabilidades sean visibles, tengan un responsable y se aborden dentro de las mismas herramientas que ya utilizan sus equipos de desarrollo y operaciones.

| Edición      | Integraciones de seguimiento de incidencias admitidas |
|--------------|---------------------------------------|
| Community Edition  | * [Jira](/connectors/os_jira/os__jira_guide/)                          |
| Pro          | * [Jira](/connectors/toolreference/jira/) ([guía heredada](/connectors/downstream/pro__jira_guide/))<br>* [Azure DevOps](/connectors/toolreference/azure_devops_boards/)<br>* [Bitbucket](/connectors/toolreference/bitbucket/#downstream-connector)<br>* [Freshservice](/connectors/toolreference/freshservice/)<br>* [GitHub](/connectors/toolreference/github/#downstream-connector)<br>* [GitLab Boards](/connectors/toolreference/gitlab/#downstream-connector)<br>* [Linear](/connectors/toolreference/linear/)<br>* [PagerDuty](/connectors/toolreference/pagerduty/)<br>* [ServiceDesk Plus](/connectors/toolreference/servicedesk_plus/)<br>* [ServiceNow](/connectors/toolreference/servicenow/)<br>* [Shortcut](/connectors/toolreference/shortcut/)<br>* [Zendesk](/connectors/toolreference/zendesk/) |


Cuando está habilitada, DefectDojo puede crear incidencias automáticamente, o de forma selectiva desde Productos o Compromisos. A medida que los Hallazgos se actualizan en DefectDojo —resueltos, mitigados o reactivados—, las incidencias correspondientes se pueden mantener sincronizadas, garantizando que ambos sistemas reflejen el estado actual del riesgo.

## Qué se rastrea

Cada incidencia puede incluir detalles clave de la vulnerabilidad, como la severidad, la descripción, la evidencia y las indicaciones de remediación. Los enlaces entre DefectDojo y el sistema de seguimiento de incidencias proporcionan trazabilidad desde el descubrimiento hasta la resolución, respaldando los informes, las auditorías y la mejora continua.

## Por qué son importantes las integraciones de seguimiento de incidencias

Los hallazgos de seguridad son más eficaces cuando son procesables. Integrar DefectDojo con un sistema de seguimiento de incidencias cierra la brecha entre la detección y la remediación, integrando el trabajo de seguridad directamente en los flujos de trabajo de ingeniería ya establecidos. Esto reduce el cambio de contexto, mejora la rendición de cuentas y ayuda a los equipos a remediar los problemas más rápido.
