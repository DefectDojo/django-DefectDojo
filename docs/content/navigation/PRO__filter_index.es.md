---
title: Índice de filtros
description: Referencia de todos los filtros en DefectDojo
weight: 5
aliases:
- /es/en/working_with_findings/organizing_engagements_tests/filter_index
---

**Nota: Actualmente este artículo solo cubre los filtros de Hallazgos disponibles en la interfaz de DefectDojo Pro, pero se ampliará en el futuro para abarcar más tipos de objetos, junto con los filtros de código abierto.** 

A continuación se muestra una lista de filtros que se pueden aplicar en la interfaz de DefectDojo Pro para ordenar listas de Hallazgos.  Los filtros de DefectDojo pueden usarse para ayudar a navegar por listas de objetos, crear [paneles](/metrics_reports/dashboards/custom-dashboards/) personalizados o crear automatizaciones mediante el [Motor de reglas](/automation/rules_engine/about).

## Cómo se evalúan los filtros de fecha

Los filtros que aceptan una fecha — **Date Created**, **SLA Expiration Date**, **Last Status Update**, **Planned Remediation Date**, y los filtros de fecha de Jira que se indican a continuación — ofrecen cinco operadores:

| Operador | Coincide con |
| --- | --- |
| **On** | Todo el día indicado. |
| **Before** | Todo hasta el inicio del día indicado. El día indicado en sí **no** se incluye. |
| **After** | Todo lo posterior al inicio del día indicado — por lo que el día indicado **sí** se incluye. |
| **During** | Desde un día de inicio hasta un día de fin, ambos **inclusive**. |
| **Within** | Una ventana móvil que termina ahora: los últimos 7, 14, 30, 90 o 180 días, o el último año. |

Tenga en cuenta que **Before** y **After** no son deliberadamente imágenes especulares una de la otra: *Before 8 August* excluye el 8 de agosto, mientras que *After 8 August* lo incluye.

### Límites del día y su zona horaria

**On**, **Before**, **After** y **During** resuelven sus límites de día en **su propia zona horaria**, detectada desde su navegador. Por lo tanto, un rango de fechas abarca de medianoche a medianoche tal como *usted* lo experimenta, en lugar de en UTC o en la zona horaria del servidor. Dos personas en zonas horarias distintas pueden ver resultados ligeramente diferentes del mismo filtro para Hallazgos que caen cerca de un límite de día.

**Within** no se ve afectado — es una ventana móvil medida hacia atrás desde el momento actual, por lo que no tiene ningún límite de día que resolver.

> **Dónde no se aplica esto.** Solo las solicitudes desde la interfaz Pro transportan su zona horaria. Todo lo que se ejecuta sin un navegador — la API REST `/api/v2`, los informes programados y el Motor de reglas — recurre a la zona horaria configurada en el servidor (`DD_TIME_ZONE`, `UTC` salvo que su administrador la haya cambiado). Si su zona horaria de navegador difiere de la del servidor, un informe programado y un filtro en pantalla que usen la misma fecha pueden devolver filas ligeramente distintas. Las exportaciones iniciadas desde una tabla filtrada en la interfaz no se ven afectadas — usan su zona horaria, coincidiendo con lo que estaba viendo.

## Cómo se evalúan los filtros numéricos

Los filtros numéricos — incluidos **Age** y **SLA** — ofrecen un operador de coincidencia junto con el valor: **Equals**, **Not Equals**, **Greater Than**, **Greater Than or Equal To**, **Less Than**, **Less Than or Equal To**, **In List** y **Not In List**. Ingresar un valor sin elegir un operador coincide con **Equals**.

## Filtros de SLA

Tres filtros cubren el SLA, y cada uno responde a una pregunta distinta:

| Filtro | Tipo | Con qué coincide |
| --- | --- | --- |
| **SLA Expiration Date** | Fecha, con los operadores anteriores | La fecha en que vence el SLA del Hallazgo. |
| **SLA** | Número, con operadores | **Días restantes** en el reloj del SLA. Los valores negativos están vencidos, por lo que `Less Than 0` encuentra todo lo que actualmente ha superado su plazo, y `Less Than 7` encuentra lo que vence dentro de la semana. |
| **Mitigated Within SLA** | Verdadero / Falso | Si un Hallazgo que **ha sido mitigado** se mitigó antes de que venciera su SLA. |

**Mitigated Within SLA es más restrictivo de lo que parece, y esto suele confundir a la gente.** Ambos valores solo coinciden con Hallazgos que **ya están mitigados** y que **no tienen severidad Informativa**:

* **True** — mitigado en la fecha de vencimiento del SLA o antes.
* **False** — mitigado después de la fecha de vencimiento del SLA.

Un Hallazgo **abierto** que ya está vencido no coincide con **ninguno** de los dos valores, porque aún no ha sido mitigado. Para encontrar esos casos, use en su lugar **SLA** `Less Than 0`. Los Hallazgos de severidad Informativa quedan excluidos de ambos lados.

> Si la configuración de SLA de un Hallazgo tiene habilitado **Cap SLA by CISA KEV Due Date**, tanto **SLA** como **SLA Expiration Date** reflejan el plazo ajustado y limitado por KEV, en lugar de la ventana simple basada en severidad. No hay un indicador independiente para esto en los filtros — consulte [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/).

## Hallazgos
Estos campos son específicos de los Hallazgos de DefectDojo y se usan para organizar un Hallazgo.  Cada uno de estos filtros es una columna independiente en la tabla de Todos los Hallazgos.

Los Hallazgos en DefectDojo se pueden filtrar por:

### Metadatos de DefectDojo
Estos filtros están relacionados directamente con la funcionalidad principal de DefectDojo.

##### No se pueden modificar
Estos filtros se asignan en el momento de la creación del incidente, y no se pueden modificar directamente mediante Edit Finding.

* Severidad del hallazgo (cualquiera de Info, Low, Medium, High, Critical)
* Product
* Product Type
* Engagement
* Engagement Version
* Test
* Test Type
* Test Version
* Date Created
* Age (antigüedad del hallazgo en días)
* SLA (días restantes en el reloj del SLA — negativo significa vencido; consulte [Filtros de SLA](#sla-filters))
* SLA Expiration Date (consulte [Filtros de SLA](#sla-filters))
* Mitigated Within SLA (Verdadero o Falso — tenga en cuenta que esto solo coincide con Hallazgos que ya han sido Mitigated; consulte [Filtros de SLA](#sla-filters))
* Reporter (usuario o servicio que creó el Hallazgo)
* Found by (se refiere a la herramienta)

##### Se pueden modificar
Estos campos se establecen cuando se crea un incidente, pero se pueden modificar a medida que este avanza.

* [Status](/triage_findings/findings_workflows/finding_status_definitions/)
* Last Status Update (marca de tiempo)
* Mitigated (Verdadero o Falso)

##### Funciones adicionales del modelo
Estas funciones de DefectDojo se pueden usar para organizar aún más sus Hallazgos o hacer seguimiento de la remediación.

* Finding Tags
* Reviewers (usuario asignado)
* Has Notes (Verdadero/Falso)
* Group (se refiere al [Finding Group](/triage_findings/findings_workflows/editing_findings/#finding-group-actions), si existe alguno)
* Risk Acceptance (seleccione una o más Risk Acceptances existentes de la lista)

### Metadatos específicos de la herramienta
Estos campos no tienen un impacto directo en la funcionalidad de DefectDojo, pero proporcionan información adicional para ayudar a explicar y mitigar los incidentes.  Se pueden establecer cuando se crea inicialmente un Hallazgo (usando información de un informe entrante), o pueden ser modificados por un usuario.

* CWE Value
* Vulnerability ID (generalmente un CVE)
* EPSS Score
* EPSS Percentile
* Service
* Planned Remediation Date
* Planned Remediation Version
* Has Component (Verdadero/Falso)
* Component Name
* Component Version
* File Path
* Effort for Fixing

### Metadatos de Jira
Si usa la integración con Jira, estos filtros hacen seguimiento de las actualizaciones de los issues de Jira vinculados.

* Jira Issue (se puede filtrar según si el Hallazgo tiene uno o no)
* Jira Age (antigüedad del issue de Jira)
* Jira Change (última vez que se enviaron cambios a Jira)
