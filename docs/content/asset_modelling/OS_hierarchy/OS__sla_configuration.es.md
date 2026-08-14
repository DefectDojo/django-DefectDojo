---
title: Configuración de SLA
description: Configure Acuerdos de Nivel de Servicio para diferentes Productos
weight: 2
audience: opensource
aliases:
- /es/en/working_with_findings/sla_configuration
---

Cada Producto en DefectDojo puede tener su propia configuración de Acuerdo de Nivel de Servicio (SLA), que representa los días que tiene su organización para remediar o gestionar de otro modo un Hallazgo.

El SLA se puede configurar según la **[Severidad del Hallazgo](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** o el **[Riesgo del Hallazgo](/asset_modelling/pro_hierarchy/priority_sla/)** (en DefectDojo Pro).

![image](images/sla_multiple.png)

Los SLA aplican una cuenta regresiva de días a un Hallazgo según el día en que el Hallazgo fue creado en DefectDojo.  Si un Hallazgo no se Cierra dentro de la cuenta regresiva, se etiquetará como en incumplimiento del SLA.

## Trabajar con SLAs

Puede usar los SLA como una forma de representar las políticas de remediación de su organización.  También puede usarlos como una forma de priorizar los Hallazgos más críticos y con más tiempo activo en su instancia de DefectDojo.  

* Puede ordenar o filtrar las tablas de Hallazgos por días de SLA.
* Las infracciones de SLA se pueden configurar para activar [Notificaciones](/admin/notifications/about_notifications/) a los usuarios de DefectDojo asignados al Producto relacionado.
* En **DefectDojo Pro**, el rendimiento del SLA también se registra en los Paneles de métricas de [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/).
* El cumplimiento del SLA también se puede mostrar en un [panel](/metrics_reports/dashboards/custom-dashboards/) personalizado en **DefectDojo Pro** — por ejemplo, con un SLA Burndown o un widget de Count filtrado.

### Estado Mitigated Within SLA

Si un Hallazgo pasa a estar Mitigado antes de la fecha límite del SLA, el Hallazgo registrará una marca de verificación verde ✅ en la columna Mitigated Within SLA.

![image](images/sla_mitigated_within.png)

Si un Hallazgo quedó Mitigado, pero no antes de que se incumpliera el SLA, el Hallazgo registrará una X roja ❌ en la columna Mitigated Within SLA.

### Incumplimiento de SLAs

Cuando se incumple el SLA de un Hallazgo determinado (el Hallazgo no se Cierra dentro del plazo del SLA), la marca verde ✅ cambiará a una X roja ❌.  El SLA seguirá registrándose con un número negativo, para representar cuántos días lleva incumplido el SLA.

![image](images/sla_breached.png)

## Gestionar configuraciones de SLA (Pro)

En DefectDojo Pro, una o más configuraciones de SLA se gestionan en la sección **Configuration > Service Level Agreements** de la barra lateral.  Puede crear un **New Service Level Agreement** o trabajar con las configuraciones de SLA existentes desde la página **All Service Level Agreements**.

![image](images/pro_sla_risk.png)

Las configuraciones de SLA solo pueden ser editadas por Superusers o por un usuario con el [Permiso de configuración](/admin/user_management/user_permission_chart/#configuration-permission-chart) correspondiente.

### Configurar el SLA

Las configuraciones de SLA contienen los días asignados a cada valor de **Severidad** o **Riesgo** de DefectDojo.

![image](images/pro_new_sla.png)

Cada Service Level Agreement puede tener un nombre único, junto con una descripción opcional.

**Restart SLA on Finding Reactivation**: si está habilitada, esta opción reiniciará el SLA cuando un Hallazgo se Reabra.  De lo contrario, el SLA se basará en el momento en que se creó el Hallazgo.

Al editar un SLA, puede elegir si ese SLA usará la **Severidad** o el **Riesgo** como referencia para asignar los Days To Remediate.  Esto se hace seleccionando la opción correspondiente en la sección **Service Level configuration Type** del formulario.

Desde aquí, puede establecer la cantidad de días permitidos para cada nivel de **Severidad** o **Riesgo**.  También puede aplicar los SLA de forma selectiva; al desmarcar **Enforce ___ Finding Days** puede omitir el cálculo del SLA para esos niveles de Severidad o Riesgo.

## Aplicar una configuración de SLA a un Producto (Pro)

Los Productos recién creados en DefectDojo siempre aplicarán la **Default SLA Configuration**, que se puede configurar con valores diferentes si lo desea.

Si tiene configuraciones de SLA, puede elegir cuál de ellas se aplica a su Producto desde el formulario **Edit Product**.  

![image](images/pro_sla_product.png)

### Recálculo del SLA

Una vez que se ha seleccionado un nuevo SLA para un Producto, DefectDojo deberá recalcular los SLA de todos los Hallazgos asociados.  Mientras se ejecuta este proceso, no se puede cambiar el SLA de un Producto.

## Notas sobre los SLAs

* Los SLA se pueden reiniciar opcionalmente una vez que un Hallazgo con [Riesgo aceptado](/triage_findings/findings_workflows/os__risk_acceptance/) se reactiva.  Esto se configura al crear la Aceptación de riesgo mediante el campo **Restart SLA Expired**.
* Reimportar un Hallazgo no reinicia el SLA - los SLA siempre se calculan desde el momento en que el Hallazgo se detectó por primera vez, a menos que esté habilitada la opción **Restart SLA on Finding Reactivation**.
* La expiración de la Aceptación de riesgo o la reactivación de un Hallazgo Cerrado son las únicas formas de restablecer o recalcular el SLA de un Hallazgo una vez creado (sin cambiar la configuración de SLA del Producto).
