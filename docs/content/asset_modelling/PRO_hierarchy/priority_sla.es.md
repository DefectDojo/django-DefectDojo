---
title: Asignar Prioridad, Riesgo y SLA
description: Cómo DefectDojo clasifica sus Hallazgos
weight: 1
audience: pro
aliases:
- /es/en/working_with_findings/finding_priority
- /es/en/working_with_findings/priority_adjustments
---

![image](images/pro_finding_priority.png)

Una gestión eficaz de vulnerabilidades basada en riesgo requiere un enfoque que tenga en cuenta tanto el contexto de negocio como la explotabilidad técnica. Con la función de Prioridad y Riesgo de DefectDojo Pro, los usuarios pueden clasificar automáticamente los Hallazgos en un contexto significativo, garantizando que las vulnerabilidades de mayor impacto puedan abordarse primero.

**Prioridad** es una clasificación numérica calculada que se aplica a todos los Hallazgos de su instancia de DefectDojo. Le permite comprender rápidamente las vulnerabilidades en contexto, especialmente en organizaciones grandes que supervisan las necesidades de seguridad de muchos Hallazgos y/o Productos.

**Riesgo** es un sistema de clasificación de 4 niveles que tiene en cuenta en mayor medida la explotabilidad de un Hallazgo. Está pensado como una versión menos granular y más 'de nivel ejecutivo' de la Prioridad.

![image](images/pro_risk_example.png)

Los valores de Prioridad y Riesgo pueden usarse junto con otros filtros para comparar Hallazgos en cualquier contexto, como por ejemplo:

* dentro de un único Producto, Compromiso o Test
* de forma global en todos los Productos de DefectDojo
* entre varios Productos específicos

Aplicar la Prioridad y el Riesgo de los Hallazgos ayuda a su equipo a responder a las vulnerabilidades más relevantes de su organización, además de ofrecer un marco de trabajo que facilita el cumplimiento de normativas regulatorias.


Obtenga más información sobre Prioridad y Riesgo con las Office Hours de DefectDojo, Inc. de mayo de 2025:
<iframe width="560" height="315" src="https://www.youtube.com/embed/4SN0BWWsVm4?si=VYUzEGNeijjhoD22" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


## Cómo se calculan la Prioridad y el Riesgo
El rango de valores de Prioridad va de 0 a 1150. Cuanto más alto es el número, mayor es la urgencia de triar o remediar el Hallazgo.

De forma similar a la Severidad, el Riesgo se puntúa de Baja -> Media -> Requiere acción -> Urgente.  **Riesgo** tiene en cuenta los campos de Prioridad y, como resultado, puede diferir de la Severidad reportada por una herramienta.

![image](images/priority-overview.png)

## Campos de Prioridad: nivel de Producto

Cada Producto en DefectDojo tiene metadatos que registran la criticidad de negocio y los factores de riesgo. Estos metadatos se utilizan para ayudar a calcular la Prioridad y el Riesgo de los Hallazgos asociados.

Todos estos campos de metadatos pueden establecerse en el formulario **Editar Producto** de un Producto determinado.

![image](images/priority_edit_product.png)

* **Criticidad** puede establecerse en cualquier valor entre Ninguna, Muy baja, Baja, Media, Alta o Muy alta. La Criticidad es un campo subjetivo, así que al asignarlo, tenga en cuenta cómo se compara el Producto con otros Productos de su organización.
* **Registros de usuarios** es una estimación numérica de los registros de usuarios en una base de datos (o en un sistema que pueda acceder a dicha base de datos).
* **Ingresos** es una estimación numérica de los ingresos anuales del Producto. Para calcular la Prioridad, DefectDojo calculará un porcentaje comparando los ingresos de este Producto con la suma de los ingresos de todos los Productos dentro del Tipo de Producto.

No es posible establecer un tipo de moneda en DefectDojo, así que asegúrese de que todas sus estimaciones de Ingresos usen la misma denominación de moneda. ("50000" podría significar 50.000 dólares estadounidenses o ¥50.000 yenes japoneses - la denominación no importa siempre que todos sus Productos calculen los ingresos en la misma moneda).
* **Audiencia externa** es un valor verdadero/falso - establézcalo en Verdadero si este Producto puede ser accedido por una audiencia externa. Por ejemplo, clientes, usuarios o cualquier persona fuera de su organización.
* **Accesible por Internet** es un valor verdadero/falso. Si este Producto puede conectarse a Internet abierto, debería establecer este valor en Verdadero.

La Prioridad es un cálculo 'relativo', pensado para comparar diferentes Productos dentro de su instancia de DefectDojo. En última instancia, depende de su organización decidir cómo se configuran estos filtros. Estos valores deben ser lo más precisos posible, pero el objetivo principal es resaltar sus Productos clave para que pueda priorizar las vulnerabilidades según las políticas de su organización, por lo que no es estrictamente necesario que estos campos se configuren de forma perfecta.

## Campos de Prioridad: nivel de Hallazgo

Los Hallazgos dentro de un Producto pueden tener metadatos adicionales que ajusten aún más el nivel de Prioridad y Riesgo del Hallazgo:

* Si el Hallazgo tiene o no una **Puntuación EPSS**, esta se añade automáticamente a los Hallazgos y se mantiene actualizada para los usuarios de Pro.  La **Puntuación EPSS** es el campo que contribuye a la Puntuación de Prioridad — el **Percentil EPSS** se registra en el Hallazgo como referencia, pero no alimenta directamente el cálculo.
* Cuántos Endpoints del Producto se ven afectados por este Hallazgo
* Si el Hallazgo está o no En revisión
* Si el Hallazgo está en la base de datos KEV (Known Exploited Vulnerabilities), que DefectDojo comprueba periódicamente
* La Severidad reportada por la herramienta para un Hallazgo (Informativa, Baja, Media, Alta, Crítica)

#### Puntuación EPSS frente a Percentil EPSS

Dos Hallazgos que parecen idénticos en los factores visibles (Severidad, Criticidad de negocio, Accesible por Internet, Exploit disponible) pueden acabar con Puntuaciones de Prioridad distintas si sus **Puntuaciones EPSS** difieren.  Esto es lo esperado: la Puntuación EPSS es una entrada contextual del cálculo.

El Percentil EPSS se muestra en el Hallazgo como contexto, pero no se utiliza en el cálculo de la Puntuación de Prioridad.  Si necesita comparar dos Hallazgos para entender una diferencia en la Puntuación de Prioridad, fíjese en los valores de Puntuación EPSS, no en los valores de Percentil.

El peso exacto que tiene la Puntuación EPSS (y los demás factores) en el cálculo de la Puntuación de Prioridad no se publica de forma intencionada.  Si necesita influir en cuánto afecta la Puntuación EPSS a la puntuación en su entorno, ajuste el control deslizante de **Explotabilidad** en su [Motor de Priorización](#prioritization-engines).


## Cálculo del Riesgo de un Hallazgo

![image](images/risk_table.png)

La columna Riesgo en una tabla de Hallazgos es otra forma rápida de priorizar Hallazgos.  El Riesgo se calcula a partir del nivel de Prioridad de un Hallazgo, pero además tiene en cuenta en mayor medida la explotabilidad del Hallazgo.  Está pensado como una versión menos granular y más 'de nivel ejecutivo' de la Prioridad.

Los cuatro niveles de Riesgo asignables son:

![image](images/pro_risk_levels.png)

El EPSS / la explotabilidad de un Hallazgo tiene mucho más peso en el cálculo del Riesgo.  Como resultado, un Hallazgo puede tener a la vez una Prioridad alta y un valor de Riesgo bajo.

El cálculo del Riesgo en sí mismo no puede ajustarse directamente por el momento. Sin embargo, si la función de [Inteligencia de amenazas](/asset_modelling/pro_hierarchy/threat_intelligence/) está habilitada, el **Piso de Riesgo por Explotación Activa** sí le permite controlar el resultado en el caso que más importa: un Hallazgo confirmado como explotado activamente se eleva como mínimo a la banda de Riesgo que usted elija, en lugar de quedar en una banda baja porque su severidad base es Baja.  Viene configurado en **Requiere acción** de forma predeterminada, y cada Motor de Priorización puede subirlo, bajarlo o desactivarlo por completo.  Consulte [el Piso de Riesgo por Explotación Activa](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor).

## Panel de Información de Prioridad

Los usuarios pueden obtener una vista de nivel ejecutivo de la Prioridad y el Riesgo en su entorno usando el Panel de Información de Prioridad (Métricas > Información de Prioridad en la barra lateral)

![image](images/priority_dashboard.png)

Este panel puede filtrarse para incluir Productos o rangos de fechas específicos. Al igual que otros paneles de Pro, este panel puede exportarse desde DefectDojo como PDF para generar un informe rápidamente.

## Configurar Prioridad y Riesgo para el cumplimiento normativo

Esta es una lista no exhaustiva de normativas que requieren específicamente métodos de priorización de vulnerabilidades:

* El cumplimiento de [SOX (Sarbanes-Oxley Act](https://www.sarbanes-oxley-act.com/)) exige una priorización basada en ingresos para los sistemas que afectan a los datos financieros. En DefectDojo, los ingresos de un sistema pueden introducirse a nivel de Producto.
* El cumplimiento de [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) exige una priorización basada en clasificaciones de riesgo y en la criticidad para los entornos de datos de titulares de tarjetas. La Criticidad de negocio y la Audiencia externa pueden establecerse a nivel de Producto, mientras que la sincronización EPSS a nivel de Hallazgo de DefectDojo respalda el enfoque basado en riesgo de PCI.
* [NIST SP 800-40](https://csrc.nist.gov/pubs/sp/800/40/r4/final) es una guía de mantenimiento preventivo que exige específicamente la priorización de vulnerabilidades en función del impacto de negocio, la criticidad del producto y los factores de accesibilidad por Internet. Todos estos pueden configurarse a nivel de Producto en DefectDojo.
* El cumplimiento del control A.12.6.1 de [ISO 27001/27002](https://www.iso.org/standard/27001) exige la gestión de vulnerabilidades técnicas con una Prioridad basada en la evaluación de riesgos.
* El [Artículo 32 del RGPD](https://gdpr-info.eu/art-32-gdpr/) exige medidas de seguridad basadas en riesgo - los indicadores de registros de usuarios y audiencia externa a nivel de Producto pueden ayudar a priorizar los sistemas de su organización que procesan datos personales.
* El cumplimiento de [FISMA/FedRAMP](https://help.fedramp.gov/hc/en-us) exige monitorización continua y remediación de vulnerabilidades basada en riesgo.

Los cálculos de Prioridad y Riesgo de DefectDojo Pro pueden ajustarse, lo que le permite adaptar DefectDojo Pro para que coincida con los estándares internos de su organización en materia de Prioridad y Riesgo de Hallazgos.

## Motores de Priorización

De forma similar a las configuraciones de SLA, los Motores de Priorización le permiten establecer las reglas que rigen cómo se calculan la Prioridad y el Riesgo.

![image](images/priority_default.png)

DefectDojo incluye un Motor de Priorización integrado, que se aplica a todos los Productos.  Sin embargo, puede editar este Motor de Priorización para cambiar la ponderación de los multiplicadores de **Hallazgo** y de **Producto**, lo que ajustará cómo se asignan la Prioridad y el Riesgo de los Hallazgos.

### Multiplicadores de Hallazgo

Ocho factores contextuales influyen en la Puntuación de Prioridad de un Hallazgo.  Tres de ellos son específicos del Hallazgo, y los otros cinco se asignan según el Producto que contiene el Hallazgo.

Puede ajustar su Motor de Priorización modificando cómo se aplican estos factores al cálculo final.

![image](images/priority_sliders.png)

Seleccione un factor haciendo clic en el botón, y este control deslizante le permite controlar el porcentaje con el que se aplica un factor concreto.  A medida que ajusta el control deslizante, verá cómo cambian los umbrales de Riesgo como resultado.

#### Multiplicadores a nivel de Hallazgo

* **Severidad** - el nivel de Severidad de un Hallazgo
* **Explotabilidad** - la puntuación KEV y/o EPSS de un Hallazgo
* **Endpoints** - la cantidad de Endpoints asociados a un Hallazgo

#### Multiplicadores a nivel de Producto

* **Criticidad de negocio** - la Criticidad de negocio del Producto relacionado (Ninguna, Muy baja, Baja, Media, Alta o Muy alta)
* **Registros de usuarios** - el recuento de Registros de usuarios del Producto relacionado
* **Ingresos** - los ingresos del Producto relacionado, en relación con los ingresos totales del Tipo de Producto
* **Audiencia externa** - si el Producto relacionado tiene o no una audiencia externa
* **Accesible por Internet** - si el Producto relacionado es o no accesible por Internet

### Umbrales de Riesgo

Según el ajuste del Motor de Prioridad, DefectDojo recomendará automáticamente Umbrales de Riesgo.  Sin embargo, estos umbrales también pueden ajustarse y establecerse en los valores que considere apropiados.

![image](images/risk_threshold.png)

## Crear nuevos Motores de Priorización

Puede utilizar varios Motores de Priorización, cada uno de los cuales puede asignarse a Productos distintos.

![image](images/priority_engine_new.png)

Al crear un nuevo Motor de Priorización se abrirá el formulario del Motor de Priorización.  Una vez enviado este formulario, se añadirá un nuevo Motor de Priorización a la tabla.

## Asignar Motores de Priorización a Productos

Cada Producto puede tener un Motor de Priorización en uso actualmente a través del formulario **Editar Producto** de un Producto determinado.

![image](images/priority_chooseengine.png)

Tenga en cuenta que cuando se cambia el Motor de Priorización de un Producto, o se actualiza un Motor de Priorización, el Motor de Priorización del Producto o el propio Motor de Priorización quedará "Bloqueado" hasta que se complete el cálculo de priorización.

Cada Producto en DefectDojo puede tener su propia configuración de Acuerdo de Nivel de Servicio (SLA), que representa los días de los que dispone su organización para remediar o gestionar de otro modo un Hallazgo.

El SLA puede establecerse en función de la **[Severidad del Hallazgo](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** o del **[Riesgo del Hallazgo](/asset_modelling/pro_hierarchy/priority_sla/)** (en DefectDojo Pro).

![image](images/sla_multiple.png)

Los SLA aplican una cuenta regresiva de días a un Hallazgo a partir del día en que el Hallazgo se creó en DefectDojo.  Si un Hallazgo no se Cierra antes de que termine la cuenta regresiva, el Hallazgo se etiquetará como en incumplimiento de SLA.

## Trabajar con SLA

Puede usar los SLA como una forma de representar las políticas de remediación de su organización.  También puede usarlos como una forma de priorizar los Hallazgos más críticos y con más tiempo activo en su instancia de DefectDojo.

* Puede ordenar o filtrar las tablas de Hallazgos por días de SLA.
* Las infracciones de SLA pueden configurarse para activar [Notificaciones](/admin/notifications/about_notifications/) a los usuarios de DefectDojo asignados al Producto relacionado.
* En **DefectDojo Pro**, el rendimiento del SLA también se registra en los Paneles de Métricas de [Información Ejecutiva y Remediación](/metrics_reports/pro_metrics/pro__overview/).
* El cumplimiento del SLA también puede mostrarse en un [panel](/metrics_reports/dashboards/custom-dashboards/) personalizado en **DefectDojo Pro** — por ejemplo con un widget de Consumo de SLA (SLA Burndown) o un widget de Conteo filtrado.

### Estado Mitigado dentro del SLA

Si un Hallazgo se Mitiga correctamente antes de la fecha límite del SLA, el Hallazgo mostrará una marca de verificación verde ✅ en la columna Mitigado dentro del SLA.

![image](images/sla_mitigated_within.png)

Si un Hallazgo se Mitigó, pero no antes de que se incumpliera el SLA, el Hallazgo mostrará una X roja ❌ en la columna Mitigado dentro del SLA.

### Incumplimiento de SLA

Cuando se incumple el SLA de un Hallazgo determinado (el Hallazgo no se Cierra dentro del plazo del SLA) la marca de verificación verde ✅ cambiará a una X roja ❌.  El SLA seguirá registrándose con un número negativo, para representar cuántos días lleva incumplido el SLA.

![image](images/sla_breached.png)

## Gestionar configuraciones de SLA (Pro)

En DefectDojo Pro, una o más configuraciones de SLA se gestionan en la sección **Configuración > Acuerdos de Nivel de Servicio** de la barra lateral.  Puede crear un **Nuevo Acuerdo de Nivel de Servicio** o trabajar con configuraciones de SLA existentes desde la página **Todos los Acuerdos de Nivel de Servicio**.

![image](images/pro_sla_risk.png)

Las configuraciones de SLA solo pueden editarlas los Superusuarios o un usuario con el [Permiso de Configuración](/admin/user_management/user_permission_chart/#configuration-permission-chart) correspondiente.

### Configurar el SLA

Las configuraciones de SLA contienen los días asignados a cada valor de **Severidad** o **Riesgo** de DefectDojo.

![image](images/pro_new_sla.png)

Cada Acuerdo de Nivel de Servicio puede tener un nombre único, junto con una descripción opcional.

**Reiniciar SLA al reactivar un Hallazgo**: si se habilita, esta opción reiniciará el SLA cuando se Reabra un Hallazgo.  De lo contrario, el SLA se basará en la fecha de creación del Hallazgo.

Al editar un SLA, puede elegir si ese SLA usará la **Severidad** o el **Riesgo** como referencia para asignar los Días para remediar.  Esto se hace seleccionando la opción correspondiente en la sección **Tipo de configuración de Nivel de Servicio** del formulario.

A partir de ahí, puede establecer el número de días permitidos para cada nivel de **Severidad** o **Riesgo**.  También puede aplicar los SLA de forma selectiva; al desmarcar **Aplicar días de Hallazgo ___** puede ignorar el cálculo de SLA para esos niveles de Severidad o Riesgo.

## Aplicar una configuración de SLA a un Producto (Pro)

Los Productos recién creados en DefectDojo siempre aplicarán la **Configuración de SLA predeterminada**, que puede establecerse con valores distintos si lo desea.

Si dispone de configuraciones de SLA, puede elegir cuál de ellas se aplica a su Producto desde el formulario **Editar Producto**.

![image](images/pro_sla_product.png)

### Recálculo del SLA

Una vez seleccionado un nuevo SLA para un Producto, DefectDojo deberá recalcular los SLA de todos los Hallazgos asociados.  Mientras se ejecuta este proceso, no se puede cambiar el SLA de un Producto.

## Notas sobre los SLA

* Los SLA pueden reiniciarse opcionalmente cuando se reactiva un Hallazgo con [Riesgo aceptado](/triage_findings/findings_workflows/pro__risk_acceptance/).  Esto se configura al crear la Aceptación de riesgo, estableciendo el campo **Reiniciar SLA al expirar**.
* Reimportar un Hallazgo no reinicia el SLA - los SLA siempre se calculan desde el momento en que se detectó por primera vez un Hallazgo, a menos que esté habilitado **Reiniciar SLA al reactivar un Hallazgo**.
* La expiración de la Aceptación de riesgo o la reactivación de un Hallazgo Cerrado son las únicas formas de reiniciar o recalcular el SLA de un Hallazgo una vez creado (sin cambiar la configuración de SLA del Producto).
