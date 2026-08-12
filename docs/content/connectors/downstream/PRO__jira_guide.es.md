---
title: Jira (Legacy)
description: Trabaje con la integración de Jira
weight: 1
audience: pro
aliases:
- /es/issue_tracking/jira/pro__jira_guide/
- /es/en/share_your_findings/jira_guide
---

> **Esta página documenta la integración legacy de Jira.** La integración de Jira por producto descrita aquí ha sido reemplazada por el **[Conector descendente de Jira](/connectors/downstream/about/)**, que está disponible de forma general en todas las instancias de DefectDojo Pro y es la forma recomendada de enviar Hallazgos a Jira. En la barra lateral de Pro, **Connect > Jira** muestra una insignia `LEGACY` por este motivo — consulte [Insignias de menú](/navigation/pro__menu_badges/).
>
> **Si está configurando Jira por primera vez, comience con el [Conector descendente](/connectors/downstream/about/) en lugar de esta guía.**
>
> **¿Ya utiliza la integración legacy?** DefectDojo Pro incluye una migración integrada que traslada su configuración clásica existente de Jira a los Conectores descendentes, incluidos los tickets que ya ha enviado — consulte [Migración al conector descendente de Jira](#migrating-to-the-jira-downstream-connector) más abajo.
>
> La integración legacy sigue funcionando, y esta guía sigue siendo precisa para ella.

La integración de Jira de DefectDojo se puede utilizar para enviar datos de Hallazgos a uno o más Espacios de Jira.  De este modo, puede integrar DefectDojo en su flujo de trabajo de desarrollo habitual.  Estos son algunos ejemplos de cómo puede funcionar esto:

* El equipo de AppSec puede enviar Hallazgos de forma selectiva a un Espacio de Jira utilizado por los desarrolladores, de modo que la remediación de incidencias pueda priorizarse adecuadamente junto con el desarrollo habitual.  Los desarrolladores de ese tablero no necesitan acceder a DefectDojo: pueden mantener todo su trabajo en un solo lugar.
* DefectDojo puede enviar TODOS los Hallazgos a un Espacio de Jira bidireccional que utiliza el equipo de AppSec, lo que les permite repartirse la validación de incidencias.  Este tablero se mantiene sincronizado con DefectDojo y permite flujos de trabajo de remediación complejos.
* DefectDojo puede enviar Hallazgos de forma selectiva desde Productos y/o Compromisos independientes a Espacios de Jira independientes, para mantener cada cosa en su contexto adecuado.

## Migración al conector descendente de Jira

DefectDojo Pro puede convertir por usted una configuración clásica de Jira existente en una configuración de Conector descendente, en lugar de obligarle a reconstruirla manualmente.

**Dónde encontrarlo:** vaya a **Connect \> Downstream** para abrir la página **Downstream Connectors**, y use la tarjeta **Classic Jira Migration**. Haga clic en **Migrate from classic Jira** y luego confirme.

La tarjeta solo aparece si hay una configuración clásica de Jira que migrar, o una ejecución anterior que reportar — por lo que una instancia que nunca usó Jira clásico no la verá. Una vez que todo se ha migrado, la tarjeta permanece pero el botón queda deshabilitado, porque ya no queda nada por hacer.

Ejecutar la migración requiere **permisos de nivel Maintainer globales** (concretamente, permiso para editar integraciones), y debe ejecutarse desde una sesión de navegador con la sesión iniciada — no se puede realizar con un token de API.

### Qué sucede con los tickets que ya ha enviado

**Sus tickets de Jira existentes se conservan y se vuelven a enlazar — no quedan huérfanos, y el conector no abre duplicados.** Cada Hallazgo que Jira clásico ya había enviado conserva su ticket, y el conector pasa a actualizar ese mismo ticket en el mismo lugar. Los enlaces en los Grupos de hallazgos se trasladan de la misma manera.

La única excepción son los **épicos de Compromiso**. El Conector descendente no tiene el concepto de épicos, por lo que las incidencias de tipo épico se reportan en las advertencias de la migración y se dejan sin modificar.

### Qué se migra

* Su conexión de **instancia** de Jira — URL y credenciales — se convierte en una instancia de integración de Conector descendente, conservando su nombre.
* Las **asignaciones de severidad** y las **asignaciones de estado** (sus claves de transición de apertura y cierre) se trasladan.
* Cada configuración de **Proyecto de Jira** se convierte en una asignación de rastreador de incidencias, conservando su clave de proyecto y su tipo de incidencia, y permanece asignada al mismo Producto o Compromiso.
* **Push All Issues** se conserva: los proyectos que lo tenían habilitado siguen enviando automáticamente.
* Los **campos personalizados**, los **campos de transición de cierre/reapertura**, el **componente**, el **responsable predeterminado** y las **etiquetas** se convierten en asignaciones de campos. Donde usaba *Add Vulnerability Id as a Jira label*, eso también se convierte en una asignación de etiqueta.
* Un directorio de **plantilla de incidencia personalizada** se convierte en una plantilla de ticket. Las plantillas estándar no se copian, porque el conector ya incluye sus equivalentes.

### Qué no se traslada

Esto se reporta como advertencias en la ejecución de la migración — no la detienen. Busque la lista *"things the connector cannot carry over"* en los resultados.

* **Sincronización inversa de Jira → DefectDojo.** Este es el importante. El Conector descendente no sincroniza cambios *de vuelta* desde Jira, por lo que las asignaciones de resolución que aplican Riesgo aceptado o Falso positivo a partir de una resolución de Jira no se migran. **Si depende de la sincronización inversa, deje configurada la instancia clásica de Jira** — la migración no la elimina.
* **Engagement Epic Mapping** — el conector no tiene concepto de épicos.
* **Push Notes**, los **comentarios de notificación de SLA** y los **comentarios de expiración de aceptación de riesgo** — el conector no los publica en Jira.
* Campos personalizados llamados `summary`, `description`, `project`, `issuetype` o `status` — están reservados por el conector, y una asignación de campo que use alguno de ellos se omite.
* Valores de campo personalizado de más de 512 caracteres — se omiten en lugar de truncarse.
* Un Proyecto de Jira que no está vinculado ni a un Producto ni a un Compromiso no produce ninguna asignación.

### Qué sucede después con la integración clásica

**Nada se envía dos veces.** Por cada proyecto que migra, la migración desactiva el proyecto clásico de Jira, de modo que a partir de ese momento solo envía el conector. No es necesario deshabilitar nada manualmente.

Su configuración clásica se **conserva, no se elimina** — la instancia, el proyecto y los registros de incidencias permanecen todos, y solo se desactivan los ajustes de envío. Esto es intencionado: es lo que hace que el cambio sea reversible, y es lo que mantiene funcionando la sincronización inversa si depende de ella.

**Para revertir**, vuelva a habilitar los ajustes del proyecto clásico de Jira y elimine la configuración del conector creada por la migración. No existe una opción de deshacer con un solo clic.

**Volver a ejecutarla es seguro.** La migración registra lo que ya ha convertido y lo omite en una segunda ejecución, por lo que nada se duplica. Si un proyecto o una instancia falla, el resto se sigue migrando — un proyecto fallido se deja funcionando en la integración clásica en lugar de desactivarse, de modo que sigue funcionando mientras usted investiga.

### Mientras se ejecuta

La migración se ejecuta en segundo plano e informa del progreso a medida que avanza. Cuando termina, obtiene un resumen — cuántos conectores, asignaciones, asignaciones de destino, plantillas y enlaces de tickets se crearon, cuántos proyectos clásicos se desactivaron y qué se omitió — junto con las advertencias descritas anteriormente. Solo se ejecuta una migración a la vez.

# Configuración de Jira

Configurar Jira requiere los siguientes pasos:
1. Habilitar la integración de Jira en la Configuración del sistema.  Hasta que lo haga, el resto de los ajustes de Jira permanecen ocultos en todo DefectDojo.
2. Conectar una Instancia de Jira, ya sea con un usuario/contraseña o con un token de API.  Se pueden vincular varias instancias.
3. Añadir esa Instancia de Jira a uno o más Productos o Compromisos dentro de DefectDojo.
4. Si desea usar sincronización bidireccional, crear un Webhook de Jira que enviará actualizaciones a DefectDojo.

## Paso 1: Habilitar la integración de Jira en la Configuración del sistema

La integración de Jira está desactivada de forma predeterminada, y mientras lo está, DefectDojo oculta el resto de los controles de Jira en la interfaz.  Esto es lo primero que hay que configurar: ninguno de los pasos siguientes está disponible hasta que se habilita.

Mientras la integración está deshabilitada, no hay ninguna entrada de **Jira Instances** en la barra lateral, por lo que no hay dónde añadir una Instancia de Jira:

![imagen](images/jira-menu-hidden-pro.png)

### Habilitar la integración

1. Vaya a **Settings \> System \> System Settings** desde la barra lateral de DefectDojo. En las instancias que todavía usan el diseño de menú anterior, esto se encuentra bajo un grupo con el nombre de su paquete de licencia — **Pro Settings** o **Enterprise Settings**. Consulte [El menú de Configuración](/navigation/pro__settings_menu/).
​
2. En la sección **Jira Integration Settings**, marque **Enable Jira Integration**.
​
3. Haga clic en **Submit**.  **Jira Instances** aparece en la barra lateral inmediatamente, sin necesidad de recargar la página:

![imagen](images/jira-enable-system-settings-pro.png)

### Qué controla este ajuste

Habilitar **Enable Jira Integration** es lo que hace que aparezca el resto de la interfaz de Jira.  Con él activado, obtiene:

* el menú **Jira Instances**, donde se añaden y editan las Instancias de Jira
* la página **Jira Project Settings** en el menú ⚙️ del Activo, y los ajustes de Jira en los Compromisos
* las acciones **Push to Jira** en Hallazgos y Grupos de hallazgos, los campos de Jira en los formularios de Hallazgo y de edición masiva, y las columnas de Jira en las listas de Activos, Compromisos, Hallazgos y Grupos de hallazgos (incluidas las exportaciones a CSV)

El ajuste también controla la integración fuera de la interfaz: mientras está desactivado, DefectDojo no enviará Hallazgos a Jira (incluidas las solicitudes `push_to_jira` enviadas a través de la API), y los webhooks entrantes de Jira se ignoran.

El resto de los campos de Jira en **Jira Integration Settings** (**Add Vulnerability ID as Jira Label**, **Enable Jira Web Hook**, **Disable Jira Web Hook Secret**, **Jira Web Hook Secret**, **Jira Minimum Severity**) permanecen visibles tanto si la integración está activada como si no, pero no tienen ningún efecto hasta que se habilita.

## Paso 2: Conectar una Instancia de Jira

Con la integración habilitada, conectar una Instancia de Jira es el siguiente paso para configurar la integración de Jira de DefectDojo.  Tenga en cuenta que Jira Service Management no es compatible actualmente.

#### Información necesaria de Jira

Atlassian utiliza formas de autenticación distintas entre Jira Cloud y Jira Data Center.

para **Jira Cloud**, necesitará:
* una URL de Jira, por ejemplo https://yourcompany.atlassian.net/
* una cuenta con permisos para crear y actualizar incidencias en su instancia de Jira.  Puede ser:
    * Una combinación estándar de **usuario/contraseña**
    * Una combinación de **usuario/token de API**

para **Jira Data Center (o Server)**, necesitará:
* una URL de Jira, por ejemplo https://jira.yourcompany.com
* una cuenta con permisos para crear y actualizar incidencias en su instancia de Jira.  Puede ser:
    * Una combinación estándar de **usuario/contraseña**
    * Una combinación de **dirección de correo/Token de acceso personal**

Opcionalmente, puede asignar:
* Transiciones de Jira para activar la Reapertura y el Cierre de Hallazgos
* Resoluciones de Jira que puedan aplicar los estados Riesgo aceptado y Falso positivo a los Hallazgos (opcional)

Una única conexión de Instancia de Jira puede gestionar varios Espacios de Jira, siempre que la cuenta/token de Jira que use DefectDojo tenga permiso para crear Incidencias en el Espacio de Jira asociado.

### Añadir una Instancia de Jira

1. Asegúrese de que **Enable Jira Integration** esté marcado en la Configuración del sistema, como se describe en el [Paso 1](#step-1-enable-the-jira-integration-in-system-settings).  El menú **Jira Instances** no aparece en la barra lateral hasta entonces.

2. Vaya a la página **Enterprise Settings \> Jira Instances \> + New Jira Instance** desde la barra lateral de DefectDojo.

![imagen](images/jira-instance-beta.png)

3. Seleccione un **Configuration Name** para que esta Instancia de Jira lo use en DefectDojo. Este nombre es simplemente una etiqueta para la conexión de la Instancia en DefectDojo, y no necesita estar relacionado con ningún dato de Jira.

4. Seleccione la URL de la instancia de Jira de su empresa, probablemente similar a `https://**yourcompany**.atlassian.net` si utiliza una instalación de Jira Cloud.

5. Introduzca un método de autenticación adecuado en los campos Username/Password de Jira:
    * Para la **autenticación estándar de usuario/contraseña de Jira**, introduzca un nombre de usuario de Jira y la contraseña correspondiente en estos campos.
    * Para la autenticación con un **token de API de usuario (Jira Cloud)**, introduzca el nombre de usuario junto con el **token de API** correspondiente en el campo de contraseña.
    * Para la autenticación con un **Token de acceso personal de Jira (también llamado PAT, usado solo en Jira Data Center y Jira Server)**, introduzca el PAT en el campo de contraseña.  El nombre de usuario no se utiliza para la autenticación con un PAT de Jira, pero el campo sigue siendo obligatorio en este formulario, así que puede usar un valor de marcador de posición aquí para identificar su PAT.

Tenga en cuenta que el usuario asociado a esta conexión debe tener permiso para crear Incidencias y acceder a los datos de su instancia de Jira.

6. Deberá proporcionar valores para un Epic Name ID, un Re-open Transition ID y un Close Transition ID.  Estos valores se pueden cambiar más adelante.  Con la sesión iniciada en Jira, puede acceder a estos valores desde las siguientes URL:
- **Epic Name ID**: visite `https://<YOUR JIRA URL>/rest/api/2/field` y busque Epic Name. Copie el número que aparece en `number` y péguelo aquí.  Si no tiene un Epic Name ID asociado a su Espacio en Jira (por usar, por ejemplo, un Espacio gestionado por el equipo), introduzca 0 en este campo.
- **Re-open Transition ID**: visite `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar el ID de su instancia de Jira. Péguelo en el campo Reopen Transition ID.
- **Close Transition ID**: visite `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar el ID de su instancia de Jira. Péguelo en el campo Close Transition ID.

7. Seleccione el tipo de incidencia predeterminado con el que desea crear las Incidencias en Jira. Las opciones son **Bug, Task, Story** y **Epic** (que son tipos de incidencia estándar de Jira), así como **Spike** y **Security**, que son tipos de incidencia personalizados. Si tiene un tipo de incidencia distinto que desee usar, póngase en contacto con [support@defectdojo.com](mailto:support@defectdojo.com) para obtener ayuda.

8. Seleccione su Plantilla de incidencia, que determinará la Descripción de la incidencia cuando se creen Incidencias en Jira.

Los dos tipos son:
- **Jira\_full**, que incluirá toda la información del Hallazgo en las Incidencias de Jira
- **Jira\_limited**, que incluirá una cantidad menor de información y metadatos del Hallazgo.

Si deja este campo en blanco, se usará de forma predeterminada **Jira\_full.**  Si necesita otro tipo de plantilla, póngase en contacto con [support@defectdojo.com](mailto:support@defectdojo.com).

9. Si lo desea, introduzca el nombre de una Resolución de Jira que cambiará el estado de un Hallazgo a Aceptado o a Falso positivo (cuando se active la Resolución en la Incidencia).

El formulario se puede enviar desde aquí.  Si lo desea, puede personalizar aún más su integración de Jira en Optional Fields.  Al hacer clic en este botón podrá aplicar texto genérico a las Incidencias de Jira o cambiar la asignación de Jira Severity Mappings.

## Paso 3: Conectar un Producto o Compromiso a Jira

Cada Producto o Compromiso en DefectDojo tiene sus propios ajustes que rigen cómo se convierten los Hallazgos en Incidencias de JIRA. Desde aquí, puede decidir el Espacio de Jira asociado y establecer el comportamiento predeterminado para crear Incidencias, Épicos, Etiquetas y otros metadatos de JIRA.

### Añadir Jira a un Producto

Puede encontrar esta página haciendo clic en el menú de engranaje de un Producto ⚙️ y abriendo la página **Jira Project Settings**.

![imagen](images/jira-project-settings.png)

#### Instancia de Jira

Si tiene configuradas varias instancias de Jira, para productos o equipos distintos dentro de su organización, puede indicar en qué Espacio de Jira desea que DefectDojo cree Incidencias. Seleccione un Espacio en el menú desplegable.

Si este menú no lista ninguna instancia de Jira, confirme que esos Espacios están conectados en su Configuración global de Jira para DefectDojo — yourcompany.defectdojo.com/jira.

#### Clave de proyecto

Esta es la clave del Espacio que desea usar con DefectDojo.  La Space Key de un Espacio determinado se puede encontrar en la URL.  (Anteriormente esto se conocía como **Jira Project Key**, pero desde septiembre de 2025 Jira lo denomina **Space Key**).

![imagen](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Nombre del tipo de incidencia Epic

El nombre del tipo de incidencia Epic en Jira. Este valor es "Epic" de forma predeterminada, pero se puede cambiar si su instancia de Jira usa un nombre distinto.

#### Plantilla de incidencia

Aquí puede determinar cuántos metadatos de DefectDojo desea enviar a Jira. Seleccione una de las dos opciones:

* **jira\_full**: las Incidencias registrarán todos los parámetros de DefectDojo — una Descripción completa, CVE, Severidad, etc. Útil si necesita el contexto completo del Hallazgo en Jira (por ejemplo, si alguien que trabaja en esta Incidencia no tiene acceso a DefectDojo).

Aquí tiene un ejemplo de una Incidencia **jira\_full**:
​
![imagen](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** las Incidencias solo registrarán el enlace a DefectDojo, los enlaces de Producto/Compromiso/Test, y los campos Reporter y Environment. El resto de los campos se registran únicamente en DefectDojo. Útil si no necesita el contexto completo del Hallazgo en Jira (por ejemplo, si alguien que trabaja en esta Incidencia trabaja principalmente en DefectDojo y no necesita también toda la información en JIRA).

​Aquí tiene un ejemplo de una Incidencia **jira\_limited**:

![imagen](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Componente

Si gestiona su Espacio de Jira mediante Componentes, aquí puede asignar el Componente adecuado para DefectDojo. Para asignar más de un Componente, introduzca una lista separada por comas (por ejemplo, `Security, DevSecOps`); cada valor se envía a Jira como un componente independiente.

#### Campos personalizados

Si no necesita usar Campos personalizados con las incidencias de DefectDojo, puede dejar este campo como 'null'.

Sin embargo, si la configuración de su Espacio de Jira **le obliga** a usar Campos personalizados en las Incidencias nuevas, deberá codificar directamente estas asignaciones.

Tenga en cuenta que DefectDojo no puede enviar ningún metadato específico de la Incidencia como Campo personalizado, solo un valor predeterminado. Esta sección solo debería configurarse si su Espacio de Jira **requiere que existan estos Campos personalizados** en cada Incidencia de su Espacio.

Siga **[esta guía](#custom-fields-in-jira)** para empezar a trabajar con Campos personalizados.

#### Campos de transición de cierre/reapertura

Algunos flujos de trabajo de Jira **requieren** que se establezcan ciertos campos como parte de una transición — por ejemplo, un flujo de trabajo que se niega a cerrar una Incidencia a menos que se proporcionen los campos Resolution y Justification en la pantalla de cierre. El ajuste de Campos personalizados anterior solo se aplica cuando se *crea* una Incidencia, por lo que no puede satisfacer estos flujos de trabajo.

Sin estos ajustes, DefectDojo envía las transiciones de cierre/reapertura sin campos. Un flujo de trabajo que requiera campos rechazará esa transición, y el Hallazgo y la Incidencia de Jira quedarán desincronizados: el Hallazgo aparece como Mitigado en DefectDojo mientras la Incidencia sigue abierta en Jira.

Los ajustes **Close Transition fields** y **Reopen Transition fields** aceptan un objeto JSON que se envía como el payload `fields` de la llamada de transición de cierre/reapertura. Por ejemplo, para cerrar Incidencias con una Resolution de *Won't Fix* más un valor de justificación:

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

Deje estos ajustes como 'null' si el flujo de trabajo de su Jira no requiere campos en las transiciones.

**¿Qué campos necesita?**

* Pregunte a su administrador de Jira qué campos aparecen en las **pantallas de transición** de cierre/reapertura, y cuáles de ellos son obligatorios según un validador. El JSON configurado debe satisfacer **todos** los campos obligatorios: si falta en el payload algún campo obligatorio, Jira rechaza toda la transición y no establece nada — proporcionar solo algunos de los campos obligatorios no sirve de nada.
* A la inversa, los campos deben estar presentes **en la pantalla de transición** para poder enviarse: Jira rechaza las transiciones que intentan establecer campos que no están en la pantalla de esa transición.
* En los flujos de trabajo creados con el editor de flujos de trabajo actual de Jira Cloud, Jira completa automáticamente la Resolution predeterminada del sitio cuando una Incidencia pasa a un estado de la categoría "hecho".  Por lo tanto, una Resolution obligatoria por sí sola no bloqueará ahí una transición sin campos, y el uso práctico de `"resolution"` en este payload es elegir un valor *significativo* (por ejemplo, *False Positive*) en lugar del valor predeterminado del sitio. Los flujos de trabajo creados con el editor clásico, o con aplicaciones de validación del marketplace, todavía pueden exigir obligatoriamente la Resolution.
* Las transiciones de reapertura normalmente borran la Resolution mediante el propio flujo de trabajo, por lo que **Reopen Transition fields** suele necesitar solo los campos personalizados que requiera su flujo de trabajo.

**Notas:**

* Se envía el mismo JSON para *cada* transición de cierre (o reapertura) del Producto o Compromiso — los valores son estáticos y no varían según el Hallazgo. Si necesita campos distintos según la disposición (por ejemplo, una Resolution distinta para los hallazgos de Falso positivo que para los remediados), use el Jira Integrator de DefectDojo Pro, que admite asignaciones de campos de transición por estado.
* Los valores usan el mismo formato que la API REST de Jira: cadenas de texto para los campos de texto, `{"name": ...}` para las resoluciones, `[{"name": ...}]` para los campos de selección múltiple, y así sucesivamente.
* Si las transiciones se rechazaron mientras estos ajustes estaban ausentes o incompletos, corregir los ajustes repara el desfase: el siguiente envío de estado del Hallazgo reintenta la transición con los campos configurados.
* Ambos ajustes también están disponibles en el endpoint REST `/api/v2/jira_projects/` (`close_transition_fields`/`reopen_transition_fields`), por lo que se pueden gestionar mediante la API.
* Estos campos también se aplican cuando DefectDojo cierra una Incidencia porque su Hallazgo fue **eliminado** — los valores se capturan en el momento en que se pone en cola el cierre.

#### Etiquetas de Jira

Seleccione las etiquetas pertinentes con las que desea que se cree la Incidencia en Jira, por ejemplo **DefectDojo**, **YourProductName..**

![imagen](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Responsable predeterminado

El nombre del responsable predeterminado en Jira. Si se deja en blanco, DefectDojo seguirá el comportamiento predeterminado de su Espacio de Jira al crear Incidencias.

### Jira Project Settings

#### Habilitado

Este interruptor controla si DefectDojo envía Hallazgos a Jira para este Producto. Deshabilitarlo no eliminará ni modificará ningún ticket de Jira existente creado por DefectDojo, pero impedirá cualquier actualización posterior o la creación de nuevas Incidencias.

Las integraciones de Jira solo se pueden eliminar de su instancia si no se ha creado ninguna Incidencia relacionada.  Si ya se han creado Incidencias, no hay forma de eliminar por completo una Instancia de Jira de DefectDojo.

#### Añadir Vulnerability Id como etiqueta de Jira

Esto le permite añadir automáticamente los datos de Vulnerability ID como una etiqueta de Jira. Los Vulnerability ID se añaden a los Hallazgos a partir de herramientas de seguridad individuales — pueden ser identificadores de Common Vulnerabilities and Exposures (CVE) o un formato distinto, específico de la herramienta que reporta el Hallazgo.

#### Push All Issues

Si está marcado, DefectDojo enviará automáticamente a Jira como Incidencias cualquier Hallazgo Activo y Verificado. Si se deja sin marcar, todos los Hallazgos deberán enviarse a Jira manualmente (de forma individual o mediante envío masivo).

Cuando este ajuste está habilitado, las Incidencias de Jira seguirán sincronizándose con DefectDojo aunque cambie el estado del Hallazgo.

#### Enable Engagement Epic Mapping

En DefectDojo, los Compromisos representan un conjunto de trabajo. Cada Compromiso contiene uno o más tests, que contienen uno o más Hallazgos que deben mitigarse. Los Épicos en Jira funcionan de forma similar, y esta casilla le permite enviar Compromisos a Jira como Épicos.

* Un Compromiso en DefectDojo — observe los tres hallazgos listados en la parte inferior.
​
![imagen](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Cómo el mismo Compromiso se convierte en un Épico al enviarse a JIRA — los Hallazgos del Compromiso también se envían, y quedan dentro del Épico como Incidencias hijas.

![imagen](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push Notes

Si está habilitado, los comentarios de Jira se reflejarán en el Hallazgo asociado en DefectDojo, en Notas, y viceversa; las Notas de los Hallazgos se añadirán a la Incidencia de Jira asociada como Comentarios.

#### Send SLA Notifications As Comments

Si está habilitado, cualquier Incidencia que incumpla las reglas del Acuerdo de nivel de servicio de DefectDojo tendrá comentarios añadidos en la incidencia de Jira indicándolo. Estos comentarios se publicarán a diario hasta que se resuelva la Incidencia.

Los Acuerdos de nivel de servicio se pueden configurar en **Configuration \> SLA Configuration** en DefectDojo y asignarse a cada Producto.

#### Send Risk Acceptance Expiration Notifications As Comment

Si está habilitado, cualquier Incidencia cuya Aceptación de riesgo asociada de DefectDojo expire tendrá un comentario añadido en la incidencia de Jira indicándolo. Estos comentarios se publicarán a diario hasta que se resuelva la Incidencia.

### Ajustes de Jira a nivel de Compromiso

De forma predeterminada, los Compromisos **heredan los ajustes de Jira de su Producto**. Sin embargo, puede anular los ajustes de Jira para Compromisos individuales.

Para acceder a los ajustes de Jira a nivel de Compromiso, haga clic en el menú de engranaje ⚙️ de un Compromiso y abra la página **Jira Project Settings**.

Desde aquí, puede desmarcar **Inherit from Product** y proporcionar valores específicos del Compromiso para: **Project Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee**, y otros ajustes.

Tenga en cuenta que, una vez que un Compromiso tiene asignado su propio proyecto de Jira, ya no puede heredar del Producto.

![imagen](images/Creating_Issues_in_Jira_5.png)

## Paso 4: Configurar la sincronización bidireccional: webhook de Jira

La integración con Jira permite la sincronización bidireccional mediante un webhook. DefectDojo recibe notificaciones de Jira en una dirección única, lo que permite que los comentarios de Jira se reciban en los Hallazgos, o que los Hallazgos se resuelvan a través de Jira, según su configuración.

### Cómo localizar la URL de su webhook de Jira

Su webhook de Jira se encuentra en el formulario de configuración del sistema, en **Jira Integration Settings**: **Enterprise Settings \> System Settings** en la barra lateral.

También debe marcar **Enable Jira Web Hook** en la misma página para que DefectDojo procese las notificaciones entrantes de Jira.  Los webhooks entrantes se ignoran si esa casilla o **Enable Jira Integration** (consulte el [Paso 1](#step-1-enable-the-jira-integration-in-system-settings)) no están marcadas.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Cómo crear el webhook de Jira

1. Visite `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Haga clic en 'Create a Webhook'.
3. En el campo denominado 'URL', ingrese: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. El Web Hook Secret aparece en Jira Integration Settings, como se indicó anteriormente.
4. En 'Comments', habilite 'Created'. En Issue, habilite 'Updated'.
5. Asegúrese de que su instancia de JIRA confíe en el certificado SSL utilizado por su instancia de DefectDojo. Para JIRA Cloud, DefectDojo debe usar [un certificado SSL/TLS válido, firmado por una autoridad certificadora globalmente confiable](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Tenga en cuenta que no es necesario crear un Secret dentro de Jira para usar este webhook. El Secret está integrado en la URL de DefectDojo, por lo que basta con agregar la URL completa al formulario de webhook de Jira.

Las solicitudes de webhook entrantes se autentican mediante el secreto incluido en esa URL, así que trate la URL completa como una credencial y manténgala privada.

#### Cómo probar el webhook

Una vez que tenga uno o más Issues creados a partir de Hallazgos de DefectDojo, puede probar el webhook agregando una nota a uno de esos Hallazgos. La nota debería recibirse en el webhook de Jira como un comentario.

Si esto no funciona correctamente, podría deberse a un problema de firewall en su instancia de Jira que esté bloqueando el webhook.

* Las reglas de firewall de DefectDojo incluyen una casilla para **Jira Cloud,** que debe habilitarse antes de que DefectDojo pueda recibir mensajes de webhook desde Jira.

### Alternativa: usar Jira Automation (Send web request)

Algunas instancias de Jira no permiten webhooks del sistema en `/plugins/servlet/webhooks` — por ejemplo, cuando esa área de administración está restringida y solo se permiten reglas de **Jira Automation**. En ese caso, puede lograr la misma sincronización bidireccional utilizando la acción **Send web request** de Automation, que envía datos al mismo endpoint de webhook de DefectDojo.

El endpoint de webhook de DefectDojo acepta cualquier `POST` HTTP con `Content-Type: application/json` y un secreto válido en la ruta de la URL. No requiere que la solicitud se origine en el mecanismo de webhook del sistema de Jira, por lo que la acción "Send web request" de Automation funciona como una alternativa directa.

#### Requisitos previos

Se aplican los mismos requisitos previos que para el webhook del sistema:

* **Enable JIRA integration** y **Enable JIRA web hook** están ambas marcadas en la página ⚙️ **Configuration \> System Settings**.
* Se ha configurado un **Jira webhook secret** no vacío en esa página. El secreto solo puede contener los caracteres `A-Z`, `a-z`, `0-9`, `_` y `-`.
* El Hallazgo (o Grupo de hallazgos) ya está vinculado al issue de Jira. Si el issue no está vinculado a un Hallazgo de DefectDojo, la solicitud igualmente se acepta (HTTP `200`), pero no se realiza ninguna acción.

#### Cómo procesa DefectDojo la solicitud

* DefectDojo se ramifica según un campo de nivel superior llamado `webhookEvent`. Solo se procesan `"jira:issue_updated"` y `"comment_created"`; cualquier otro valor se acepta pero se ignora. Automation no agrega este campo por sí sola, por lo que debe incluirlo usted mismo en el cuerpo de la solicitud.
* Por ese motivo, configure el **Body** de la solicitud como **Custom data** y proporcione el JSON que se muestra a continuación. Las opciones de cuerpo **Empty** y **Jira issue data** no incluyen el campo obligatorio `webhookEvent`, por lo que DefectDojo las ignorará.
* El endpoint siempre devuelve HTTP `200`, sin importar si se aplicó una actualización. El éxito o el fracaso solo son visibles en el cuerpo de la respuesta y en los registros de DefectDojo; un `200` en el registro de auditoría de Automation no confirma por sí solo que la actualización llegó a un Hallazgo.

#### Regla 1 — Issue actualizado

Cree una regla de Automation con:

* **Trigger:** *Issue transitioned* (u otro disparador que se active cuando cambien los campos que sincroniza, por ejemplo *Field value changed* en Status).
* **Action:** *Send web request*
  * **Web request URL:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method:** `POST`
  * **Web request body:** *Custom data*
  * **Headers:** `Content-Type: application/json`
  * **Custom data:**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

Restricciones para las actualizaciones de issues:

* `issue.id` debe ser el **ID numérico interno del issue de Jira** (`{{issue.id}}`), no la clave del issue (por ejemplo, `PROJ-123`). DefectDojo relaciona la actualización con un Hallazgo mediante este ID numérico.
* Los campos `resolution` y `updated` deben estar siempre presentes. `resolution` puede ser `null`, pero si falta alguno de los dos campos, la solicitud se acepta (`200`) y no se procesa, sin ningún aviso.
* La sincronización de estado y la auto-mitigación se basan en `status.statusCategory.key`, cuyos valores en Jira son `new` (To Do), `indeterminate` (In Progress) y `done` (Done). Un Hallazgo solo se mitiga cuando el issue está realmente cerrado, no simplemente porque exista un valor de resolution.

#### Regla 2 — Comentario en un issue

Cree una segunda regla de Automation con:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — misma URL, método, encabezado y opción de cuerpo *Custom data* que en la Regla 1, con este cuerpo:

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

Restricciones para los comentarios:

* Deben estar presentes tanto `body` como `updateAuthor`.
* DefectDojo obtiene el issue de destino a partir de la URL de `comment.self` — específicamente el `<id>` en el segmento `.../issue/<id>/comment/...` — por lo que `{{issue.id}}` (el ID numérico) debe aparecer allí.
* **Prevención de bucles:** si el autor del comentario coincide con la cuenta de Jira que usa DefectDojo para publicar sus propios comentarios, DefectDojo omite el comentario para evitar un bucle de eco. Si desea que se ingieran *todos* los comentarios, ejecute la regla de Automation como un usuario de Jira **distinto** del configurado en la instancia de Jira de DefectDojo.

#### Nota sobre los smart values

Los smart values mostrados arriba (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, etc.) son los nombres estándar de Jira Cloud, pero pueden variar entre instancias. Antes de pasar a producción, use la vista previa del payload de Automation para confirmar que cada smart value se resuelve como espera.

## Cómo probar la integración con Jira

#### Prueba 1: ¿los Hallazgos se envían correctamente a Jira?

Para comprobar que la integración con Jira funciona correctamente, puede agregar un nuevo Hallazgo en blanco al Producto asociado con Jira en DefectDojo. **Product \> Findings \> Add New Finding.**

Agregue el título, la severidad y la descripción que desee, y luego haga clic en "Finished". El Hallazgo debería aparecer como un Issue en Jira con todos los metadatos correspondientes.

Si los issues de Jira no se están creando correctamente, revise sus notificaciones en busca de códigos de error.

* Confirme que el usuario de Jira asociado con la configuración de Jira de DefectDojo tenga permisos para crear y actualizar issues en ese espacio de Jira en particular.

#### Prueba 2: los webhooks de Jira envían datos a DefectDojo

Para probar los webhooks de Jira, agregue una nota a un Hallazgo que también exista en JIRA como Issue (por ejemplo, el issue de prueba de la sección anterior).

Si los webhooks están configurados correctamente, debería ver la nota en Jira como un comentario en el issue.

Si esto no funciona correctamente, podría deberse a un problema de firewall en su instancia de Jira que esté bloqueando el webhook.

* Las reglas de firewall de DefectDojo incluyen una casilla para **Jira Cloud,** que debe habilitarse antes de que DefectDojo pueda recibir mensajes de webhook desde Jira.

## Cómo desconectarse de Jira

Las integraciones con Jira solo pueden eliminarse de su instancia si no se han creado issues relacionados.  Si se han creado issues, no hay forma de eliminar por completo una instancia de Jira de DefectDojo.

Sin embargo, puede desactivar su integración con Jira desactivándola a nivel de Producto.  En la página **Jira Project Settings** (accesible desde el menú ⚙️ Gear de un Producto), desmarque el interruptor **Enabled**.  Esto no eliminará ni modificará ningún ticket de Jira existente creado por DefectDojo, pero desactivará cualquier actualización futura.

# Cómo enviar Hallazgos a Jira

Un Producto con una asignación de JIRA puede enviar Hallazgos a Jira como Issues mediante varios métodos.  Puede enviar Hallazgos de forma individual, en bloque, como Grupos de hallazgos o automáticamente.

## Cómo enviar un solo Hallazgo

1. Abra el Hallazgo que desea enviar.
2. Haga clic en el **☰ Finding Menu** y seleccione **Push to Jira**.
3. Confirme el envío cuando se le solicite. DefectDojo creará un Issue de Jira y lo vinculará al Hallazgo.

Una vez creado el Issue, DefectDojo mostrará un enlace al Issue de Jira en la página del Hallazgo.

![image](images/Creating_Issues_in_Jira_2.png)

También puede marcar la casilla **Push to Jira** al editar un Hallazgo mediante el formulario **Edit Finding**. Cuando se guarde el Hallazgo, se enviará a Jira.

### Cómo actualizar un Issue de Jira vinculado

Si un Hallazgo ya tiene un Issue de Jira vinculado, al volver a seleccionar **Push to Jira** se actualizará el Issue de Jira existente con los cambios realizados en DefectDojo. Si **Push All Issues** está habilitado en el Producto, esta sincronización ocurre automáticamente.

### Cómo desvincular un Hallazgo de Jira

Para eliminar la asociación entre un Hallazgo y su Issue de Jira, haga clic en el **☰ Finding Menu** y seleccione **Unlink From Jira**. Esto elimina el vínculo en DefectDojo, pero no elimina el Issue de Jira en sí.

## Cómo enviar Hallazgos en bloque

Puede enviar varios Hallazgos a Jira a la vez mediante el formulario Bulk Update:

1. En una lista de Hallazgos, seleccione los Hallazgos que desea enviar usando las casillas de verificación.
2. Abra el formulario **Bulk Update**.
3. En **Jira Settings**, marque la casilla **Push to Jira**.
4. Haga clic en **Submit**.

Los Hallazgos seleccionados se pondrán en cola para enviarse a Jira. DefectDojo mostrará un mensaje de confirmación que indica cuántos Hallazgos se pusieron en cola.

## Cómo enviar Compromisos como Epics

Si **Enable Engagement Epic Mapping** está activado en Jira Project Settings, puede enviar un Compromiso a Jira como un Epic. Los Hallazgos del Compromiso se enviarán como Child Issues dentro de ese Epic.

Para enviar un Compromiso como Epic:

1. Abra el Compromiso que desea enviar.
2. Haga clic en el **☰ Engagement Menu** y seleccione **Push to Jira**.
3. Opcionalmente, proporcione un **Epic Name** (por defecto, el nombre del Compromiso si se deja en blanco) y una **Epic Priority**.
4. Marque **Push to Jira (Create Epic)** y envíe el formulario.

## Cómo enviar Grupos de hallazgos como Issues de Jira

Si tiene habilitados los Grupos de hallazgos, puede enviar un Grupo de Hallazgos a Jira como un único Issue en lugar de Issues separados para cada Hallazgo.

Para enviar un Grupo de hallazgos:

1. Abra el Grupo de hallazgos.
2. Haga clic en el **☰ Finding Group Menu** y seleccione **Push to Jira**, o marque la casilla **Push to Jira** al editar el Grupo de hallazgos.

Si es necesario eliminarlo, el Issue de Jira asociado con un Grupo de hallazgos debe eliminarse directamente desde la instancia de Jira.

### Cómo crear y enviar Grupos de hallazgos automáticamente

Con **Push All Issues** habilitado en el Producto, y una opción **Group By** seleccionada durante la importación:

Siempre que los Grupos de hallazgos se creen correctamente, será el Grupo de hallazgos el que se envíe automáticamente a Jira como Issue, y no los Hallazgos individuales.

![image](images/Creating_Issues_in_Jira_4.png)

## Comportamiento del envío automático

DefectDojo puede enviar Hallazgos y actualizaciones a Jira automáticamente en varios escenarios:

### Push All Issues

Cuando la opción **Push All Issues** está habilitada en Jira Project Settings de un Producto, DefectDojo creará automáticamente Issues de Jira para todos los Hallazgos Activos y Verificados. Esto incluye los Hallazgos creados mediante la importación de escaneos. Una vez creado un Issue de Jira, seguirá sincronizándose con DefectDojo aunque cambie el estado del Hallazgo.

### Sincronización automática ante cambios de estado

Cuando **Push All Issues** o la opción de nivel de sistema **Finding Jira Sync** está habilitada, DefectDojo actualizará automáticamente los Issues de Jira vinculados al realizar ciertas acciones sobre los Hallazgos:

* **Request Review** \- Se agrega un comentario al Issue de Jira vinculado (o al Issue de Jira del Grupo de hallazgos, si el Hallazgo pertenece a un grupo).
* **Clear Review** \- Se agrega un comentario al Issue de Jira vinculado.
* **Close Finding** \- El Issue de Jira vinculado se actualiza para reflejar el cierre. Si **Push Notes** está habilitado, también se agrega un comentario.

## Comentarios y notas de Jira

Cuando **Push Notes** está habilitado en Jira Project Settings:

* Si se agrega un comentario a un Issue de Jira, el mismo comentario se agregará al Hallazgo, en la sección **Notes**.
* Del mismo modo, si se agrega una nota a un Hallazgo, la nota se agregará al issue de Jira como un comentario.

## Cambios de estado en Jira

La configuración de la instancia de Jira incluye entradas para dos Transiciones de Jira que activarán un cambio de estado en un Hallazgo.

* Cuando se realiza la **'Close' Transition** en Jira, el Hallazgo asociado también se cerrará y se marcará como **Inactivo** y **Mitigado** en DefectDojo. DefectDojo registrará este cambio en la página del Hallazgo, bajo el encabezado **Mitigated By**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Cuando se realiza la **'Reopen' Transition** en el Issue de Jira, el Hallazgo asociado se establecerá como **Activo** en DefectDojo y perderá su estado **Mitigado**.

## Cómo asignar resoluciones de Jira a Riesgo aceptado / Falso positivo

La configuración de la instancia de Jira incluye dos campos opcionales que permiten asignar una **Resolution** de Jira a un estado de Hallazgo de DefectDojo:

* **Risk Accepted Finding Mapping Resolution** — cuando un issue de Jira se cierra con esta Resolution, el Hallazgo vinculado pasa a Riesgo aceptado en DefectDojo.
* **False Positive Finding Mapping Resolution** — cuando un issue de Jira se cierra con esta Resolution, el Hallazgo vinculado pasa a Falso positivo en DefectDojo.

### Status frente a Resolution: una fuente habitual de confusión

Estos campos asignan la **Resolution** de Jira, no el **Status** de Jira.  Status y Resolution son dos conceptos independientes en Jira: Status describe en qué punto del flujo de trabajo se encuentra el issue (Open, In Progress, Done), mientras que Resolution describe cómo se resolvió (Fixed, Won't Do, Duplicate, False Positive, etc.).

### Requisito previo: una post-function "Set issue resolution" en la transición del flujo de trabajo de Jira

El motor de flujo de trabajo de Jira no completa el campo Resolution automáticamente.  Cada transición que deba cerrar un issue con una Resolution específica necesita una post-function **Set issue resolution** configurada en la propia transición.  Sin esa post-function, el issue pasa al nuevo Status, pero Resolution permanece en blanco, y la asignación de DefectDojo no tiene nada con qué coincidir.

Un administrador de Jira puede agregar esta post-function desde **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

# Campos personalizados en Jira

<span style="background: rgba(243, 122, 78,0.5">Actualmente, DefectDojo no admite pasar información específica del Issue a estos Custom Fields \- estos campos deberán actualizarse manualmente en Jira después de crear el issue. Cada Custom Field solo se creará desde DefectDojo con un valor predeterminado.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud ahora le permite crear un valor predeterminado para un Custom Field directamente desde la aplicación. [Consulte la documentación de Atlassian sobre Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) para obtener más información sobre cómo configurarlo.</span>

Los Jira Issue Types integrados de DefectDojo (**Bug, Task, Story** y **Epic)** están configurados para funcionar "de fábrica". Los campos de datos de DefectDojo se asignarán automáticamente a los campos correspondientes en Jira. De forma predeterminada, DefectDojo asignará Priority, Labels y un Reporter a cualquier Issue nuevo que cree.

Algunas configuraciones de Jira requieren tener en cuenta campos personalizados adicionales antes de poder crear un issue. Este proceso le permitirá tener en cuenta estos campos personalizados en su integración DefectDojo \-\> Jira, garantizando que los issues se creen correctamente. Estos campos personalizados se agregarán a todas las llamadas a la API enviadas desde DefectDojo a una instancia de Jira vinculada.

Si aún no utiliza Custom Fields en Jira, no es necesario seguir este proceso.

1. Registrar los nombres de sus Custom Fields en Jira (**Jira UI**)
2. Determinar los valores de Key para los nuevos Custom Fields (Jira Field Spec Endpoint)
3. Localizar los datos aceptables para cada Custom Field, usando los valores de Key como referencia (Jira Issue Endpoint)
4. Crear un bloque JSON de referencia de campos para registrar todas las Keys de Custom Fields y los datos aceptables (Jira Issue Endpoint)
5. Guardar el bloque JSON en el Producto de DefectDojo asociado, para permitir que los Custom Fields se creen desde Jira (DefectDojo UI)
6. Probar su trabajo y asegurarse de que todos los datos requeridos fluyan correctamente desde Jira

#### Paso 1: registrar los nombres de sus Custom Fields en Jira

Jira admite una variedad de Context Fields diferentes, incluidos Date Pickers, Custom Labels y Radio Buttons. Cada uno de estos Context Fields tendrá un valor de Key diferente que se puede encontrar en la API de Jira.

Anote los nombres de cada Custom Field requerido, ya que deberá buscarlos en la API de Jira en el siguiente paso.

**Ejemplo de una lista de Custom Fields (los nombres de sus Custom Fields serán diferentes):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### Paso 2: encontrar los valores de Key de sus Custom Fields de Jira

Comience este proceso navegando a la URL de Field Spec de toda su instancia de Jira.

Aquí tiene un ejemplo de una URL de Field Spec:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

La API devolverá una larga cadena de JSON, que debe formatearse como texto legible (usando un editor de código, una extensión de navegador o <https://jsonformatter.org/>).

El JSON devuelto desde esta URL contendrá todos sus custom fields de Jira, la mayoría de los cuales son irrelevantes para DefectDojo y tienen valores de `"Null"`. Cada objeto de esta respuesta de la API corresponde a un campo distinto en Jira. Deberá buscar los objetos cuyo atributo `"name"` coincida con los nombres de cada Custom Field que creó en la Jira UI, y luego anotar el valor de su atributo "key".

![image](images/Using_Custom_Fields.png)

Una vez que haya encontrado el objeto correspondiente en la salida JSON, podrá determinar el valor de "key" \- en este caso, es `customfield_10050`.

Jira genera valores de key diferentes para cada Custom Field, pero estos valores de key no cambian una vez creados. Si crea otro Custom Field en el futuro, tendrá un nuevo valor de key.

**Ampliando nuestra lista de Custom Fields:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Another example of a Custom Field" \= customfield\_12345
* ...

#### Paso 3 \- encontrar los Custom Fields en un Issue de Jira

Localice un Issue en Jira que contenga los Custom Fields que registró en el Paso 2\. Copie la Issue Key del título (debería verse similar a "`EXAMPLE-123`") y navegue a la siguiente URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Esto devolverá otra cadena de JSON.

Como antes, la salida de la API contendrá muchos parámetros de objeto `customfield_##` con valores `null` \- estos son custom fields que Jira agrega de forma predeterminada, que no son relevantes para este issue. También contendrá valores `customfield_##` que coinciden con los valores de Key de Custom Field que encontró en el paso anterior. A diferencia de la salida de Field Spec, no verá nombres que identifiquen a ninguno de estos custom fields, por lo que necesitaba registrar los valores de key en el Paso 2\.

![image](images/Using_Custom_Fields_2.png)

**Ejemplo:**
Sabemos que `customfield_10050` representa el DefectDojo Custom URL Field porque lo registramos en el Paso 2\. Ahora podemos ver que `customfield_10050` contiene un valor de `"https://google.com"` en el issue `EXAMPLE-123`.

#### Paso 4 \- crear una referencia de campos JSON a partir de cada Key de Custom Field de Jira

Ahora deberá tomar el valor de cada uno de los Custom Fields de su lista y guardarlos en un objeto JSON (para usarlo como referencia). Puede ignorar cualquier Custom Field que no corresponda a su lista.

Este objeto JSON contendrá todos los valores predeterminados para los nuevos Issues de Jira. Recomendamos usar nombres que su equipo pueda reconocer fácilmente como valores 'predeterminados' que deben cambiarse: '`change-me.com`', '`Change this paragraph.`' etc.

**Ejemplo:**

Del paso 3, ahora sabemos que Jira espera una cadena de URL para "`customfield_10050`". Podemos usar esto para construir nuestro objeto JSON de ejemplo.

Supongamos que también hemos localizado un campo de texto corto relacionado con DefectDojo, que identificamos como "`customfield_67890`". Buscaríamos este campo en nuestra segunda salida de la API, veríamos el valor asociado y también haríamos referencia al valor guardado en nuestro objeto JSON de ejemplo.
​
Su objeto JSON comenzará a verse así a medida que agregue más Custom Fields.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Repita este proceso hasta que se hayan agregado a su referencia de campos JSON todos los custom fields de Jira relevantes para DefectDojo.

#### Tipos de datos y sintaxis de Jira

Algunos campos, como los campos de fecha, pueden relacionarse con varios custom fields en Jira. Si es así, deberá agregar ambos campos a su referencia de campos JSON.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Otros campos, como el campo Label, pueden registrarse como una lista de cadenas \- asegúrese de que su referencia de campos JSON use un formato que coincida con la salida de la API de Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Otros custom fields pueden contener información contextual adicional que debe eliminarse de la referencia de campos. Por ejemplo, el Custom Multichoice Field contiene un bloque adicional en la salida de la API, que deberá eliminar, ya que ese bloque almacena el valor actual del campo.

* debe eliminar el objeto adicional de este campo:

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* en su lugar, puede acortarlo de la siguiente manera y descartar la segunda parte:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Ejemplo de referencia de campos completa

Aquí tiene una referencia de campos JSON completa, con comentarios en línea que explican a qué corresponde cada custom field. Esto pretende ser un ejemplo integral. Su JSON contendrá valores de key y datos diferentes según los Custom Values que desee usar durante la creación del issue.

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### Paso 5 \- agregar los Custom Fields a un Producto de DefectDojo

Ahora puede agregar estos custom fields al Producto de DefectDojo asociado, en la página Jira Project Settings (accesible desde el menú ⚙️ Gear del Producto). Pegue la referencia de campos JSON como texto sin formato en el cuadro **Custom Fields** y guarde.

#### Paso 6 \- probar sus Custom Fields de Jira desde un nuevo Hallazgo:

Ahora, cuando cree un nuevo Hallazgo en el Producto asociado con Jira, Jira creará automáticamente todos estos Custom Fields según el bloque JSON contenido allí. Estos Custom Fields se crearán con los valores predeterminados ("change\-me\-please", etc.).

Dentro del Producto en DefectDojo, navegue a la página Findings \> Add New Finding. Asegúrese de que el Hallazgo esté tanto Activo como Verificado para garantizar que se envíe a Jira, y luego confirme del lado de Jira que los Custom Fields se crearon correctamente sin inconsistencias.
