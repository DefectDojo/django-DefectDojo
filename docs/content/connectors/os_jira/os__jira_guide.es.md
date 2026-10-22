---
title: Jira
description: Trabaje con la integración de Jira
weight: 2
audience: opensource
aliases:
- /es/issue_tracking/jira/os__jira_guide/
---

La integración de Jira de DefectDojo se puede usar para enviar datos de Hallazgos a uno o más Espacios de Jira.  De este modo, puede integrar DefectDojo en su flujo de trabajo de desarrollo habitual.  Estos son algunos ejemplos de cómo puede funcionar esto:

* El equipo de AppSec puede enviar Hallazgos de forma selectiva a un Espacio de Jira que utilizan los desarrolladores, de modo que la corrección de los problemas se pueda priorizar adecuadamente junto con el desarrollo habitual. Los desarrolladores de este tablero no necesitan acceder a DefectDojo: pueden mantener todo su trabajo en un solo lugar.
* DefectDojo puede enviar TODOS los Hallazgos a un Espacio de Jira bidireccional que utiliza el equipo de AppSec, lo que les permite repartirse la validación de los problemas. Este tablero se mantiene sincronizado con DefectDojo y permite flujos de trabajo de corrección complejos.
* DefectDojo puede enviar Hallazgos de forma selectiva desde Productos o Compromisos independientes a Espacios de Jira independientes, para mantener cada cosa en su contexto correspondiente.

# Configuración de Jira

La configuración de Jira requiere los siguientes pasos:
1. Habilite la integración de Jira en la Configuración del sistema. Hasta que lo haga, el resto de los ajustes de Jira permanecen ocultos en toda la interfaz de DefectDojo.
2. Conecte una Instancia de Jira, ya sea con un nombre de usuario y contraseña o con un token de API. Se pueden vincular varias instancias.
3. Agregue esa Instancia de Jira a uno o más Productos o Compromisos dentro de DefectDojo.
4. Si desea usar sincronización bidireccional, cree un webhook de Jira que enviará actualizaciones a DefectDojo.

## Paso 1: Habilitar la integración de Jira en la Configuración del sistema

La integración de Jira está desactivada de forma predeterminada, y mientras lo esté, DefectDojo oculta el resto de los controles de Jira en la interfaz. Esto es lo primero que hay que configurar: ninguno de los pasos siguientes está disponible hasta que se habilite.

Mientras la integración esté deshabilitada, la entrada ⚙️ **Configuración \> JIRA** no aparece en la barra lateral, por lo que no hay dónde agregar una Instancia de Jira:

![image](images/jira-config-menu-hidden-os.png)

### Habilitar la integración

1. Vaya a ⚙️ **Configuración \> Configuración del sistema** desde la barra lateral de DefectDojo.

2. Marque **Habilitar la integración de JIRA**.

3. En cuanto se habilita la integración, se requiere un **secreto del webhook de Jira**. Haga clic en el icono 🔄 junto al campo para generar uno. Si envía el formulario sin un secreto, el formulario se rechaza con *"This field is required when enable Jira Integration is True"*:

![image](images/jira-webhook-secret-required-os.png)

El secreto forma parte de la URL del webhook a la que Jira envía las solicitudes (`https://<YOUR DOJO DOMAIN>/jira/webhook/<SECRET>`), así que trate el valor generado como una credencial. Solo necesita proporcionárselo a Jira si configura la sincronización bidireccional en el [Paso 4](#step-4-configure-bidirectional-sync-jira-webhook); generarlo ahora simplemente permite enviar el formulario.

4. Haga clic en **Enviar**. Ahora ⚙️ **Configuración \> JIRA** aparece en la barra lateral:

![image](images/jira-enable-system-settings-os.png)

### Qué controla este ajuste

Habilitar **Habilitar la integración de JIRA** es lo que hace que aparezca el resto de la interfaz de Jira. Con esta opción activada, obtiene:

* la página ⚙️ **Configuración \> JIRA**, donde se agregan y editan las Instancias de Jira
* la sección **JIRA** en los formularios Editar Producto (Asset) y Editar Compromiso, utilizada para vincular un Producto o Compromiso a un Espacio de Jira
* los controles **Enviar a Jira** en Hallazgos, Grupos de hallazgos y formularios de edición masiva, además de las columnas y filtros de Jira en las listas de Hallazgos, Compromisos y Productos

Por ejemplo, la sección **JIRA** solo aparece en la parte inferior del formulario Editar Producto una vez que se habilita la integración:

![image](images/jira-asset-settings-visible-os.png)

El ajuste también controla la integración fuera de la interfaz: mientras esté desactivado, DefectDojo no enviará Hallazgos a Jira (incluidas las solicitudes `push_to_jira` enviadas a través de la API), y los webhooks entrantes de Jira se ignoran.

El resto de los campos de Jira en la página Configuración del sistema (**Habilitar el webhook de JIRA**, **Severidad mínima de Jira**, **Etiquetas de Jira**, **Agregar el ID de vulnerabilidad como etiqueta de JIRA**) permanecen visibles esté activada o no la integración, pero no tienen ningún efecto hasta que se habilita.

## Paso 2: Conectar una Instancia de Jira

Con la integración habilitada, conectar una Instancia de Jira es el siguiente paso para configurar la integración de Jira de DefectDojo. Tenga en cuenta que Jira Service Management actualmente no es compatible.

#### Información necesaria de Jira

Atlassian utiliza métodos de autenticación distintos entre Jira Cloud y Jira Data Center.

para **Jira Cloud**, necesitará:
* una URL de Jira, p. ej. https://yourcompany.atlassian.net/
* una cuenta con permisos para crear y actualizar incidencias en su instancia de Jira. Puede ser:
    * Una combinación estándar de **nombre de usuario / contraseña**
    * Una combinación de **nombre de usuario / token de API**

para **Jira Data Center (o Server)**, necesitará:
* una URL de Jira, p. ej. https://jira.yourcompany.com
* una cuenta con permisos para crear y actualizar incidencias en su instancia de Jira. Puede ser:
    * Una combinación estándar de **nombre de usuario / contraseña**

De forma opcional, puede asignar:
* Transiciones de Jira que activen la Reapertura y el Cierre de Hallazgos
* Resoluciones de Jira que puedan aplicar los estados de Riesgo aceptado y Falso positivo a los Hallazgos (opcional)

Una sola conexión de Instancia de Jira puede gestionar varios Espacios de Jira, siempre que la cuenta o el token de Jira que utiliza DefectDojo tenga permiso para crear incidencias en el Espacio de Jira asociado.

### Agregar una Instancia de Jira

1. Asegúrese de que **Habilitar la integración de JIRA** esté marcada en Configuración del sistema, como se describe en el [Paso 1](#step-1-enable-the-jira-integration-in-system-settings). La opción ⚙️ **Configuración \> JIRA** no aparece en la barra lateral hasta que lo esté.

2. Vaya a la página ⚙️ **Configuración \> JIRA**  desde la barra lateral de DefectDojo.

![image](images/Connect_DefectDojo_to_Jira.png)

3. Verá una lista de todos los Espacios de Jira configurados actualmente que están vinculados a DefectDojo. Para agregar una nueva Configuración de proyecto, haga clic en el icono de llave inglesa y elija la opción **Agregar configuración de Jira (Express)** o **Agregar configuración de Jira**.

#### Agregar configuración de Jira (Express)

El método Express permite un modo más rápido de vincular un Espacio. Utilice el método Express si simplemente desea conectar un Espacio de Jira con rapidez y no está lidiando con un flujo de trabajo complejo de Jira.

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. Seleccione un nombre para esta Configuración de Jira que se usará en DefectDojo. Este nombre es simplemente una etiqueta para la conexión de la Instancia en DefectDojo y no necesita estar relacionado con ningún dato de Jira.

2. Seleccione la URL de la instancia de Jira de su empresa: probablemente similar a `https://**yourcompany**.atlassian.net` si utiliza una instalación de Jira Cloud.

3. Introduzca un método de autenticación adecuado en los campos de nombre de usuario y contraseña de Jira:
    * Para la autenticación estándar de Jira con **nombre de usuario y contraseña**, introduzca un nombre de usuario de Jira y la contraseña correspondiente en estos campos.
    * Para la autenticación con el **token de API de un usuario (Jira Cloud)**, introduzca el nombre de usuario junto con el **token de API** correspondiente en el campo de contraseña.

4. Seleccione el tipo de incidencia predeterminado con el que desea crear las incidencias en Jira. Las opciones son **Bug, Task, Story** y **Epic** (que son tipos de incidencia estándar de Jira), además de **Spike** y **Security**, que son tipos de incidencia personalizados. Si desea usar un tipo de incidencia diferente, comuníquese con [support@defectdojo.com](mailto:support@defectdojo.com) para obtener ayuda.

5. Seleccione su Plantilla de incidencia, que determinará la Descripción de la incidencia cuando se creen incidencias en Jira.

Los dos tipos son:
- **Jira\_full**, que incluirá toda la información del Hallazgo en las incidencias de Jira
- **Jira\_limited**, que incluirá una cantidad menor de información y metadatos del Hallazgo.

Si deja este campo en blanco, se usará de forma predeterminada **Jira\_full.**

6. Seleccione uno o más tipos de Resolución de Jira que cambiarán el estado de un Hallazgo a Aceptado (cuando se active la Resolución en la incidencia). Si no desea usar esta automatización, puede dejar el campo en blanco.

7. Seleccione uno o más tipos de Resolución de Jira que cambiarán el estado de un Hallazgo a Falso positivo (cuando se active la Resolución en la incidencia). Si no desea usar esta automatización, puede dejar el campo en blanco.

8. Decida si desea enviar Notificaciones de SLA como comentario en una incidencia de Jira.

9. Decida si desea sincronizar automáticamente los Hallazgos con Jira. Si esto está habilitado, las incidencias de Jira se mantendrán sincronizadas automáticamente con los Hallazgos relacionados. Si no está habilitado, deberá enviar manualmente cualquier cambio realizado en un Hallazgo después de que se haya creado la incidencia en Jira.

10. Seleccione su clave de incidencia. En Jira, esta es la cadena asociada a una incidencia (por ejemplo, la palabra **'EXAMPLE'** en una incidencia llamada **EXAMPLE\-123**). Si no conoce su clave de incidencia, cree una nueva incidencia en el Espacio de Jira. En la siguiente captura de pantalla, se puede ver que la clave de incidencia de nuestro Espacio de Jira es **DEF**.

![image](images/Connect_DefectDojo_to_Jira_3.png)

11. Haga clic en **Enviar.** DefectDojo buscará automáticamente las asignaciones adecuadas en Jira y las agregará a la configuración. Ahora está listo para vincular esta configuración a uno o más Productos en DefectDojo.

#### Agregar configuración de Jira (estándar)

La configuración estándar de Jira agrega algunos pasos adicionales para permitir un control más preciso sobre las asignaciones e interacciones de Jira. Esto se puede cambiar después de haber agregado una configuración de Jira, incluso si se creó mediante el método Express.

### Opciones adicionales del formulario

* **Epic Name ID:** Si tiene varios tipos de Epic en Jira, puede especificar el que desea usar buscando su ID en la especificación de campos de Jira.

Para obtener el 'Epic name id', visite `https://<YOUR JIRA URL>/rest/api/2/field` y busque Epic Name. Copie el número que aparece en `number` y péguelo aquí.

* **Reopen Transition ID:** Si desea que una Transición específica de Jira reabra una incidencia, puede especificar aquí el ID de la Transición. Si utiliza la Configuración de Jira Express, DefectDojo encontrará automáticamente una Transición adecuada y creará la asignación.

Visite `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar el ID de su instancia de Jira. Péguelo en el campo Reopen Transition ID.

* **Close Transition ID:** Si desea que una Transición específica de Jira cierre una incidencia, puede especificar aquí el ID de la Transición. Si utiliza la **Configuración de Jira Express**, DefectDojo encontrará automáticamente una Transición adecuada y creará la asignación.

Visite `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` para encontrar el ID de su instancia de Jira. Péguelo en el campo Close Transition ID.

* **Mapping Severity Fields:** Cada incidencia de Jira tiene asociada una Prioridad, que DefectDojo asignará automáticamente según la Severidad de un Hallazgo. Introduzca el nombre de cada Prioridad a la que desea asignar las Severidades Informativa, Baja, Media, Alta y Crítica.

* **Finding Text**: si desea agregar texto estandarizado adicional a cada incidencia creada, puede introducirlo aquí. No se trata de texto que se asigne a ningún campo de Jira, sino de texto adicional que se añade a la Descripción de la incidencia. Por ejemplo, "**Created by DefectDojo**".

Los comentarios (en Jira) y las Notas (en DefectDojo) se pueden mantener sincronizados. Este ajuste se puede habilitar una vez que se haya agregado la configuración de Jira a un Producto, mediante el formulario **Editar Producto**.

## Paso 3: Conectar un Producto o Compromiso a Jira

Cada Producto o Compromiso en DefectDojo tiene su propia configuración que rige cómo se convierten los Hallazgos en incidencias de JIRA. Desde aquí, puede decidir el Espacio de Jira asociado y establecer el comportamiento predeterminado para la creación de incidencias, Epics, etiquetas y otros metadatos de JIRA.

### Agregar Jira a un Producto o Compromiso

En la interfaz clásica, puede encontrar la configuración de Jira abriendo el formulario Editar Producto o Editar Compromiso. Botón "**📝 Editar**" en **Configuración**, en la página:

![image](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### Lista de ajustes de Jira

Los ajustes de Jira se encuentran cerca de la parte inferior de la página de Configuración del producto.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Instancia de Jira

Si tiene configuradas varias instancias de Jira para productos o equipos independientes dentro de su organización, puede indicar en qué Espacio de Jira desea que DefectDojo cree las incidencias. Seleccione un proyecto en el menú desplegable.

Si este menú no muestra ninguna instancia de Jira, confirme que esos proyectos estén conectados en la Configuración global de Jira de DefectDojo \- yourcompany.defectdojo.com/jira.

#### Clave del proyecto

Esta es la clave del Espacio que desea usar con DefectDojo.  La clave del Espacio de un proyecto determinado se puede encontrar en la URL, o en "Space key", dentro de la Configuración del Espacio.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Plantilla de incidencia

Aquí puede determinar cuántos metadatos de DefectDojo desea enviar a Jira. Seleccione una de estas dos opciones:

* **jira\_full**: las incidencias registrarán todos los parámetros de DefectDojo \- una Descripción completa, CVE, Severidad, etc. Es útil si necesita el contexto completo del Hallazgo en Jira (por ejemplo, si alguien que trabaja en esta incidencia no tiene acceso a DefectDojo).

Este es un ejemplo de una incidencia **jira\_full**:

![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** las incidencias solo registrarán el enlace a DefectDojo, los enlaces de Producto/Compromiso/Test, y los campos Reporter y Environment. El resto de los campos se registran únicamente en DefectDojo. Es útil si no necesita el contexto completo del Hallazgo en Jira (por ejemplo, si alguien que trabaja en esta incidencia trabaja principalmente en DefectDojo y no necesita también contar con la imagen completa en JIRA.)

Este es un ejemplo de una incidencia **jira\_limited**:

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Componente

Si gestiona su Espacio de Jira mediante Componentes, aquí puede asignar el Componente correspondiente para DefectDojo. Para asignar más de un Componente, introduzca una lista separada por comas (por ejemplo, `Security, DevSecOps`); cada valor se envía a Jira como un componente independiente.

**Campos personalizados**

Si no necesita usar Campos personalizados con las incidencias de DefectDojo, puede dejar este campo como 'null'.

Sin embargo, si la Configuración de su Espacio de Jira **exige** el uso de Campos personalizados en las incidencias nuevas, deberá codificar estas asignaciones de forma fija.

**Jira Cloud ahora le permite crear un valor predeterminado de Campo personalizado directamente desde la aplicación. [Consulte la documentación de Atlassian sobre Campos personalizados](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) para obtener más información sobre cómo configurarlo.**

Tenga en cuenta que DefectDojo no puede enviar metadatos específicos de una incidencia como Campos personalizados, solo un valor predeterminado. Esta sección solo debe configurarse si su Espacio de Jira **exige que estos Campos personalizados existan** en todas las incidencias de su Espacio.

Siga **[esta guía](#custom-fields-in-jira)** para comenzar a trabajar con Campos personalizados.

**Etiquetas de Jira**

Seleccione las etiquetas correspondientes con las que desea que se cree la incidencia en Jira, p. ej. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Persona asignada predeterminada

El nombre de la persona asignada predeterminada en Jira. Si se deja en blanco, DefectDojo seguirá el comportamiento predeterminado de su Espacio de Jira al crear incidencias.

### Opciones adicionales del formulario

#### Habilitar conexión con el Espacio de Jira

Las integraciones de Jira solo se pueden eliminar de su instancia si no se han creado incidencias relacionadas.  Si ya se han creado incidencias, no hay forma de eliminar por completo una Instancia de Jira de DefectDojo.

Sin embargo, puede deshabilitar su integración de Jira desactivándola a nivel de Producto. Esto no eliminará ni modificará ninguno de los tickets de Jira existentes creados por DefectDojo, pero deshabilitará cualquier actualización posterior.

#### Agregar el ID de vulnerabilidad como etiqueta de Jira

Esto le permite agregar automáticamente los datos del ID de vulnerabilidad como una Etiqueta de Jira. Los ID de vulnerabilidad se agregan a los Hallazgos desde herramientas de seguridad individuales \- pueden ser ID de Common Vulnerabilities and Exposures (CVE) o un formato diferente, específico de la herramienta que reporta el Hallazgo.

#### Habilitar la asignación de Compromisos a Epics (para Productos)

En DefectDojo, los Compromisos representan un conjunto de trabajo. Cada Compromiso contiene uno o más tests, que a su vez contienen uno o más Hallazgos que deben mitigarse. Los Epics en Jira funcionan de forma similar, y esta casilla le permite enviar los Compromisos a Jira como Epics.

* Un Compromiso en DefectDojo \- observe los tres hallazgos listados en la parte inferior.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Cómo el mismo Compromiso se convierte en un Epic al enviarse a JIRA \- los Hallazgos del Compromiso también se envían y quedan dentro del Compromiso como incidencias secundarias.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Enviar todas las incidencias

Si está marcada, DefectDojo enviará automáticamente a Jira, como incidencias, todos los Hallazgos que estén Activos y Verificados. Si no está marcada, todos los Hallazgos deberán enviarse a Jira manualmente.

#### Enviar notas

Si está habilitada, los comentarios de Jira se completarán en el Hallazgo asociado en DefectDojo, en Notas de la incidencia (captura de pantalla), y viceversa; las Notas de los Hallazgos se agregarán a la incidencia de Jira asociada como Comentarios.

#### Enviar notificaciones de SLA como comentarios

Si está habilitada, cualquier incidencia que incumpla las reglas del Acuerdo de nivel de servicio de DefectDojo tendrá comentarios agregados en la incidencia de Jira que lo indiquen. Estos comentarios se publicarán diariamente hasta que se resuelva la incidencia.

Los Acuerdos de nivel de servicio se pueden configurar en **Configuración \> Configuración de SLA** en DefectDojo y asignarse a cada Producto.

#### ¿Enviar notificaciones de vencimiento de la Aceptación de riesgo como comentario?

Si está habilitada, cualquier incidencia cuya Aceptación de riesgo asociada en DefectDojo venza tendrá un comentario agregado en la incidencia de Jira que lo indique. Estos comentarios se publicarán diariamente hasta que se resuelva la incidencia.

### Ajustes de Jira a nivel de Compromiso

Como resultado, distintos Compromisos dentro de un Producto pueden tener configuraciones de Jira subyacentes diferentes. De forma predeterminada, los Compromisos '**heredan la configuración de Jira del producto**', lo que significa que comparten los mismos ajustes de Jira que el Producto bajo el que están anidados.

Sin embargo, puede cambiar la **Clave del proyecto**, la **Plantilla de incidencia, los Campos personalizados, las Etiquetas de Jira y la Persona asignada predeterminada** de un Compromiso para que sean diferentes de la configuración predeterminada del Producto

Puede acceder a esta página desde la página **Editar Compromiso**: **your\-instance.defectdojo.com/engagement/\[id]/edit**.

La página Editar Compromiso se encuentra en la página del Compromiso, haciendo clic en el menú ☰ junto a la Descripción del compromiso.

![image](images/Creating_Issues_in_Jira_5.png)

## Paso 4: Configurar la sincronización bidireccional: webhook de Jira

La integración de Jira permite la sincronización bidireccional mediante un webhook. DefectDojo recibe las notificaciones de Jira en una dirección única, lo que permite recibir comentarios de Jira en los Hallazgos, o resolver Hallazgos a través de Jira, según su configuración.

### Ubicar la URL de su webhook de Jira

Su webhook de Jira se compone de su URL de DefectDojo y el **secreto del webhook de Jira** que generó en el [Paso 1](#step-1-enable-the-jira-integration-in-system-settings).  Ambos se muestran en la página ⚙️ **Configuración \> Configuración del sistema**, junto al campo **secreto del webhook de Jira** (consulte la captura de pantalla del Paso 1).

También debe marcar **Habilitar el webhook de JIRA** en la misma página antes de que DefectDojo procese las notificaciones entrantes de Jira.  Los webhooks entrantes se ignoran si esa casilla o **Habilitar la integración de JIRA** no están marcadas.

### Crear el webhook de Jira

1. Visite `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Haga clic en 'Create a Webhook'.
3. En el campo denominado 'URL', introduzca: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. El Web Hook Secret aparece junto al campo **secreto del webhook de Jira** mencionado anteriormente.
4. En 'Comments', habilite 'Created'. En Issue, habilite 'Updated'.
5. Asegúrese de que su instancia de JIRA confíe en el certificado SSL utilizado por su instancia de DefectDojo. Para JIRA Cloud, DefectDojo debe usar [un certificado SSL/TLS válido, firmado por una autoridad de certificación reconocida globalmente](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Tenga en cuenta que no es necesario crear un Secret dentro de Jira para usar este webhook. El Secret está integrado en la URL de DefectDojo, por lo que basta con agregar la URL completa al formulario del Webhook de Jira.

Las solicitudes entrantes del webhook se autentican mediante el secreto incluido en esa URL, así que trate la URL completa como una credencial y manténgala privada.

#### Probar el webhook

Una vez que tenga una o más incidencias creadas a partir de Hallazgos de DefectDojo, puede probar el webhook agregando un comentario a uno de esos Hallazgos. El comentario debería ser recibido por el webhook de Jira como una nota.

Si esto no funciona correctamente, podría deberse a un problema de firewall en su instancia de Jira que esté bloqueando el webhook.

* Las Reglas de firewall de DefectDojo incluyen una casilla para **Jira Cloud,** que debe habilitarse antes de que DefectDojo pueda recibir mensajes de webhook de Jira.

### Alternativa: usar Jira Automation (Send web request)

Algunas instancias de Jira no permiten webhooks del sistema en `/plugins/servlet/webhooks` — por ejemplo, cuando esa área de administración está restringida y solo se permiten reglas de **Jira Automation**. En ese caso, puede lograr la misma sincronización bidireccional usando la acción **Send web request** de Automation, que envía la solicitud al mismo endpoint de webhook de DefectDojo.

El endpoint de webhook de DefectDojo acepta cualquier solicitud HTTP `POST` con `Content-Type: application/json` y un secreto válido en la ruta de la URL. **No** requiere que la solicitud se origine en el mecanismo de webhooks del sistema de Jira, por lo que la acción "Send web request" de Automation funciona como una alternativa directa.

#### Requisitos previos

Se aplican los mismos requisitos previos que para el webhook del sistema:

* **Habilitar la integración de JIRA** y **Habilitar el webhook de JIRA** están ambas marcadas en la página ⚙️ **Configuración \> Configuración del sistema**.
* Se ha establecido un **secreto del webhook de Jira** no vacío en esa página. El secreto solo puede contener los caracteres `A-Z`, `a-z`, `0-9`, `_` y `-`.
* El Hallazgo (o Grupo de hallazgos) ya está vinculado a la incidencia de Jira. Si la incidencia no está vinculada a un Hallazgo de DefectDojo, la solicitud igualmente se acepta (HTTP `200`), pero no se realiza ninguna acción.

#### Cómo procesa DefectDojo la solicitud

* DefectDojo se ramifica según un campo `webhookEvent` de nivel superior. Solo se procesan `"jira:issue_updated"` y `"comment_created"`; cualquier otro valor se acepta y se ignora. Automation **no** agrega este campo por sí solo, por lo que debe incluirlo usted mismo en el cuerpo de la solicitud.
* Por ese motivo, configure el **Body** de la solicitud como **Custom data** y proporcione el JSON que aparece a continuación. Las opciones de cuerpo **Empty** y **Jira issue data** no incluyen el campo `webhookEvent` requerido, por lo que DefectDojo las ignorará.
* El endpoint siempre devuelve HTTP `200`, independientemente de si se aplicó una actualización. El éxito o el fracaso solo se pueden ver en el cuerpo de la respuesta y en los registros de DefectDojo — un `200` en el registro de auditoría de Automation no confirma, por sí solo, que la actualización llegó a un Hallazgo.

#### Regla 1 — incidencia actualizada

Cree una regla de Automation con:

* **Trigger:** *Issue transitioned* (u otro disparador que se active cuando cambien los campos que sincroniza, por ejemplo, *Field value changed* en Status).
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

Restricciones para las actualizaciones de incidencias:

* `issue.id` debe ser el **ID numérico interno de la incidencia de Jira** (`{{issue.id}}`), no la clave de la incidencia (por ejemplo, `PROJ-123`). DefectDojo relaciona la actualización con un Hallazgo mediante este ID numérico.
* Los campos `resolution` y `updated` deben estar siempre presentes. `resolution` puede ser `null`, pero si falta alguno de los dos campos, la solicitud se acepta (`200`) y no se procesa, sin ningún aviso.
* La sincronización de estado y la automitigación se rigen por `status.statusCategory.key`, cuyos valores en Jira son `new` (To Do), `indeterminate` (In Progress) y `done` (Done). Un Hallazgo solo se mitiga cuando la incidencia se cierra genuinamente, no simplemente porque haya un valor de resolución presente.

#### Regla 2 — comentario en una incidencia

Cree una segunda regla de Automation con:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — la misma URL, método, encabezado y opción de cuerpo *Custom data* que en la Regla 1, con este cuerpo:

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

* Tanto `body` como `updateAuthor` deben estar presentes.
* DefectDojo obtiene la incidencia de destino a partir de la URL de `comment.self` — concretamente del `<id>` en el segmento `.../issue/<id>/comment/...` — por lo que `{{issue.id}}` (el ID numérico) debe aparecer allí.
* **Prevención de bucles:** si el autor del comentario coincide con la cuenta de Jira que usa DefectDojo para publicar sus propios comentarios, DefectDojo omite el comentario para evitar un bucle de eco. Si desea que se incorporen *todos* los comentarios, ejecute la regla de Automation como un usuario de Jira **distinto** del configurado en la instancia de Jira de DefectDojo.

#### Nota sobre los valores inteligentes

Los valores inteligentes (smart values) que se muestran arriba (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, entre otros) son los nombres estándar de Jira Cloud, pero pueden variar entre instancias. Antes de pasar a producción, use la vista previa del payload de Automation para confirmar que cada valor inteligente se resuelve como se espera.

## Prueba de la integración con Jira

#### Prueba 1: ¿Los Hallazgos se envían correctamente a Jira?

Para comprobar que la integración con Jira funciona correctamente, puede agregar un nuevo Hallazgo en blanco al Producto asociado con Jira en DefectDojo. **Producto \> Hallazgos \> Agregar nuevo hallazgo.**

Agregue el título, la severidad y la descripción que desee y, a continuación, haga clic en "Finished". El Hallazgo debería aparecer como un Issue en Jira con todos los metadatos correspondientes.

Si los Issues de Jira no se están creando correctamente, revise sus Notificaciones para ver los códigos de error.

* Confirme que el Usuario de Jira asociado con la Configuración de Jira de DefectDojo tenga permiso para crear y actualizar issues en ese Espacio de Jira en particular.

#### Prueba 2: Los Webhooks de Jira se envían a DefectDojo

Para probar los webhooks de Jira, agregue una Nota a un Hallazgo que también exista en JIRA como un Issue (por ejemplo, el issue de prueba de la sección anterior).

Si los webhooks están configurados correctamente, debería ver la Nota en Jira como un comentario en el issue.

Si esto no funciona correctamente, podría deberse a un problema de Firewall en su instancia de Jira que esté bloqueando el Webhook.

* Las Reglas de Firewall de DefectDojo incluyen una casilla para **Jira Cloud,** que debe habilitarse antes de que DefectDojo pueda recibir mensajes de Webhook desde Jira.

## Desconexión de Jira

Las integraciones con Jira solo se pueden eliminar de su instancia si no se han creado Issues relacionados. Si se han creado Issues, no hay manera de eliminar por completo una instancia de Jira de DefectDojo.

Sin embargo, puede deshabilitar su integración con Jira desactivándola a nivel de Producto. Desde el formulario **Edit Product** puede desmarcar la opción "Enable Connection With Jira Space". Esto no eliminará ni modificará ningún ticket de Jira existente creado por DefectDojo, pero deshabilitará cualquier actualización posterior.

# Envío de Hallazgos a Jira

## Envío de Hallazgos a Jira
Un Producto con una asignación de JIRA puede enviar Hallazgos a Jira como Issues. Esto se puede gestionar de dos maneras diferentes:

* Los Hallazgos se pueden crear como Issues manualmente, Hallazgo por Hallazgo.
* Los Hallazgos se pueden enviar automáticamente si la opción '**Push All Issues**' está habilitada en un Producto. (Esto solo se aplica a los Hallazgos que son **Activos** y **Verificados**).

Además, tiene la opción de enviar Grupos de Hallazgos a Jira en lugar de Hallazgos individuales. Esto creará un único Issue que contiene muchos Hallazgos relacionados de DefectDojo.

### Envío manual de un Hallazgo

1. Desde una página de Hallazgo en DefectDojo, vaya al encabezado **JIRA**. Si el Hallazgo aún no existe en JIRA como un Issue, el encabezado de JIRA tendrá un valor de '**None**'.
​
2. Al hacer clic en la flecha junto al valor **None** se creará un nuevo issue de Jira. El estado en el que se crea el issue dependerá del flujo de trabajo de su equipo y de la configuración de Jira con DefectDojo. Si el Hallazgo no aparece, actualice la página.
​
![image](images/Creating_Issues_in_Jira.png)

3. Una vez que se crea el Issue, DefectDojo creará un enlace al issue compuesto por la clave de Jira y el ID del Issue. Este enlace también tendrá un ícono de papelera roja junto a él, que le permite eliminar el Issue de Jira.
​
![image](images/Creating_Issues_in_Jira_2.png)

4. Al hacer clic en la flecha nuevamente se enviarán a Jira todos los cambios realizados en un issue, y se actualizará el Issue de Jira en consecuencia. Si la opción '**Push All Issues**' está habilitada en el Producto asociado al Hallazgo, este proceso ocurrirá automáticamente.

### Comentarios de Jira

* Si se agrega un comentario a un Issue de Jira, ese mismo comentario se agregará al Hallazgo, en la sección **Notas**.
* Del mismo modo, si se agrega una Nota a un Hallazgo, la Nota se agregará al issue de Jira como un comentario.

### Cambios de estado en Jira

La Configuración de Jira en DefectDojo tiene entradas para dos Transiciones de Jira que activarán un cambio de estado en un Hallazgo.

* Cuando se realiza la **Transición 'Close'** en Jira, el Hallazgo asociado también se cerrará y quedará marcado como **Inactivo** y **Mitigado** en DefectDojo. DefectDojo registrará este cambio en la página del Hallazgo bajo el encabezado **Mitigated By**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Cuando se realiza la **Transición 'Reopen'** en el Issue de Jira, el Hallazgo asociado se establecerá como **Activo** en DefectDojo, y perderá su estado **Mitigado**.

### Asignación de Resoluciones de Jira a Aceptación de riesgo / Falso positivo

Además de las transiciones Close / Reopen, la Configuración de Jira incluye campos opcionales que le permiten asignar una **Resolution** de Jira a un estado de Hallazgo de DefectDojo. Estos se configuran durante el flujo de trabajo **Add Jira Configuration (Express)** (pasos 6 y 7), y se pueden editar más adelante en la Configuración de Jira:

* **Risk Accepted Finding Mapping Resolution** — cuando un issue de Jira se cierra con esta Resolution, el Hallazgo vinculado pasa a estado Riesgo aceptado en DefectDojo.
* **False Positive Finding Mapping Resolution** — cuando un issue de Jira se cierra con esta Resolution, el Hallazgo vinculado pasa a estado Falso positivo en DefectDojo.

#### Status vs Resolution: un punto común de confusión

Estos campos asignan la **Resolution** de Jira, no el **Status** de Jira. Status y Resolution son dos conceptos independientes de Jira: Status describe en qué punto del flujo de trabajo se encuentra el issue (Open, In Progress, Done), mientras que Resolution describe cómo se resolvió (Fixed, Won't Do, Duplicate, False Positive, etc.).

Un punto común de confusión es que una transición del flujo de trabajo de Jira puede cambiar el Status a "Done" *sin* establecer ninguna Resolution. Cuando eso ocurre, la asignación de resolución de DefectDojo nunca se activa; en su lugar, el Hallazgo se marca como **Mitigado** mediante el comportamiento estándar de la **Transición 'Close'** descrito anteriormente, y no como Riesgo aceptado o Falso positivo.

#### Requisito previo: una post-function "Set issue resolution" en la transición del flujo de trabajo de Jira

El motor de flujo de trabajo de Jira no completa el campo Resolution automáticamente. Cada transición que deba cerrar un issue con una Resolution específica necesita una post-function **Set issue resolution** configurada en la transición misma. Sin esa post-function, el issue pasa al nuevo Status pero la Resolution permanece en blanco, y la asignación de DefectDojo no tiene nada con qué coincidir.

Un administrador de Jira puede agregar esta post-function desde **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

## Envío de Grupos de Hallazgos como Issues de Jira

Si tiene habilitados los Grupos de Hallazgos, puede enviar un Grupo de Hallazgos a Jira como un único Issue en lugar de Issues separados para cada Hallazgo.

Sin embargo, DefectDojo no puede interactuar con el Issue de Jira asociado a un Grupo de Hallazgos ni eliminarlo. Debe eliminarse directamente desde la instancia de Jira.

### Creación y envío automático de Grupos de Hallazgos

Con Auto\-Push To Jira habilitado y una opción Group By seleccionada durante la importación:

Mientras los Grupos de Hallazgos se creen correctamente, será el Grupo de Hallazgos el que se envíe automáticamente a Jira como un Issue, y no los Hallazgos individuales.

![image](images/Creating_Issues_in_Jira_4.png)

## Campos personalizados en Jira
<span style="background: rgba(243, 122, 78,0.5">DefectDojo actualmente no admite el envío de información específica del Issue a estos Custom Fields; estos campos deberán actualizarse manualmente en Jira después de crear el issue. Cada Custom Field se creará desde DefectDojo únicamente con un valor predeterminado.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud ahora le permite crear un valor predeterminado para un campo personalizado directamente en la aplicación. [Consulte la documentación de Atlassian sobre campos personalizados](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) para obtener más información sobre cómo configurar esto.</span>

Los tipos de Issue de Jira integrados en DefectDojo (**Bug, Task, Story** y **Epic)** están configurados para funcionar 'de fábrica'. Los campos de datos en DefectDojo se asignarán automáticamente a los campos correspondientes en Jira. De forma predeterminada, DefectDojo asignará Priority, Labels y un Reporter a cualquier Issue nuevo que cree.

Algunas configuraciones de Jira requieren que se contemplen campos personalizados adicionales antes de poder crear un issue. Este proceso le permitirá contemplar estos campos personalizados en su integración de DefectDojo \-\> Jira, garantizando que los issues se creen correctamente. Estos campos personalizados se agregarán a cualquier llamada a la API enviada desde DefectDojo a una instancia de Jira vinculada.

Si aún no utiliza campos personalizados en Jira, no es necesario seguir este proceso.

1. Registre los nombres de sus campos personalizados en Jira (**Jira UI**)
2. Determine los valores Key para los nuevos campos personalizados (Jira Field Spec Endpoint)
3. Localice los datos aceptables para cada campo personalizado, utilizando los valores Key como referencia (Jira Issue Endpoint)
4. Cree un bloque JSON de Field Reference para llevar un registro de todas las Keys de los campos personalizados y los datos aceptables (Jira Issue Endpoint)
5. Guarde el bloque JSON en el Producto de DefectDojo asociado, para permitir que los campos personalizados se creen desde Jira (DefectDojo UI)
6. Pruebe su trabajo y asegúrese de que todos los datos requeridos fluyan correctamente desde Jira

#### Paso 1: registre los nombres de sus campos personalizados en Jira

Jira admite una variedad de Context Fields diferentes, incluidos Date Pickers, Custom Labels y Radio Buttons. Cada uno de estos Context Fields tendrá un valor Key diferente que se puede encontrar en la API de Jira.

Anote los nombres de cada campo personalizado requerido, ya que necesitará buscarlos en la API de Jira en el siguiente paso.

**Ejemplo de una lista de campos personalizados (los nombres de sus campos personalizados serán diferentes):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### Paso 2: cómo encontrar los valores Key de sus campos personalizados de Jira

Comience este proceso navegando a la Field Spec URL de toda su instancia de Jira.

Aquí tiene un ejemplo de una Field Spec URL:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

La API devolverá una larga cadena de JSON, que debe darse formato para convertirla en texto legible (usando un editor de código, una extensión del navegador o <https://jsonformatter.org/>).

El JSON que devuelve esta URL contendrá todos sus campos personalizados de Jira, la mayoría de los cuales son irrelevantes para DefectDojo y tienen valores `"Null"`. Cada objeto de esta respuesta de la API corresponde a un campo diferente en Jira. Deberá buscar los objetos que tengan atributos `"name"` que coincidan con los nombres de cada campo personalizado que creó en la Jira UI, y luego anotar el valor de su atributo "key".

![image](images/Using_Custom_Fields.png)

Una vez que encuentre el objeto correspondiente en la salida JSON, podrá determinar el valor "key"; en este caso, es `customfield_10050`.

Jira genera valores key diferentes para cada campo personalizado, pero estos valores key no cambian una vez creados. Si crea otro campo personalizado en el futuro, tendrá un nuevo valor key.

**Ampliando nuestra lista de campos personalizados:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Another example of a Custom Field" \= customfield\_12345
* ...

#### Paso 3: cómo encontrar los campos personalizados en un Issue de Jira

Localice un Issue en Jira que contenga los campos personalizados que registró en el Paso 2. Copie la Issue Key del título (debería verse similar a "`EXAMPLE-123`") y navegue a la siguiente URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Esto devolverá otra cadena de JSON.

Como antes, la salida de la API contendrá muchos parámetros de objeto `customfield_##` con valores `null`; estos son campos personalizados que Jira agrega de forma predeterminada, que no son relevantes para este issue. También contendrá valores `customfield_##` que coinciden con los valores Key de los campos personalizados que encontró en el paso anterior. A diferencia de la salida de Field Spec, no verá nombres que identifiquen ninguno de estos campos personalizados, por lo que necesitaba registrar los valores key en el Paso 2.

![image](images/Using_Custom_Fields_2.png)

**Ejemplo:**
Sabemos que `customfield_10050` representa el DefectDojo Custom URL Field porque lo registramos en el Paso 2. Ahora podemos ver que `customfield_10050` contiene un valor de `"https://google.com"` en el issue `EXAMPLE-123`.

#### Paso 4: cómo crear un Field Reference JSON a partir de cada Key de campo personalizado de Jira

Ahora deberá tomar el valor de cada uno de los campos personalizados de su lista y almacenarlos en un objeto JSON (para usarlo como referencia). Puede ignorar cualquier campo personalizado que no corresponda a su lista.

Este objeto JSON contendrá todos los valores predeterminados para los nuevos Issues de Jira. Recomendamos usar nombres que su equipo pueda reconocer fácilmente como valores 'predeterminados' que deben cambiarse: '`change-me.com`', '`Change this paragraph.`' etc.

**Ejemplo:**

A partir del paso 3, ahora sabemos que Jira espera una cadena de URL para "`customfield_10050`". Podemos usar esto para construir nuestro objeto JSON de ejemplo.

Supongamos que también hubiéramos localizado un campo de texto corto relacionado con DefectDojo, que identificamos como "`customfield_67890`". Buscaríamos este campo en nuestra segunda salida de la API, veríamos el valor asociado, y también haríamos referencia al valor almacenado en nuestro objeto JSON de ejemplo.
​
Su objeto JSON comenzará a verse así a medida que le agregue más campos personalizados.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Repita este proceso hasta que se hayan agregado al Field Reference JSON todos los campos personalizados de Jira relevantes para DefectDojo.

#### Tipos de datos y sintaxis de Jira

Algunos campos, como los campos de fecha, pueden estar relacionados con varios campos personalizados en Jira. Si ese es el caso, deberá agregar ambos campos a su Field Reference JSON.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Otros campos, como el campo Label, pueden registrarse como una lista de strings \- asegúrese de que su Field Reference JSON use un formato que coincida con la salida de la API de Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Otros campos personalizados pueden contener información adicional y contextual que debe eliminarse del Field Reference. Por ejemplo, el Custom Multichoice Field contiene un bloque adicional en la salida de la API, que deberá eliminar, ya que ese bloque almacena el valor actual del campo.

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
* en su lugar, puede reducirlo a lo siguiente y descartar la segunda parte:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Ejemplo de Field Reference completo

Aquí tiene un Field Reference JSON completo, con comentarios en línea que explican a qué corresponde cada campo personalizado. Esto se plantea como un ejemplo abarcador. Su JSON contendrá valores key y datos diferentes según los Custom Values que desee usar durante la creación del issue.

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

#### Paso 5: cómo agregar los campos personalizados a un Producto de DefectDojo

Ahora puede agregar estos campos personalizados al Producto de DefectDojo asociado, en la sección Custom Fields. Nuevamente,

* Vaya a Edit Product \- defectdojo.com/product/ID/edit .
* Vaya a Custom fields y pegue el Field Reference JSON como texto sin formato en el cuadro Custom Fields.
* Haga clic en 'Submit'.

#### Paso 6: cómo probar sus campos personalizados de Jira desde un nuevo Hallazgo:

Ahora, cuando cree un nuevo Hallazgo en el Producto asociado a Jira, Jira creará automáticamente todos estos campos personalizados según el bloque JSON contenido en él. Estos campos personalizados se crearán con los valores predeterminados ("change\-me\-please", etc.).

Dentro del Producto en DefectDojo, vaya a la página Hallazgos \> Agregar nuevo hallazgo. Asegúrese de que el Hallazgo esté Activo y Verificado para garantizar que se envíe a Jira, y luego confirme del lado de Jira que los campos personalizados se hayan creado correctamente sin inconsistencias.
