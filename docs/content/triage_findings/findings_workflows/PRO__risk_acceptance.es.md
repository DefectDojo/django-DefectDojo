---
title: Aceptaciones de riesgo
description: Cómo aprovechar las Aceptaciones de riesgo en DefectDojo Pro
audience: pro
weight: 2
aliases:
- /es/en/working_with_findings/findings_workflows/risk_acceptances/
---

Las **Aceptaciones de riesgo** son un estado especial que se puede aplicar a los Hallazgos mediante objetos de **Aceptación de riesgo completa** o el flujo de trabajo de **Aceptación de riesgo simple**. Las Aceptaciones de riesgo se utilizan para documentar y formalizar la decisión de reconocer un Hallazgo vulnerable sin remediarlo de inmediato.

DefectDojo Pro incluye funciones avanzadas de Aceptación de riesgo para escalar las decisiones de gestión de riesgos, entre ellas: 
- **Aceptaciones de riesgo entre Productos**: una sola Aceptación de riesgo se puede aplicar a varios productos, lo que le permite agrupar todas las instancias de Hallazgos iguales o similares en todo su portafolio de Activos dentro de un único objeto de Aceptación de riesgo. 
- **Gestión masiva de Aceptaciones de riesgo**: filtre y busque Hallazgos específicos por ID de vulnerabilidad y aplique la Aceptación de riesgo a todos los resultados simultáneamente, sin importar a qué Activo pertenezcan.

### Acceso a los Hallazgos con riesgo aceptado

La barra lateral incluye una sección de Aceptaciones de riesgo que contiene tres subsecciones en su menú desplegable: 
- **Hallazgos con riesgo aceptado**
    - Esta sección incluye una tabla con todos los Hallazgos a los que se les ha aceptado el riesgo, ya sea como parte de un objeto de Aceptación de riesgo completa o mediante el flujo de trabajo de Aceptación de riesgo simple. 
- **Todas las Aceptaciones de riesgo**
    - Esta sección incluye una tabla con todos los objetos de Aceptación de riesgo completa, ordenados cronológicamente.
- **Nueva Aceptación de riesgo**
    - Al hacer clic en esta opción de la barra lateral se inicia el flujo de trabajo para crear un objeto de Aceptación de riesgo completa.  

![Risk acceptance sidebar](images/RA_image1.png)

## Creación de Aceptaciones de riesgo

Cuando se acepta el riesgo de un Hallazgo, ocurre lo siguiente:

- El estado del Hallazgo dejará de ser “Activo”.
- El estado del Hallazgo cambiará a “Riesgo aceptado”.
- El Hallazgo ya no se contará en las Métricas, pero seguirá apareciendo dentro del Test del que se originó.

El riesgo de los Hallazgos se puede aceptar de dos maneras: agregándolos a objetos de Aceptación de riesgo completa, o mediante el flujo de trabajo de Aceptación de riesgo simple.

### Aceptaciones de riesgo completas 

Una Aceptación de riesgo completa permite a los Usuarios aceptar el riesgo de varios Hallazgos agrupándolos en un único objeto, sin importar el Activo, Compromiso o Test del que se originaron. 

Si la política organizacional exige aceptaciones de riesgo formales y documentadas, o si los Usuarios desean que las aceptaciones de riesgo caduquen automáticamente después de una fecha determinada, la Aceptación de riesgo completa es la mejor opción, ya que registra el proceso interno de toma de decisiones y puede servir como fuente de verdad.

Cada Aceptación de riesgo completa agrega contexto adicional a la Aceptación de riesgo, como:
- El nombre del objeto de Aceptación de riesgo.
- El propietario del objeto de Aceptación de riesgo.
- La recomendación de seguridad y la decisión sobre cómo gestionar el/los Hallazgo(s).
- Cualquier prueba asociada con la recomendación o decisión.
- Detalles sobre la recomendación o decisión.
- El Usuario que acepta el riesgo asociado con la decisión.
- La fecha de vencimiento.
    - Si el estado del Hallazgo volverá a “Activo” al vencer.
    - Si el SLA se reiniciará al vencer.

El vencimiento es exclusivo de los objetos de Aceptación de riesgo completa y permite reexaminar en el momento adecuado los Hallazgos a los que se les ha aceptado el riesgo. Una vez que una Aceptación de riesgo vence, los Hallazgos volverán a establecerse como Activos. 

Si no especifica una fecha, se utilizarán los días de Aceptación de riesgo predeterminada / Vencimiento de Aceptación de riesgo predeterminado de la página de Configuración del sistema.

#### Cómo completar una Aceptación de riesgo completa

Un objeto de Aceptación de riesgo completa se puede crear de tres maneras distintas:
- Usando el botón **Nueva Aceptación de riesgo** en la barra lateral.
- Usando el botón **Agregar Aceptación de riesgo** en un Hallazgo individual.
- Haciendo clic en el botón **Acciones de Aceptación de riesgo** que aparece al seleccionar uno o varios Hallazgos dentro de una tabla.

##### Nueva Aceptación de riesgo (barra lateral)

Al hacer clic en Nueva Aceptación de riesgo desde la barra lateral, se abrirá una página en la que el Usuario podrá establecer los datos y detalles asociados con el nuevo objeto de Aceptación de riesgo completa. La segunda página permitirá al Usuario filtrar y seleccionar los Hallazgos que se agregarán a ese objeto.

##### Agregar Aceptación de riesgo (individual) 

Después de abrir un Hallazgo individual, haga clic en el icono de engranaje en la esquina superior derecha de la vista y seleccione **Agregar Aceptación de riesgo**. Desde allí podrá agregar el Hallazgo a un objeto de Aceptación de riesgo completa existente, o crear uno nuevo. 

![Risk Acceptance in Finding Submenu](images/RA_image2.png)

##### Acciones de Aceptación de riesgo (tabla)

Después de seleccionar uno o varios Hallazgos dentro de una tabla, haga clic en el botón **Acciones de Aceptación de riesgo** que aparece en la parte superior y seleccione **Agregar a nuevo objeto de Aceptación de riesgo** o **Agregar a objeto de Aceptación de riesgo existente**, y complete los campos requeridos. 

Los Hallazgos solo se pueden agregar a una única Aceptación de riesgo a la vez.  Si el botón Acciones de Aceptación de riesgo no se puede pulsar, probablemente se deba a que uno de los Hallazgos seleccionados ya se agregó a un objeto de Aceptación de riesgo completa.

![Risk Acceptance Actions button](images/RA_image5.png)

##### Edición de Aceptaciones de riesgo completas

Una vez creado un objeto de Aceptación de riesgo completa, puede editar sus detalles, subir un archivo como prueba de la Aceptación de riesgo, o eliminar por completo el objeto haciendo clic en el icono de engranaje en la parte superior derecha de la vista del objeto. 

Los Hallazgos también se pueden agregar y quitar del objeto mediante el mismo menú. Alternativamente, se pueden quitar Hallazgos del objeto haciendo clic en el menú ⋮ (kebab) junto a un Hallazgo individual, haciendo clic en **Acciones de actualización masiva**, y seleccionando **Rechazar riesgo** en el menú desplegable de Estado de Aceptación de riesgo simple.

Por último, si agrega Hallazgos a un objeto de Aceptación de riesgo completa y luego elimina ese objeto, el estado de los Hallazgos incluidos volverá automáticamente a “Activo.”

### Aceptaciones de riesgo simples

Las Aceptaciones de riesgo simples no tienen metadatos ni fecha de vencimiento asociados. Son más adecuadas cuando aún se necesita hacer seguimiento de los Hallazgos con riesgo aceptado por motivos de cumplimiento, pero no existe la necesidad de contar con un objeto para rastrear o cambiar el estado de los Hallazgos afectados.

La Aceptación de riesgo simple no está habilitada de forma predeterminada, pero se puede activar en la sección de Campos opcionales de la configuración del Activo, después de hacer clic en el icono de engranaje en la parte superior derecha de la vista del Activo.

![Enabling simple risk acceptance](images/RA_image3.png)

Una vez habilitada, la Aceptación de riesgo simple se puede ejecutar desde la tabla de Hallazgos dentro de la vista de un Test.

#### Cómo completar una Aceptación de riesgo simple

Puede completar el flujo de trabajo de Aceptación de riesgo simple desde la tabla Todos los Hallazgos (accesible desde la barra lateral) o desde la tabla de Hallazgos dentro de un test específico. El flujo de trabajo es idéntico en ambos casos. 

Seleccione los Hallazgos a los que desea aceptarles el riesgo y haga clic en el botón **Acciones de actualización masiva** que aparece en la parte superior de la tabla. Desde allí, seleccione **Aceptar riesgo** en el menú desplegable de Estado de Aceptación de riesgo simple. Dado que a los Hallazgos se les aplicó una Aceptación de riesgo simple, no existe un objeto de Aceptación de riesgo completa asociado. Los Hallazgos con riesgo aceptado son accesibles desde el menú **Hallazgos con riesgo aceptado** en la barra lateral.

![Risk Acceptance Actions in Table](images/RA_image4.png)

Por el contrario, si desea rechazar el riesgo de Hallazgos a los que previamente se les había aceptado el riesgo, seleccione **Rechazar riesgo**. Si a un Hallazgo se le aplicó una Aceptación de riesgo simple, es necesario rechazar el riesgo antes de agregarlo a un objeto de Aceptación de riesgo completa.

## Permisos y visibilidad de la Aceptación de riesgo

La visibilidad de la Aceptación de riesgo **está controlada por un permiso mínimo distinto al de la visibilidad de los Hallazgos**.  Un usuario que puede ver un Hallazgo no tiene automáticamente permiso para ver una Aceptación de riesgo que contenga ese Hallazgo.

### Rol mínimo para las acciones de Aceptación de riesgo

| Action | Minimum role on the parent Asset (Product) |
| --- | --- |
| View a Risk Acceptance | Writer |
| Add or Edit a Risk Acceptance | Writer |

Para ver el cuadro completo de roles y permisos que enumera los permisos de Aceptación de riesgo junto con otras acciones a nivel de Activo, consulte [Cuadros de permisos de acciones](/admin/user_management/user_permission_chart/#role-permission-chart).

## Vencimiento y restablecimiento de una Aceptación de riesgo

Una Aceptación de riesgo que ha vencido se marca como **Vencida** junto a su fecha de vencimiento en la tabla de Aceptaciones de riesgo, para que pueda identificar de un vistazo cuáles ya no están suprimiendo sus Hallazgos.

El menú de engranaje de una Aceptación de riesgo — en la tabla o en su página de detalle — ofrece la opción que corresponda:

- **Vencer Aceptación de riesgo**, en una que sigue vigente.  Vence de inmediato en lugar de esperar a su fecha de vencimiento, y sus Hallazgos se reactivan según su configuración de **Reactivar Hallazgos vencidos** y **Reiniciar SLA vencido**.
- **Restablecer Aceptación de riesgo**, en una que ya venció.  Sus Hallazgos se aceptan nuevamente, y vence tras el número de días indicado en la configuración **Días predeterminados del formulario de Aceptación de riesgo**.

Ambas requieren el mismo permiso que editar la Aceptación de riesgo, y ambas piden confirmación antes de ejecutarse.  Para restablecerla por un período específico en lugar de la ventana predeterminada, edite la fecha de vencimiento en lugar de usar la acción Restablecer — ver más abajo.

## Cuándo se cambia la fecha de vencimiento de una Aceptación de riesgo

La fecha de vencimiento de una Aceptación de riesgo se puede editar en cualquier momento después de su creación.  La forma en que responde DefectDojo depende de si la Aceptación de riesgo está actualmente activa o ya ha vencido.

### Edición de la fecha en una Aceptación de riesgo activa

Si una Aceptación de riesgo aún no ha vencido — su fecha de vencimiento está en el futuro, o acaba de pasar pero el trabajo periódico de vencimiento aún no la ha procesado —, editar la fecha es sencillo:

- La nueva fecha se guarda tal cual.  Si el usuario eligió `2027-01-15`, la Aceptación de riesgo almacena `2027-01-15`.
- Los Hallazgos vinculados permanecen con el riesgo aceptado.
- El objeto de Aceptación de riesgo permanece activo.

### Adelantar la fecha en una Aceptación de riesgo ya vencida

Si la Aceptación de riesgo **ya venció** — es decir, el trabajo periódico ya procesó su vencimiento, los Hallazgos vinculados volvieron a Activo según la configuración de vencimiento de la Aceptación de riesgo, y la Aceptación de riesgo se encuentra en estado vencido —, editar la fecha de vencimiento a un valor futuro activa un flujo de trabajo de **restablecimiento**:

- La Aceptación de riesgo se restablece y deja de estar en estado vencido.
- Todo Hallazgo que estaba vinculado a la Aceptación de riesgo y que actualmente está Activo se vuelve a aceptar (se establece nuevamente como Riesgo aceptado / Inactivo).
- Los estados de Endpoint de esos Hallazgos se actualizan para reflejar la nueva aceptación.
- Se publica un comentario en los problemas de Jira vinculados registrando el restablecimiento.

La fecha que ingrese es la que se guarda.  La configuración del sistema **Días predeterminados del formulario de Aceptación de riesgo** (predeterminado: 180) solo se utiliza cuando no solicitó una fecha en particular — por ejemplo cuando usa la acción **Restablecer**, que restablece la Aceptación de riesgo sin editar su fecha de vencimiento y, por lo tanto, la establece en hoy + N días.

### Retroceder la fecha o establecerla en una fecha ya pasada

Retroceder la fecha de vencimiento a una fecha anterior pero aún futura no tiene ningún comportamiento especial — la Aceptación de riesgo permanece activa y se guarda la nueva fecha.

Establecer la fecha en una fecha pasada no hace que la Aceptación de riesgo venza de inmediato desde el formulario de edición; el siguiente trabajo periódico de vencimiento la detectará y aplicará el comportamiento estándar de vencimiento (los Hallazgos se reactivan según la configuración **Reactivar Hallazgos vencidos** de la Aceptación de riesgo, y se aplica el reinicio del SLA si está activada **Reiniciar SLA vencido**).

### Qué expone la API

Los consumidores de la API pueden observar el estado de vencimiento del objeto de Aceptación de riesgo mediante los campos `expiration_date`, `expiration_date_handled` y `expiration_date_warned`:

- `expiration_date` es la fecha configurada.
- `expiration_date_handled` es `null` mientras la Aceptación de riesgo está activa, y se establece con una marca de tiempo cuando el trabajo periódico ha procesado el vencimiento.  Una Aceptación de riesgo está "vencida" precisamente cuando `expiration_date_handled` no es nulo.
- `expiration_date_warned` se establece cuando el sistema ha enviado la notificación de advertencia de vencimiento.

Cuando ocurre un restablecimiento, tanto `expiration_date_handled` como `expiration_date_warned` vuelven a `null`, y `expiration_date` contiene la fecha que envió — o bien hoy + N días cuando el restablecimiento se activó sin una nueva fecha.  Las herramientas que monitorean cambios de estado en las Aceptaciones de riesgo pueden usar el campo `expiration_date_handled` como el indicador canónico de si esta Aceptación de riesgo está actualmente vencida.

El vencimiento y el restablecimiento también están disponibles directamente, por lo que no es necesario controlarlos editando `expiration_date`:

- `POST /api/v2/risk_acceptance/{id}/expire/` la vence de inmediato.  Devuelve `400` si ya había vencido.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` restablece una que venció, volviendo a aceptar los Hallazgos que cubre.  Devuelve `400` si no ha vencido.  Envíe `expiration_date` para elegir la duración; omítalo para usar hoy + N días.

Ambos aceptan un `reason` opcional, que se registra como nota en la Aceptación de riesgo junto con quién realizó la acción.  Ambos requieren el mismo permiso que editar la Aceptación de riesgo.

## Prácticas recomendadas para la Aceptación de riesgo 

Si bien es posible afectar Hallazgos dentro de objetos de Aceptación de riesgo completa mediante los flujos de trabajo de Aceptación de riesgo simple (y viceversa), en general es preferible optar exclusivamente por uno de los dos procesos en lugar de tener ambos habilitados a la vez. 

Por ejemplo, si los objetos de Aceptación de riesgo completa son el enfoque predeterminado, que a un Hallazgo se le aplique una Aceptación de riesgo simple puede generar confusión si no existe un objeto asociado que contenga ese Hallazgo. De manera similar, si a los Hallazgos normalmente se les aplica una Aceptación de riesgo simple, puede generar una confusión parecida agregar algunos Hallazgos a un objeto de Aceptación de riesgo completa cuando no existen tales objetos para la mayoría de los demás Hallazgos.
