---
title: Aceptaciones de riesgo
description: Aprovechamiento de las Aceptaciones de riesgo en DefectDojo OS
audience: opensource
weight: 2
---

**Las Aceptaciones de riesgo** son un estado especial que se puede aplicar a los Hallazgos para documentar formalmente y poner en práctica la decisión de reconocerlos sin remediarlos de inmediato.

A diferencia de DefectDojo Pro, en DefectDojo OS las Aceptaciones de riesgo no son objetos independientes. Por el contrario, las Aceptaciones de riesgo solo están vinculadas a los Compromisos. Por ello, solo pueden contener Hallazgos del Compromiso en el que se encuentran. Si 3 instancias del mismo Hallazgo aparecen en un Test dentro de 3 Compromisos diferentes, se necesitarán 3 Aceptaciones de riesgo distintas para aceptar por completo esos Hallazgos.

### Accediendo a las Aceptaciones de riesgo 

Las Aceptaciones de riesgo incluyen Hallazgos particulares del Test o los Tests dentro de cada Compromiso. Por ello, se puede acceder a ellas desde el Compromiso que contiene el Test del que provienen esos Hallazgos. 

![image](images/OS_RA_image1.png)

Una lista completa de los Hallazgos con riesgo aceptado de forma individual se puede consultar en el submenú **Hallazgos con riesgo aceptado** de la sección **Hallazgos** en la barra lateral.

![image](images/OS_RA_image2.png)

## Creación de Aceptaciones de riesgo 

Cuando el riesgo de un Hallazgo se acepta, ocurre lo siguiente: 
- El estado del Hallazgo dejará de ser "Activo", pero seguirá siendo consultable, incluible en informes y auditable.
- El estado del Hallazgo cambiará a "Riesgo aceptado".
- El Hallazgo ya no se contará en las Métricas, pero seguirá apareciendo dentro del Test del que proviene.

Los Hallazgos pueden tener el riesgo aceptado de dos maneras: se pueden agregar manualmente a una **Aceptación de riesgo completa**, o mediante el flujo de trabajo de **Aceptación de riesgo simple**.

### Aceptaciones de riesgo completas

Una Aceptación de riesgo completa permite a los Usuarios aceptar el riesgo de varios Hallazgos dentro de un Compromiso y agruparlos en una sola unidad. Si la política organizacional exige aceptaciones de riesgo formales y documentadas, o si los Usuarios desean activar determinadas acciones al expirar una Aceptación de riesgo, las Aceptaciones de riesgo completas son la mejor opción, ya que capturan el proceso interno de toma de decisiones y pueden servir como fuente de verdad.

Cada Aceptación de riesgo completa añade contexto adicional, como:
- El nombre de la Aceptación de riesgo.
- El propietario de la Aceptación de riesgo.
- La recomendación de seguridad y la decisión sobre cómo gestionar el/los Hallazgo(s).
- Cualquier prueba asociada a la recomendación o decisión.
- Detalles sobre la recomendación o decisión.
- El Usuario que acepta el riesgo asociado a la decisión.
- La fecha de expiración.
    - Si el estado del Hallazgo volverá a "Activo" al expirar.
    - Si el SLA se reiniciará al expirar.

La expiración es exclusiva de las Aceptaciones de riesgo completas y permite que cualquier Hallazgo cuyo riesgo se haya aceptado sea reexaminado en el momento adecuado. Una vez que expira una Aceptación de riesgo completa, todos los Hallazgos se establecerán nuevamente como Activos. Si no especifica una fecha, se utilizará la fecha predeterminada de Aceptación de riesgo / Expiración predeterminada de Aceptación de riesgo definida en la página de Configuración del sistema.

Es importante señalar que, dado que las Aceptaciones de riesgo completas están restringidas a Compromisos individuales, no existe una sección única en la que ver todas las Aceptaciones de riesgo completas. Solo se pueden ver dentro del Compromiso respectivo que incluye los Hallazgos que contiene la Aceptación de riesgo completa.

#### Cómo crear una Aceptación de riesgo completa

Para crear una Aceptación de riesgo completa, vaya a la vista del Compromiso y haga clic en el símbolo **+** en el cuadro de Aceptación de riesgo. 

![image](images/OS_RA_image3.png)

A continuación, complete los detalles de la Aceptación de riesgo completa y seleccione los Hallazgos que se incluirán. **Hallazgos aceptados** contiene una lista desplegable con todos los Hallazgos disponibles para agregar a la Aceptación de riesgo. La lista de Hallazgos dentro del Compromiso aparecerá en orden descendente de severidad (los Hallazgos Críticos en la parte superior, los Hallazgos Bajos en la parte inferior). Si un Hallazgo ya ha tenido el riesgo aceptado previamente, no aparecerá en la lista desplegable. 

Una vez completada, la Aceptación de riesgo completa aparecerá dentro del cuadro de Aceptación de riesgo en la vista del Compromiso. 

También se puede crear una Aceptación de riesgo haciendo clic en el botón **Agregar aceptación de riesgo** desde el menú kebab (⋮) de un Hallazgo individual. 

![image](images/OS_RA_image7.png)

#### Interactuar con las Aceptaciones de riesgo completas

Una vez creada una Aceptación de riesgo completa, se puede abrir para ver los Hallazgos que se agregaron a ella, así como cualquier detalle ingresado al crearla (por ejemplo, la fecha, el propietario, la decisión, la expiración, etc.).

Para quitar un Hallazgo de una Aceptación de riesgo completa, haga clic en el botón **Quitar** dentro de la tabla de Hallazgos aceptados. 

![image](images/OS_RA_image8.png)

La vista de la Aceptación de riesgo completa también incluye una tabla en la parte inferior con todos los demás Hallazgos de los Tests dentro de ese Compromiso. Desde allí, puede seleccionar Hallazgos adicionales y agregarlos a esa Aceptación de riesgo completa. 

Además, existe una función de Notas que permite a los Usuarios incluir contexto adicional en la Aceptación de riesgo completa. Todas las notas públicas aparecerán en cualquier Informe que se genere para la Aceptación de riesgo completa. Las notas marcadas como **Privada** son visibles solo para su autor y para los superusuarios, y se excluyen de los informes. 

Es importante señalar que, si se elimina por completo una Aceptación de riesgo completa, el estado de los Hallazgos que contenía volverá automáticamente a "Activo."

### Aceptaciones de riesgo simples

Si bien la Aceptación de riesgo completa está habilitada de forma predeterminada, la Aceptación de riesgo simple debe habilitarse manualmente, ya sea al crear un Activo o dentro de la configuración del Activo.

![image](images/OS_RA_image4.png)

Una Aceptación de riesgo simple se puede realizar de una de dos maneras: 
1. Desde la vista de un Test, mediante el menú de Edición masiva que aparece después de seleccionar uno o más Hallazgos en la tabla de Hallazgos. 

![image](images/OS_RA_image5.png)

2. Haciendo clic en **Aceptar riesgo** desde el menú kebab (⋮) de un Hallazgo individual. 

![image](images/OS_RA_image6.png)

Una vez que un Hallazgo ha tenido el riesgo aceptado de forma simple, seguirá apareciendo en la tabla de Hallazgos del Test, pero su estado cambiará a **Inactivo, riesgo aceptado.** Una lista completa de los Hallazgos con riesgo aceptado de forma individual se puede consultar en el submenú **Hallazgos con riesgo aceptado** de la sección **Hallazgos** en la barra lateral.

Si acepta el riesgo de un Hallazgo de forma simple y más adelante desea agregarlo a una Aceptación de riesgo completa, primero deberá revertir la aceptación del riesgo antes de agregarlo a la Aceptación de riesgo completa. 

## Cuando se cambia la fecha de expiración de una Aceptación de riesgo

La fecha de expiración de una Aceptación de riesgo completa se puede editar en cualquier momento después de crearla.  La forma en que responde DefectDojo depende de si la Aceptación de riesgo está actualmente activa o si ya ha expirado.

### Editar la fecha en una Aceptación de riesgo activa

Si una Aceptación de riesgo aún no ha expirado — es decir, su fecha de expiración está en el futuro, o acaba de pasar pero el trabajo periódico de expiración aún no la ha procesado — editar la fecha es sencillo:

- La nueva fecha se guarda tal cual.
- Los Hallazgos vinculados permanecen con el riesgo aceptado.
- El objeto de Aceptación de riesgo permanece activo.

### Adelantar la fecha en una Aceptación de riesgo ya expirada

Si la Aceptación de riesgo **ya ha expirado** — es decir, el trabajo periódico de expiración ya procesó su expiración y los Hallazgos vinculados volvieron a estado Activo — editar la fecha de expiración a un valor futuro activa un flujo de trabajo de **reincorporación**:

- La Aceptación de riesgo se reincorpora y deja de estar en estado expirado.
- Todos los Hallazgos vinculados a la Aceptación de riesgo que estén actualmente Activos vuelven a tener el riesgo aceptado (se restablecen a Riesgo aceptado / Inactivo).
- Se publica un comentario en cualquier incidencia de Jira vinculada, registrando la reincorporación.

La fecha que ingrese es la fecha que se guarda.  El ajuste del sistema **Risk Acceptance Form Default Days** (predeterminado: 180) solo se usa cuando no solicitó una fecha específica — por ejemplo, al usar la acción **Reinstate**, que reincorpora la Aceptación de riesgo sin editar su fecha de expiración y, por lo tanto, la establece en hoy + N días.

### Retrasar la fecha o establecerla en una fecha que ya pasó

Mover la fecha de expiración a una fecha anterior pero aún futura no tiene ningún comportamiento especial — la Aceptación de riesgo permanece activa y se guarda la nueva fecha.

Mover la fecha a una fecha en el pasado no hace que la Aceptación de riesgo expire de inmediato desde el formulario de edición; el siguiente trabajo periódico de expiración la detectará y aplicará el comportamiento estándar de expiración.  Esto también aplica a una Aceptación de riesgo **ya expirada**: una fecha pasada sigue siendo la fecha que eligió, por lo que se guarda tal cual y la siguiente ejecución de expiración hará que la Aceptación de riesgo expire nuevamente.

### Qué expone la API

Los consumidores de la API pueden observar el estado de expiración en el objeto de Aceptación de riesgo mediante los campos `expiration_date`, `expiration_date_handled` y `expiration_date_warned`.  Una Aceptación de riesgo está "expirada" precisamente cuando `expiration_date_handled` no es nulo.  Cuando ocurre una reincorporación, tanto `expiration_date_handled` como `expiration_date_warned` se restablecen a `null`, y `expiration_date` contiene la fecha que envió — o bien hoy + N días si no se solicitó ninguna fecha.

Expirar y reincorporar también están disponibles directamente, por lo que no es necesario aplicarlos editando `expiration_date`:

- `POST /api/v2/risk_acceptance/{id}/expire/` la expira de inmediato.  Devuelve `400` si ya había expirado.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` reincorpora una que ha expirado, restableciendo el riesgo aceptado en los Hallazgos que cubre.  Devuelve `400` si no ha expirado.  Envíe `expiration_date` para elegir la duración; omítalo para usar hoy + N días.

Ambos aceptan un `reason` opcional, que se registra como una nota en la Aceptación de riesgo junto con quién realizó la acción.  Ambos requieren el mismo permiso que editar la Aceptación de riesgo.

## Prácticas recomendadas para las Aceptaciones de riesgo 

Como práctica estándar, generalmente es preferible usar exclusivamente Aceptaciones de riesgo completas o Aceptaciones de riesgo simples, en lugar de combinar ambas.

Por ejemplo, si las Aceptaciones de riesgo completas son el enfoque predeterminado, que un Hallazgo tenga el riesgo aceptado de forma simple puede generar confusión si no existe una Aceptación de riesgo completa asociada que contenga el Hallazgo afectado. De manera similar, si normalmente se acepta el riesgo de los Hallazgos de forma simple, también puede generar confusión agregar algunos Hallazgos a una Aceptación de riesgo completa cuando no existen ese tipo de objetos para la mayoría de los demás Hallazgos. 
