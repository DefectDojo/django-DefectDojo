---
title: Cuestionarios
description: Comprender los Cuestionarios en DefectDojo OS
audience: opensource
weight: 2
---

En DefectDojo, un Cuestionario es un conjunto reutilizable de preguntas que recopila información de desarrolladores, equipos y partes interesadas tanto internas como externas. Se pueden utilizar para recopilar información antes de que comience el trabajo, garantizar la alineación entre personas y equipos a medida que avanza el trabajo, y permitir un análisis retrospectivo una vez finalizado el trabajo.

## Plantillas de Cuestionario

Una plantilla de Cuestionario define la estructura y el contenido del Cuestionario, incluyendo su nombre, descripción y las Preguntas asociadas. Crear una plantilla de Cuestionario no la hace disponible automáticamente para recibir respuestas. Para recopilar respuestas, una plantilla de Cuestionario debe implementarse como un **Cuestionario General** o como un **Cuestionario Vinculado**.

### Cuestionarios Generales y Vinculados

Los Cuestionarios Generales y Vinculados difieren en varios aspectos, incluyendo cómo se distribuyen, quién puede responderlos y dónde se almacenan las respuestas.

| Cuestionarios Generales | Cuestionarios Vinculados |
|---|---|
| Requieren publicación | No requieren publicación |
| Requieren una fecha de vencimiento | Permanecen activos si el Compromiso sigue activo |
| Permiten respuestas anónimas | No permiten respuestas anónimas |
| Se pueden compartir interna y externamente | Solo se pueden compartir internamente |
| No permiten cambiar las respuestas | Permiten cambiar las respuestas |
| Las respuestas solo son visibles al vencer | Las respuestas son visibles de inmediato |
| Las respuestas son visibles en "Todos los Cuestionarios" | Las respuestas son visibles dentro del Compromiso |
| Se pueden convertir en un Compromiso | Ya están vinculados a un Compromiso |

#### Ciclo de vida de implementación del Cuestionario

Las plantillas de Cuestionario siguen ciclos de vida diferentes según el tipo de implementación:

**Cuestionarios Generales**
Plantilla → Publicado → Aceptar respuestas → Vencer → Conversión opcional a Compromiso

**Cuestionarios Vinculados**
Plantilla → Vinculado a un Compromiso → Aceptar respuestas → Permanece activo mientras el Compromiso esté activo

#### Separación de respuestas

Una misma plantilla de Cuestionario se puede implementar varias veces simultáneamente, tanto como Cuestionario General como Cuestionario Vinculado. Cada implementación crea su propio conjunto independiente de respuestas.

Si la misma plantilla de Cuestionario se implementa como Cuestionario General y también se vincula a un Compromiso, las respuestas enviadas a través de cada implementación se almacenan de forma independiente y no se combinan. Esto permite reutilizar la misma plantilla de Cuestionario en distintos contextos, manteniendo separados los conjuntos de respuestas.

## Acceder a Cuestionarios y Preguntas

Se puede acceder a los Cuestionarios y las Preguntas desde la barra lateral haciendo clic en la opción **Cuestionarios**. El submenú brinda acceso a **Todos los Cuestionarios** y **Todas las Preguntas**.

![imagen](images/q_ss1.png)

Cabe destacar que el acceso a las vistas Todos los Cuestionarios y Todas las Preguntas está restringido a Usuarios con estado de Superusuario. Solo los Superusuarios pueden crear plantillas de Cuestionario, crear Preguntas e implementar Cuestionarios. Los Usuarios sin estado de Superusuario aún pueden responder a los Cuestionarios Generales que se compartan con ellos, así como responder a los Cuestionarios Vinculados de los Compromisos a los que tengan acceso, pero no pueden crearlos ni gestionarlos.

### Cuestionarios

La vista de Todos los Cuestionarios incluye dos tablas:
- **Cuestionarios**
    - Esta sección incluye todas las plantillas de Cuestionario existentes.
- **Cuestionarios Generales**
    - Esta sección incluye todos los Cuestionarios Generales que actualmente están abiertos para recibir respuestas.

Ambas secciones se pueden filtrar por nombre, descripción o estado activo.

### Preguntas

La vista de Todas las Preguntas incluye una tabla de Preguntas que actualmente se pueden agregar a un Cuestionario. También se puede filtrar por el estado opcional de cada Pregunta, su contenido o el tipo de pregunta (por ejemplo, pregunta de texto o pregunta de opción múltiple).

## Gestionar Plantillas de Cuestionario

### Crear Cuestionarios

Se pueden crear nuevos Cuestionarios utilizando el botón Crear Cuestionario en la vista Todos los Cuestionarios.

![imagen](images/q_ss2.png)

Después de incluir un nombre y una descripción, el Cuestionario se puede crear sin Preguntas (que se pueden agregar más adelante) o se pueden agregar Preguntas de inmediato.

#### Agregar Preguntas de inmediato a un nuevo Cuestionario

Si se van a agregar Preguntas de inmediato, seleccione todas las Preguntas correspondientes en el menú desplegable que aparece. También puede crear una nueva Pregunta para agregarla al Cuestionario haciendo clic en el signo + a la derecha del menú desplegable.

![imagen](images/q_ss12.png)

Una vez seleccionadas todas las Preguntas correspondientes, haga clic en **Actualizar Preguntas del Cuestionario** para agregar todas las Preguntas seleccionadas al Cuestionario.

#### Agregar Preguntas a un Cuestionario preexistente

Para agregar Preguntas a un Cuestionario preexistente, haga clic en el nombre del Cuestionario en la tabla de Cuestionarios, haga clic en **Editar Preguntas**, seleccione las nuevas Preguntas que desee agregar al Cuestionario en el menú desplegable y, a continuación, haga clic en **Actualizar Preguntas del Cuestionario**.

### Crear Preguntas

Se pueden crear nuevas Preguntas utilizando el botón **Crear Pregunta** en la vista Todas las Preguntas.

![imagen](images/q_ss3.png)

Además, las Preguntas también se pueden crear al decidir qué Preguntas agregar a un Cuestionario, haciendo clic en el signo + a la derecha del menú desplegable.

#### Tipos de Pregunta

Al crear una nueva Pregunta, se puede dar formato como pregunta basada en texto o como pregunta de opción múltiple, seleccionando **Texto** o **Opción** en el menú desplegable.

#### Permitir múltiples respuestas y respuestas opcionales

El número máximo de respuestas permitidas en una pregunta de opción múltiple es seis. Al hacer clic en la casilla **Multichoice** se permite seleccionar varias respuestas (solo disponible para preguntas de opción múltiple). Las Preguntas también se pueden marcar como **Opcionales** haciendo clic en la casilla correspondiente.

Consulte la sección [Editar Preguntas](#editing-questions) para saber cómo agregar respuestas adicionales a una pregunta de opción múltiple.

#### Orden de las Preguntas

Determine el orden de una Pregunta asignándole un número de orden. Por ejemplo, si una Pregunta tiene el valor 1 en el campo Orden, esa Pregunta aparecerá por encima de una Pregunta con el valor 2 en el campo Orden.

![imagen](images/q_ss13.png)

### Editar Preguntas

Una vez creada una Pregunta, se puede editar accediendo al submenú Todas las Preguntas y haciendo clic en la Pregunta que se desea modificar. Las Preguntas no se pueden eliminar.

Es importante evitar editar Preguntas que formen parte de Cuestionarios activos. Si se modifica cualquier parte de una Pregunta (por ejemplo, el orden, el estado opcional, la corrección de un error tipográfico, la adición de una posible respuesta, etc.) y esa Pregunta formaba parte de un Cuestionario activo que ya había recibido respuestas, todas las respuestas enviadas previamente quedarán invalidadas y deberán volver a enviarse.

#### Editar Preguntas de texto

Después de la creación, los únicos cambios que se pueden realizar en las Preguntas basadas en texto son el orden, el estado opcional y la redacción de la pregunta.

#### Editar Preguntas de opción múltiple

Si bien el número predeterminado de posibles respuestas para una pregunta de opción múltiple es seis, esto se puede aumentar después de haber creado el Cuestionario. Para hacerlo, haga clic en la Pregunta en la vista Todas las Preguntas, haga clic en el signo **+** a la derecha del menú desplegable de Opciones, agregue la nueva respuesta y haga clic en **Enviar**.

![imagen](images/q_ss16.png)

![imagen](images/q_ss17.png)

La opción recién creada no se agregará automáticamente al Cuestionario. Para agregarla, haga clic en el menú desplegable **Opciones** y seleccione la opción recién agregada. Aparecerá una marca de verificación junto a ella indicando que ahora está incluida como una posible respuesta en el Cuestionario.

![imagen](images/q_ss18.png)

## Implementar Cuestionarios

Una vez que se ha creado correctamente una plantilla de Cuestionario, se puede implementar para aceptar respuestas. El proceso de implementación varía ligeramente según el tipo de Cuestionario.

### Implementación de un Cuestionario General

Para implementar un Cuestionario General:
1. Vaya a la vista Todos los Cuestionarios.
2. Haga clic en el **+** en el lado derecho de la tabla de Cuestionarios Generales.
3. Seleccione el Cuestionario que desea implementar.
4. Establezca la fecha de vencimiento.
5. Haga clic en **Agregar Cuestionario**.

#### Compartir un Cuestionario General

Una vez implementado, un Cuestionario General se puede compartir haciendo clic en **Compartir Cuestionario** desde la columna Acciones de la tabla de Cuestionarios Generales. Esto generará un enlace que podrá compartir con los destinatarios deseados, además de permitirle confirmar que el Cuestionario tiene el formato previsto antes de hacerlo.

![imagen](images/q_ss14.png)

Tenga en cuenta lo siguiente:
- Las respuestas a un Cuestionario General no se podrán visualizar hasta que el Cuestionario haya vencido.
- No es posible cambiar la fecha de vencimiento una vez que el Cuestionario ha sido publicado.
- La hora predeterminada en que un Cuestionario vencerá es la medianoche (por ejemplo, un Cuestionario con vencimiento el 31 de diciembre de 2026 solo será visible hasta las 23:59:59 de esa fecha).
- No es posible establecer una hora de vencimiento personalizada.

Consulte [Habilitar Respuestas Anónimas](#enabling-anonymous-responses) a continuación para permitir respuestas de Usuarios externos.

### Implementación de un Cuestionario Vinculado

Para implementar un Cuestionario Vinculado:
1. Vaya al Compromiso que se vinculará al Cuestionario.
2. Haga clic en la flecha hacia abajo de la tabla **Funciones Adicionales**.
3. Haga clic en el **+** en el lado derecho de la subtabla de Cuestionarios.
4. Seleccione el Cuestionario que se vinculará en el menú desplegable.
5. Haga clic en **Agregar Cuestionario** o **Agregar Cuestionario y Responder**.

El Cuestionario Vinculado quedará ahora activo para todos los Usuarios con acceso al Compromiso.

#### Compartir un Cuestionario Vinculado

Para compartir el Cuestionario Vinculado directamente con Usuarios internos de DefectDojo, haga clic en el menú de tres puntos (⋮) y seleccione **Compartir Cuestionario** en el menú desplegable. Aparecerá un enlace que se puede copiar y reenviar al destinatario deseado.

![imagen](images/q_ss10.png)

Como se mencionó, los Cuestionarios Vinculados solo se pueden compartir con Usuarios de DefectDojo.

## Responder Cuestionarios

El flujo de respuesta difiere ligeramente según si el Cuestionario es General o Vinculado.

### Responder a un Cuestionario General

Para responder a un Cuestionario General, los usuarios que no sean Superusuarios deben recibir el enlace directamente de un Superusuario, como se describe [aquí](#sharing-a-general-questionnaire).

#### Habilitar Respuestas Anónimas

De forma predeterminada, los Cuestionarios Generales solo son accesibles para los Usuarios de DefectDojo. Para permitir que partes externas respondan a los Cuestionarios de DefectDojo, asegúrese de que la opción **Allow Anonymous Survey Responses** esté activada en la Configuración del Sistema, que se encuentra dentro de la sección **Configuraciones** de la barra lateral.

![imagen](images/q_ss4.png)

![imagen](images/q_ss5.png)

Las respuestas externas aparecerán como anónimas porque no hay un ID de usuario de DefectDojo asociado a la respuesta.

Si el alcance de un Cuestionario incluye tanto Usuarios internos como externos, cree un Cuestionario General y especifique el nombre del Compromiso en la descripción al momento de crearlo, lo que permitirá filtrar los resultados.

![imagen](images/q_ss8.png)

![imagen](images/q_ss9.png)

### Responder a Cuestionarios Vinculados

Para responder a un Cuestionario Vinculado:
1. Vaya a la vista del Compromiso.
2. Expanda la tabla Funciones Adicionales.
3. Expanda la subtabla de Cuestionarios.
4. Haga clic en el menú de tres puntos (⋮) del Cuestionario Vinculado.
5. Haga clic en **Responder Cuestionario**.

![imagen](images/q_ss15.png)

Los Cuestionarios Vinculados no permiten respuestas externas/anónimas, ya que se requiere acceso a DefectDojo para acceder al Compromiso.

## Respuestas

Como se mencionó, cada implementación de una plantilla de Cuestionario crea su propio contenedor de respuestas. Vincular la misma plantilla de Cuestionario a varios Compromisos genera conjuntos de respuestas independientes, y publicar un Cuestionario General no afecta los conjuntos de respuestas de los Cuestionarios Vinculados.

### Respuestas de Cuestionario General

Una vez que ha vencido un Cuestionario General:
- Ya no será posible enviar respuestas adicionales.
- Todas las respuestas previas se guardarán y se podrán visualizar.
- El Cuestionario aparecerá listado como un Cuestionario de Compromiso Respondido No Asignado en el panel de DefectDojo.

Hay tres acciones que se pueden realizar cuando se ha cerrado la ventana de respuesta de un Cuestionario: **Ver Respuestas**, **Crear Compromiso** y **Asignar Usuario**.

#### Ver Respuestas del Cuestionario

Al seleccionar **Ver Respuestas** se mostrarán todas las respuestas del Cuestionario.

#### Crear un Compromiso a partir de un Cuestionario

Al vencer, un Cuestionario General se puede conectar a un Activo mediante un Compromiso seleccionando la acción **Crear Compromiso**. Seleccione un Activo en la lista desplegable que aparece y haga clic en **Crear Compromiso**. Luego se puede crear un nuevo Compromiso y asignarle detalles específicos similares a los de otros Compromisos en DefectDojo, como Descripción, Versión, Estado, Etiquetas, etc.

![imagen](images/q_ss6.png)

![imagen](images/q_ss7.png)

#### Asignar Usuario

La acción Asignar Usuario solicitará que se seleccione un Usuario del menú desplegable de Usuarios disponibles. Seleccione un Usuario del menú desplegable y haga clic en **Asignar Cuestionario**, lo que lo convertirá en el propietario de ese Cuestionario.

### Respuestas de Cuestionario Vinculado

Los Cuestionarios Vinculados permanecen disponibles mientras el Compromiso asociado esté activo. Por lo tanto, las respuestas se pueden visualizar en cualquier momento.

El menú de tres puntos (⋮) de un Cuestionario Vinculado incluye varias funciones para gestionar el Cuestionario y sus respuestas:
- **Responder Cuestionario**: Esta opción aparecerá si un Usuario aún no ha respondido al Cuestionario Vinculado. Una vez respondido, aparecerán Ver Respuestas y Editar Respuestas.
- **Ver Respuestas**: Permite a los Usuarios ver todas las respuestas del Cuestionario hasta la fecha.
- **Editar Respuestas**: Permite a los Usuarios individuales editar sus respuestas previas.
- **Asignar Usuario**: Asigna el cuestionario a un Usuario.
- **Vincular a un Compromiso diferente**: Abre un menú desplegable de otros Compromisos a los que asignar el Cuestionario.
- **Compartir Cuestionario**: Genera un enlace para compartir el Cuestionario con Usuarios internos.
- **Eliminar Cuestionario**: Desvinculará el Cuestionario del Compromiso y eliminará cualquier respuesta recopilada previamente.

## Eliminar Cuestionarios

Eliminar Cuestionarios Generales y Vinculados tiene efectos posteriores distintos según el resultado deseado de la eliminación.

### Eliminar Cuestionarios Generales

Eliminar un Cuestionario General desde la tabla de Cuestionarios Generales en la sección Todos los Cuestionarios eliminará todas las respuestas que se hayan recopilado a partir de esa implementación antes de la eliminación. Los Cuestionarios Vinculados que hayan utilizado la misma plantilla de Cuestionario no se eliminarán.

### Eliminar Cuestionarios Vinculados

Eliminar un Cuestionario Vinculado desvinculará el Cuestionario del Compromiso. Se perderán todas las respuestas que se hayan recopilado dentro del Compromiso antes de la eliminación. Los Cuestionarios Generales que se hayan implementado previamente utilizando la misma plantilla de Cuestionario no se verán afectados.

### Eliminar Plantillas de Cuestionario

Para eliminar completamente una plantilla de Cuestionario, selecciónela en la tabla de Cuestionarios en la vista Todos los Cuestionarios y haga clic en **Eliminar Cuestionario**. Esto eliminará permanentemente la plantilla de Cuestionario y todas las respuestas asociadas de todas las implementaciones. Esta acción no se puede deshacer.
