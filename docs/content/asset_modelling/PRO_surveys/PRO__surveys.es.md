---
title: Encuestas
description: Cómo funcionan las Encuestas en DefectDojo Pro
audience: pro
weight: 2
---

En DefectDojo, una plantilla de Encuesta es un conjunto reutilizable de Preguntas que sirve para recopilar información de desarrolladores, equipos y partes interesadas tanto internas como externas. Se pueden usar para recabar información antes de que comience el trabajo, garantizar la alineación entre individuos y equipos a medida que avanza el trabajo, y permitir un análisis retrospectivo una vez que el trabajo se ha completado. 

En DefectDojo, un sistema de Encuestas consta de tres componentes:
- **Plantillas de Encuesta**, que agrupan y ordenan las Preguntas. 
- **Implementaciones de Encuesta**, que son instancias activas que recopilan respuestas.
- **Respuestas**, que son las contestaciones enviadas por los Usuarios.

Crear una plantilla de Encuesta no la pone automáticamente disponible para recibir respuestas. Para recopilar respuestas, se debe implementar una plantilla de Encuesta.

## Permisos

La sección Encuestas de la barra lateral solo es visible para los Usuarios con estado de Superusuario, y solo los Superusuarios pueden crear plantillas de Encuesta, crear Preguntas e implementar Encuestas. 

Los Usuarios sin estado de Superusuario pueden responder a las Encuestas que se comparten con ellos, pero no pueden crearlas ni gestionarlas, ni gestionar sus Preguntas asociadas.

## Acceso a Encuestas y Preguntas 

Los Usuarios con estado de Superusuario pueden acceder a Encuestas y Preguntas desde la barra lateral haciendo clic en la opción **Encuestas**. El submenú brinda acceso a **Todas las encuestas** y **Todas las preguntas**, además de la opción para crear nuevas Encuestas y Preguntas.

![imagen](images/pq_ss1.png)

### Acceso a Encuestas 

La vista de Todas las encuestas incluye una tabla con todas las plantillas de Encuesta, incluyendo su ID, nombre, descripción y estado activo. La tabla se puede filtrar mediante palabras clave y se puede reorganizar haciendo clic en el encabezado de cada columna. 

### Acceso a Preguntas 

La vista de Todas las preguntas incluye una tabla de Preguntas que se pueden agregar a una Encuesta. La tabla se puede filtrar mediante palabras clave y se puede reorganizar haciendo clic en el encabezado de cada columna. 

## Gestión de plantillas de Encuesta 

### Crear plantillas de Encuesta 

Las plantillas de Encuesta se pueden crear haciendo clic en **Nueva encuesta** en la barra lateral, o haciendo clic en el botón **Nueva encuesta** en la parte superior de la vista Todas las encuestas. 

![imagen](images/pq_ss2.png)

A la plantilla de Encuesta se le debe asignar un nombre y una descripción, y debe tener al menos una Pregunta elegida en el menú desplegable antes de crearse.

#### Agregar Preguntas a una plantilla de Encuesta existente 

Para agregar Preguntas a una plantilla de Encuesta existente, haga clic en el icono de kebab ⋮ a la izquierda de la Encuesta deseada, haga clic en **Editar encuesta**, seleccione en el menú desplegable las nuevas Preguntas que desea agregar a la Encuesta y luego haga clic en **Enviar**.

Como buena práctica, se recomienda encarecidamente evitar modificar o agregar Preguntas a una plantilla de Encuesta mientras tenga implementaciones activas. Agregar nuevas Preguntas no afectará a las Respuestas existentes, pero esas Respuestas se habrán enviado sin responder a las Preguntas recién agregadas, lo que puede dar lugar a datos incompletos.

### Crear Preguntas 

De manera similar a las plantillas de Encuesta, las Preguntas se pueden crear haciendo clic en **Nueva pregunta** en la barra lateral, o haciendo clic en el botón **Nueva pregunta** en la parte superior de la vista Todas las preguntas. 

#### Tipos de pregunta 

Al crear una nueva Pregunta, se puede dar formato como pregunta de texto o como pregunta de opción múltiple seleccionando **Pregunta de texto** o **Pregunta de opción múltiple** en la parte superior de la vista Nueva pregunta. 

![imagen](images/pq_ss3.png)

#### Orden de las preguntas 

Determine el orden de una Pregunta asignándole un número de orden. Por ejemplo, si una Pregunta tiene 1 en el campo Orden, esa Pregunta aparecerá por encima de una Pregunta con 2 en el campo Orden. 

#### Respuestas opcionales 

Tanto las preguntas de texto como las preguntas de opción múltiple se pueden marcar como **Opcional** haciendo clic en la casilla correspondiente. 

#### Permitir múltiples respuestas 

Se puede agregar un número ilimitado de posibles respuestas a una pregunta de opción múltiple. Al hacer clic en la casilla **Permitir selecciones múltiples** se permite seleccionar varias respuestas (solo disponible para preguntas de opción múltiple).

### Editar Preguntas 

Para cambiar una Pregunta, vaya a la vista Todas las preguntas, haga clic en el icono de kebab ⋮ a la izquierda de la Pregunta que desea cambiar, haga clic en Editar pregunta, realice el cambio deseado y finalícelo haciendo clic en Enviar. Las Preguntas no se pueden eliminar. 

![imagen](images/pq_ss4.png)

Es importante evitar editar Preguntas que formen parte de Cuestionarios activos o agregar Preguntas a Cuestionarios activos. Hacerlo no afectará ninguna respuesta recopilada previamente, pero puede dar lugar a datos incompletos o poco confiables. 

## Implementación de Encuestas 

Una vez que se ha creado correctamente una plantilla de Encuesta, implementar una Encuesta crea una instancia activa que acepta respuestas.

Para implementar una Encuesta, vaya a la vista Todas las encuestas, haga clic en el icono de kebab ⋮ a la izquierda de la Encuesta que desea implementar, haga clic en **Abrir encuesta**, establezca la fecha de vencimiento y haga clic en Enviar. 

Si desea implementar la misma Encuesta nuevamente, siga el mismo proceso. Todas las implementaciones aparecerán en la tabla de Instancias de encuesta abiertas dentro de la vista de la Encuesta, y se pueden distinguir por su ID, hora de creación y fecha de vencimiento. 

![imagen](images/pq_ss10.png)

Una Encuesta se cerrará en la fecha elegida, a la misma hora en que fue implementada. Por ejemplo, si implementa una Encuesta a las 8:00 a. m. del 1 de febrero de 2026 y la programa para que se cierre el 1 de marzo de 2026, la encuesta se cerrará a las 8:00 a. m. de la mañana del 1 de marzo de 2026. 

Una vez que se ha abierto una Encuesta, su fecha y hora de vencimiento no se pueden cambiar. Si se requiere un plazo diferente, se debe crear una nueva implementación.

Una vez que ha pasado la fecha de vencimiento, ya no será posible enviar respuestas a esa implementación de la Encuesta, pero la implementación seguirá apareciendo en la tabla de Instancias de encuesta abiertas de la vista de esa Encuesta. 

#### Compartir una Encuesta 

Una vez que se ha implementado una Encuesta, se puede compartir con otros Usuarios haciendo clic en el icono ↗ a la izquierda de la Encuesta dentro de la tabla de Instancias de encuesta abiertas en la vista de la plantilla de Encuesta. Esto mostrará un enlace único para esa implementación que se puede copiar y compartir con los destinatarios previstos. 

![imagen](images/pq_ss5.png)

![imagen](images/pq_ss9.png)

#### Cerrar una Encuesta 

Para cerrar una Encuesta, haga clic en la **X** roja a la izquierda de la Encuesta dentro de la tabla de Instancias de encuesta abiertas en la vista de la plantilla de Encuesta.

![imagen](images/pq_ss13.png)

Como se indica en la sección Respuestas más adelante, esto solo evitará que se envíen más respuestas. Las Respuestas enviadas anteriormente seguirán visibles en la tabla de Respuestas en la parte inferior de la vista de la plantilla de Encuesta.

## Responder Encuestas

Para responder a una Encuesta, los usuarios que no son Superusuarios deben recibir el enlace compartido directamente siguiendo las instrucciones de la sección [Compartir una Encuesta](#sharing-a-survey) mencionada anteriormente. Los Superusuarios también pueden responder usando el mismo enlace.

#### Habilitar respuestas anónimas 

De forma predeterminada, las Encuestas solo son accesibles para los Usuarios de DefectDojo. Para permitir que terceros externos respondan a las Encuestas de DefectDojo, asegúrese de que la opción **Habilitar respuestas anónimas de encuesta** esté activada en la **Configuración del sistema**, que se encuentra en **Configuración > Sistema** en la barra lateral (dentro del submenú **Configuración Pro** en las instancias que aún usan el diseño de menú anterior).

![imagen](images/pq_ss6.png)

Las respuestas externas aparecerán como anónimas porque no hay ningún ID de usuario de DefectDojo asociado con la respuesta. 

Si el alcance de una Encuesta incluye tanto Usuarios internos como externos, especifique el nombre del Compromiso en la descripción al momento de la creación, lo que permitirá filtrar los resultados.

![imagen](images/pq_ss7.png)

![imagen](images/pq_ss8.png)

## Gestión de Respuestas 

Una misma plantilla de Encuesta se puede implementar varias veces simultáneamente. Todas las respuestas a las múltiples implementaciones de la misma plantilla de Encuesta se mostrarán juntas en la tabla de Respuestas en la parte inferior de la vista de esa Encuesta. 

![imagen](images/pq_ss11.png)

Incluso después de que una implementación de Encuesta haya vencido o se haya cerrado, sus respuestas permanecen visibles en la tabla de Respuestas en la parte inferior de la vista de la Encuesta, siempre que la propia plantilla de Encuesta no se haya eliminado. Estas respuestas son permanentes y no se pueden eliminar.

Como se muestra en la imagen a continuación, actualmente no hay implementaciones de Encuesta abiertas, pero las respuestas de implementaciones anteriores todavía están presentes en la tabla de Respuestas.

![imagen](images/pq_ss12.png)

### Eliminar plantillas de Encuesta

Para eliminar una plantilla de Encuesta, vaya a la vista Todas las encuestas, haga clic en el icono de kebab ⋮ a la izquierda de la Encuesta elegida y haga clic en **Eliminar encuesta**. Esto elimina permanentemente la plantilla de Encuesta y todas las implementaciones y Respuestas asociadas. Esta acción no se puede deshacer.
