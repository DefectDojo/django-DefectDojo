---
title: Edición masiva de Hallazgos
description: Aplique cambios de metadatos, etiquetas, notas y revisión a muchos Hallazgos
  a la vez en la interfaz de DefectDojo Pro
audience: pro
weight: 3
---

En la interfaz de DefectDojo Pro, los Hallazgos se pueden editar de forma masiva desde cualquier lista de Hallazgos — la página **Todos los Hallazgos**, o la lista de Hallazgos dentro de un Test.

## Selección de Hallazgos para edición masiva

En cualquier tabla de Hallazgos, use las casillas de verificación junto a los Hallazgos para seleccionarlos. Al seleccionar uno o más Hallazgos, aparece una **barra de acciones masivas** con los siguientes controles:

* **Edición masiva** — abre un único formulario en el que se aplican cambios de metadatos, etiquetas, notas y solicitudes de revisión a todos los Hallazgos seleccionados. Es la superficie consolidada principal (detallada más abajo).
* **Aceptación de riesgo** — agrega los Hallazgos seleccionados a una **Aceptación de riesgo completa** nueva o existente.
* **Grupo de hallazgos** — agrega los Hallazgos seleccionados a un **Grupo de hallazgos** nuevo o existente, o los quita de su grupo.
* **Combinar** — combina los Hallazgos seleccionados en un único Hallazgo.
* **Eliminar** — elimina los Hallazgos seleccionados (con confirmación).

Un control se deshabilita cuando la acción no se puede aplicar a la selección actual — consulte [Disponibilidad y Hallazgos omitidos](#availability-and-skipped-findings).

## Edición masiva

El botón **Edición masiva** abre un formulario que contiene todas las acciones masivas a nivel de campo. Configure solo los campos que desea cambiar y deje el resto sin modificar, luego haga clic en **Actualizar hallazgos seleccionados** para aplicar los cambios. Las acciones disponibles son:

* **Severidad** — establece la severidad (Crítica, Alta, Media, Baja o Informativa).
* **Estado** — aplica uno de los siguientes: Activo, Verificado, Falso positivo, Fuera de alcance, Mitigado o En revisión de defecto.
* **Fecha** — establece la fecha de descubrimiento.
* **Fecha de remediación planificada** y **Versión de remediación planificada**.
* **Aceptación de riesgo simple** — Aceptar riesgo o Revertir aceptación de riesgo. Se aplica solo a los Hallazgos cuyo Producto tiene habilitada la Aceptación de riesgo simple; los demás se omiten.
* **Etiquetas** — agrega etiquetas a los Hallazgos seleccionados, o use el conmutador **Agregar / Reemplazar** para sobrescribir todo el conjunto de etiquetas de cada Hallazgo (**Agregar** añade las etiquetas; **Reemplazar** reemplaza todas las etiquetas existentes).
* **Reemplazar etiqueta específica** — intercambia una etiqueta con nombre por otra (ver más abajo).
* **Nota** — agrega una nota, con un tipo de nota opcional, a cada Hallazgo seleccionado.
* **Revisión** — solicita o borra la revisión en los Hallazgos seleccionados (ver más abajo).
* **Enviar a Jira** — pone en cola los Hallazgos seleccionados para enviarlos a Jira. Se muestra solo cuando la integración con Jira está habilitada.
* **Enviar a conector** — envía los Hallazgos seleccionados a su conector configurado. Se muestra solo cuando esa función está habilitada.

### Reemplazar etiqueta específica

**Reemplazar etiqueta específica** realiza un intercambio de etiquetas dirigido y no destructivo. Ingrese la etiqueta a reemplazar en **Etiqueta existente a reemplazar** y el reemplazo en **Nueva etiqueta**. Para cada Hallazgo seleccionado que realmente tenga la etiqueta antigua, DefectDojo elimina esa etiqueta y agrega la nueva — el resto de las etiquetas se conserva, y los Hallazgos que no tienen la etiqueta antigua quedan sin cambios.

Esto es diferente del campo **Etiquetas** descrito arriba: **Etiquetas** ya sea *agrega* etiquetas (Agregar) o *sobrescribe todo el conjunto de etiquetas* (Reemplazar), mientras que **Reemplazar etiqueta específica** cambia solo la etiqueta indicada.

### Revisión

La acción **Revisión** gestiona la revisión por pares en todos los Hallazgos seleccionados:

* **Solicitar revisión** — elija uno o más **Revisores** e ingrese una **Nota de revisión** (obligatoria). Cada Hallazgo seleccionado se establece como *En revisión* (Activo, no Verificado), se asignan los revisores elegidos, se agrega una nota de solicitud de revisión y se notifica a los revisores.
* **Anular revisión** — ingrese una **Nota de revisión** (obligatoria) para sacar a los Hallazgos seleccionados del estado *En revisión* y borrar sus revisores asignados.

Los revisores entre los que puede elegir son los usuarios con acceso de edición a los Hallazgos seleccionados.

## Aceptación de riesgo, Grupo de hallazgos, Combinar y Eliminar

Los demás botones de acción masiva abren sus propios cuadros de diálogo:

* **Aceptación de riesgo** — cree una nueva **Aceptación de riesgo completa** para regir los Hallazgos seleccionados, o agréguelos a una existente.
* **Grupo de hallazgos** — cree un nuevo **Grupo de hallazgos**, agregue los Hallazgos a un grupo existente, o quítelos de su grupo actual. Los Grupos de hallazgos solo se pueden crear dentro de un único **Test** — los Hallazgos de diferentes Tests, Compromisos o Productos no pueden compartir un grupo.
* **Combinar** — combina varios Hallazgos seleccionados (todos del mismo Activo) en uno solo.
* **Eliminar** — elimina los Hallazgos seleccionados tras confirmar en una ventana emergente.

## Disponibilidad y Hallazgos omitidos

Cada acción masiva está disponible solo cuando se puede aplicar a toda la selección:

* **Edición masiva**, las etiquetas y la revisión requieren que todos los Hallazgos seleccionados sean editables por usted.
* **Aceptación de riesgo** no está disponible si algún Hallazgo seleccionado no es editable, ya tiene el riesgo aceptado o es un duplicado.
* La creación de **Grupo de hallazgos** requiere que todos los Hallazgos sean editables, no estén agrupados y estén en el mismo Test.
* **Combinar** requiere más de un Hallazgo, todos editables y del mismo Activo.
* **Eliminar** requiere que todos los Hallazgos seleccionados sean eliminables por usted.

Cuando una acción se ejecuta pero algunos Hallazgos no se pueden actualizar — por ejemplo, no son editables por usted, ya están en revisión, o pertenecen a un Producto sin la Aceptación de riesgo simple habilitada — DefectDojo aplica el cambio al resto y muestra una advertencia **"Uno o más Hallazgos omitidos"** que explica por qué se omitió cada uno.
