---
title: Edición de Hallazgos
description: Cambie el Estado de un Hallazgo o agregue más metadatos a medida que
  resuelve un problema
weight: 2
aliases:
- /es/en/working_with_findings/findings_workflows/editing_findings
---

Si desea agregar notas o actualizar el lenguaje de un Hallazgo para que sea más relevante a la situación actual, puede hacerlo a través del formulario Editar Hallazgo.

## Abrir el formulario Editar Hallazgo

Puede actualizar un Hallazgo abriendo el **Menú** del **⚙️ engranaje** en la parte superior y haciendo clic en **Editar Hallazgo.**

![image](images/Editing_Findings.png)

Esto abrirá el formulario **Editar Hallazgo**, donde podrá editar los metadatos, cambiar el Estado del Hallazgo y agregar información adicional.

![image](images/Editing_Findings_2.png)

### Formulario Editar Hallazgo: campos

* **"Test" no se puede editar:** los Hallazgos siempre deben estar asociados a un objeto Test, y no se pueden mover fuera de ese contexto. Sin embargo, el Compromiso que contiene un Test sí se puede mover a otro Producto.  
​
* **Detectado por** es la herramienta de escaneo que descubrió este Hallazgo. Tenga en cuenta que puede agregar herramientas de escaneo adicionales además de la asociada con el Test.  
​
* **Título** se crea a partir del informe de escaneo, pero puede editar este título para que sea más útil si lo necesita. Tenga en cuenta que esto puede afectar la Deduplicación, ya que la Deduplicación generalmente utiliza los títulos de los Hallazgos para identificar duplicados.  
​
* **Fecha** representa la fecha en que el escáner descubrió el Hallazgo \- no necesariamente la fecha en que el Hallazgo se importó a DefectDojo. Esta fecha se toma del informe de escaneo, pero puede actualizarla para que sea más precisa si lo necesita (por ejemplo, si trabaja con datos históricos, o si usa una herramienta de escaneo que no registra fechas de descubrimiento).  
​
* **Descripción** es la descripción de un Hallazgo proporcionada por la herramienta de escaneo. Puede agregar o quitar información de la Descripción del Hallazgo si lo desea.  
​
* **Severidad** se calcula en función de varios factores. A un nivel básico, será la Severidad informada por una herramienta, pero la Severidad de un Hallazgo puede verse afectada por cambios en el EPSS. También puede ajustar manualmente la Severidad del Hallazgo al nivel adecuado.  
​
* **Etiquetas** son etiquetas de texto genéricas que puede usar para organizar sus Hallazgos mediante Filtros \- o simplemente como una forma abreviada de identificar un Hallazgo específico.  
​
* **Activo / Verificado** son los estados principales de Hallazgo utilizados por una herramienta. Los Hallazgos Activos son Hallazgos que actualmente están activos en su red y que han sido reportados por una herramienta. Verificado significa que un miembro del equipo ha confirmado que este Hallazgo existe.  
​
* **SAST / DAST** son etiquetas utilizadas para organizar sus Hallazgos según el contexto en el que se descubrieron. Generalmente, esta etiqueta se completa según la herramienta de escaneo utilizada, pero puede ajustarla a un nivel más preciso (por ejemplo, si el Hallazgo fue encontrado tanto por una herramienta SAST como por una DAST).

### Edición de la Fecha de mitigación y Mitigado por

De forma predeterminada, los valores de **Fecha de mitigación** y **Mitigado por** de un Hallazgo **no se pueden editar**. Estos campos están ocultos tanto en el formulario Editar Hallazgo como en el diálogo Cerrar Hallazgo, y la Fecha de mitigación siempre se establece automáticamente en el momento en que se cierra el Hallazgo. Intentar establecer o poner una fecha anterior a estos valores mediante la API se rechaza por el mismo motivo.

La edición se puede activar con la configuración de servidor `DD_EDITABLE_MITIGATED_DATA`. Cuando está habilitada, los campos **Fecha de mitigación** y **Mitigado por** aparecen en el formulario Editar Hallazgo y en el diálogo Cerrar Hallazgo, y también se pueden establecer a través de la API — pero solo para usuarios con estado de **superusuario**. En otras palabras, la edición requiere *tanto* que la configuración esté habilitada *como* que el usuario que realiza la acción sea superusuario.

* **Por qué está desactivada de forma predeterminada:** permitir que una mitigación tenga una fecha anterior puede tergiversar el cumplimiento del SLA — un Hallazgo que en realidad se remedió *fuera* de su ventana de SLA podría registrarse como si se hubiera mitigado *dentro* del SLA. Habilitar la configuración es solo para el futuro; **no** cambia la Fecha de mitigación ni la antigüedad de ningún Hallazgo existente.
* **Todo permanece auditable:** cada cambio en un Hallazgo, incluidas las ediciones a la Fecha de mitigación y Mitigado por, queda registrado en el registro de historial del Hallazgo — quién hizo el cambio, cuándo, y los valores anterior y nuevo.
* **Aplicación de la configuración:** `DD_EDITABLE_MITIGATED_DATA` es una variable de entorno a nivel de servidor (consulte [Configuración](/get_started/open_source/configuration/)). Cambiarla requiere reiniciar el servicio para que surta efecto.
* **DefectDojo Cloud / Pro:** esta configuración no se puede cambiar desde la interfaz. Comuníquese con el Soporte de DefectDojo para que se habilite en su instancia.

## Edición masiva de Hallazgos

Los Hallazgos se pueden editar en masa desde una Lista de Hallazgos, que se puede encontrar en la página de Hallazgos misma, o dentro de un Test. 

### Selección de Hallazgos para la edición masiva

Al ver una tabla con varios Hallazgos, como la tabla ‘Hallazgos de \[herramienta]’ en una página de Test o la lista Todos los Hallazgos, puede usar las casillas de verificación junto a los Hallazgos para marcarlos para la Edición masiva. 

Al seleccionar uno o más Hallazgos de esta manera, se abrirá el menú (oculto) de Edición masiva, que contiene las siguientes cuatro opciones:

* **Acciones de actualización masiva**: aplica cambios de metadatos a los Hallazgos seleccionados.
* **Acciones de Aceptación de riesgo: crea una Aceptación de riesgo completa para regir los Hallazgos seleccionados, o agrega los Hallazgos a una Aceptación de riesgo completa existente**
* **Acciones de Grupo de Hallazgos: crea un Grupo de Hallazgos formado por los Hallazgos seleccionados. Tenga en cuenta que los Grupos de Hallazgos solo se pueden crear dentro de un Test individual.**
* **Eliminar: elimina los Hallazgos seleccionados. Deberá confirmar esta acción en una nueva ventana.**

![image](images/Bulk_Editing_Findings.png)

### Acciones de actualización masiva

A través del menú Acciones de actualización masiva, puede aplicar los siguientes cambios a cualquier Hallazgo que haya seleccionado:

* Actualizar la **Severidad**
* Aplicar un nuevo **Estado de Hallazgo**
* Cambiar la Fecha de descubrimiento o de Remediación planificada de los Hallazgos
* Agregar una **Aceptación de riesgo simple,** si la opción está habilitada a nivel de Producto
* Aplicar **Etiquetas** o **Notas** a todos los Hallazgos seleccionados.

![image](images/Bulk_Editing_Findings_2.png)

### Acciones de Aceptación de riesgo

Esta página le permite agregar una **Aceptación de riesgo completa** a los Hallazgos seleccionados. Puede crear una nueva **Aceptación de riesgo completa** o agregar los Hallazgos a una que ya exista.

![image](images/Bulk_Editing_Findings_3.png)

### Acciones de Grupo de Hallazgos

Esta página le permite crear un nuevo Grupo de Hallazgos a partir de los Hallazgos seleccionados, o agregarlos a un Grupo de Hallazgos existente.

Sin embargo, los Grupos de Hallazgos solo se pueden crear dentro de un **Test** individual \- los Hallazgos de diferentes Tests, Compromisos o Productos no se pueden agregar al mismo Grupo de Hallazgos.

![image](images/Bulk_Editing_Findings_4.png)

### Eliminación masiva de Hallazgos

También puede eliminar los Hallazgos seleccionados haciendo clic en el botón rojo **Eliminar**. Aparecerá una ventana emergente pidiéndole que confirme esta decisión.

![image](images/Bulk_Editing_Findings_5.png)
