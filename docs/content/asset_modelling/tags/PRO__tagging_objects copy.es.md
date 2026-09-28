---
title: Etiquetado de objetos
description: Utilice las Etiquetas para crear un nuevo corte de su modelo de datos
draft: false
weight: 2
exclude_search: false
audience: pro
aliases:
- /es/en/working_with_findings/organizing_engagements_tests/tagging_objects
---

Las Etiquetas son ideales para agrupar objetos de manera que puedan filtrarse en fragmentos más pequeños y manejables.  Pueden usarse para indicar el estado o para crear conjuntos personalizados de Tipo de producto, Productos, Compromisos o Hallazgos en todo el modelo de datos.

En DefectDojo, las etiquetas son un elemento de primera clase y se reconocen como los facilitadores
de la organización dentro de cada nivel del modelo de datos.

Aquí tiene un ejemplo con un Producto con dos etiquetas y cuatro hallazgos, cada uno con una única etiqueta:

![Ejemplo de alto nivel de uso con etiquetas](images/tags-high-level-example.png)

### Formatos de etiqueta

Las etiquetas se pueden formatear de cualquiera de las siguientes maneras:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Gestión de etiquetas (Pro UI)

### Agregar y quitar

Las etiquetas se pueden gestionar de las siguientes maneras:

1. **Creación o edición de objetos nuevos**

   Cuando se crea o edita un objeto nuevo a través de la UI o la API, hay un campo para especificar
   las etiquetas que se establecerán en un objeto determinado.

   ![etiqueta](images/tags_product.png)

2. **Al importar/reimportar Hallazgos**

  Las etiquetas están disponibles en el formulario de importación/reimportación, tanto en la UI como a través de la API.  Cuando se envía este formulario, el **Test** se etiquetará con `[tag]` y `[daily-import]`.  Si se selecciona "Aplicar etiquetas a Hallazgos" o "Aplicar etiquetas a Endpoints", esos objetos también se etiquetarán.  Las etiquetas ofrecen la oportunidad de agregar detalles de la ejecución de automatización e información de la herramienta que puede no capturarse directamente en el objeto Test o Hallazgo. 

   ![etiqueta](images/tags_importscan.png)

3. **Mediante edición masiva**

  Cuando se seleccionan muchos Hallazgos en una tabla, puede usar el menú de edición masiva para cambiar las Etiquetas asociadas de muchos Hallazgos simultáneamente.  Tenga en cuenta que esto reemplazará todas las Etiquetas a nivel de Hallazgo por las Etiquetas especificadas; las Etiquetas de Hallazgo existentes se sobrescribirán.

  ![edición masiva de hallazgos](images/Bulk_Editing_Findings.png)


## Gestión de etiquetas (Classic UI / OpenSource)

### Agregar y quitar

Las etiquetas se pueden gestionar de las siguientes maneras:

1. Creación o edición de objetos nuevos

   Cuando se crea o edita un objeto nuevo a través de la UI o la API, hay un campo para especificar
   las etiquetas que se establecerán en un objeto determinado. Este campo es un campo de selección múltiple que también cuenta con
   autocompletado para facilitar la búsqueda y adición de etiquetas existentes. Así es como se ve el campo 
   en el Producto de la captura de pantalla de la sección anterior:

   ![Gestión de etiquetas en un objeto](images/tags-management-on-object.png)

2. Importar y reimportar

    Las etiquetas también se pueden aplicar a un test determinado en el momento de la importación o reimportación. Este es un caso de uso
    muy útil al importar a través de la API con automatización, ya que ofrece la oportunidad de
    agregar detalles de la ejecución de automatización e información de la herramienta que puede no capturarse directamente en el objeto
    test o hallazgo. 

    El campo se ve y se comporta exactamente igual que en cualquier otro objeto

3. Menú de edición masiva (solo Hallazgos)

    Cuando se necesita actualizar muchos Hallazgos con el mismo conjunto de etiquetas, se puede
    usar el menú de edición masiva para aliviar la carga.

    En el siguiente ejemplo, supongamos que quiero actualizar las etiquetas de los dos hallazgos con la etiqueta "tag-group-alpha" a una nueva lista de etiquetas como esta ["tag-group-charlie", "tag-group-delta"]. 
    Primero seleccionaría las etiquetas a actualizar:

    ![Seleccionar hallazgos para la actualización de etiquetas mediante edición masiva](images/tags-select-findings-for-bulk-edit.png)

    Una vez que se selecciona un hallazgo, aparece un nuevo botón con el nombre "Bulk Edit". Al hacer clic en este botón
    aparece un menú desplegable con muchas opciones, pero por ahora nos centraremos solo en las etiquetas. Actualice el
    campo con la lista de etiquetas deseada de la siguiente manera y haga clic en enviar

    ![Aplicar cambios para la actualización de etiquetas mediante edición masiva](images/tags-bulk-edit-submit.png)

    Las etiquetas de los Hallazgos seleccionados se actualizarán con lo que se haya especificado en el campo de etiquetas
    dentro del menú de edición masiva

    ![Actualización de etiquetas mediante edición masiva completada](images/tags-bulk-edit-complete.png)

## Herencia de etiquetas

**Nota de Pro UI: aunque la herencia de etiquetas se puede configurar mediante la Pro UI, actualmente las Etiquetas heredadas solo se pueden acceder y filtrar a través de la Classic UI o la API.**

Cuando la herencia de etiquetas está habilitada, las etiquetas aplicadas a un Producto determinado se aplicarán automáticamente a todos los objetos bajo Productos en la [Jerarquía de productos](/asset_modelling/os_hierarchy/product_hierarchy/).

### Configuración

La herencia de etiquetas se puede habilitar en los siguientes niveles de alcance:
- Alcance global
  - Todos los Productos del sistema comenzarán a aplicar etiquetas a todos los objetos secundarios (Compromisos, Tests y Hallazgos)
  - Esto se establece dentro de la Configuración del sistema
- Alcance de producto
  - Solo el Producto seleccionado comenzará a aplicar etiquetas a todos los objetos secundarios (Compromisos, Tests y Hallazgos)
  - Esto se establece en la página de creación/edición del Producto

### Comportamientos

Cuando la herencia de etiquetas está habilitada, las Etiquetas estándar se pueden agregar y quitar de los objetos de la manera habitual.
Sin embargo, las etiquetas heredadas no se pueden quitar de un objeto secundario sin quitarlas del objeto principal
Vea el siguiente ejemplo de cómo agregar una etiqueta "test_only_tag" al objeto Test y una etiqueta "engagement_only_tag" al Compromiso.

![Ejemplo de etiquetas heredadas](images/tags-inherit-exmaple.png)

Cuando se realizan actualizaciones en la lista de etiquetas de un Producto, los mismos cambios se aplican de forma asíncrona a todos los objetos dentro del Producto. La duración de esta tarea está directamente relacionada con la cantidad de objetos contenidos dentro de un hallazgo.

**Open-Source:** Si los cambios de Etiquetas no se observan dentro de un período de tiempo razonable, consulte los registros del worker de celery para identificar dónde podrían haber surgido los problemas.


### Filtrado por etiquetas (Classic UI)

Las etiquetas se pueden filtrar de muchas maneras tanto a través de la UI como de la API. Por ejemplo, aquí hay un fragmento
de los filtros de Hallazgo:

![Fragmento de los filtros de hallazgo](images/tags-finding-filter-snippet.png)

Hay diez campos relacionados con las etiquetas:

 - Tags: filtra por cualquier etiqueta adjunta a un Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "B"
     - El Hallazgo *no* se devolverá
       - Etiquetas del hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "F"
 - Not Tags: filtra por cualquier etiqueta que *no* esté adjunta a un Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "F"
     - El Hallazgo *no* se devolverá
       - Etiquetas del hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "B"
 - Tag Name Contains: filtra por cualquier etiqueta que contenga parte o la totalidad de la consulta en el Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "et" (parte de "Beta")
     - El Hallazgo *no* se devolverá
       - Etiquetas del hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "meg" (parte de "Omega")
 - Not Tags: filtra por cualquier etiqueta que *no* contenga parte o la totalidad de la consulta en el Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "meg" (parte de "Omega")
     - El Hallazgo *no* se devolverá
       - Etiquetas del hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "et" (parte de "Beta")

Para los otros seis filtros de etiquetas, se aplican las mismas reglas que para "Tags" y "Not Tags" descritas arriba,
pero en diferentes niveles del modelo de datos:

 - Tags (Test): filtra por cualquier etiqueta adjunta al Test de un Hallazgo determinado
 - Not Tags (Test): filtra por cualquier etiqueta que *no* esté adjunta al Test de un Hallazgo determinado
 - Tags (Engagement): filtra por cualquier etiqueta adjunta al Compromiso de un Hallazgo determinado
 - Not Tags (Engagement): filtra por cualquier etiqueta que *no* esté adjunta al Compromiso de un Hallazgo determinado
 - Tags (Product): filtra por cualquier etiqueta adjunta al Producto de un Hallazgo determinado
 - Not Tags (Product): filtra por cualquier etiqueta que *no* esté adjunta al Producto de un Hallazgo determinado
