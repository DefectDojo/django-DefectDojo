---
title: Etiquetar objetos
description: Use Etiquetas para crear un nuevo corte de su modelo de datos
draft: false
weight: 2
exclude_search: false
audience: opensource
---

Las Etiquetas son ideales para agrupar objetos de forma que puedan filtrarse en fragmentos más pequeños y fáciles de digerir.  Pueden usarse para indicar un estado, o para crear conjuntos personalizados de Organizaciones, Activos, Compromisos o Hallazgos en todo el modelo de datos.

En DefectDojo, las etiquetas son un elemento de primera clase y se reconocen como facilitadoras
de la organización en cada nivel del modelo de datos.

A continuación se muestra un ejemplo con un Activo con dos etiquetas y cuatro hallazgos, cada uno con una única etiqueta:

![Ejemplo de alto nivel de uso con etiquetas](images/tags-high-level-example.png)

### Formatos de etiqueta

Las etiquetas pueden formatearse de cualquiera de las siguientes maneras:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Gestión de etiquetas

### Añadir y quitar

Las etiquetas pueden gestionarse de las siguientes maneras:

1. Crear o Editar nuevos objetos

   Cuando se crea o edita un nuevo objeto a través de la interfaz o de la API, hay un campo para especificar
   las etiquetas que se establecerán en ese objeto. Este campo es un campo de selección múltiple que además
   tiene autocompletado, lo que facilita enormemente la búsqueda y adición de etiquetas existentes. Así es
   como se ve el campo en el Activo de la captura de pantalla de la sección anterior:

   ![Gestión de etiquetas en un objeto](images/tags-management-on-object.png)

2. Importar y Reimportar

    Las etiquetas también pueden aplicarse a un test determinado en el momento de la importación o
    reimportación. Este es un caso de uso muy útil al importar mediante la API con automatización, ya que
    ofrece la posibilidad de añadir detalles de la ejecución de la automatización e información de la
    herramienta que puede que no queden recogidos directamente en el objeto test o hallazgo.

    El campo tiene el mismo aspecto y se comporta exactamente igual que en cualquier otro objeto

3. Menú de Edición masiva (solo Hallazgos)

    Cuando es necesario actualizar muchos Hallazgos con el mismo conjunto de etiquetas, se puede usar el
    menú de edición masiva para aliviar la carga de trabajo.

    En el siguiente ejemplo, supongamos que quiero actualizar las etiquetas de los dos hallazgos que tienen
    la etiqueta "tag-group-alpha" para que tengan una nueva lista de etiquetas como esta ["tag-group-charlie", "tag-group-delta"].
    Primero seleccionaría las etiquetas que se van a actualizar:

    ![Seleccionar hallazgos para la actualización masiva de etiquetas](images/tags-select-findings-for-bulk-edit.png)

    Una vez seleccionado un hallazgo, aparece un nuevo botón llamado "Bulk Edit". Al hacer clic en este
    botón se despliega un menú con muchas opciones, pero por ahora nos centraremos solo en las etiquetas.
    Actualice el campo con la lista de etiquetas deseada de la siguiente manera y haga clic en enviar

    ![Aplicar cambios para la actualización masiva de etiquetas](images/tags-bulk-edit-submit.png)

    Las etiquetas de los Hallazgos seleccionados se actualizarán con lo que se haya especificado en el
    campo de etiquetas dentro del menú de edición masiva

    ![Actualización masiva de etiquetas completada](images/tags-bulk-edit-complete.png)

## Herencia de etiquetas

Cuando la Herencia de etiquetas está habilitada, las etiquetas aplicadas a un Activo determinado se aplicarán automáticamente a todos los objetos bajo los Activos en la [Jerarquía de Activos](/asset_modelling/os_hierarchy/os__asset_hierarchy/).

### Configuración

La Herencia de etiquetas puede habilitarse en los siguientes niveles de alcance:
- Alcance global
  - Todos los Activos del sistema comenzarán a aplicar etiquetas a todos los objetos hijos (Compromisos, Tests y Hallazgos)
  - Esto se configura en la Configuración del Sistema
- Alcance de Activo
  - Solo el Activo seleccionado comenzará a aplicar etiquetas a todos los objetos hijos (Compromisos, Tests y Hallazgos)
  - Esto se configura en la página de creación/edición del Activo

### Comportamientos

Cuando la Herencia de etiquetas está habilitada, las Etiquetas estándar pueden añadirse y eliminarse de los objetos de la forma habitual.
Sin embargo, las etiquetas heredadas no pueden eliminarse de un objeto hijo sin eliminarlas también del objeto padre.
Vea el siguiente ejemplo, en el que se añade una etiqueta "test_only_tag" al objeto Test y una etiqueta "engagement_only_tag" al Compromiso.

![Ejemplo de etiquetas heredadas](images/tags-inherit-exmaple.png)

Cuando se realizan actualizaciones en la lista de etiquetas de un Activo, los mismos cambios se aplican de forma asíncrona a todos los objetos dentro del Activo. La duración de esta tarea está directamente relacionada con el número de objetos contenidos dentro de un hallazgo.

**Código abierto:** Si los cambios de etiquetas no se observan en un período de tiempo razonable, consulte los registros del worker de Celery para identificar dónde pueden haber surgido los problemas.


### Filtrar por etiquetas (interfaz clásica)

Las etiquetas pueden filtrarse de muchas maneras, tanto a través de la interfaz como de la API. Por ejemplo, aquí tiene un fragmento
de los filtros de Hallazgos:

![Fragmento de los filtros de hallazgos](images/tags-finding-filter-snippet.png)

Hay diez campos relacionados con las etiquetas:

 - Etiquetas: filtra por cualquier etiqueta que esté adjunta a un Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del Hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "B"
     - El Hallazgo *no* se devolverá
       - Etiquetas del Hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "F"
 - No Etiquetas: filtra por cualquier etiqueta que *no* esté adjunta a un Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del Hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "F"
     - El Hallazgo *no* se devolverá
       - Etiquetas del Hallazgo: ["A", "B", "C"]
       - Consulta de filtro: "B"
 - El nombre de la etiqueta contiene: filtra por cualquier etiqueta que contenga parte o la totalidad de la consulta en el Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del Hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "et" (parte de "Beta")
     - El Hallazgo *no* se devolverá
       - Etiquetas del Hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "meg" (parte de "Omega")
 - No Etiquetas: filtra por cualquier etiqueta que *no* contenga parte o la totalidad de la consulta en el Hallazgo determinado
   - Ejemplos:
     - El Hallazgo se devolverá
       - Etiquetas del Hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "meg" (parte de "Omega")
     - El Hallazgo *no* se devolverá
       - Etiquetas del Hallazgo: ["Alpha", "Beta", "Charlie"]
       - Consulta de filtro: "et" (parte de "Beta")

Para los otros seis filtros de etiquetas, siguen las mismas reglas que "Etiquetas" y "No Etiquetas" descritas anteriormente,
pero en distintos niveles del modelo de datos:

 - Etiquetas (Test): filtra por cualquier etiqueta que esté adjunta al Test de un Hallazgo determinado
 - No Etiquetas (Test): filtra por cualquier etiqueta que *no* esté adjunta al Test de un Hallazgo determinado
 - Etiquetas (Compromiso): filtra por cualquier etiqueta que esté adjunta al Compromiso de un Hallazgo determinado
 - No Etiquetas (Compromiso): filtra por cualquier etiqueta que *no* esté adjunta al Compromiso de un Hallazgo determinado
 - Etiquetas (Activo): filtra por cualquier etiqueta que esté adjunta al Activo de un Hallazgo determinado
 - No Etiquetas (Activo): filtra por cualquier etiqueta que *no* esté adjunta al Activo de un Hallazgo determinado
