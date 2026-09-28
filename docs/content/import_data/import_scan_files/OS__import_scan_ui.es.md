---
title: Formulario Import Scan
description: ''
weight: 1
audience: opensource
---

Una vez que tenga configurada su Jerarquía de Productos con al menos un Tipo de Producto, un Producto, un Test y un Compromiso, puede importar un archivo de análisis a DefectDojo y crear Hallazgos.

Es fácil reorganizar su Jerarquía de Productos en DefectDojo, así que no hay problema si todavía no está seguro de cómo configurar todo. 

Por ahora, es útil saber que los **Compromisos** pueden almacenar datos de múltiples herramientas, lo cual puede ser útil si está ejecutando distintas herramientas simultáneamente como parte de un mismo esfuerzo de pruebas.

## Acceder al formulario Import Scan (interfaz clásica / Open Source)

En DefectDojo OS, puede acceder a este formulario desde dos ubicaciones:

* La sección Tests de un Compromiso:
    ![image](images/import_scan_os.png)
* La sección Findings de la barra de navegación en un Producto:
    ![image](images/import_scan_os_2.png)

## Completar el formulario Import Scan

![image](images/import_scan_ui.png)
El formulario Import Scan creará un nuevo Test anidado dentro de un Compromiso, que contendrá un Hallazgo único por cada vulnerabilidad incluida en su archivo de análisis.

El Test se creará con un nombre que coincide con el Scan Type: por ejemplo, un análisis de Tenable se titulará ‘Tenable Scan’.

### Opciones del formulario

* **Scan File:** al hacer clic en el botón Choose, puede seleccionar un archivo de su computadora para cargarlo.
* **Scan Date (opcional):** si desea seleccionar una única Scan Date que se aplique a todos los Hallazgos resultantes de esta importación, puede seleccionar la fecha en este campo.   
Si no selecciona una Scan Date, los Hallazgos creados a partir de este informe usarán la fecha especificada por la herramienta. Los SLA de cada Hallazgo se calcularán según esa fecha.
* **Scan Type:** seleccione la herramienta usada para generar estos datos.
* **Environment:** seleccione un Environment que corresponda a los datos que está cargando.
* **Tags:** si desea usar etiquetas para organizar mejor los datos de su Test, puede agregar Etiquetas mediante este formulario. Escriba el nombre de la etiqueta que desea crear y pulse Enter en su teclado para agregarla a la lista de etiquetas.

### Campos opcionales

* **Minimum Severity**: si solo desea crear Hallazgos para un determinado nivel de Severidad y superiores, puede seleccionar aquí el nivel mínimo de Severidad. Se ignorarán todas las vulnerabilidades con una severidad inferior a la de este campo.
* **Active**: si desea establecer todos los Hallazgos entrantes como Activo o Inactivo, puede especificarlo aquí. De lo contrario, DefectDojo usará los datos de vulnerabilidad de la herramienta para determinar si el Hallazgo está Activo o Inactivo. Esta opción es relevante si necesita que su equipo triage y verifique manualmente los Hallazgos de una herramienta en particular.
* **Verified**: al igual que con Active, puede establecer el nuevo conjunto de Hallazgos como Verificado o No verificado de forma predeterminada. Esto depende de las preferencias de su flujo de trabajo. Por ejemplo, si su equipo prefiere asumir que los Hallazgos están verificados salvo que se demuestre lo contrario, puede establecer este campo en True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** pueden especificarse todos si desea incluir estos detalles en el Test.
* **Source Code Management URI** también puede especificarse. Esta opción del formulario debe ser una URI válida.
* **Group By:** si desea crear Finding Groups a partir de este archivo, puede especificar aquí el método de agrupación.

### Escáneres sin triaje: campo Do Not Reactivate

Algunos escáneres podrían no incluir información de triaje en sus informes (por ejemplo, tfsec). Simplemente analizan el código o las dependencias, señalan problemas y devuelven todo, sin importar si una vulnerabilidad ya ha sido triada o no.

Para manejar este caso, DefectDojo también incluye una casilla "Do not reactivate" al cargar informes (también disponible en la API de reimportación), de modo que pueda usar DefectDojo como fuente de verdad para el triaje, en lugar de reactivar sus Hallazgos ya triados en cada importación o reimportación.

### Usar el campo Scan Completion Date (API: `scan_date`)

DefectDojo admite una gran cantidad de informes de escáner, pero no todos ellos contienen la
información más importante para un usuario. El campo `scan_date` es una función inteligente y flexible que
permite a los usuarios establecer la fecha de finalización de un informe de análisis determinado, y que esta se propague
a todos los hallazgos importados. Este campo **no** es obligatorio, pero su valor predeterminado es la fecha de
importación (el momento en que se procesa la solicitud y se devuelve una respuesta exitosa).

A continuación se presentan los casos de uso para este campo:

1. El informe **no** establece la fecha, y `scan_date` **no** se establece en la importación
    - La fecha del Hallazgo será el valor predeterminado de `scan_date`
2. El informe **establece** la fecha, y la `scan_date` **no** se establece en la importación
    - La fecha del Hallazgo será la que establezca el informe
3. El informe **no** establece la fecha, y la `scan_date` **se establece** en la importación
    - La fecha del Hallazgo será la que el usuario haya establecido para `scan_date`
4. El informe **establece** la fecha, y la `scan_date` **se establece** en la importación
    - La fecha del Hallazgo será la que el usuario haya establecido para `scan_date`
