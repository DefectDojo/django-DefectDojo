---
title: Formulario para agregar Hallazgos
description: ''
weight: 1
audience: pro
aliases:
- /es/en/connecting_your_tools/import_scan_files/import_scan_ui
---

Si tiene una instancia de DefectDojo completamente nueva, el Formulario de importación de escaneo es un primer paso lógico para aprender el software y configurar su entorno. Desde este formulario, puede cargar un archivo de escaneo de una herramienta compatible, lo que creará Hallazgos que representen esas vulnerabilidades. Al completar el formulario, puede decidir si desea:

* Almacenar estos Hallazgos en un Tipo de producto / Producto / Compromiso existente **o**
* Crear un nuevo Tipo de producto / Producto / Compromiso para almacenar estos Hallazgos

Es fácil reorganizar la Jerarquía de productos en DefectDojo, así que no hay problema si aún no está seguro de cómo configurar todo.

Por ahora, es útil saber que los **Compromisos** pueden almacenar datos de varias herramientas, lo cual puede ser útil si está ejecutando distintas herramientas simultáneamente como parte de un mismo esfuerzo de pruebas.

## Acceso al Formulario de importación de escaneo (interfaz Pro)

Se puede acceder al Formulario de importación de escaneo desde varios lugares:

1. Mediante la opción de menú **Import > Add Findings** en la barra lateral
2. Desde el **Menú '⋮' (puntos horizontales) de un Producto**, en una **Tabla de productos**
3. Desde el **Menú ⚙️Gear** en una **Página de producto**

## Cómo completar el Formulario de importación de escaneo

El Formulario de importación de escaneo creará un nuevo Test anidado bajo un Compromiso, que contendrá un Hallazgo único por cada vulnerabilidad incluida en su archivo de escaneo.

El Test se creará con un nombre que coincida con el Tipo de escaneo: por ejemplo, un escaneo de Tenable se titulará 'Tenable Scan'.

### Opciones del formulario

* **Scan File:** al hacer clic en el botón Choose, puede seleccionar un archivo de su computadora para cargarlo.
* **Scan Date (opcional):** si desea seleccionar una única fecha de escaneo que se aplicará a todos los Hallazgos resultantes de esta importación, puede seleccionar la fecha en este campo.
Si no selecciona una fecha de escaneo, los Hallazgos creados a partir de este informe usarán la fecha especificada por la herramienta. Los SLA de cada Hallazgo se calcularán en función de esa fecha.
* **Scan Type:** seleccione la herramienta utilizada para crear estos datos.
* **Product Type / Product / Engagement Name:** seleccione el Tipo de producto, el Producto y el nombre del Compromiso bajo el cual desea crear un nuevo Test. También puede crear un nuevo Tipo de producto, Producto y/o Compromiso en este momento si lo desea, ingresando los nombres de los objetos que quiere crear.
* **Environment:** seleccione un Entorno que corresponda a los datos que está cargando.
* **Tags:** si desea usar etiquetas para organizar mejor los datos de su Test, puede agregar Etiquetas mediante este formulario. Escriba el nombre de la etiqueta que desea crear y presione Enter en su teclado para agregarla a la lista de etiquetas.
* **Process Findings Asynchronously**: este campo está habilitado de forma predeterminada, pero puede deshabilitarlo si lo desea. Vea la explicación a continuación.

### Process Findings Asynchronously

Cuando este campo está habilitado, DefectDojo utilizará un proceso en segundo plano para completar el archivo de su Test con Hallazgos. Esto le permite seguir trabajando con DefectDojo mientras se crean los Hallazgos a partir de su archivo de escaneo.

Cuando este campo está deshabilitado, DefectDojo esperará hasta que se hayan creado correctamente todos los Hallazgos antes de que pueda continuar a la siguiente pantalla. Esto puede llevar bastante tiempo según el tamaño de su archivo.

Esta opción es especialmente relevante cuando se utiliza la API para importar datos. Si carga datos con Process Findings Asynchronously **desactivado**, DefectDojo no devolverá una respuesta exitosa hasta que todos los Hallazgos se hayan creado correctamente,

### Campos opcionales

Para abrir los Campos opcionales, haga clic en el botón etiquetado **"Optional Fields +"** encima del botón **Submit**

![image](images/import_scan_ui.png)

#### Descripciones de los campos opcionales
* **Minimum Severity**: si solo desea crear Hallazgos para un determinado nivel de Severidad o superior, puede seleccionar aquí el nivel mínimo de Severidad. Se ignorarán todas las vulnerabilidades con una severidad inferior a la de este campo.
* **Active**: si desea establecer todos los Hallazgos entrantes como Activo o Inactivo, puede especificarlo aquí. De lo contrario, DefectDojo utilizará los datos de vulnerabilidad de la herramienta para determinar si el Hallazgo está Activo o Inactivo. Esta opción es relevante si necesita que su equipo triage y verifique manualmente los Hallazgos de una herramienta en particular.
* **Verified**: al igual que con Active, puede establecer el nuevo conjunto de Hallazgos como Verificado o No verificado de forma predeterminada. Esto depende de las preferencias de su flujo de trabajo. Por ejemplo, si su equipo prefiere asumir que los Hallazgos están verificados salvo que se demuestre lo contrario, puede establecer este campo en True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** pueden especificarse todos si desea incluir estos detalles en el Test.
* **Source Code Management URI** también puede especificarse. Esta opción del formulario debe ser un URI válido.
* **Group By:** si desea crear Grupos de hallazgos a partir de este archivo, puede especificar aquí el método de agrupación.

### Close Old Findings

Al importar un escaneo, puede cerrar automáticamente los Hallazgos de escaneos anteriores que ya no estén presentes en el nuevo informe. Habilite esto marcando la casilla **Close Old Findings** en la interfaz, o configurando `close_old_findings: true` en la API.

#### Alcance: Compromiso vs. Producto

De forma predeterminada, `close_old_findings` cierra los Hallazgos del mismo tipo de escaneo dentro del **mismo Compromiso**. DefectDojo Pro agrega una segunda opción, **Close Old Findings Within This Product**, que amplía el alcance a todos los Hallazgos del mismo tipo de escaneo en **todo el Producto**, sin importar a qué Compromiso pertenezcan.

| Option | UI checkbox | API parameter | Scope |
|---|---|---|---|
| Cerrar hallazgos antiguos (alcance de compromiso) | **Close Old Findings** | `close_old_findings: true` | Mismo Compromiso |
| Cerrar hallazgos antiguos (alcance de producto) | **Close Old Findings Within This Product** | `close_old_findings_product_scope: true` | Todo el Producto |

`close_old_findings_product_scope` requiere que `close_old_findings` también esté habilitado. Configurar `close_old_findings_product_scope` sin `close_old_findings` no tiene ningún efecto.

> **Nota:** `close_old_findings_product_scope` solo se aplica al endpoint de importación (`/import-scan`). No tiene ningún efecto en el endpoint de reimportación (`/reimport-scan`), donde el alcance siempre se limita al Test actual.

El campo `service` también se respeta: solo se considerarán para el cierre los Hallazgos con un valor de `service` idéntico (o sin valor de `service`, si no se especificó ninguno al momento de la importación).

### Escáneres sin triage: campo Do Not Reactivate

Algunos escáneres podrían no incluir información de triage en sus informes (por ejemplo, tfsec). Simplemente escanean código o dependencias, marcan problemas y devuelven todo, sin importar si una vulnerabilidad ya fue triada o no.

Para manejar este caso, DefectDojo también incluye una casilla "Do not reactivate" al cargar informes (también en la API de reimportación), de modo que pueda usar DefectDojo como fuente de verdad para el triage, en lugar de reactivar sus Hallazgos ya triados en cada importación / reimportación.

### Uso del campo de fecha de finalización del escaneo (API: `scan_date`)

DefectDojo ofrece una gran variedad de informes de escáneres compatibles, pero no todos contienen la información más importante para un usuario. El campo `scan_date` es una función inteligente y flexible que permite a los usuarios establecer la fecha de finalización de un informe de escaneo determinado, y que esta se propague a todos los hallazgos importados. Este campo **no** es obligatorio, pero su valor predeterminado es la fecha de importación (el momento en que se procesa la solicitud y se devuelve una respuesta exitosa).

Estos son los casos de uso al utilizar este campo:

1. El informe **no** establece la fecha, y `scan_date` **no** se establece en la importación
    - La fecha del Hallazgo será el valor predeterminado de `scan_date`
2. El informe **establece** la fecha, y `scan_date` **no** se establece en la importación
    - La fecha del Hallazgo será la que establezca el informe
3. El informe **no** establece la fecha, y `scan_date` **se establece** en la importación
    - La fecha del Hallazgo será la que el usuario haya establecido para `scan_date`
4. El informe **establece** la fecha, y `scan_date` **se establece** en la importación
    - La fecha del Hallazgo será la que el usuario haya establecido para `scan_date`
