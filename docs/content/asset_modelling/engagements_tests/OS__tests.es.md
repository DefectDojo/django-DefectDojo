---
title: Tests
description: Cómo entender los Tests en DefectDojo OS
audience: opensource
weight: 4
---

Organizaciones → Activos → Compromisos → **TESTS** → Hallazgos

## Resumen

Un Test es un contenedor de una o más ejecuciones de escaneo, que se utilizan para descubrir fallos en un Producto. Los Tests son el componente final y más granular de la jerarquía de productos de DefectDojo, y sirven como contenedor de los Hallazgos que resultan de la ejecución de una herramienta de seguridad o de una evaluación manual, además de añadir el contexto en el que se encontraron dichos Hallazgos (es decir, qué herramienta lo reportó, cuándo se ejecutó esa herramienta por última vez, etc.).

Algunos ejemplos de Tests incluyen:
- Pruebas estáticas de seguridad de aplicaciones
- Pruebas dinámicas de seguridad de aplicaciones
- Análisis de composición de software
- Escaneos de seguridad de contenedores
- Escaneos de infraestructura / red
- Tests de penetración manuales
- Escaneos de pipelines de CI/CD

### Tipos de Test

Existen dos formas principales de crear Tests en DefectDojo:
1. **Parsers específicos de proveedor** (por ejemplo, Burp, OWASP ZAP, Acunetix, Invicti)
2. **Generic Findings Import**

Cada método puede crear nuevos Tests o reimportar Hallazgos en Tests existentes, según la configuración y la estrategia de deduplicación.

Aunque cada método difiere principalmente en la forma en que se analizan e ingieren los datos de escaneo, todos ellos terminan asociando Hallazgos a un Test.

#### Parsers

Los **Parsers** son componentes que procesan formatos de salida de escaneo específicos (por ejemplo, XML, JSON, CSV) y los asignan al modelo interno de Hallazgos de DefectDojo. Cuando se importan resultados de escaneo, DefectDojo utiliza el parser seleccionado para extraer los Hallazgos y adjuntarlos a un Test nuevo o existente.

#### Generic Findings Import

Cuando no existe un parser nativo para una herramienta determinada, **Generic Findings Import** le permite importar hallazgos utilizando un esquema JSON o CSV estandarizado, independientemente del origen original.

DefectDojo analiza los datos proporcionados, crea un nuevo Test (o los importa en uno existente) y adjunta los Hallazgos. También se crea un Test Type correspondiente en función del campo opcional `type` del informe: cuando se omite `type` (o es igual al scan type) el Test Type es “Generic Findings Import”; cuando se proporciona `type` se convierte en “{type} Scan (Generic Findings Import)” (un `type` que ya termina con el sufijo “(Generic Findings Import)” se utiliza tal cual).

|  | **Native Parsers** | **Generic Findings Import** |
|----------|---------------|------------------------|
| **Propósito principal** | Ingerir las salidas de herramientas compatibles | Ingerir datos no compatibles/personalizados mediante un esquema fijo |
| **Formato de entrada** | Específico de la herramienta (por ejemplo, ZAP XML, SARIF) | Esquema JSON/CSV estricto |
| **Quién gestiona la normalización** | DefectDojo (parser integrado) | Usuario (debe ajustarse al esquema) |
| **Disparador de creación de Test** | Carga manual o importación por API | Carga manual o importación por API |
| **Test Type** | Predefinido (por ejemplo, "ZAP Scan") | Tipo "Generic" creado automáticamente |
| **Esfuerzo de configuración** | Bajo | Moderado (requiere transformación de datos) |
| **Flexibilidad** | Baja (solo herramientas compatibles) | Media |
| **Nivel de automatización** | Bajo-Moderado | Bajo-Moderado |
| **Caso de uso típico** | Escáneres estándar (SAST, DAST, SCA) | Scripts personalizados, herramientas no compatibles |

Independientemente del método de ingesta, todos los datos de escaneo en DefectDojo se representan finalmente como Hallazgos adjuntos a un Test, que sirve como unidad de ejecución y de seguimiento del ciclo de vida.

### Datos del Test

Los Tests almacenan una variedad de metadatos que ayudan a documentar los distintos componentes de cada esfuerzo de prueba, tales como:
- Título / nombre del Test
- Tipo de Test
- Descripción / notas del Test
- Fecha de inicio y finalización
- El Entorno en el que se ejecutó el Test (por ejemplo, Development, Staging, Pre-Production, Production, etc.)
- Versión / Branch / Build ID / Commit Hash
- Configuración de escaneo de la API
- Archivos adicionales que se pueden usar para auditorías o reimportaciones posteriores
- El Compromiso, Activo y Organización principal
- Historial de importación y reimportación

Cada Test mantiene un historial de importación, que registra todas las importaciones y reimportaciones de escaneo asociadas con el Test. Esto incluye metadatos como la fecha de escaneo, la versión, el branch, el commit hash y el build ID.

Este historial proporciona trazabilidad entre múltiples ejecuciones de escaneo dentro del mismo Test.

### Permisos

Se pueden almacenar varios Tests dentro de un mismo Compromiso, y los Compromisos se almacenan dentro de Productos. Por lo tanto, el acceso a un Producto otorga automáticamente acceso a todos los Tests (y Compromisos) dentro de ese Producto. Los Tests no cuentan con listas de control de acceso independientes.

### Acceso a los Tests

Aunque los Tests existen como un objeto independiente en DefectDojo OS, no cuentan con una sección específica dedicada a ellos dentro de la interfaz. Por ello, cada Test es accesible principalmente a través del Producto y/o el Compromiso que lo contiene.

### Vista del Test

La vista del Test alberga diversas tablas, incluyendo el Compromiso principal, el historial de importación y reimportación, una lista de los Hallazgos contenidos en el Test, así como cualquier Grupo de Hallazgos.

También hay tablas para Hallazgos Potenciales, Archivos y Notas, todas las cuales se pueden agregar manualmente.

#### Configuración del Test

Los siguientes ajustes están disponibles en cada vista de Test:
- **Edit Test**
    - Permite editar los datos del Test, como el título, la programación, el entorno y otros diversos detalles.
- **Copy Test**
    - Duplica un Test, junto con todos los metadatos y Hallazgos asociados, y permite atribuirlo a un Compromiso diferente.
- **Re-Upload Scan**
    - Inicia el proceso de reimportación. Más información sobre la reimportación se encuentra más adelante en este artículo.
- **Add Notes**
    - Permite al usuario agregar una Nota. También hay una tabla de Notas en la parte inferior de la página.
        - Una Nota se puede marcar como Privada, en cuyo caso se evita que se envíe a Jira, a los Informes y a las exportaciones de Hallazgos.
- **Report**
    - Inicia el proceso de generación de un Informe, en el que se pueden aplicar múltiples filtros para crear un informe únicamente con los Hallazgos filtrados.
- **Add To Calendar**
    - Descarga un archivo .ics del Test elegido que se puede agregar a su aplicación de calendario de terceros.
- **View History**
    - Abre un historial de las ediciones realizadas al Test con fines de seguimiento, generación de informes y auditoría.

## Trabajar con Tests

### Crear Tests

Los Tests se pueden crear automáticamente cuando los datos de escaneo se importan directamente en un Compromiso, lo que da como resultado un nuevo Test que contiene los datos de escaneo. Los Tests también se pueden crear anticipándose a la planificación de futuros Compromisos, o para hallazgos de seguridad introducidos manualmente que requieran seguimiento y remediación.

#### Flujos de trabajo manuales

Existen varias formas de crear un Test en la versión OS:

- Seleccione un Producto y haga clic en “Import Scan Results” en el menú de Hallazgos de la barra de navegación
    - Esto creará un Compromiso ad hoc para contener el Test

![image](images/tests_ss5.png)

- Seleccione un Compromiso dentro de un Producto, haga clic en el menú desplegable de la subsección Tests y haga clic en “Add Tests” o en “Import Scan Results”
    - Esto creará el Test resultante directamente dentro del Compromiso elegido

![image](images/tests_ss6.png)

- Al crear un Compromiso

![image](images/tests_ss7.png)

Con el tercer método anterior, puede realizar lo siguiente al crear un Compromiso:

- Importar inmediatamente los resultados del escaneo
- Crear un Test vacío (en el que posteriormente importará un escaneo)
- No hacer ninguna de las dos cosas y simplemente crear el Compromiso haciendo clic en “Done”

Tendrá la oportunidad de agregar metadatos tanto al importar un escaneo como al crear un Test vacío. Cualquier metadato se reflejará en la sección Import History de la vista del Test.

#### Flujos de trabajo automatizados

En los flujos de trabajo automatizados, los Tests se pueden crear mediante programación como parte del proceso de importación de escaneo, lo que permite que los pipelines carguen resultados sin necesidad de crear un Test manualmente de antemano.

Al usar la API para importar resultados de escaneo, se puede crear un nuevo Test automáticamente proporcionando un engagement en lugar de un test.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Dado lo anterior, se crea un nuevo Test bajo el Compromiso especificado, y los resultados del escaneo se adjuntan a ese Test.

Si en su lugar se proporciona un ID de `test`, los resultados del escaneo se agregarán a un Test existente, lo cual es habitual en los flujos de trabajo de reimportación.

### Editar Tests

Los Tests se pueden editar haciendo clic en **Edit Test** desde el menú de tres puntos (⋮) en la tabla Tests dentro de la vista del Compromiso principal, o desde el menú de configuración dentro de la vista del Test. Todos los campos que se pueden editar posteriormente también están disponibles al crear el Test.

![image](images/tests_ss24.png)

![image](images/tests_ss12.png)

#### Agregar Hallazgos manualmente a un Test

Un Hallazgo se puede agregar manualmente a un Test haciendo clic en **Add Finding to Test** desde el menú de tres puntos (⋮) junto al Test en la vista del Compromiso principal, o desde la configuración de la tabla Findings en la vista del Test.

![image](images/tests_ss29.png)

![image](images/tests_ss30.png)

### Eliminar Tests

Para eliminar un Test, seleccione **Delete Test** en el menú de tres puntos (⋮) junto al Test en la vista del Compromiso principal, o en el menú de configuración dentro de la vista del Test. Esta acción no se puede deshacer.

Eliminar un Test también eliminará cualquier Hallazgo contenido en ese Test.

![image](images/tests_ss25.png)

![image](images/tests_ss26.png)

## Reimportación

Reimportar escaneos dentro de los Tests es fundamental para una deduplicación eficaz. Cuando los resultados de un escaneo se reimportan en el mismo Test:

- Los Hallazgos existentes pueden actualizarse
- Los Hallazgos duplicados pueden suprimirse
- Se pueden crear nuevos Hallazgos si no se encuentra una coincidencia

Este comportamiento depende de las reglas de deduplicación configuradas y del tipo de escaneo.

Crear un nuevo Test en lugar de reimportar en uno existente puede provocar que se creen Hallazgos duplicados en lugar de actualizarlos.

#### Reimportación frente a Importación

La reimportación se utiliza normalmente cuando:

- Se ejecutan escaneos recurrentes contra el mismo objetivo
- Se realiza un seguimiento de cómo evolucionan los Hallazgos a lo largo del tiempo
- Se mantiene una vista continua de la postura de seguridad de la aplicación

En cambio, importar (crear un nuevo Test) es más adecuado para ejecuciones de escaneo puntuales o independientes.

### Reimportación de resultados de escaneo (UI)

Para agregar nuevos datos a un Test existente, puede hacer clic en **Re-Upload Scan Results** desde el menú de tres puntos (⋮) junto al Test en la vista del Compromiso principal, o hacer clic en **Re-Upload Scan** en el menú de configuración dentro de la vista del Test.

![image](images/tests_ss27.png)

![image](images/tests_ss10.png)

Al completar el formulario Reimport Scan, tendrá la opción de actualizar los metadatos del escaneo que se está reimportando, incluidos la versión, el branch tag, el commit hash y el build ID.

Estos cambios se reflejan en la sección Import History de la vista del Test, que también incluirá los mismos metadatos de importaciones de escaneo anteriores.

Por ejemplo, en la siguiente captura de pantalla, el branch tag, el build ID, el commit hash y la versión se actualizaron manualmente entre la importación inicial y la reimportación posterior.

![image](images/tests_ss28.png)

Para editar los metadatos del escaneo reimportado más recientemente, siga las instrucciones anteriores de la sección Editar Tests y actualice los metadatos según lo desee. Solo se pueden editar los metadatos de la importación más reciente.

### Reimportación de resultados de escaneo (API)

Cuando los Tests se crean o actualizan mediante un pipeline de CI/CD, puede incluir metadatos de la ejecución del pipeline para que los Tests se vinculen correctamente con el código que escanearon. Esto le permite:
- Asociar los resultados del escaneo con un commit o branch específico.
- Realizar un seguimiento de cómo evolucionan los Hallazgos a través de los cambios de código.
- Mejorar la Deduplicación al comprender cuándo dos escaneos se aplican a la misma versión del código o a versiones diferentes.
- Facilitar la auditabilidad al mostrar exactamente qué código se escaneó y cuándo.

La API de DefectDojo acepta estos valores durante la importación o reimportación para que puedan almacenarse como parte de la importación del escaneo y reflejarse en el historial de importación del Test. Estos metadatos se pueden usar para identificar commit hashes o cualquier información relevante del repositorio asociada con una ejecución de CI/CD.

#### Campos de metadatos admitidos

La API admite un conjunto definido de campos de metadatos que se pueden incluir durante la reimportación. Estos incluyen:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- Indicadores `active / verified`

Estos campos representan el mecanismo principal para adjuntar metadatos contextuales durante una operación de reimportación.

En los pipelines automatizados, los metadatos que se proporcionan con mayor frecuencia incluyen:
- build_id (identificador del job de CI)
- commit_hash (referencia de control de código fuente)
- branch_tag (contexto de branch o entorno)
- tags (por ejemplo, nightly, staging, production)

Estos campos proporcionan trazabilidad entre escaneos sin necesidad de intervención manual.

Aunque los metadatos se pueden actualizar manualmente mediante el formulario Reimport Scan, la mayoría de los entornos automatizados lo gestionan llamando directamente al endpoint `/api/v2/reimport-scan/`. Este enfoque permite que el pipeline adjunte automáticamente los metadatos al reimportar.

##### Reimportación por API con metadatos

curl -X POST `"https://<your-instance>/api/v2/reimport-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"test=123"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"` \
  -F `"tags=nightly,api-scan"` \
  -F `"version=1.4.2"` \
  -F `"build_id=jenkins-842"` \
  -F `"branch_tag=main"` \
  -F `"commit_hash=a1b2c3d4"`

##### Metadatos, reimportación y escaneos programados

Los escaneos también se pueden programar para ejecutarse en intervalos rutinarios, como los desencadenados por cron jobs. Los escaneos programados no están vinculados a la actividad del repositorio, lo que hace que metadatos como los commit hashes o los nombres de branch sean irrelevantes a menos que el propio script los inyecte explícitamente. Aun así, usar la reimportación puede seguir siendo útil si prefiere mantener un registro continuo de su postura de seguridad dentro de un único Test. 
