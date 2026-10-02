---
title: Tests
description: Cómo funcionan los Tests en DefectDojo Pro
audience: pro
weight: 4
---

Organizaciones → Activos → Compromisos → **TESTS** → Hallazgos

## Resumen

Un Test es un contenedor para una o más ejecuciones de escaneo, que se utilizan para descubrir fallos en un Activo. Los Tests son el componente final y más granular de la jerarquía de objetos de DefectDojo, y sirven como contenedor de los Hallazgos que resultan de la ejecución de una herramienta de seguridad o de una evaluación manual, añadiendo además el contexto en el que se encontraron dichos Hallazgos (es decir, qué herramienta los reportó, cuándo se ejecutó esa herramienta por última vez, etc.).

Ejemplos de Tests incluyen: 
- Pruebas Estáticas de Seguridad de Aplicaciones
- Pruebas Dinámicas de Seguridad de Aplicaciones
- Análisis de Composición de Software
- Escaneos de Seguridad de Contenedores
- Escaneos de Infraestructura / Red
- Pruebas de Penetración Manuales
- Escaneos de Pipeline de CI/CD

### Tipos de Test 

Existen varias formas de crear Tests en DefectDojo, incluidos los **parsers específicos de proveedor** (por ejemplo, Burp, OWASP ZAP, Acunetix, Invicti), **Generic Findings Import**, **Universal Parser** y **Connectors**.

Estos métodos pueden crear nuevos Tests o reimportar Hallazgos en Tests existentes, según la configuración y la estrategia de deduplicación.

Aunque cada método difiere principalmente en la forma en que se analizan e ingieren los datos de escaneo, todos terminan asociando Hallazgos a un Test.

#### Parsers 

**Parsers** son componentes que procesan formatos específicos de salida de escaneo (por ejemplo, XML, JSON, CSV) y los asignan al modelo interno de Hallazgos de DefectDojo. Cuando se importan resultados de escaneo, DefectDojo utiliza el parser seleccionado para extraer los Hallazgos y adjuntarlos a un Test nuevo o existente.

#### Generic Findings Import

Cuando no existe un parser nativo para una herramienta determinada, [**Generic Findings Import**](/supported_tools/parsers/generic_findings_import) le permite importar hallazgos utilizando un esquema JSON o CSV estandarizado, sin importar el origen. 

DefectDojo analiza los datos proporcionados, crea un nuevo Test (o los importa en uno existente) y adjunta los Hallazgos. También se crea un Test Type correspondiente según el campo opcional `type` del informe: cuando se omite `type` (o es igual al tipo de escaneo) el Test Type es “Generic Findings Import”; cuando se proporciona `type`, se convierte en “`{type}` Scan (Generic Findings Import)” (un `type` que ya termina con el sufijo “(Generic Findings Import)” se utiliza tal cual).

#### Universal Parser 

[**Universal Parser**](/supported_tools/parsers/universal_parser) permite a los usuarios definir cómo se asignan los datos de entrada arbitrarios al modelo de Hallazgos de DefectDojo. Después de configurar el parser y cargar los datos de escaneo, DefectDojo aplica las reglas de asignación para extraer los Hallazgos, crea un Test (o actualiza uno existente) y asocia los Hallazgos con ese Test.

#### Connectors 

Los [**Connectors**](/connectors/upstream/about/) pueden utilizarse para ingerir y organizar automáticamente datos de vulnerabilidades de herramientas externas mediante llamadas a la API. Una vez configurado, un Connector obtiene los resultados del escaneo, analiza los datos y crea nuevos Tests o actualiza los existentes según su configuración. Los Hallazgos se adjuntan luego al Test correspondiente.

#### Comparación de mecanismos de creación de Test 

| | **Parsers nativos** | **Generic Findings Import** | **Universal Parser (Pro)** | **Connectors** |
|----------|---------------|------------------------|------------------------|------------|
| **Propósito principal** | Ingerir salidas de herramientas compatibles | Ingerir datos no compatibles/personalizados mediante un esquema fijo | Ingerir formatos arbitrarios mediante asignaciones configurables | Sincronizar continuamente sistemas externos |
| **Formato de entrada** | Específico de la herramienta (por ejemplo, ZAP XML, SARIF) | Esquema JSON/CSV estricto | Arbitrario (JSON, XML, etc.) | Respuestas de API externas |
| **Quién gestiona la normalización** | DefectDojo (parser integrado) | Usuario (debe ajustarse al esquema) | DefectDojo (mediante configuración del parser) | Herramienta externa + DefectDojo |
| **Disparador de creación del Test** | Carga manual o importación por API | Carga manual o importación por API | Carga manual o importación por API | Sincronización automatizada (programada o basada en eventos) |
| **Test Type** | Predefinido (por ejemplo, “ZAP Scan”) | Tipo “Generic” creado automáticamente | Derivado de la configuración del parser | Depende del connector / parser subyacente |
| **Esfuerzo de configuración** | Bajo | Moderado (requiere transformación de datos) | Alto (configuración del parser) | Moderado–Alto (configuración de la integración) |
| **Flexibilidad** | Baja (solo herramientas compatibles) | Media | Alta | Media–Alta |
| **Nivel de automatización** | Bajo–Moderado | Bajo–Moderado | Bajo–Moderado | Alto |
| **Caso de uso típico** | Escáneres estándar (SAST, DAST, SCA) | Scripts personalizados, herramientas no compatibles | Formatos complejos/personalizados a gran escala | Integraciones de CI/CD, SCM o de plataforma |

Independientemente del método de ingesta, todos los datos de escaneo en DefectDojo terminan representándose como Hallazgos adjuntos a un Test, que sirve como unidad de ejecución y seguimiento del ciclo de vida.

### Datos del Test 

Los Tests almacenan una variedad de metadatos que ayudan a documentar distintos componentes de cada esfuerzo de testing, tales como: 
- Título / nombre del Test 
- Tipo de Test
- Descripción / notas del Test
- Fecha de inicio y fin 
- El Entorno en el que se ejecutó el Test (por ejemplo, Development, Staging, Pre-Production, Production, etc.)
- Versión / Branch / Build ID / Commit Hash
- Configuración de escaneo por API 
- Personal asociado al Test 
- Archivos adicionales que se pueden utilizar para auditorías o reimportaciones posteriores
- El Compromiso, Activo y Organización superiores 
- Historial de importación y reimportación

Cada Test mantiene un historial de importación, que registra todas las importaciones y reimportaciones de escaneo asociadas con el Test. Cada elemento del historial incluye metadatos como la fecha de escaneo, la versión, el branch, el commit hash y el build ID.

Este historial proporciona trazabilidad a través de múltiples ejecuciones de escaneo dentro del mismo Test.

### Permisos 

Varios Tests pueden almacenarse dentro de un mismo Compromiso, y los Compromisos se almacenan dentro de los Activos. Por lo tanto, el acceso a un Activo otorga automáticamente acceso a todos los Tests (y Compromisos) dentro de ese Activo. Los Tests no tienen listas de control de acceso independientes.

## Acceso a los Tests 

Se puede acceder a los Tests desde varias secciones de la interfaz de DefectDojo. 

- La barra lateral 

![image](images/tests_ss13.png)

- Dentro de un Compromiso 

![image](images/tests_ss14.png)

- La barra superior de un Activo

![image](images/tests_ss15.png)

- La tabla de metadatos dentro de la vista de un Hallazgo

![image](images/tests_ss16.png)

## Trabajar con Tests 

### Crear Tests

Los Tests pueden crearse automáticamente cuando los datos de escaneo se importan directamente en un Compromiso, lo que da como resultado un nuevo Test que contiene los datos del escaneo. Los Tests también pueden crearse anticipándose a la planificación de futuros Compromisos, o para hallazgos de seguridad ingresados manualmente que requieran seguimiento y remediación.

#### Flujos de trabajo manuales 

Para crear un Test, primero debe crearse un Compromiso que lo contenga, así como un Activo que contenga a ese Compromiso. Después, existen varias formas de crear un Test: 

- En la barra lateral, en Tests dentro de la subsección **Manage**
    - Deberá seleccionar el Compromiso preexistente al que se atribuirá el Test al completar el formulario New Test. 

![image](images/tests_ss1.png)

- El menú desplegable de configuración en la esquina superior derecha de la vista de un Activo
    - **Import Scan** creará automáticamente un Test una vez que se haya añadido un archivo de escaneo al formulario Import Scan. Tendrá la opción de atribuir el Test a un Compromiso preexistente o de crear y nombrar un nuevo Compromiso que contenga el nuevo Test. 
        - Al completar el formulario Import Scan, puede agregar metadatos como la versión, el branch tag, el commit hash y el build ID. Esto se reflejará en la sección Import History de la vista del Test.

![image](images/tests_ss2.png)

- El menú desplegable de configuración en la parte superior derecha de la vista de un Compromiso
    - **Import Scan** seguirá el mismo flujo de trabajo que en los Activos, pero colocará automáticamente el objeto Test dentro del Compromiso en el que hizo clic en Import Scan. 
    - **Add Test** creará un objeto Test, pero no requiere que se cargue un escaneo en el propio Test, lo cual es útil para anticiparse a la planificación de futuros Tests o para hallazgos de seguridad ingresados manualmente que requieran seguimiento y remediación.

![image](images/tests_ss3.png)

Si selecciona Add Test y más adelante desea importar manualmente los resultados de un escaneo a un Test, puede hacerlo abriendo el Test y haciendo clic en el botón Reimport Findings en la configuración del Test, o en el botón Reimport Scan de la tabla de Hallazgos.

![image](images/tests_ss21.png)

#### Flujos de trabajo automatizados 

En los flujos de trabajo automatizados, los Tests pueden crearse mediante programación como parte del proceso de importación de escaneo, lo que permite que los pipelines carguen resultados sin necesidad de crear un Test manualmente de antemano.

Al usar la API o la CLI para importar resultados de escaneo, se puede crear un nuevo Test automáticamente proporcionando un `engagement` en lugar de un `test`.

##### API 

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Dado lo anterior, se crea un nuevo Test bajo el Compromiso especificado, y los resultados del escaneo se adjuntan a ese Test.

Si en su lugar se proporciona un ID de `test`, los resultados del escaneo se agregarán a un Test existente, lo cual es común en los flujos de trabajo de reimportación.  

##### CLI 

Con la CLI de DefectDojo, este comportamiento se gestiona automáticamente según los argumentos proporcionados.

defectdojo-cli import \
  --engagement-id 45 \
  --scan-type `"ZAP Scan"` \
GOog  --file report.xml

Dado lo anterior, proporcionar un `engagement-id` crea un nuevo Test, y proporcionar un `test-id` reutiliza un Test existente y reimporta los resultados del escaneo en ese Test. 

Consulte [DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/#defectdojo-cli) para obtener más detalles sobre los flags requeridos.

### Editar Tests

Los Tests se pueden editar haciendo clic en **Edit Test** dentro del menú de engranaje. Todos los campos que se pueden editar a continuación también están disponibles al crear el Test.

### Eliminar Tests 

Para eliminar un Test, seleccione **Delete Test** en la configuración del Test. Esta acción no se puede deshacer. 

Eliminar un Test también eliminará todos los Hallazgos contenidos en ese Test.

### Reimportar resultados de escaneo (UI)

Para agregar nuevos datos a un Test existente, abra el Test al que desea agregar los nuevos datos y haga clic en el botón Reimport Findings en la configuración del Test, o en el botón Reimport Scan en la tabla de Hallazgos. 

![image](images/tests_ss21.png)

Al completar el formulario Reimport Scan, tendrá la opción de actualizar los metadatos del escaneo que se está reimportando, incluidos la versión, el branch tag, el commit hash y el build ID. Estos cambios se reflejan en la sección Import History de la vista del Test, que también incluirá los mismos metadatos de importaciones de escaneo anteriores. 

Por ejemplo, en la captura de pantalla a continuación, el branch tag, el build ID, el commit hash y la versión se actualizaron manualmente entre la importación inicial y la reimportación posterior. 

![image](images/tests_ss23.png)

Para editar los metadatos del escaneo reimportado más recientemente, haga clic en el ícono de engranaje ubicado en la esquina superior derecha de la vista del Compromiso y seleccione “Edit Test”. Solo se pueden editar los metadatos de la importación más reciente.

### Reimportar resultados de escaneo (API/CLI)

Cuando los Tests se crean o actualizan a través de un pipeline de CI/CD, puede incluir metadatos de la ejecución del pipeline para que los Tests queden correctamente vinculados al código que escanearon. Esto le permite:
- Asociar los resultados del escaneo con un commit o branch específico.
- Realizar seguimiento de cómo evolucionan los Hallazgos a través de los cambios de código.
- Mejorar la Deduplicación al comprender cuándo dos escaneos corresponden a la misma versión del código o a versiones diferentes.
- Facilitar la auditabilidad mostrando exactamente qué código se escaneó y cuándo.

La CLI y la API de DefectDojo aceptan estos valores durante la importación o reimportación para que puedan almacenarse como parte de la importación del escaneo y reflejarse en el historial de importación del Test. Estos metadatos se pueden usar para identificar commit hashes o cualquier información relevante del repositorio asociada con una ejecución de CI/CD.

#### Campos de metadatos admitidos 

La API y la CLI admiten un conjunto definido de campos de metadatos que se pueden incluir durante la reimportación. Estos incluyen:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- Indicadores `active / verified`

Estos campos representan el mecanismo principal para adjuntar metadatos contextuales durante una operación de reimportación. 

En los pipelines automatizados, los metadatos suministrados con mayor frecuencia incluyen:
- `build_id` (identificador del job de CI)
- `commit_hash` (referencia de control de versiones)
- `branch_tag` (contexto de branch o entorno)
- `tags` (por ejemplo, `nightly`, `staging`, `production`)

Estos campos proporcionan trazabilidad entre escaneos sin requerir intervención manual.

Aunque los metadatos se pueden actualizar manualmente a través del formulario Reimport Scan, la mayoría de los entornos automatizados gestionan esto llamando directamente al endpoint `/api/v2/reimport-scan/` o usando la CLI de DefectDojo (`defectdojo-cli reimport`) como parte del proceso de build. Este enfoque permite que el pipeline adjunte automáticamente los metadatos al reimportar.

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

##### Reimportación por CLI con metadatos 

defectdojo-cli import \
  --test-id 123 \
  --scan-type "ZAP Scan" \
  --file report.xml \
  --tag nightly \
  --tag api \
  --build-id jenkins-842 \
  --branch main \
  --commit a1b2c3d4

La CLI se mapea directamente al mismo endpoint de la API y admite el mismo conjunto de campos de metadatos.

Existen algunas limitaciones a tener en cuenta al trabajar con metadatos durante la reimportación:
- La API/CLI solo admite parámetros predefinidos. No se pueden agregar metadatos personalizados de clave-valor durante la reimportación
- Es posible que se extraigan metadatos adicionales del propio archivo de escaneo, según el tipo de escaneo y el parser.
- Los metadatos proporcionados durante la reimportación no se comportan como una actualización directa del objeto Test, a diferencia de las ediciones manuales en la interfaz.

##### Metadatos, reimportación y escaneos programados 

Los escaneos también pueden programarse para ejecutarse a intervalos rutinarios, como los activados por cron jobs. Los escaneos programados no están vinculados a la actividad del repositorio, lo que hace que metadatos como los commit hashes o los nombres de branch sean irrelevantes a menos que el propio script los inyecte explícitamente. Aun así, usar la reimportación puede seguir siendo útil si prefiere mantener un registro continuo de su postura de seguridad dentro de un mismo Test. 

## Reimportación y Deduplicación 

Reimportar escaneos dentro de los Tests es fundamental para una deduplicación efectiva. Cuando los resultados de escaneo se reimportan en el mismo Test:

- Los Hallazgos existentes pueden actualizarse
- Los Hallazgos duplicados pueden suprimirse
- Se pueden crear nuevos Hallazgos si no se encuentra ninguna coincidencia

Este comportamiento depende de las reglas de deduplicación configuradas y del tipo de escaneo.

Crear un nuevo Test en lugar de reimportar en uno existente puede provocar que se creen Hallazgos duplicados en vez de actualizarse.

### Reimportación vs. Importación 

La reimportación se utiliza normalmente cuando:

- Se ejecutan escaneos recurrentes contra el mismo objetivo
- Se realiza seguimiento de cómo evolucionan los Hallazgos con el tiempo
- Se mantiene una vista continua de la postura de seguridad de la aplicación

Por el contrario, importar (crear un nuevo Test) es más apropiado para ejecuciones de escaneo únicas o independientes.
