---
title: Universal Importer y DefectDojo-CLI
description: Importe archivos a DefectDojo desde la línea de comandos
draft: false
weight: 2
audience: pro
aliases:
- /es/en/connecting_your_tools/external_tools
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Las siguientes herramientas externas son funciones exclusivas de DefectDojo Pro. Estos binarios no funcionarán a menos que estén conectados a una instancia con una licencia de DefectDojo Pro.</span>

## Acerca de las herramientas externas

`defectdojo-cli` y `universal-importer` son herramientas de línea de comandos diseñadas para agilizar los procesos de importación y reimportación de Hallazgos y objetos asociados, lo que las hace ideales para los usuarios que desean configurar rápidamente estas interacciones con la API de DefectDojo.

DefectDojo-CLI tiene la misma funcionalidad que Universal Importer, pero también incluye la capacidad de exportar Hallazgos desde DefectDojo a JSON o CSV.

## Instalación

1. Localice “External Tools” en el menú de su perfil de usuario:

2. Descargue el binario adecuado para su sistema operativo desde la plataforma.

![imagen](images/external-tools.png)

3. Extraiga el archivo descargado en un directorio de su elección. Opcionalmente, agregue el directorio que contiene el binario extraído a la variable $PATH de su sistema para un acceso repetido.

**Tenga en cuenta que es posible que los usuarios de Macintosh no puedan ejecutar DefectDojo-CLI o Universal Importer, ya que son aplicaciones de un desarrollador no identificado. Consulte [Soporte de Apple](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac) para obtener instrucciones sobre cómo anular el bloqueo de Apple.**  

**Usuarios de Windows: si recibe el error "Couldn't download - virus detected", puede que funcione deshabilitar Smartscreen. De lo contrario, utilice un navegador diferente para descargar la herramienta desde el portal Cloud.**

## Configuración

Universal Importer y DefectDojo-CLI pueden configurarse mediante flags, variables de entorno o un archivo de configuración. La configuración más importante es el token de la API, que debe establecerse como una variable de entorno:

1. Agregue su clave de API a las variables de entorno. 
Puede obtener su clave de API desde: `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

o 

A través de la interfaz de usuario de DefectDojo 
en el menú desplegable de usuario en la esquina superior derecha:

![imagen](images/api-token.png)

2. Establezca la variable de entorno para el token de la API.

**Para DefectDojo-CLI:**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**Para Universal Importer:**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

Nota: en Windows, use `set` en lugar de `export`.

### Windows: uso de PowerShell

1. Abra PowerShell (tecla de Windows y luego busque "PowerShell").
2. Establezca las variables de entorno:
   - **Temporal:**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente:**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. Reinicie su sesión de PowerShell.
4. Verifique la configuración:
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows: uso del símbolo del sistema (cuentas administrativas)
1. Abra el símbolo del sistema (tecla de Windows y luego busque "Command Prompt").
2. Establezca las variables de entorno:
   - **Temporal:**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente:**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### Uso de la configuración de Windows (cuentas no administrativas)
1. Presione `Win + I` para abrir el cuadro de diálogo de configuración del sistema.
2. En el cuadro de búsqueda, escriba "environment".
3. Elija "Edit Environment variables for your account".
4. En "User variables for [username]", haga clic en el botón "New…".
5. Configure la variable:
   - **Nombre de la variable:** `DD_IMPORTER_DOJO_API_TOKEN`
   - **Valor de la variable:** `[VALUE_FROM_DEFECTDOJO_API]`
6. Haga clic en "OK".
7. Repita los pasos 4 a 6 para la variable DD_IMPORTER_DEFECTDOJO_URL
8. Reinicie cualquier ventana de comandos abierta.
9. Verifique la configuración:
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli` integra sin problemas los resultados de los escaneos en DefectDojo, agilizando los procesos de importación y reimportación de Hallazgos y objetos asociados. Diseñada para facilitar su uso, la herramienta admite varios endpoints, tanto para importaciones iniciales como para reimportaciones posteriores, lo que la hace ideal para los usuarios que requieren una interacción sólida y flexible con la API de DefectDojo. DefectDojo-CLI puede realizar las mismas funciones que `universal-importer`, y además agrega funcionalidad de exportación para los Hallazgos.

### Comandos

- [`import`](./#import)       Importa hallazgos en DefectDojo.
- [`reimport`](./#reimport)     Reimporta hallazgos en DefectDojo.
- [`export`](./#export)	Exporta hallazgos desde DefectDojo.
- [`interactive`](./#interactive)   Inicia un modo interactivo para configurar el proceso de importación y reimportación, paso a 

### Opciones globales

`--help, -h`     
* muestra la ayuda

`--version, -v`
* imprime la versión

#### Formato de la CLI

`--no-color`
* Deshabilita la salida en color. (default: false) `[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* Deshabilita los emojis en la salida. (default: false) `[$DD_CLI_NO_EMOJIS]`

* `--verbose`
Habilita la salida detallada. (default: false) `[$DD_CLI_VERBOSE]`

### Import

Utilice el comando import para importar nuevos hallazgos en DefectDojo.

#### Uso

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

`import` puede importar Hallazgos de dos maneras:

**Por ID:**
* Cree un Producto (o utilice uno existente)
* Cree un Compromiso dentro del producto
* Proporcione el id del Compromiso en el parámetro engagement

En este escenario, se creará un nuevo Test dentro del Compromiso.

**Por nombre:**

* Cree un Producto (o utilice uno existente)
* Cree un Compromiso dentro del producto
* Proporcione product-name
* Proporcione engagement-name
* Opcionalmente, proporcione product-type-name

En este escenario, DefectDojo buscará el Compromiso según los detalles proporcionados.

Cuando utiliza nombres, puede dejar que el importador cree automáticamente Compromisos, Productos y Tipos de producto mediante `auto-create-context=true`.
Puede usar `deduplication-on-engagement` para restringir la deduplicación de los Hallazgos importados al Compromiso recién creado.


**Sintaxis básica de import:**
```
defectdojo-cli import [options]
```

#### **Ejemplo de import:**
```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Comandos
`example, x`
* Muestra un ejemplo de flags obligatorios y opcionales para la operación import

#### Options

`--active, -a` 
* Determina si los Hallazgos deben forzarse a Activo o Inactivo durante la importación. Un valor de True fuerza los Hallazgos a Activo, mientras que un valor de False fuerza todos los Hallazgos a Inactivo. Si no se establece ningún valor, el estado Activo dependerá del archivo de informe entrante. (default: unset) `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* El ID del objeto API Scan Configuration que se utilizará al importar o reimportar. (default: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los endpoints (default: false) 
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los hallazgos (default: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Si se establece en true, el importador crea automáticamente Compromisos, Productos y Product_Types (default: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si es True, los Hallazgos antiguos que ya no estén presentes en el informe se Cerrarán como Mitigados al importar. Si se ha establecido Service, solo se cerrarán los Hallazgos de ese Service. [$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleccione si --close-old-findings se aplica a **todos** los Hallazgos del mismo tipo en el Producto. Por defecto, esto está establecido en false, lo que significa que solo los Hallazgos antiguos del mismo tipo dentro del Compromiso están en el alcance (y serán cerrados por Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Si se establece en true, el importador restringe la deduplicación de los hallazgos importados al Compromiso recién creado. (default: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* El ID del Compromiso en el que se importarán los hallazgos. (default: 0) `[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* El nombre del Compromiso en el que se importarán los hallazgos. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Determina el nivel de severidad mínimo que debe importarse. Los valores válidos son: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* El nombre del Producto en el que se importarán los hallazgos. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* El nombre del Tipo de producto en el que se importarán los hallazgos. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* La ruta al informe que se va a importar. (required). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* El tipo de escaneo de la herramienta (required). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Cualquier etiqueta que se aplicará al objeto Test `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* El nombre del Test en el que se importarán los hallazgos. El valor predeterminado es el nombre del tipo de escaneo. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* La versión del test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* Determina si los Hallazgos deben establecerse como Verificado durante la importación. Un valor de True fuerza los Hallazgos a Verificado. Si no se establece ningún valor, el estado Verificado dependerá del archivo de informe entrante. `[$DD_CLI_VERIFIED]`

**Configuración:**

`--config value, -c value`          
* La ruta al archivo de configuración TOML se utiliza para establecer los valores de las opciones. Si la opción se establece tanto en el archivo de configuración como en la CLI, se tomará el valor establecido en la CLI. `[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* La URL de la instancia de DefectDojo en la que se importarán los hallazgos. (required). `[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignora los errores de validación de TLS al conectarse a la instancia de DefectDojo proporcionada. La mayoría de los usuarios no deberían habilitar este flag. (default: false) `[$DD_CLI_INSECURE_TLS]`

### Reimport

Utilice el comando `reimport` para extender un Test existente con Hallazgos de un nuevo informe de una de dos maneras:

Por ID:
- Cree un Producto (o utilice uno existente)
- Cree un Compromiso dentro del producto
- Importe un informe de escaneo y busque el id del Test
- Proporciónelo en el parámetro test-id

Por nombres:
- Cree un Producto (o utilice uno existente)
- Cree un Compromiso dentro del producto
- Importe un informe, lo que creará un Test
- Proporcione product-name
- Proporcione engagement-name
- Opcional: proporcione test-name

En este escenario, DefectDojo buscará el Test según los detalles proporcionados. Si no se proporciona test-name, se elegirá el test más reciente dentro del compromiso según scan-type.

Cuando utiliza nombres, puede dejar que el importador cree automáticamente Compromisos, Productos y Tipos de producto mediante `auto-create-context=true`.
Puede usar `deduplication-on-engagement` para restringir la deduplicación de los Hallazgos importados al Compromiso recién creado.

#### Uso

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **Ejemplo de reimport:**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Comandos

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Options

`--active, -a`                                    
* Determina si los Hallazgos deben forzarse a Activo o Inactivo durante la importación. Un valor de True fuerza los Hallazgos a Activo, mientras que un valor de False fuerza todos los Hallazgos a Inactivo. Si no se establece ningún valor, el estado Activo dependerá del archivo de informe entrante. `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* El ID del objeto API Scan Configuration que se utilizará al importar o reimportar. (default: 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los endpoints (default: false) `[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los hallazgos (default: false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Si se establece en true, el importador crea automáticamente Compromisos, Productos y Product_Types (default: false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si es True, los Hallazgos antiguos que ya no estén presentes en el informe se Cerrarán como Mitigados al importar. Si se ha establecido Service, solo se cerrarán los hallazgos de ese Service.[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleccione si --close-old-findings se aplica a **todos** los Hallazgos del mismo tipo en el Producto. Por defecto, esto está establecido en false, lo que significa que solo los Hallazgos antiguos del mismo tipo dentro del Compromiso están en el alcance (y serán cerrados por Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Si se establece en true, el importador restringe la deduplicación de los hallazgos importados al Compromiso recién creado. (default: false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* El nombre del Compromiso en el que se importarán los hallazgos. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Determina el nivel de severidad mínimo que debe importarse. Los valores válidos son: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* El nombre del Producto en el que se importarán los hallazgos. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* El nombre del Tipo de producto en el que se importarán los hallazgos. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* La ruta al informe que se va a importar. (required). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`                      
* El tipo de escaneo de la herramienta (required). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Cualquier etiqueta que se aplicará al objeto Test `[$DD_CLI_TAGS]`

`--test-id value, --ti value`                      
* El ID del Test en el que se reimportarán los hallazgos. (default: 0) `[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`                    
* El nombre del Test en el que se importarán los hallazgos. El valor predeterminado es el nombre del tipo de escaneo. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`                   
* La versión del test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`                                   
* Determina si los Hallazgos deben establecerse como Verificado durante la importación. Un valor de True fuerza los Hallazgos a Verificado. Si no se establece ningún valor, el estado Verificado dependerá del archivo de informe entrante. `[$DD_CLI_VERIFIED]`

**Configuración:**

`--config value, -c value`
* La ruta al archivo de configuración TOML se utiliza para establecer los valores de las opciones. Si la opción se establece tanto en el archivo de configuración como en la CLI, se tomará el valor establecido en la CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* La URL de la instancia de DefectDojo en la que se importarán los hallazgos. (required). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignora los errores de validación de TLS al conectarse a la instancia de DefectDojo proporcionada. La mayoría de los usuarios no deberían habilitar este flag. (default: false) `[$DD_CLI_INSECURE_TLS]`

### Export

#### Uso

```
defectdojo-cli export <required options> [optional options]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --config ./config-file-path
	or: defectdojo-cli [global options] export --config ./config-file-path --json ./output_file_path.json
	or: defectdojo-cli [global options] export --config ./config-file-path --csv ./output_file_path.csv
	or: defectdojo-cli export [-h | --help]
	or: defectdojo-cli export example [subcommand options]
	or: defectdojo-cli export example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

Para exportar Hallazgos desde DefectDojo-CLI, deberá proporcionar un archivo de configuración que contenga los detalles que indican qué Hallazgos desea exportar. Esto es similar al método GET Findings de la API.

Para obtener ayuda, use `defectdojo-cli export --help`.

#### **Ejemplo de export**

Este ejemplo especifica la URL, el formato de exportación y algunos parámetros de filtro para crear una lista de Hallazgos.

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### Comandos

`example, x`
* Muestra un ejemplo de flags obligatorios y opcionales para la operación export

`help, h`
* Muestra una lista de comandos o ayuda para un comando

#### Options

**Filtros de hallazgos:**

`--active true|false, -a true|false`
* Hallazgos por estado activo. `[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* Hallazgos por fecha de creación. Valores admitidos: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* Hallazgos por puntuación CVSS v3. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value` 
* Hallazgos por ID de CWE. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* Hallazgos por fecha. Valores admitidos: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* Hallazgos descubiertos después de la fecha especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* Hallazgos descubiertos antes de la fecha especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* Hallazgos por fecha de descubrimiento. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* Hallazgos por estado de duplicado. `[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* Hallazgos por IDs de compromiso. Este flag puede usarse varias veces o como una lista separada por comas. `[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* Hallazgos por percentil EPSS. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* Hallazgos por puntuación EPSS. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* Hallazgos por estado de Falso positivo. `[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* Hallazgos por estado de mitigación. `[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* Hallazgos por el rango de fechas en el que fueron marcados como mitigados. Valores admitidos: None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* Hallazgos mitigados después de la fecha especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* Hallazgos mitigados antes de la fecha especificada. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* Hallazgos por IDs de usuario mitigated_by. Este flag puede usarse varias veces o como una lista separada por comas. Puede combinarse con --mitigated-by-names. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* Hallazgos por nombres de usuario mitigated_by. Este flag puede usarse varias veces o como una lista separada por comas. Puede combinarse con --mitigated-by-ids. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* Hallazgos por fecha de mitigación. Formato: YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* Hallazgos por etiquetas que no deben estar presentes. Este flag puede usarse varias veces o como una lista separada por comas. `[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* Hallazgos por estado Fuera de alcance o dentro de alcance. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* Hallazgos por estado dentro o fuera del SLA. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* Hallazgos por nombre de producto. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* Hallazgos cuyo nombre de producto contiene el valor indicado. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* Hallazgos por IDs de tipo de producto. Este flag puede usarse varias veces o como una lista separada por comas. Puede combinarse con --product-type-names `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* Hallazgos por nombres de tipo de producto. Este flag puede usarse varias veces o como una lista separada por comas. Puede combinarse con --product-type-ids `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* Hallazgos por estado de Riesgo aceptado. `[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* Hallazgos por severidad. Los valores válidos son: Critical, High, Medium, Low, Info. Este flag puede usarse varias veces o como una lista separada por comas. `[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* Hallazgos por etiquetas que deben estar presentes. Este flag puede usarse varias veces o como una lista separada por comas. `[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* Hallazgos por ID de test. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* Hallazgos cuyo título contiene la cadena indicada. `[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* Hallazgos por estado en revisión. `[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* Hallazgos por estado Verificado. (default: ignored) `[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* Hallazgos por ID de vulnerabilidad. Este flag puede usarse varias veces o como una lista separada por comas. `[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**Salida de hallazgos**

`--csv value`
* Ruta del archivo donde se escribirá el archivo CSV de los hallazgos. `[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  Ruta del archivo donde se escribirá el archivo JSON de los hallazgos. `[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**Configuración**

`--config value, -c value`
La ruta al archivo de configuración TOML se utiliza para establecer los valores de las opciones. Si la opción se establece tanto en el archivo de configuración como en la CLI, se tomará el valor establecido en la CLI. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
La URL de la instancia de DefectDojo en la que se importarán los hallazgos. (required). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
ignora los errores de validación de TLS al conectarse a la instancia de DefectDojo proporcionada. La mayoría de los usuarios no deberían habilitar este flag. (default: false) `[$DD_CLI_INSECURE_TLS]`

#### Ejemplo de export:

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### Interactive

El modo interactive le permite configurar el proceso de importación y reimportación, paso a paso.

#### Uso

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### Options

`--skip-intro `    
* Omite la pantalla de introducción (default: false)

`--no-full-screen`
* Deshabilita el modo de pantalla completa (default: false)

`--log-path value`
* Ruta al archivo de registro

`--help, -h`
* muestra la ayuda

## Universal Importer

`universal-importer` integra sin problemas los resultados de los escaneos en DefectDojo, agilizando los procesos de importación y reimportación de hallazgos y objetos asociados. Diseñada para facilitar su uso, la herramienta admite varios endpoints, tanto para importaciones iniciales como para reimportaciones posteriores, lo que la hace ideal para los usuarios que requieren una interacción sólida y flexible con la API de DefectDojo.

Si bien es similar a DefectDojo-CLI, Universal Importer no cuenta con la funcionalidad de exportación, y las variables de entorno se codifican de forma diferente.

### Comandos

- [`import`](./#import-1)       Importa hallazgos en DefectDojo.
- [`reimport`](./#reimport-1)     Reimporta hallazgos en DefectDojo.
- [`interactive`](./#interactive-1)   Inicia un modo interactivo para configurar el proceso de importación y reimportación, paso a 

### Opciones globales

`--help, -h`     
* muestra la ayuda

`--version, -v`
* imprime la versión

#### Formato de la CLI

`--no-color`
* Deshabilita la salida en color. (default: false) `[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* Deshabilita los emojis en la salida. (default: false) `[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* Habilita la salida detallada. (default: false) `[$DD_IMPORTER_VERBOSE]`

### Import

Utilice el comando import para importar nuevos hallazgos en DefectDojo.

#### Uso

```
universal-importer [global options] import <required flags> [optional flags]
	or: universal-importer [global options] import  --config ./config-file-path
	or: universal-importer import [-h | --help]
	or: universal-importer import example [subcommand options]
	or: universal-importer import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import` puede importar Hallazgos de dos maneras:

**Por ID:**
* Cree un Producto (o utilice uno existente)
* Cree un Compromiso dentro del producto
* Proporcione el id del Compromiso en el parámetro engagement

En este escenario, se creará un nuevo Test dentro del Compromiso.

**Por nombre:**
* Cree un Producto (o utilice uno existente)
* Cree un Compromiso dentro del producto
* Proporcione product-name
* Proporcione engagement-name
* Opcionalmente, proporcione product-type-name

En este escenario, DefectDojo buscará el Compromiso según los detalles proporcionados.

Cuando utiliza nombres, puede dejar que el importador cree automáticamente Compromisos, Productos y Tipos de producto mediante `auto-create-context=true`.
Puede usar `deduplication-on-engagement` para restringir la deduplicación de los Hallazgos importados al Compromiso recién creado.


**Sintaxis básica de import:**

```
universal-importer import [options]
```

#### **Ejemplo de import:**

```
universal-importer import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Comandos

`example, x`
* Muestra un ejemplo de flags obligatorios y opcionales para la operación import

#### Options

`--active, -a` 
* Determina si los Hallazgos deben forzarse a Activo o Inactivo durante la importación. Un valor de True fuerza los Hallazgos a Activo, mientras que un valor de False fuerza todos los Hallazgos a Inactivo. Si no se establece ningún valor, el estado Activo dependerá del archivo de informe entrante. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* El ID del objeto API Scan Configuration que se utilizará al importar o reimportar. (default: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los endpoints (default: false) 
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los hallazgos (default: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Si se establece en true, el importador crea automáticamente Compromisos, Productos y Product_Types (default: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si es True, los Hallazgos antiguos que ya no estén presentes en el informe se Cerrarán como Mitigados al importar. Si se ha establecido Service, solo se cerrarán los hallazgos de ese Service. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleccione si --close-old-findings se aplica a **todos** los Hallazgos del mismo tipo en el Producto. Por defecto, esto está establecido en false, lo que significa que solo los Hallazgos antiguos del mismo tipo dentro del Compromiso están en el alcance (y serán cerrados por Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Si se establece en true, el importador restringe la deduplicación de los hallazgos importados al Compromiso recién creado. (default: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* El ID del Compromiso en el que se importarán los hallazgos. (default: 0) `[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* El nombre del Compromiso en el que se importarán los hallazgos. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Determina el nivel de severidad mínimo que debe importarse. Los valores válidos son: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* El nombre del Producto en el que se importarán los hallazgos. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* El nombre del Tipo de producto en el que se importarán los hallazgos. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* La ruta al informe que se va a importar. (required). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* El tipo de escaneo de la herramienta (required). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Cualquier etiqueta que se aplicará al objeto Test `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* El nombre del Test en el que se importarán los hallazgos. El valor predeterminado es el nombre del tipo de escaneo. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* La versión del test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* Determina si los Hallazgos deben establecerse como Verificado durante la importación. Un valor de True fuerza los Hallazgos a Verificado. Si no se establece ningún valor, el estado Verificado dependerá del archivo de informe entrante. `[$DD_IMPORTER_VERIFIED]`

**Configuración:**

`--config value, -c value`          
* La ruta al archivo de configuración TOML se utiliza para establecer los valores de las opciones. Si la opción se establece tanto en el archivo de configuración como en la CLI, se tomará el valor establecido en la CLI. `[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* La URL de la instancia de DefectDojo en la que se importarán los hallazgos. (required). `[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignora los errores de validación de TLS al conectarse a la instancia de DefectDojo proporcionada. La mayoría de los usuarios no deberían habilitar este flag. (default: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Reimport

Utilice el comando `reimport` para extender un Test existente con Hallazgos de un nuevo informe de una de dos maneras:

Por ID:
- Cree un Producto (o utilice uno existente)
- Cree un Compromiso dentro del producto
- Importe un informe de escaneo y busque el id del Test
- Proporciónelo en el parámetro test-id

Por nombres:
- Cree un Producto (o utilice uno existente)
- Cree un Compromiso dentro del producto
- Importe un informe, lo que creará un Test
- Proporcione product-name
- Proporcione engagement-name
- Opcional: proporcione test-name

En este escenario, DefectDojo buscará el Test según los detalles proporcionados. Si no se proporciona test-name, se elegirá el test más reciente dentro del compromiso según scan-type.

Cuando utiliza nombres, puede dejar que el importador cree automáticamente Compromisos, Productos y Tipos de producto mediante `auto-create-context=true`.
Puede usar `deduplication-on-engagement` para restringir la deduplicación de los Hallazgos importados al Compromiso recién creado.

#### Uso

```
universal-importer [global options] reimport <required flags> [optional flags]
   or: universal-importer [global options] reimport  --config ./config-file-path
   or: universal-importer reimport [-h | --help]
   or: universal-importer reimport example [subcommand options]
   or: universal-importer reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **Ejemplo de reimport:**

```
universal-importer reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Comandos

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Options

`--active, -a`                                    
* Determina si los Hallazgos deben forzarse a Activo o Inactivo durante la importación. Un valor de True fuerza los Hallazgos a Activo, mientras que un valor de False fuerza todos los Hallazgos a Inactivo. Si no se establece ningún valor, el estado Activo dependerá del archivo de informe entrante. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* El ID del objeto API Scan Configuration que se utilizará al importar o reimportar. (default: 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los endpoints (default: false) `[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Si se establece en true, las etiquetas (de la opción --tag) se aplicarán a los hallazgos (default: false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Si se establece en true, el importador crea automáticamente Compromisos, Productos y Product_Types (default: false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si es True, los Hallazgos antiguos que ya no estén presentes en el informe se Cerrarán como Mitigados al importar. Si se ha establecido Service, solo se cerrarán los Hallazgos de ese Service. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Seleccione si --close-old-findings se aplica a **todos** los Hallazgos del mismo tipo en el Producto. Por defecto, esto está establecido en false, lo que significa que solo los Hallazgos antiguos del mismo tipo dentro del Compromiso están en el alcance (y serán cerrados por Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Si se establece en true, el importador restringe la deduplicación de los hallazgos importados al Compromiso recién creado. (default: false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* El nombre del Compromiso en el que se importarán los hallazgos. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Determina el nivel de severidad mínimo que debe importarse. Los valores válidos son: Critical, High, Medium, Low, Info. (default: "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* El nombre del Producto en el que se importarán los hallazgos. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* El nombre del Tipo de producto en el que se importarán los hallazgos. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* La ruta al informe que se va a importar. (required). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`                      
* El tipo de escaneo de la herramienta (required). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Cualquier etiqueta que se aplicará al objeto Test `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`                      
* El ID del Test en el que se reimportarán los hallazgos. (default: 0) `[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`                    
* El nombre del Test en el que se importarán los hallazgos. El valor predeterminado es el nombre del tipo de escaneo. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`                   
* La versión del test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`                                   
* Determina si los Hallazgos deben establecerse como Verificado durante la importación. Un valor de True fuerza los Hallazgos a Verificado. Si no se establece ningún valor, el estado Verificado dependerá del archivo de informe entrante. (default: unset) `[$DD_IMPORTER_VERIFIED]`

**Configuración:**

`--config value, -c value`
* La ruta al archivo de configuración TOML se utiliza para establecer los valores de las opciones. Si la opción se establece tanto en el archivo de configuración como en la CLI, se tomará el valor establecido en la CLI. `[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* La URL de la instancia de DefectDojo en la que se importarán los hallazgos. (required). `[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignora los errores de validación de TLS al conectarse a la instancia de DefectDojo proporcionada. La mayoría de los usuarios no deberían habilitar este flag. (default: false) `[$DD_IMPORTER_INSECURE_TLS]`

### Interactive
El modo interactive le permite configurar el proceso de importación y reimportación, paso a paso.

#### Uso

```
universal-importer interactive
	or: universal-importer interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: universal-importer interactive [-h | --help]
```

#### Options

`--skip-intro `    
* Omite la pantalla de introducción (default: false)

`--no-full-screen`
* Deshabilita el modo de pantalla completa (default: false)
`--log-path value`
* Ruta al archivo de registro
`--help, -h`
* muestra la ayuda


## Solución de problemas

Si tiene algún problema con estas herramientas, verifique lo siguiente:
- Asegúrese de estar usando el binario correcto para su sistema operativo y arquitectura de CPU.
- Verifique que la clave de API esté configurada correctamente en sus variables de entorno.
- Compruebe que la URL de DefectDojo sea correcta y accesible.
- Al importar, confirme que el archivo de informe existe y está en el formato admitido para el tipo de escaneo especificado. Puede consultar las herramientas de escaneo compatibles con DefectDojo en nuestra [lista de herramientas compatibles](/supported_tools). 
