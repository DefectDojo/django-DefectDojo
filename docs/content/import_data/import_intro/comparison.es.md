---
title: Comparación de métodos de importación
description: Aprenda a importar datos manualmente, mediante la API o a través de un
  conector
weight: 1
aliases:
- /es/en/connecting_your_tools/import_intro
---

Una de las cosas que entendemos en DefectDojo es que las necesidades de seguridad de cada empresa son completamente diferentes. No existe un enfoque único que sirva para todos. A medida que su organización cambia, contar con un enfoque flexible es clave, y DefectDojo le permite conectar sus herramientas de seguridad de forma flexible para adaptarse a esos cambios.

## Métodos de carga de escaneos

Cuando DefectDojo recibe un informe de vulnerabilidades de una herramienta de seguridad, crea Hallazgos basados en las vulnerabilidades contenidas en ese informe. DefectDojo actúa como el repositorio central de estos Hallazgos, donde usted y su equipo pueden triarlos, remediarlos o abordarlos de otra manera.

Hay dos formas principales en las que DefectDojo puede cargar informes de Hallazgos.

* Mediante **importación** directa a través de la interfaz
* Mediante el endpoint de la **API** (que permite la ingesta automatizada de datos): consulte [API Docs](/automation/api/api-v2-docs/)

#### Métodos de DefectDojo Pro

Los usuarios de <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> cuentan con tres métodos adicionales para gestionar informes y datos:

* Mediante **Universal Importer** o **DefectDojo CLI**, herramientas de línea de comandos que aprovechan la API de DefectDojo: consulte [Universal Importer & DefectDojo-CLI guides](/import_data/pro/specialized_import/external_tools/)
* Mediante **Connectors** para ciertas herramientas, una integración de datos 'lista para usar': consulte [Connectors Guide](/connectors/upstream/about/)
* Mediante **Smart Upload** para ciertas herramientas, un importador diseñado para gestionar escaneos de infraestructura: consulte [Smart Upload Guide](/import_data/pro/specialized_import/smart_upload/)

### Comparación de métodos de carga

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Tipos de escaneo compatibles** | Todos: consulte [Supported Tools](/supported_tools/) | Todos: consulte [Supported Tools](/supported_tools/) | Akamai API Security, Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, IriusRisk, JFrog Xray, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **¿Automatización?** | Disponible mediante la API: endpoints `/reimport` `/import` | Se activa desde [CLI Tools](/import_data/pro/specialized_import/external_tools/) o código externo | Connectors es una función inherentemente automatizada | Disponible mediante la API: endpoint `/smart_upload_import` |

### Jerarquía de productos y organización

Cada uno de estos métodos puede crear Jerarquía de productos sobre la marcha. La Jerarquía de productos se refiere a los Tipos de producto, Productos, Compromisos o Tests de DefectDojo: objetos en DefectDojo que ayudan a organizar sus datos en un contexto relevante.

* **Los datos de vulnerabilidad pueden importarse a una Jerarquía de productos existente**. Los Tipos de producto, Productos, Compromisos y Tests pueden crearse todos con antelación, y luego los datos pueden importarse a esa ubicación en DefectDojo.
* **La Jerarquía de productos contextual puede crearse en el momento de la Importación.** Al importar un informe, puede crear un nuevo Tipo de producto, Producto, Compromiso y/o Test. Esto lo gestiona DefectDojo mediante la opción 'auto-create context'. En DefectDojo OS, esta opción solo puede accederse a través de la API. Las importaciones desde la interfaz en DefectDojo OS requerirán que la Jerarquía de productos se cree primero.
