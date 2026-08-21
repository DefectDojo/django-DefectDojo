---
title: ❓ Preguntas frecuentes
description: Preguntas frecuentes de DefectDojo
draft: 'false'
weight: 2
chapter: true
aliases:
- /es/en/about_defectdojo/faq
---

A continuación, algunas preguntas frecuentes sobre cómo trabajar con DefectDojo, tanto en DefectDojo Pro como en DefectDojo OS.

## Preguntas generales

### ¿Cómo debo organizar mis pruebas de seguridad en DefectDojo?

Si bien DefectDojo puede adaptarse a cualquier entorno de seguridad o de pruebas, cada equipo de seguridad y cada operación son diferentes, por lo que no existe un enfoque único para usarlo. Contamos con un artículo muy detallado sobre [casos de uso comunes](/get_started/common_use_cases/common_use_cases/) que incluye ejemplos de cómo distintas organizaciones aplican RBAC y el modelo de datos de DefectDojo para cubrir sus necesidades.

### ¿Cuáles son los flujos de trabajo recomendados para las pruebas de seguridad en DefectDojo?

DefectDojo está diseñado para ser la fuente central de verdad sobre la postura de seguridad de su organización, y puede cubrir distintas necesidades según los requisitos de su organización, tales como:

- Permitir que los usuarios identifiquen hallazgos duplicados entre escaneos y herramientas, minimizando la fatiga por alertas.
- Aplicar SLAs sobre las vulnerabilidades, garantizando que su organización gestione cada Hallazgo dentro de un plazo adecuado.
- [Enviar tickets](/connectors/issue_tracking/) a Jira, ServiceNow u otro software de seguimiento de proyectos, permitiendo que su equipo de desarrollo integre la remediación de incidencias en su proceso de lanzamiento estándar sin necesidad de aprender otra herramienta de gestión de proyectos.
- Integrarse con [pipelines de CI/CD](/import_data/import_scan_files/api_pipeline_modelling/) automatizados para ingerir automáticamente los datos de los informes provenientes de repositorios, incluso a nivel de rama.
- Crear [informes](/metrics_reports/reports/) sobre cualquier conjunto de vulnerabilidades o contexto de software, para compartir rápidamente los resultados de los escaneos o actualizaciones de estado con las partes interesadas.
- Establecer flujos de trabajo de aceptación y mitigación, dando soporte a un seguimiento formal de la gestión de riesgos.


DefectDojo está diseñado para dar soporte y estandarizar su flujo de trabajo de seguridad actual. Todos estos métodos se pueden usar para mejorar los procesos de su equipo y adaptarse a la forma en que opera actualmente.

### ¿Qué funciones están disponibles en DefectDojo Pro?

DefectDojo Pro amplía aún más los flujos de trabajo anteriores, añadiendo:

- Una [UI mejorada](/get_started/about/ui_pro_vs_os/) diseñada para la velocidad y la eficiencia al navegar por volúmenes de datos de nivel empresarial. También incluye un modo oscuro.
- La capacidad de [pretriajear sus Hallazgos](/asset_modelling/pro_hierarchy/priority_sla/) por Prioridad y Riesgo, permitiendo que su equipo identifique y corrija primero los problemas más críticos.
- Un [Motor de reglas](/automation/rules_engine/about) para programar acciones masivas automatizadas y crear flujos de trabajo personalizados para gestionar Hallazgos y otros objetos, sin necesidad de experiencia en programación.
- [Capacidades mejoradas de generación de informes y métricas](/get_started/about/ui_pro_vs_os/#new-dashboards) para compartir fácilmente la postura de seguridad de sus aplicaciones y repositorios.
- [Ajustes avanzados de deduplicación](/triage_findings/finding_deduplication/pro__deduplication_tuning/) para afinar cómo DefectDojo identifica y gestiona los hallazgos duplicados.
- Capacidades de importación optimizadas, tales como:
  - Un método de carga optimizado que procesa los Hallazgos en segundo plano.
  - La capacidad de crear rápidamente un [pipeline de línea de comandos](/import_data/pro/specialized_import/external_tools/) usando nuestras aplicaciones Universal Importer y DefectDojo CLI, lo que le permite importar, reimportar y exportar datos fácilmente hacia su instancia de DefectDojo Pro.
  - Un [Universal Parser](/import_data/pro/specialized_import/universal_parser/) para convertir cualquier informe .json o .csv en un conjunto procesable de Hallazgos, haciendo que DefectDojo Pro analice los datos de la forma que usted prefiera.
  - [Conectores](/connectors/upstream/about/), que ofrecen una conexión instantánea con las herramientas compatibles para importar nuevos datos de Hallazgos, de modo que pueda establecer un pipeline de importación automatizado sin necesidad de configurar llamadas a la API ni tareas cron.

### ¿Cómo gestiona DefectDojo el control de acceso?

DefectDojo puede ser utilizado por equipos grandes, y se recomienda encarecidamente configurar [RBAC (Control de acceso basado en reglas)](/admin/user_management/about_perms_and_roles/), tanto para establecer correctamente el contexto de cada miembro del equipo como para controlar el acceso a determinadas partes de la infraestructura.

La asignación de roles y permisos generalmente se realiza a nivel de Tipo de producto / Producto.  Cada miembro del equipo puede asignarse a uno o más Productos o Tipos de producto, y se le puede otorgar un rol que determina cómo puede interactuar con los datos de vulnerabilidades correspondientes (solo lectura, lectura-escritura o control total).  Para obtener más información, consulte nuestra [guía de RBAC](/admin/user_management/about_perms_and_roles/).

### ¿Cómo gestiona DefectDojo el control de acceso para un equipo de usuarios?

Ya sea que forme un equipo de seguridad de una sola persona en una organización pequeña o que sea un CISO a cargo de numerosos proyectos de software, puede organizar fácilmente el [Control de acceso basado en roles (RBAC)](/admin/user_management/about_perms_and_roles/) para establecer correctamente el contexto de cada miembro del equipo y controlar el acceso a determinadas partes de la infraestructura.

Por lo general, la asignación de roles y permisos se realiza a [nivel de Tipo de producto/Producto](/asset_modelling/os_hierarchy/product_hierarchy/). A cada miembro del equipo se le puede otorgar un rol correspondiente a uno o más Productos o Tipos de producto que determina cómo puede interactuar con los datos de vulnerabilidades correspondientes (por ejemplo, solo lectura, lectura-escritura o control total).

## Flujos de trabajo de importación

### ¿Qué herramientas son compatibles con DefectDojo?

DefectDojo admite informes de [más de 500](/supported_tools/) herramientas de seguridad comerciales y de código abierto.

Si está buscando añadir una nueva herramienta a su conjunto, tenemos una lista de herramientas Open-Source recomendadas que puede consultar [aquí](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards).

### ¿Cuál es la diferencia entre Import y Reimport?

Existen dos métodos distintos para importar un único informe de una herramienta de seguridad:

- **Import** trata el informe como un registro puntual en el tiempo. Importar un informe crea un Test que contiene los Hallazgos resultantes.
- **[Reimport](/import_data/import_intro/reimport/)** se utiliza para actualizar un Test existente con un nuevo conjunto de resultados. Si su proceso de pruebas tiene un enfoque más abierto, puede reimportar (Reimport) continuamente la última versión de su informe a un Test existente. DefectDojo comparará los resultados del informe entrante con sus datos existentes, registrará cualquier cambio y luego ajustará los Hallazgos del Test para que coincidan con el informe más reciente.

Para entender la diferencia, resulta útil pensar en Import como el registro de una única instancia de un evento de escaneo, y en Reimport como la actualización de un registro continuo de escaneos.

A modo de analogía: si fuera contador, podría usar Import para registrar un único recibo, mientras que usaría Reimport para llevar un libro contable continuo de gastos

Ambos métodos también utilizan la Deduplicación de forma diferente: mientras que dos Tests Importados por separado dentro del mismo Producto identificarán y etiquetarán los Hallazgos duplicados de manera independiente, Reimport no creará ningún Hallazgo que identifique como [duplicado](/triage_findings/finding_deduplication/avoid_excess_duplicates/) dentro del Test.

En términos generales, si lo que necesita es un informe puntual, Import es el mejor método a utilizar. Si ejecuta e ingiere informes de una herramienta de forma continua, Reimport es el mejor método para mantener todo organizado.

### ¿Cómo puedo solucionar errores de Import?

DefectDojo admite una amplia variedad de herramientas. Si observa un comportamiento inconsistente al importar un informe, le recomendamos verificar que la estructura del archivo coincida con lo que la herramienta espera. Consulte nuestra [lista de parsers](/supported_tools/) para confirmar que su herramienta es compatible, y verifique que el formato del archivo coincida con lo que la herramienta espera. También puede comparar la estructura con nuestros Unit Tests.

DefectDojo Pro cuenta con un método de importación Universal Parser que le permite gestionar cualquier archivo JSON, CSV o XML. Los usuarios de DefectDojo OS pueden escribir parsers personalizados con el mismo fin.

Por último, se sabe que los formatos de informes de terceros pueden cambiar sin previo aviso: nuestra comunidad OS agradece enormemente los [PRs y contribuciones](/get_started/contributing/how-to-write-a-parser/) que ayudan a mantener actualizados nuestros parsers.

### ¿Cómo debo manejar archivos de escaneo grandes?

Importar un informe grande en DefectDojo puede ser un proceso largo. Los informes de 2MB contienen cantidades considerables de datos, cuya conversión en Hallazgos puede tardar bastante, según el formato del informe de la herramienta de seguridad.

Nuestro enfoque recomendado es dividir los informes grandes antes de importarlos, para reflejar las distintas subsecciones de datos disponibles. Si su herramienta de seguridad puede filtrar los resultados por proyecto de software, aplicación u otro contexto, exportar informes más pequeños facilita que DefectDojo gestione y categorice los datos. Esto también tiene el beneficio adicional de organizar proactivamente sus Hallazgos según cómo se dividieron los datos, lo que permite generar informes más relevantes y rápidos.

DefectDojo Pro puede procesar informes en segundo plano. Sin embargo, los archivos aún deben cargarse y ser validados por DefectDojo antes de que pueda comenzar el proceso de creación de Hallazgos en segundo plano.

### ¿Cómo conecto un pipeline de CI/CD a DefectDojo?

Muchas de las funciones principales de DefectDojo se pueden automatizar por completo.  El CI/CD (o cualquier tipo de importación automatizada) se puede gestionar llamando a la [API REST de DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/).

Los usuarios de **DefectDojo Pro** también tienen acceso a las **[herramientas de línea de comandos](/import_data/pro/specialized_import/external_tools/)** de **Universal Importer / DefectDojo CLI**, que se pueden instalar para ejecutarse en numerosos entornos automatizados.

## Gestión de Hallazgos

### ¿Qué significa el estado de un Hallazgo?

Los Hallazgos pueden tener numerosos estados. Un Hallazgo siempre tiene asignado un estado de Activo o Inactivo, mientras que otros estados como Verificado, Falso positivo o Fuera de alcance se pueden aplicar a su criterio.

Estos estados se describen con más detalle en nuestra guía de [Definiciones de estado de Hallazgo](/triage_findings/findings_workflows/finding_status_definitions/), junto con información sobre cómo se pueden utilizar.

### ¿Cómo puedo eliminar Hallazgos de DefectDojo?

En términos generales, recomendamos conservar los Hallazgos cerrados como 'Inactivo' en lugar de eliminarlos directamente, ya que es importante mantener registros históricos en el trabajo de AppSec. Eliminar un Hallazgo elimina por completo todas las notas y el seguimiento de métricas de ese Hallazgo, lo que puede generar informes inexactos o un archivo incompleto.

Los Hallazgos de DefectDojo se pueden eliminar de varias maneras:
- Ejecutando una acción de [Eliminación masiva](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings) sobre los Hallazgos que desea eliminar
- Llamando a `DELETE /findings/{id}` a través de la API
- Eliminando un objeto principal, como un Test, Compromiso, Tipo de producto o Producto.
  - Tenga en cuenta que las subclases no se conservan independientemente de su objeto principal: eliminar un objeto principal como un Tipo de producto eliminará todos los Productos, Compromisos, Tests, Hallazgos y Endpoints dentro de ese Tipo de producto. Por el contrario, eliminar un Compromiso conservará los Productos y Tipos de producto que lo preceden.

## Informes y Jira

### ¿Cómo puedo generar un informe en DefectDojo?

Puede crear rápidamente un informe personalizado en DefectDojo utilizando el [Generador de informes](/metrics_reports/reports/).

Los usuarios de DefectDojo Pro también tienen acceso a [paneles de Métricas de nivel ejecutivo](/get_started/about/ui_pro_vs_os/#new-dashboards) que pueden informar sobre Tipos de producto, Productos u otros datos en tiempo real.

### ¿Cómo puedo integrar una herramienta de gestión de proyectos con DefectDojo?

Tanto en la edición Pro como en la edición Open-Source de DefectDojo, los Hallazgos de DefectDojo se pueden enviar a Jira como Issues, lo que le permite integrar la remediación de incidencias con su equipo de desarrollo.

DefectDojo Pro añade soporte para [Integraciones adicionales de seguimiento de proyectos](/connectors/issue_tracking/)**: ServiceNow, Azure DevOps, GitHub y GitLab.
