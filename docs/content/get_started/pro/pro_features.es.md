---
title: 📊 Lista de funciones Pro
description: Lista de funciones Pro en DefectDojo
draft: 'false'
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
- /es/en/about_defectdojo/pro_features
---

Aquí tiene una lista de las numerosas funciones adicionales de DefectDojo Pro, junto con enlaces a la documentación para verlas en acción:

## UX mejorada

### UI Pro

La interfaz de DefectDojo se ha rediseñado en DefectDojo Pro para ser más rápida, más funcional, totalmente personalizable y mejor a la hora de navegar por volúmenes de datos de nivel empresarial. También incluye un modo oscuro.
Consulte nuestra [Guía de la UI Pro](/get_started/about/ui_pro_vs_os/) para más información.

![image](images/enabling_deduplication_within_an_engagement_2.png)

### Búsqueda global

Encuentre cualquier Hallazgo, Activo, Compromiso y mucho más desde un único cuadro de búsqueda en la barra superior. La búsqueda global de DefectDojo Pro abarca todos sus objetos con una búsqueda de texto completo en Postgres rápida y tolerante a errores tipográficos.

Consulte nuestra [Guía de búsqueda global](/navigation/pro__global_search/) para más información.

### Activos/Organizaciones

DefectDojo Pro permite una visualización organizativa mejorada para grandes listas de repositorios u otras estructuras de negocio.  Consulte la [documentación de Activos/Organizaciones](/asset_modelling/pro_hierarchy/asset_hierarchy/) para más detalles.

![image](images/asset_hierarchy_diagram.png)

### Prioridad de Hallazgo

DefectDojo Pro puede pretriar sus Hallazgos por Prioridad y Riesgo, permitiendo a su equipo identificar y solucionar primero los problemas más críticos.
Consulte nuestra [Guía de prioridad de Hallazgo](/asset_modelling/pro_hierarchy/priority_sla/) para más detalles.

### Motor de reglas

El Motor de reglas de DefectDojo Pro le permite programar acciones masivas automatizadas y crear flujos de trabajo personalizados para gestionar Hallazgos y otros objetos, sin necesidad de experiencia en programación.

Consulte nuestra [Guía del motor de reglas](/automation/rules_engine/about) para más información.

![image](images/rules_engine_4.png)

### Sensei

**Sensei** (BETA) de DefectDojo Pro es una capacidad de escaneo y corrección impulsada por IA: conecte un repositorio mediante una GitHub App y Sensei lo escanea, importa los hallazgos y abre pull requests que los remedian — con un flujo de trabajo de vista previa primero, de modo que nada se ejecuta (y no se incurre en ningún costo de LLM) hasta que usted lo aprueba.

Consulte nuestra [Guía de Sensei](/sensei/about_sensei/) para más información.

### Paneles e informes Pro

Genere [informes y métricas instantáneos](/get_started/about/ui_pro_vs_os/#new-dashboards) para compartir la postura de seguridad de sus aplicaciones y repositorios, evaluar sus herramientas de seguridad y analizar el rendimiento de su equipo a la hora de abordar los problemas de seguridad.

Los gráficos de la página de inicio se pueden exportar como archivos SVG, y los datos utilizados para crear los gráficos también se pueden exportar como tabla.

Además, DefectDojo Pro incluye varios [paneles de información](/metrics_reports/pro_metrics/pro__overview/) nuevos, que ofrecen métricas mejoradas para las distintas audiencias de su programa de seguridad.

### Ajuste de deduplicación

La configuración avanzada de deduplicación le permite ajustar con precisión cómo identifica y gestiona DefectDojo los hallazgos duplicados. Ajuste la deduplicación de la misma herramienta, **entre herramientas** y de reimportación para lograr una coincidencia precisa entre todas las herramientas de seguridad elegidas y los hallazgos de vulnerabilidades.

Consulte nuestra [Guía de ajuste de deduplicación](/triage_findings/finding_deduplication/pro__deduplication_tuning/) para más información.

![image](images/deduplication_tuning.png)

## Importación optimizada

### Más opciones de importación

DefectDojo Pro incluye cuatro métodos de importación adicionales: [Universal Importer](/import_data/pro/specialized_import/external_tools/), [Upstream Connectors](/connectors/upstream/about/), [Universal Parser](/supported_tools/parsers/universal_parser/) y [Smart Upload](/import_data/pro/specialized_import/smart_upload/).

![image](images/pro_import_methods.png)


### Importaciones en segundo plano

Para informes de nivel empresarial, DefectDojo Pro ofrece un método de carga optimizado que procesa los Hallazgos en segundo plano.

### Herramientas de CLI

Cree rápidamente un pipeline de línea de comandos para importar, reimportar y exportar datos a su instancia de DefectDojo Pro usando nuestras aplicaciones Universal Importer y DefectDojo-CLI; no es necesario programar contra la API (disponible para Windows, Macintosh o Linux).

Consulte nuestra [Guía de herramientas externas](/import_data/pro/specialized_import/external_tools/) para más información.

### Upstream Connectors

DefectDojo puede conectarse al instante a herramientas de escaneo de nivel empresarial para importar nuevos datos de Hallazgos, creando un pipeline de importación automatizado que funciona de fábrica sin necesidad de configurar llamadas a la API ni cron jobs.

Consulte nuestra [Guía de Upstream Connectors](/connectors/upstream/about/) para más información.

![image](images/add_edit_connectors_2.png)

Las herramientas compatibles con Upstream Connectors incluyen:

* Anchore
* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### Universal Parser (Beta)

Si utiliza una herramienta de escaneo no compatible o personalizada, o simplemente desea que DefectDojo gestione un informe de forma ligeramente distinta, use el Universal Parser de DefectDojo Pro para convertir cualquier informe .json o .csv en un conjunto procesable de Hallazgos. Su parser analizará y mapeará los datos como usted prefiera.

Consulte nuestra [Guía de Universal Parser](/import_data/pro/specialized_import/universal_parser//) para más información.

![image](images/universal_parser_3.png)

## Gestión de funciones opcionales

Muchas de las capacidades anteriores son opcionales y se distribuyen detrás de un feature flag, de modo que puede adoptarlas cuando esté listo. Un superusuario puede activar y desactivar la mayoría directamente desde **Settings > Feature Flags**, sin necesidad de contactar con soporte.

Consulte la guía de [Feature Flags](/admin/feature_flags/pro__feature_flags/) para saber cómo habilitar una función, y por qué una función puede estar bloqueada o no disponible según su tipo de instalación.

## Soporte

Las suscripciones de DefectDojo Pro incluyen soporte de primer nivel tanto para instalaciones on-premise como en la nube.  Nuestro equipo está disponible para ayudar a su organización a implementar y maximizar el uso de DefectDojo Pro.  Su suscripción incluye:

- **Soporte integral**: tickets de soporte y asientos ilimitados disponibles para ayudar a todo su equipo.
- **Enfoque de ingeniería dedicado**: los problemas reportados por los usuarios, los errores y las solicitudes de funciones reciben atención prioritaria de nuestro equipo de ingeniería.
- **Gestión de SaaS**: proporcionamos monitorización, mantenimiento y copias de seguridad para todas las instancias SaaS.
