---
title: Acerca de DefectDojo
date: 2021-02-02 20:46:29+01:00
draft: false
type: docs
weight: 1
aliases:
- /es/en/about_defectdojo/about_docs
---

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

![image](images/Introduction_to_Dashboard_Features.png)

</div>


<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo, Inc. y los colaboradores de código abierto mantienen esta documentación para dar soporte tanto a la edición Community como a la edición Pro de DefectDojo.</span>

## ¿Qué es DefectDojo?

DefectDojo es una plataforma de Operaciones de Seguridad para Desarrolladores (DevSecOps). DefectDojo simplifica DevSecOps al actuar como un agregador automático de su conjunto de herramientas de seguridad, lo que le permite organizar fácilmente su trabajo de seguridad e informar sobre la postura de seguridad de su organización a otras partes interesadas.

Si bien la automatización de procesos de seguridad y los pipelines de desarrollo integrados son los objetivos finales de DefectDojo, en esencia este software es un rastreador de errores (bug tracker) para vulnerabilidades de seguridad, diseñado para ingerir, organizar y estandarizar informes provenientes de numerosas herramientas de seguridad.

### ¿Qué hace DefectDojo?

DefectDojo cuenta con funciones inteligentes para mejorar y ajustar los resultados de sus herramientas de seguridad, incluida la capacidad de:

- Rastrear e informar sobre Hallazgos de seguridad en contexto
- Aplicar SLAs en contexto
- Gestionar Falsos positivos, Aceptación de riesgo y otras decisiones de triaje
- Depurar duplicados mediante el algoritmo de deduplicación de DefectDojo
- Integrarse con software externo de seguimiento de proyectos.
- Proporcionar métricas/informes entre repositorios y ramas de desarrollo mediante integración CI/CD.
- Coordinar la gestión tradicional de Pen tests.
- Establecer y aplicar SLAs para los procedimientos de remediación de vulnerabilidades.
- Crear y rastrear Aceptación de riesgo para vulnerabilidades de seguridad.

En definitiva, el modelo Producto:Compromiso de DefectDojo le permite inventariar su entorno de desarrollo y ubicar de inmediato los nuevos Hallazgos de seguridad en su contexto correspondiente.

---
A continuación, algunos ejemplos de cómo se puede implementar DefectDojo, con Matt Tesauro, cofundador y CTO de DefectDojo:
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo Open-Source

La funcionalidad principal de DefectDojo está disponible en DefectDojo Open-Source.

Esta edición de DefectDojo incluye:

- Import/Reimport para las más de 500 herramientas compatibles
- API REST
- Funciones de deduplicación
- UI, métricas y funciones de generación de informes limitadas
- Capacidad de integración con Jira

Para los equipos que gestionan un menor volumen de Hallazgos, DefectDojo Open-Source es un excelente punto de partida.

### Guías de instalación

Existen varias formas compatibles de instalar la edición Open-Source de DefectDojo ([disponible en Github](https://github.com/DefectDojo/django-DefectDojo)):

[Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) es el método más sencillo para instalar el programa principal y los servicios necesarios para ejecutar DefectDojo.
Nuestra guía de [Arquitectura](/get_started/open_source/architecture/) le ofrece una visión general de cada servicio y componente utilizado por DefectDojo.
[Ejecución en producción](/get_started/open_source/running-in-production/) enumera los requisitos del sistema, los ajustes de rendimiento y los procesos de mantenimiento para ejecutar DefectDojo en un servidor de producción (con Docker Compose).

Kubernetes no cuenta con soporte completo a nivel de Open-Source, pero esta guía puede consultarse y usarse como punto de partida para integrar DefectDojo en una arquitectura de Kubernetes.

Si tiene problemas con una instalación Open-Source, le recomendamos encarecidamente plantear sus preguntas en el [Slack de OWASP](https://owasp.org/slack/invite). Los miembros de nuestra comunidad están activos en el canal #defectdojo y pueden ayudarle con los problemas que enfrente.

## 🟧 Edición DefectDojo Pro

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

DefectDojo, Inc. aloja una edición Pro de este software con fines comerciales.  Junto con una interfaz moderna y elegante, DefectDojo Pro incluye:

* [Conectores](/connectors/upstream/about/): integraciones de API listas para usar con escáneres de nivel empresarial (como Checkmarx One, BurpSuite, Semgrep y más)
* **Métodos de importación configurables**: [Universal Parser](/supported_tools/parsers/universal_parser/), [Smart Upload](/import_data/pro/specialized_import/smart_upload/)
* **[Herramientas CLI](/import_data/pro/specialized_import/external_tools/)** para una integración rápida con sus sistemas
* **[Integraciones adicionales de seguimiento de proyectos](/connectors/issue_tracking/)**: ServiceNow, Azure DevOps, GitHub y GitLab
* **[Métricas mejoradas](/metrics_reports/pro_metrics/pro__overview/)** para informes ejecutivos y análisis de alto nivel
* **[Prioridad y riesgo](/asset_modelling/pro_hierarchy/priority_sla/)** para identificar los Hallazgos de mayor urgencia en todo el sistema
* **Soporte premium** y orientación de implementación para su organización

La edición Pro está disponible como oferta SaaS alojada en la nube, y también puede instalarse de forma local (on-premises).

Para obtener más información sobre DefectDojo Pro, consulte nuestra [página de precios](https://defectdojo.com/pricing).

## Demos en línea

Hay demos en línea disponibles tanto para las versiones Open-Source como Pro de DefectDojo.  Ambas se pueden usar con las siguientes credenciales:

- Username: `admin`
- Password: `1Defectdojo@demo#appsec`

Estas demos vienen cargadas con datos de ejemplo y se reinician diariamente.

### Demo de Open-Source

Puede encontrar un ejemplo en funcionamiento de DefectDojo (edición Open-Source) en [https://demo.defectdojo.org/](https://demo.defectdojo.org/).

### Demo de Pro

Puede encontrar un ejemplo en funcionamiento de DefectDojo Pro en
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/).

## Aprenda a usar DefectDojo

Ya sea que use la edición Pro o la edición Open-Source, contamos con numerosos recursos para ayudarle a comenzar con DefectDojo.

* Consulte nuestras [integraciones de herramientas de seguridad](/supported_tools/) compatibles para ayudarle a encajar DefectDojo en su programa DevSecOps.
* Nuestro equipo mantiene un [canal de YouTube](https://www.youtube.com/@defectdojo) que alberga tutoriales, eventos de Office Hours archivados y otro contenido.

## Póngase en contacto con nosotros

Para ponerse en contacto con el equipo de DefectDojo, Inc., siempre puede escribir a [hello@defectdojo.com](mailto:hello@defectdojo.com).

Publicamos regularmente en [LinkedIn](https://www.linkedin.com/company/33245534) y también organizamos presentaciones en línea para profesionales de AppSec, a las que se puede acceder en vivo o bajo demanda. Puede conocer los próximos eventos en nuestra [página de eventos](https://defectdojo.com/events) o ver presentaciones anteriores en nuestro [canal de YouTube](https://www.youtube.com/@defectdojo).

### Adhesivos

¿Busca geniales adhesivos de DefectDojo para su laptop? Como agradecimiento por formar parte de la comunidad de DefectDojo, puede registrarse para obtener algunos adhesivos gratuitos de DefectDojo. Para obtener más información, consulte [este enlace](https://defectdojo.com/defectdojo-sticker-request).
