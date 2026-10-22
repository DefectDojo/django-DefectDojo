---
title: Casos de uso comunes
description: Casos de uso y ejemplos
draft: 'false'
weight: 2
chapter: true
aliases:
- /es/en/about_defectdojo/examples_of_use
---

Este artículo se basa en el Office Hours de febrero de 2025 de DefectDojo, Inc.: «Abordando casos de uso comunes».
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=ilRBlfo-wvX5DPVg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Ejemplos de casos de uso

DefectDojo está diseñado para gestionar cualquier implementación de seguridad, sin importar el tamaño de su equipo de seguridad, el nivel de complejidad de TI o el volumen de informes. Las siguientes historias pretenden ser puntos de partida para sus propias necesidades, pero se basan en ejemplos reales de nuestra comunidad y del equipo de DefectDojo Pro.

### Gran empresa: RBAC y Compromisos

«BigCorp» es una gran empresa multinacional, con un Chief Information Security Officer (CISO) y un grupo centralizado de seguridad de TI que incluye AppSec.

La seguridad en BigCorp está altamente centralizada. Ciertas tareas se delegan a Business Information Security Officers (BISO).

Las principales preocupaciones de BigCorp son:

- Establecer y mantener un método de testing coherente en todas las unidades de negocio de la organización
- Cumplir los requisitos de cumplimiento normativo y evitar problemas regulatorios

#### Modelo de testing

BigCorp gestiona datos de seguridad procedentes de muchas fuentes:

- Jobs de CI/CD que ejecutan herramientas de SAST, SCA y detección de secretos automáticamente
- Pen testing de terceros para determinados Productos
- Auditorías de cumplimiento PCI para determinados Productos

Cada una de estas categorías de informes puede gestionarse mediante un Compromiso independiente, con un Test independiente para cada tipo de escaneo en DefectDojo.

![image](images/example_product_hierarchy_bigcorp.png)

- Si un Producto cuenta con un pipeline de CI/CD, todos los resultados de ese pipeline pueden importarse de forma continua a un único Compromiso abierto. Cada herramienta utilizada creará un Test independiente dentro del Compromiso de CI/CD, que puede actualizarse continuamente con nuevos datos.
(Consulte nuestra guía de [Reimportación](/import_data/import_intro/reimport/))
- Cada esfuerzo de Pen Test puede tener un Compromiso independiente creado para contener todos los resultados: por ejemplo, «Q1 Pen Test 2024», «Q2 Pen Test 2024», etc.
- Es probable que BigCorp quiera realizar su propia auditoría PCI simulada para estar preparados de cara a la auditoría real. Los resultados de esas auditorías también pueden almacenarse como un Compromiso independiente.

#### Modelo de RBAC

- Cada BISO tiene acceso de Lector asignado para cada unidad de negocio (Tipo de producto) de la que está a cargo.
- Cada Propietario de producto tiene acceso de Escritor para el Producto del que está a cargo. Dentro de su Producto, los Propietarios de producto pueden interactuar con DefectDojo manteniendo notas, configurando [pipelines de CI/CD](/import_data/import_scan_files/api_pipeline_modelling/), creando Aceptaciones de riesgo y usando otras funciones.
- Los desarrolladores de BigCorp no tienen ningún acceso a DefectDojo, y no lo necesitan. El Propietario de producto puede enviar tickets de Jira directamente desde DefectDojo que contienen toda la información relevante sobre la vulnerabilidad. Los desarrolladores ya utilizan Jira, así que no tienen que hacer seguimiento de la remediación de forma distinta a cualquier otra tarea de desarrollo.

### Sistemas embebidos: informes con control de versiones

Cyber Robotics es una empresa que vende hardware de fabricación que incluye sistemas de software embebido. Cuentan con un Chief Product Officer (CPO) que supervisa tanto su producto como la ciberseguridad en conjunto.

Aunque manejan información de seguridad menos diversa que BigCorp, sigue siendo esencial para ellos contextualizar adecuadamente su información de seguridad para poder responder de forma proactiva ante cualquier Hallazgo significativo.

Principales preocupaciones de Cyber Robotics:

- Tienen una línea de productos limitada, pero **muchas** versiones de cada producto que necesitan catalogar adecuadamente.
- El mantenimiento de sus productos es complejo y los costos son elevados, por lo que hay que evitar trabajo innecesario.

#### Modelo de testing

Cyber Robotics cuenta con un proceso de testing estandarizado para todos sus sistemas embebidos:

- Se ejecutan tests de CI/CD, SAST y SCA
- Revisiones de controles de seguridad
- Escaneos de red
- Revisión de código por terceros

Sin embargo, como cada versión de su software está aislada, inevitablemente tendrán muchos datos que organizar, gran parte de los cuales solo son útiles en un único contexto (es decir, la versión concreta del software que están ejecutando).

Cyber Robotics puede resolver este problema utilizando Tipos de producto para representar una única línea de producto, y Productos individuales para cada versión independiente. Esto les permitirá profundizar para determinar qué Productos están asociados a una vulnerabilidad concreta.

![image](images/example_product_hierarchy_robotics.png)

Asignar las versiones de software a Productos, en lugar de a Compromisos, permite a Cyber Robotics limitar el acceso a una versión de software concreta, si es necesario. Al personal técnico de campo y de soporte se les puede conceder acceso a una única versión del software sin tener que darles acceso a toda la línea de producto.

#### Modelo de RBAC

El equipo de AppSec aquí tiene Roles globales asignados que rigen su nivel de interacción.

- El CPO tiene acceso de Lector global a DefectDojo, igual que el CISO en BigCorp.
- Los Propietarios de producto individuales tienen acceso de Lector global a cualquier Producto en DefectDojo, además de acceso de Escritor al Producto que poseen.

Por el lado de soporte:

- Al personal de soporte se le concede temporalmente acceso de Lector a los Productos específicos que se les asigna mantener, pero no tienen acceso a todos los datos de DefectDojo.

### Entornos de TI dinámicos y microservicios: empresa de servicios en la nube

Kate's Cloud Service opera un entorno que cambia rápidamente y que utiliza Kubernetes, microservicios y automatización. Kate's Cloud Service cuenta con un VP of Cloud que supervisa los problemas de seguridad en la nube. También tienen un CISO que gestiona el desarrollo de software que ofrecen, pero para este ejemplo nos centraremos específicamente en sus preocupaciones de seguridad en la nube.

Kate's Cloud Service ha automatizado por completo sus informes e ingiere datos en DefectDojo tan pronto como se generan los informes.

Principales preocupaciones de Kate's Cloud Service:

- Gestionar la seguridad multiinquilino en la nube, evitando la interacción entre clientes al tiempo que se permite la prestación de servicios compartidos.
- Gestionar los cambios rápidos en su entorno de nube.

#### Etiquetado de servicios compartidos

Dado que el modelo de Kate contiene muchos servicios compartidos que pueden afectar a otros Productos, el equipo [etiqueta](/asset_modelling/tags/os__tagging_objects/) sus Productos para indicar qué ofertas de nube dependen de esos servicios. Esto permite filtrar cualquier problema con los servicios compartidos entre Productos e informar a los equipos correspondientes. Cada uno de estos servicios compartidos se encuentra en un único Tipo de producto que los separa de las ofertas principales de nube.

![image](images/example_product_hierarchy_microservices.png)

Dado que la empresa crece rápidamente y los tech leads cambian con frecuencia, Kate puede usar Etiquetas para hacer seguimiento de qué tech lead es responsable actualmente de cada producto de nube, evitando la necesidad de actualizaciones manuales constantes en su sistema DefectDojo. Estas asociaciones de tech lead son gestionadas por un servicio externo a DefectDojo que puede gobernar los pipelines de importación o llamar a la API de DefectDojo.

Para más información sobre el etiquetado, consulte nuestra guía de [Etiquetas](/asset_modelling/tags/os__tagging_objects/).

#### Modelo de RBAC

Por el lado de seguridad/cumplimiento:

- El equipo de Seguridad de producto que posee DefectDojo tiene acceso de administrador a todo el sistema.
- Los analistas que trabajan para el VP of Cloud tienen acceso de solo lectura a todo el sistema, lo que les permite generar los informes y métricas necesarios para que el VP evalúe la seguridad de las distintas ofertas de nube.

Por el lado de desarrollo:

- Los tech leads de cada producto de nube específico (por ejemplo, cómputo, almacenamiento, servicios compartidos) tienen **acceso de Mantenedor** a su Producto asignado para poder triar los resultados de seguridad relacionados con su oferta de producto de nube específica. Pueden revisar Hallazgos y tomar medidas dentro de su Producto, y también pueden reorganizar sus datos de Hallazgos de forma significativa.
- Los desarrolladores que trabajan en Productos específicos reciben **acceso de Escritor** al Producto en el que trabajan, lo que les permite comentar en los Hallazgos, solicitar Revisiones por pares y crear Aceptaciones de riesgo.

### Incorporación de nuevas adquisiciones: SaaSy Software

SaaSy Software es una empresa en rápido crecimiento que adquiere con frecuencia otras empresas de software. Cada vez que se adquiere una nueva empresa, el Director de ingeniería de calidad y el equipo de AppSec quedan repentinamente a cargo de muchos repositorios de código, desarrolladores y procesos nuevos. Su modelo de DefectDojo garantiza que puedan ponerse al día lo antes posible.

Principales preocupaciones de SaaSy Software:

- Evitar problemas de seguridad públicos manteniendo al mismo tiempo programas de cumplimiento (como SOC2).
- Capacidad de incorporar con confianza herramientas y procesos de nuevos productos.
- Capacidad de informar y categorizar vulnerabilidades tanto en ramas en producción como en desarrollo.

#### Modelo de testing

El testing en SaaSy se centra en trazos generales en lugar de en el uso estandarizado de herramientas, ya que cada adquisición llega con sus propias herramientas y procesos de AppSec. SaaSy necesita realizar tanto evaluaciones internas (CI/CD, DAST, escaneos de contenedores y modelado de amenazas) como evaluaciones externas (pen tests de terceros, auditorías de cumplimiento).

Para ayudar con la incorporación de nuevas aplicaciones, SaaSy Software tiene un enfoque estándar para su modelo de datos: cada vez que SaaSy incorpora una nueva aplicación, crea un nuevo Tipo de producto para esa app, y crea subproductos para los repositorios que la componen (Front-End, API de backend, etc.).

![image](images/example_product_hierarchy_saas.png)

Cada uno de estos Productos se subdivide a su vez en Compromisos, uno para la rama principal y uno para cada rama de desarrollo. Los Tests dentro de estos Compromisos se utilizan para categorizar los esfuerzos de testing. Las ramas de desarrollo tienen Tests independientes que almacenan los resultados de los escaneos de CI/CD y SCA. La rama principal también los tiene, pero además añade Tests que almacenan informes de Revisión manual de código y Modelo de amenazas.

Todos estos Tests son abiertos y pueden actualizarse de forma periódica mediante Reimportación. La [deduplicación](/triage_findings/finding_deduplication/about_deduplication/) solo se gestiona a nivel de Compromiso, lo que evita que los Hallazgos de una rama de código cierren Hallazgos en otra.

Al aplicar este modelo de forma coherente, SaaSy cuenta con un modelo que puede aplicar a cualquier nueva adquisición de software, y el equipo de AppSec puede comenzar rápidamente a supervisar los datos para garantizar el cumplimiento.

#### Modelo de RBAC

Por el lado de seguridad/cumplimiento:

- El equipo de AppSec de SaaSy Software posee DefectDojo y tiene acceso de administrador completo al software.
- Los equipos de QE y cumplimiento tienen acceso de solo lectura a todo el sistema, para extraer informes y profundizar en los datos cuando sea necesario.

Por el lado de desarrollo:

- Cada Propietario de producto tiene acceso de Escritor al Producto que posee en DefectDojo, lo que le permite redactar Aceptaciones de riesgo y ver métricas del Producto.
- Los desarrolladores tienen acceso de solo lectura a cada Producto en el que trabajan. Pueden solicitar Revisiones por pares sobre los Hallazgos o problemas que están intentando remediar.
