---
title: Activos
description: Comprender los Activos en DefectDojo OS
audience: opensource
weight: 2
aliases:
- /es/asset_modelling/engagements_tests/os__products/
- /es/en/asset_modelling/engagements_tests/os__products/
---

Organizations → **ACTIVOS** → Engagements → Tests → Findings

## Descripción general

Los **Activos** están en el centro de cómo se organiza el trabajo de seguridad dentro de la jerarquía de objetos de DefectDojo. Los Activos representan cualquier proyecto, programa, software o activo físico que su equipo de seguridad esté probando, y alojan todo el trabajo de seguridad y el historial de pruebas relacionado con el objetivo de las pruebas. Ejemplos de Activos pueden incluir:
- Versiones de software
- Software de terceros 
- Máquinas virtuales o activos en producción
- Una única aplicación
- Un microservicio
- Una API
- Una plataforma SaaS
- Una aplicación móvil
- Un sistema interno
- Un servicio de negocio
- Una plataforma orientada al cliente
- Un entorno en la nube o dominio de infraestructura

En general, un Activo debe representar la “cosa” cuya postura de seguridad desea rastrear a lo largo del tiempo. Esto incluye el historial de pruebas asociado, los Hallazgos, las métricas, la propiedad, las integraciones y los flujos de trabajo de remediación relacionados con esa “cosa”.

### Ejemplos de Activos

Los Activos pueden volverse aún más granulares según las necesidades de su organización. Por ejemplo, puede considerar crear Activos de DefectDojo separados en los siguientes escenarios:

- “ExampleAsset” tiene una versión para Windows, una versión para Mac y una versión en la nube
- “ExampleAsset 1.0” usa componentes de software completamente diferentes de “ExampleAsset 2.0”, y ambas versiones cuentan con soporte activo por parte de su empresa.
- El equipo asignado para trabajar en “ExampleAsset version A” es distinto del equipo de Activo asignado para trabajar en “ExampleAsset version B”, y por ello necesita tener asignados permisos de seguridad diferentes.

Si bien también puede optar por representar estas variaciones como Compromisos dentro de un único Activo, el RBAC solo puede configurarse a nivel de Activos u Organizaciones, lo que puede limitar el acceso de los usuarios al Compromiso correspondiente (así como a los Tests y Hallazgos dentro de esos Compromisos) si se organizan de esa manera. Para obtener más información sobre RBAC y permisos en DefectDojo, haga clic [aquí](/admin/user_management/about_perms_and_roles/).

## Datos del Activo 

Los Activos siempre incluirán los siguientes componentes:

- **Nombre único**
- **Descripción**
- **Organización**
- **Configuración de SLA**

Los metadatos opcionales del Activo incluyen: 

- **Etiquetas**
- **Información de personal** (por ejemplo, Asset Manager, Team Manager, Technical Contact, etc.)
- **Regulaciones** (por ejemplo, HIPAA, GLBA, OPPA, etc.)
- **Criticidad del negocio**
- **Plataforma** (por ejemplo, API, Desktop, IoT, Mobile, Web, etc.)
- **Ciclo de vida** (por ejemplo, Construction, Production, Retirement, etc.)
- **Origen** (por ejemplo, Third-Party Library, Purchased, Open Source, etc.)
- **Registros de usuario** (es decir, el número estimado de registros de usuario en el Activo)
- **Ingresos**

Estos metadatos mejoran el filtrado, la generación de informes y la priorización en todo su programa de seguridad, pero lo más importante es que los Activos también contienen todos los Compromisos, Tests y Hallazgos relacionados con los esfuerzos de prueba en torno a ese Activo. Todos los Hallazgos de los Tests finalmente se consolidan al nivel del Activo, lo que permite el seguimiento a largo plazo, el análisis de tendencias y la generación de informes.

## Acceder a los Activos 

Se puede acceder a los Activos a través de la barra lateral. El submenú también ofrece la opción de crear un nuevo Activo.

![imagen](images/asset_ss3.png)

### Permisos 

Los Activos pueden tener reglas de Control de acceso basado en roles (RBAC) aplicadas, que limitan la capacidad de los miembros del equipo para verlos e interactuar con ellos.

Los permisos se propagan en cascada hacia abajo, lo que significa que el acceso a un Activo otorga automáticamente acceso a todos los objetos dentro de ese Activo (por ejemplo, Compromisos, Tests y Hallazgos).

Para obtener más información sobre los roles de usuario, consulte nuestro [artículo de introducción a los roles](/admin/user_management/about_perms_and_roles/).

## Vista del Activo 

Las vistas de Activo contienen una variedad de tablas y gráficos para interpretar el estado de un Activo de un vistazo. Esto incluye: 

- **Metadatos**
    - Incluye Organización, criticidad del negocio, ingresos y otros detalles agregados desde la configuración del Activo. 
- **Métricas**
    - Una lista de Hallazgos abiertos dentro del Activo, agrupados por severidad 
- **Acuerdo de nivel de servicio por severidad**
    - Aplica la configuración de SLA del Activo desde la configuración a los Hallazgos dentro del Activo. 
- **Tecnologías**
    - Por ejemplo, next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Regulaciones**
- **Progreso del Benchmark**
- **Miembros**
- **Grupos**
- **Contactos**
- **Notificaciones**
    - Activa y desactiva las notificaciones según eventos específicos (por ejemplo, se ha agregado o cerrado un Compromiso) 

## Trabajar con Activos

### Crear Activos 

Hay varias formas de crear un nuevo Activo, entre ellas: 

- El botón **Agregar Activo** en la lista Todos los Activos 

![imagen](images/asset_ss2.png)

- Desde el menú desplegable de la tabla de Activos dentro de la vista de una Organización 
    - Esto creará automáticamente el Activo dentro de esa Organización. 

![imagen](images/asset_ss1.png)

- El botón **Agregar Activo** en la barra lateral 

![imagen](images/asset_ss5.png)

### Editar Activos 

Un Activo se puede editar desde su configuración, a la que se puede acceder de dos maneras: 

- El botón **Editar** dentro del menú kebab ⋮ a la izquierda del Activo en la vista Todos los Activos

![imagen](images/asset_ss6.png)

- El botón **Editar** dentro del menú desplegable **Configuración** en la vista del Activo

![imagen](images/asset_ss7.png)

### Eliminar Activos 

La opción para eliminar un Activo se encuentra en la parte inferior de los mismos menús descritos en la sección **Editar Activos** anterior. Esta acción no se puede deshacer. El Activo no se puede cerrar y volver a abrir más tarde.

Eliminar un Activo también eliminará lo siguiente: 
- Cualquier Compromiso y Test contenidos dentro del Activo
- Todo el historial de seguridad asociado, incluidos los Hallazgos y las integraciones
- Cualquier Jira Epic vinculado
- Todas las notas y archivos cargados asociados con los Compromisos y Tests del Activo

## Límites del Activo 

### Deduplicación 

Los Activos están “aislados” y no interactúan con otros Activos. Las Smart Features de DefectDojo, como la Deduplicación, solo se aplican dentro del contexto de un único Activo. Los Hallazgos de distintos Activos no se deduplicarán automáticamente.

### Métricas 

La mayoría de los informes y métricas agregan datos a nivel de Activo, lo que convierte a los Activos en la unidad principal para medir y rastrear el riesgo.

Como resultado, muchas métricas clave se calculan por Activo, entre ellas:

- Número total de Hallazgos (por severidad o estado)
- Tiempo medio de remediación (MTTR)
- Tasas de cumplimiento e incumplimiento de SLA
- Tendencias de riesgo a lo largo del tiempo

Esto significa que la forma en que se estructuran los Activos afectará directamente la precisión y utilidad de los informes. Por ejemplo, agrupar varios sistemas no relacionados bajo un único Activo puede oscurecer la visibilidad del riesgo, mientras que estructuras de Activos demasiado granulares pueden fragmentar los informes, dificultando la identificación de tendencias más amplias.

Se puede acceder a las métricas específicas del Activo desde el botón **Métricas** en la barra superior de la vista del Activo elegido. 

![imagen](images/asset_ss8.png)

### Pipeline de CI/CD

Los pipelines de CI/CD automatizan la importación de resultados de escaneo. Independientemente del método de integración, todas las importaciones de escaneo deben asociarse con un Activo, lo que convierte al Activo en el punto de anclaje de los datos de seguridad impulsados por el pipeline.

Cuando un pipeline envía resultados de escaneo, debe hacer una de dos cosas:

- Especificar un Activo existente (y opcionalmente un Compromiso), o
- Estar configurado de manera que asigne los resultados de forma consistente al Activo correcto

Todos los Hallazgos importados heredarán el contexto del Activo, incluida la propiedad, los permisos, la configuración de SLA y el alcance de los informes.

En la práctica, los Activos deben definirse de manera que reflejen cómo se construyen y despliegan los sistemas dentro de CI/CD, para garantizar que los resultados de seguridad se asocien de forma consistente con la aplicación o el servicio correcto.

### Relaciones con Jira 

Los Activos se pueden asignar directamente a Jira Projects, que envían los Hallazgos del Activo a una instancia de Jira.

Dado que los Hallazgos heredan el riesgo, la prioridad y la propiedad de su Activo padre, el Activo determina efectivamente el contexto de remediación que fluye hacia los tickets de Jira y los flujos de trabajo de Downstream Connector.

Es importante destacar que los Activos también son el factor determinante principal en las características de SLA de un Hallazgo. Por lo tanto, el SLA de un Hallazgo depende de la configuración de SLA de su Activo padre. Puede encontrar más información sobre las configuraciones de SLA [aquí](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content). 
