---
title: Activos
description: Cómo entender los Activos en DefectDojo Pro
audience: pro
weight: 2
---

Organizaciones → **ACTIVOS** → Compromisos → Tests → Hallazgos

## Resumen

Los **Activos** se ubican en el centro de cómo se organiza el trabajo de seguridad dentro de la jerarquía de objetos de DefectDojo. Los Activos representan cualquier proyecto, programa, software o activo físico que su equipo de seguridad esté probando, y albergan todo el trabajo de seguridad y el historial de pruebas relacionado con el objetivo de las pruebas. Algunos ejemplos de Activos pueden incluir:
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
- Un entorno de nube o dominio de infraestructura

En general, un Activo debe representar la “cosa” cuya postura de seguridad se desea rastrear a lo largo del tiempo. Esto incluye el historial de pruebas asociado, los Hallazgos, las métricas, la propiedad, las integraciones y los flujos de trabajo de remediación relacionados con esa “cosa”.

### Ejemplos de Activos

Los Activos pueden volverse aún más granulares según las necesidades de su organización. Por ejemplo, puede considerar crear Activos de DefectDojo independientes en los siguientes escenarios:

- “ExampleAsset” tiene una versión para Windows, una versión para Mac y una versión en la nube
- “ExampleAsset 1.0” utiliza componentes de software completamente distintos de “ExampleAsset 2.0”, y ambas versiones cuentan con soporte activo por parte de su empresa.
- El equipo asignado para trabajar en “ExampleAsset version A” es distinto del equipo de Activo asignado para trabajar en “ExampleAsset version B”, y por ello necesita tener asignados permisos de seguridad diferentes.

Aunque también puede optar por representar estas variaciones como Compromisos dentro de un único Activo, el RBAC solo se puede configurar a nivel de Activos u Organizaciones, lo que puede limitar el acceso de los usuarios al Compromiso adecuado (así como a los Tests y Hallazgos dentro de esos Compromisos) si se organizan de esa manera. Para obtener más información sobre RBAC y permisos en DefectDojo, haga clic [aquí](/admin/user_management/about_perms_and_roles/).

## Datos del Activo

Los Activos siempre incluirán los siguientes componentes:

- **Organización**
- **Nombre único**
- **Descripción**
- **Configuración de SLA**
- **Motor de priorización**

Los metadatos opcionales del Activo incluyen:

- **Etiquetas**
- **Criticidad de negocio**
- **Registros de usuario** (es decir, el número estimado de registros de usuario en el Activo)
- **Ingresos**
- **Información del personal** (por ejemplo, Asset Manager, Team Manager, Technical Contact, etc.)
- **Regulaciones** (por ejemplo, HIPAA, GLBA, OPPA, etc.)
- **Plataforma** (por ejemplo, API, Desktop, IoT, Mobile, Web, etc.)
- **Ciclo de vida** (por ejemplo, Construction, Production, Retirement, etc.)
- **Origen** (por ejemplo, Third-Party Library, Purchased, Open Source, etc.)

Estos metadatos mejoran el filtrado, la generación de informes y la priorización en todo su programa de seguridad, pero lo más importante es que los Activos también contienen todos los Compromisos, Tests y Hallazgos relacionados con los esfuerzos de prueba en torno a ese Activo. Todos los Hallazgos de los Tests terminan consolidándose a nivel de Activo, lo que permite el seguimiento a largo plazo, el análisis de tendencias y la generación de informes.

## Acceso a los Activos

Se puede acceder a los Activos desde la barra lateral. El submenú brinda acceso a [Asset Hierarchy](/asset_modelling/engagements_tests/pro__assets/#asset-nesting) y a All Assets, además de la opción de crear un nuevo Activo.

![image](images/assets_ss1.png)

### Permisos

A los Activos se les pueden aplicar reglas de Control de Acceso Basado en Roles (RBAC), que limitan la capacidad de los miembros del equipo para verlos e interactuar con ellos.

Los permisos se propagan en cascada hacia abajo, lo que significa que el acceso a un Activo otorga automáticamente acceso a todos los objetos dentro de ese Activo (por ejemplo, Compromisos, Tests y Hallazgos).

Para obtener más información sobre los roles de usuario, consulte nuestro artículo [Introduction To Roles](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

## Vista del Activo

Las vistas de Activo contienen diversas tablas y gráficos para interpretar el estado de un Activo de un vistazo. Esto incluye:

- **Open Finding Severity**
    - Una lista de los Hallazgos abiertos dentro del Activo, agrupados por severidad
- **Asset Overview**
    - Un desglose de varias características del Activo, incluyendo Descripción, Componentes, Contactos, [Grupos de Usuarios](/admin/user_management/create_user_group/
), Miembros, Tecnologías y Regulaciones.
        - Tecnologías: next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Metadata**
    - Incluyendo Activos principales y secundarios, Organización, criticidad de negocio, ingresos y otros detalles agregados desde la configuración del Activo.
- **Service Level Agreement by Severity**
    - Aplica la configuración de SLA del Activo definida en la configuración a los Hallazgos dentro del Activo.
- **Finding Severity Breakdown**
    - Un gráfico de los Hallazgos dentro del Activo, organizado por severidad.
- **Finding Distribution**
    - Un desglose de los Hallazgos dentro del Activo, organizado por estado (por ejemplo, Activo, Mitigado, Estático y Dinámico)
- **All Engagements**
    - Una lista de los Compromisos contenidos en el Activo.

## Trabajar con Activos

### Crear Activos

Existen dos maneras de crear Activos:

- Desde la opción **New Asset** en el menú lateral
- Desde el botón **New Asset** en la parte superior de la lista All Assets

## Editar Activos

Los Activos se pueden editar haciendo clic en **Edit Asset** desde el menú de engranaje en la parte superior derecha de la vista del Activo. También se puede acceder al mismo menú haciendo clic en el menú de tres puntos (⋮) situado a la izquierda del Activo en la vista All Assets.

Todos los campos que se pueden editar posteriormente también están disponibles al crear el Activo.

![image](images/assets_ss2.png)

### Eliminar Activos

Para eliminar un Activo, seleccione **Delete Asset** en la configuración del Activo. Esta acción no se puede deshacer. Los Activos no se pueden cerrar y volver a abrir posteriormente.

Eliminar un Activo también eliminará lo siguiente:
- Cualquier Compromiso y Test contenido dentro del Activo
- Todo el historial de seguridad asociado, incluidos los Hallazgos y las integraciones
- Cualquier Epic de Jira vinculado
- Todas las notas y archivos cargados asociados con los Compromisos y Tests del Activo

## Límites del Activo

### Deduplicación

Los Activos están “aislados” y no interactúan con otros Activos. Las Smart Features de DefectDojo, como la Deduplicación, solo se aplican dentro del contexto de un único Activo. Los Hallazgos de diferentes Activos no se deduplicarán automáticamente.

### Informes y métricas

La mayoría de los informes y métricas agregan datos a nivel de Activo, lo que convierte a los Activos en la unidad principal para medir y realizar seguimiento del riesgo.

Como resultado, muchas métricas clave se calculan por Activo, entre ellas:

- Número total de Hallazgos (por severidad o estado)
- Tiempo medio de remediación (MTTR)
- Tasas de cumplimiento e incumplimiento de SLA
- Tendencias de riesgo a lo largo del tiempo

Esto significa que la forma en que se estructuran los Activos repercutirá directamente en la precisión y utilidad de los informes. Por ejemplo, agrupar varios sistemas no relacionados bajo un único Activo puede oscurecer la visibilidad del riesgo, mientras que unas estructuras de Activos demasiado granulares pueden fragmentar los informes, dificultando la identificación de tendencias más amplias.

### Connectors

En DefectDojo Pro, los Conectores se asignan a diferentes Activos en DefectDojo Pro, lo que los convierte en el punto de integración principal entre DefectDojo y su ecosistema de seguridad más amplio.

Una vez que se ha vinculado un Conector a un Activo, este importará los resultados de escaneo y creará o actualizará Compromisos, Tests y Hallazgos dentro de ese Activo.

Para obtener más información sobre los Conectores, haga clic [aquí](/connectors/upstream/about/#main-content).

### Pipelines de CI/CD

Los pipelines de CI/CD automatizan la importación de resultados de escaneo. Independientemente del método de integración, todas las importaciones de escaneo deben asociarse con un Activo, lo que convierte al Activo en el punto de anclaje de los datos de seguridad impulsados por pipelines.

Cuando un pipeline envía resultados de escaneo, debe hacer una de las siguientes cosas:

- Especificar un Activo existente (y opcionalmente un Compromiso), o
- Estar configurado de manera que los resultados se asignen sistemáticamente al Activo correcto

Todos los Hallazgos importados heredarán el contexto del Activo, incluidos la propiedad, los permisos, la configuración de prioridad/riesgo y el alcance de los informes.

En la práctica, los Activos deben definirse de manera que reflejen cómo se construyen y despliegan los sistemas dentro de CI/CD, para garantizar que los resultados de seguridad se asocien sistemáticamente con la aplicación o el servicio correctos.

### SLA, prioridad y riesgo

En DefectDojo Pro, los Hallazgos heredan sus objetivos de SLA, Prioridad y Riesgo del Activo que los contiene. Los metadatos del Activo (por ejemplo, criticidad de negocio, ingresos, etc.) se utilizan para calcular automáticamente los valores de Prioridad y Riesgo.

Esto significa que la misma vulnerabilidad puede recibir una puntuación de Prioridad o Riesgo diferente según afecte a un sistema interno de desarrollo o a un activo de producción que respalde operaciones de negocio críticas.

### Relaciones con Jira / Downstream Connector

Los Activos se pueden asignar directamente a instancias de [Jira](/connectors/downstream/pro__jira_guide/#main-content) o de [Integrators](/connectors/toolreference/downstream/#main-content) (por ejemplo, GitHub, GitLab, ServiceNow, etc.), que envían los Hallazgos del Activo hacia sistemas externos de tickets/gestión de trabajo.

Dado que los Hallazgos heredan el riesgo, la prioridad y la propiedad de su Activo principal, el Activo determina de forma efectiva el contexto de remediación que fluye hacia los tickets de Jira y los flujos de trabajo de Downstream Connector.

Es importante destacar que los Activos también son el factor determinante principal de las características de SLA de un Hallazgo. Por lo tanto, el SLA de un Hallazgo depende de la configuración de SLA de su Activo principal. Puede encontrar más información sobre las configuraciones de SLA [aquí](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

## Anidamiento de Activos

DefectDojo admite relaciones de tipo padre-hijo entre dos Activos dentro de la misma Organización. Esto se puede configurar durante la creación del Activo o en la configuración del Activo.

Puede visualizar la estructura de los Activos en DefectDojo y cambiar las relaciones mediante la opción **Asset Hierarchy** en la barra lateral.

Después de seleccionar los Activos que desea visualizar en la tabla correspondiente, haga clic en **View Asset Hierarchy** para generar un diagrama de flujo de la relación entre los Activos elegidos, si la hubiera.

Puede encontrar más información sobre el efecto de anidar Activos en la deduplicación, el RBAC y otros detalles, así como ejemplos de casos de uso, [aquí](/asset_modelling/pro_hierarchy/asset_hierarchy/#asset-nesting-examples).
