---
title: Organizaciones
description: Comprender las Organizaciones en DefectDojo Pro
audience: pro
weight: 1
---

**ORGANIZACIONES** → Activos → Compromisos → Tests → Hallazgos

## Descripción general

Las **Organizaciones** se ubican en la parte más alta de la jerarquía de productos de DefectDojo. Las Organizaciones se distinguen de los objetos descendentes de la jerarquía —Activos, Compromisos, Tests y Hallazgos— porque no son objetivos técnicos de análisis, sino que funcionan principalmente como abstracciones organizativas que compartimentan sus esfuerzos de seguridad según:
- Dominio de negocio
- Equipo de desarrollo
- Equipo de seguridad
- Aplicaciones de software
- Familia de productos general
- Cliente o subsidiaria
- Estructura de generación de informes
- etc.

El hilo conductor de los ejemplos anteriores ilustra la utilidad esencial de las Organizaciones: en general, deben representar límites estables y duraderos dentro de su programa de seguridad.

## Datos y estructura de la Organización

Dado que las Organizaciones no se analizan directamente, el único campo obligatorio para crearlas es un nombre. Más allá de eso, funcionan como contenedores de Activos y de los Compromisos, Tests y Hallazgos que descienden de ellos.

Al crear una Organización, considere cómo su estructura influirá en la generación de sus informes. ¿Necesita principalmente que las Organizaciones representen a los equipos que trabajan en los proyectos (Activos) que contendrán las Organizaciones? ¿O sería mejor que las Organizaciones representaran proyectos generales que contienen diferentes iteraciones de los proyectos (Activos) dentro de ellas?

Si tiene una única Organización que contiene toda la información relevante para un dominio de negocio o equipo de desarrollo determinado, representarla como una Organización facilitará una generación de informes más fluida, en lugar de tener que reunir un informe a partir de varios Activos y Organizaciones.

Si un proyecto de software en particular tiene muchas implementaciones o versiones distintas, puede valer la pena crear una única Organización que cubra el alcance de todo el proyecto y que cada versión exista como Activos individuales. En algunos flujos de trabajo, las Organizaciones también se pueden utilizar para separar las etapas del ciclo de vida del software: una Organización para “In Development”, otra Organización para “In Production”, etc.
​
Las Organizaciones se pueden utilizar para determinar el acceso a subsidiarias, empresas adquiridas u otras unidades de negocio reguladas con fines de RBAC. En negocios complejos, donde existen muchos proyectos únicos con distintas reglas de acceso, las Organizaciones son particularmente relevantes.

En última instancia, la decisión sobre cómo utilizar las Organizaciones y los Activos depende de cómo desee reflejar mejor su estructura organizativa particular y las necesidades de su equipo de seguridad.

A continuación se presentan algunos ejemplos de estructuras que le ayudarán a decidir cómo designar sus objetos, ya sea como Organizaciones o como Activos.

- **Organización**: División de Pagos
    - Activo: API de Pagos - Producción
    - Activo: API de Pagos - Staging
    - Activo: Worker de Facturación

- **Organización**: Producto de Software A
    - Activo: Portal Web
    - Activo: Backend Móvil

Además, la siguiente es una guía ilustrativa sobre si algo se representa mejor como una Organización o como un Activo:

| Organizations | Assets |
|--------------|--------|
| Unidades de negocio | Aplicaciones individuales |
| Departamentos | Implementaciones/entornos |
| Dominios de propiedad de seguridad | Componentes de infraestructura |
| Familias de productos | Microservicios específicos |
| Informes a nivel de portafolio | Objetivos de análisis |
| Clientes | Versiones específicas de software |

Como se mencionó, su estructura puede variar según las necesidades particulares de seguridad de su organización.

## Acceso a las Organizaciones

Se puede acceder a las Organizaciones desde la barra lateral. El submenú brinda acceso a Todas las Organizaciones, así como la opción de crear una nueva Organización.

![image](images/org_ss1.png)

## Vista de la Organización

La vista de una Organización contiene una variedad de tablas y gráficos para interpretar su estado de un vistazo. Esto incluye:

- **Description**
- **Commerce**
    - Si se ha determinado que la Organización es Crítica o Clave
        - Marcar Crítica o Clave se utiliza únicamente con fines de filtrado
- **Assigned Members** (Usuarios de DefectDojo)
- **Assigned User Groups**
    - Grupos de usuarios que se han asignado a la Organización para el control de permisos. Puede encontrar más información sobre los grupos de usuarios [aquí](/admin/user_management/create_user_group/).
- **List of Assets within the Organization**

## Cómo trabajar con las Organizaciones

### Crear Organizaciones

Hay dos formas de crear Organizaciones:

- Desde la opción **New Organization** en el menú lateral
- Desde el botón **New Organization** en la parte superior de la lista Todas las Organizaciones

### Editar Organizaciones

Las Organizaciones se pueden editar haciendo clic en **Edit Organization** dentro del menú de engranaje en la parte superior derecha de la vista de la Organización. También se puede acceder al mismo menú haciendo clic en el menú kebab ⋮ a la izquierda de la Organización en la vista Todas las Organizaciones.

Todos los campos que se pueden editar posteriormente también están disponibles al crear la Organización.

### Eliminar Organizaciones

Se puede eliminar una Organización seleccionando **Delete Organization** desde la configuración de la Organización.

Dado que las Organizaciones se ubican en la parte superior de la jerarquía, eliminarlas elimina todo el historial de seguridad, las relaciones y los objetos secundarios posteriores, tales como:
- Cualquier Activo, Compromiso y Test contenido dentro de la Organización
- Todo el historial de seguridad asociado, incluidos los Hallazgos e integraciones
- Cualquier Épica de Jira vinculada
- Todas las notas y archivos cargados asociados con los Activos, Compromisos y Tests dentro de esa Organización

Eliminar una Organización no se puede deshacer. Si desea “dar de baja” una organización sin eliminar los datos subyacentes (por ejemplo, para conservar registros de pruebas de software heredado con fines de auditoría), puede cambiar el nombre de la Organización o agregar una Etiqueta que indique que se encuentra en un estado obsoleto.

## Organizaciones frente a Metadatos

Las Organizaciones están destinadas a representar la propiedad estructural o los límites de generación de informes, en lugar de clasificaciones livianas. Atributos como el estado de implementación, las etiquetas internas o los estados temporales de flujo de trabajo pueden representarse mejor mediante etiquetas o metadatos, en lugar de mediante Organizaciones separadas.

## Límites de la Organización

Las Organizaciones establecen tanto los límites de generación de informes como los de acceso dentro de DefectDojo. Dado que las integraciones, los permisos de RBAC, la propiedad, las métricas y los modelos de deduplicación suelen heredar la estructura de las Organizaciones, diseñar límites claros desde el principio ayuda a evitar una expansión descontrolada de la jerarquía y la fragmentación de los informes más adelante.

### Hallazgos y automatización

Aunque las integraciones normalmente se configuran en objetos de nivel inferior, como Activos, Compromisos o Hallazgos, las Organizaciones siguen definiendo los límites de propiedad, generación de informes y acceso dentro de los cuales operan esas integraciones.

Los permisos se propagan en cascada hacia abajo, lo que significa que el acceso a una Organización otorga automáticamente acceso a todos los objetos dentro de esa Organización (por ejemplo, Activos, Compromisos, Tests y Hallazgos).

El modelo de RBAC de DefectDojo se puede utilizar para controlar el acceso de usuarios humanos, pero también puede restringir el acceso de los tokens de API a Organizaciones particulares.

Para obtener más información sobre los roles de usuario, consulte nuestro artículo [Introducción a los tipos de permisos](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

### Propiedad

Como objetos de nivel superior, las Organizaciones también implican la propiedad sobre los objetos secundarios que contienen. El seguimiento de SLA, los flujos de trabajo de remediación, el enrutamiento de tickets y la gobernanza general fluyen con mayor fluidez cuando las Organizaciones se han configurado para reflejar con precisión a las personas responsables de ellas.

### Métricas/Generación de informes

Los paneles de métricas, los cuadros y las vistas se pueden filtrar por Organización, lo que los convierte en un componente crítico de cómo se calculan, visualizan y, en última instancia, se exportan sus datos de seguridad.

Para fines de generación de informes, generalmente es más fácil combinar varias Organizaciones en un único documento que subdividir una única Organización en documentos separados. Por lo tanto, recomendamos configurar las Organizaciones con el nivel de granularidad que tenga sentido para los informes de su equipo. Por ejemplo, no es necesario representar una gran división de negocio como una Organización si principalmente va a generar informes para departamentos individuales dentro de esa división.

Estructurar eficazmente sus Organizaciones para reflejar sus necesidades de generación de informes es fundamental para evaluar con precisión su postura de seguridad. Para obtener más información sobre Métricas, haga clic [aquí](/metrics_reports/pro_metrics/pro__overview/).

### Deduplicación

La deduplicación en DefectDojo ocurre a nivel de Activo, y no se ve afectada por la Organización principal.
