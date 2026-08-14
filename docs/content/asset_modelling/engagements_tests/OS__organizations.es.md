---
title: Organizaciones
description: Cómo entender las Organizaciones en DefectDojo OS
audience: opensource
weight: 1
aliases:
- /es/asset_modelling/engagements_tests/os_producttype/
- /es/en/asset_modelling/engagements_tests/os_producttype/
---

**ORGANIZACIONES** → Activos → Compromisos → Tests → Hallazgos

## Resumen

Las **Organizaciones** se ubican en la parte más alta de la jerarquía de objetos de DefectDojo. Las Organizaciones se diferencian de los objetos descendentes en la jerarquía (Activos, Compromisos, Tests y Hallazgos) porque no son objetivos técnicos de escaneo, sino que sirven principalmente como abstracciones organizativas que compartimentan sus esfuerzos de seguridad según:
- Dominio de negocio
- Equipo de desarrollo
- Equipo de seguridad
- Aplicaciones de software
- Familia de productos general
- Cliente o subsidiaria
- Estructura de reporte
- etc.

El hilo conductor de los ejemplos anteriores ilustra la utilidad esencial de las Organizaciones: en general, deben representar límites estables y duraderos dentro de su programa de seguridad.

## Datos y estructura de la Organización

Dado que las Organizaciones no se escanean directamente, el único campo obligatorio para crearlas es un nombre. Más allá de eso, actúan como contenedores de Activos y de los Compromisos, Tests y Hallazgos que descienden de ellos.

Al crear una Organización, considere cómo su estructura influirá en sus informes. ¿Necesita principalmente que las Organizaciones representen a los equipos que trabajan en los proyectos (Activos) que contendrán? ¿O sería mejor que las Organizaciones representen proyectos generales que contienen distintas iteraciones de los proyectos (Activos) dentro de ellas?

Si dispone de una sola Organización que contiene toda la información relevante de un determinado dominio de negocio o equipo de desarrollo, representarla como una Organización facilitará la elaboración de informes, en lugar de tener que reunir un informe a partir de varios Activos y Organizaciones.

Si un proyecto de software concreto tiene muchos despliegues o versiones distintas, puede convenir crear una única Organización que abarque el alcance de todo el proyecto y que cada versión exista como Activos individuales. En algunos flujos de trabajo, las Organizaciones también pueden usarse para separar las etapas del ciclo de vida del software: una Organización para “En desarrollo”, otra Organización para “En producción”, etc.

Las Organizaciones pueden usarse para determinar el acceso a subsidiarias, empresas adquiridas u otras unidades de negocio reguladas con fines de RBAC. En negocios complejos, donde existen muchos proyectos exclusivos con distintas reglas de acceso, las Organizaciones resultan particularmente relevantes.

En última instancia, la decisión de cómo usar las Organizaciones y los Activos depende de cómo desee reflejar mejor su estructura organizativa particular y las necesidades de su equipo de seguridad.

A continuación se muestran algunos ejemplos de estructuras que le ayudarán a determinar si sus objetos deben designarse como Organizaciones o como Activos.

- **Organización**: División de Pagos
    - Activo: API de Pagos - Producción
    - Activo: API de Pagos - Staging
    - Activo: Worker de Facturación

- **Organización**: Producto de Software A
    - Activo: Portal Web
    - Activo: Backend Móvil

Además, a continuación se ofrece una guía ilustrativa sobre si algo se representa mejor como una Organización o como un Activo:

| Organizaciones | Activos |
|--------------|--------|
| Unidades de negocio | Aplicaciones individuales |
| Departamentos | Despliegues/entornos |
| Dominios de propiedad de seguridad | Componentes de infraestructura |
| Familias de productos | Microservicios específicos |
| Informes a nivel de cartera | Objetivos de escaneo |
| Clientes | Versiones específicas de software |

Como se indicó, su estructura puede variar según las necesidades particulares de seguridad de su organización.

## Acceso a las Organizaciones

Se puede acceder a las Organizaciones desde la barra lateral. El submenú también ofrece la opción de crear nuevas Organizaciones.

![image](images/organization_ss1.png)

### Vista de la Organización

La vista de una Organización contiene diversas tablas y gráficos para interpretar su estado de un vistazo. Esto incluye:
- **Descripción**
- **Casilla Clave/Crítica**
    - Marcar Crítica o Clave se usa únicamente con fines de filtrado
- **Lista de Activos dentro de la Organización**
- **Usuarios autorizados** (Usuarios de DefectDojo)

## Trabajar con Organizaciones

### Crear Organizaciones

Existen dos maneras de crear Organizaciones:

- Desde la opción **Agregar Organización** en el menú lateral
- Desde el botón **Agregar Organización** en la parte superior de la lista de todas las Organizaciones

### Editar Organizaciones

Las Organizaciones se pueden editar haciendo clic en **Editar** desde el menú desplegable ubicado en la parte superior derecha de la tabla Descripción en la vista de la Organización. También se puede acceder al mismo menú haciendo clic en el menú de tres puntos (⋮) situado a la izquierda de la Organización en la lista de todas las Organizaciones.

Todos los campos que se pueden editar posteriormente también están disponibles al crear la Organización.

### Eliminar Organizaciones

Para eliminar una Organización, seleccione **Eliminar Organización** en la configuración de la Organización.

Debido a que las Organizaciones se ubican en la parte más alta de la jerarquía, al eliminarlas se elimina todo el historial de seguridad, las relaciones y los objetos secundarios posteriores, tales como:
- Cualquier Activo, Compromiso y Test contenido dentro de la Organización
- Todo el historial de seguridad asociado, incluidos los Hallazgos y las integraciones
- Cualquier Epic de Jira vinculado
- Todas las notas y archivos cargados asociados con los Activos, Compromisos y Tests dentro de esa Organización

La eliminación de una Organización no se puede deshacer. Si desea “dar de baja” una Organización sin eliminar los datos subyacentes (por ejemplo, para conservar registros de pruebas de software heredado con fines de auditoría), puede cambiar el nombre de la Organización o agregar una Etiqueta que indique que se encuentra en estado obsoleto.

## Organizaciones frente a Metadatos

Las Organizaciones están pensadas para representar límites de propiedad estructural o de generación de informes, en lugar de clasificaciones ligeras. Atributos como el estado de despliegue, las etiquetas internas o los estados temporales de flujo de trabajo pueden representarse mejor mediante etiquetas o metadatos que mediante Organizaciones independientes.

## Límites de la Organización

Las Organizaciones establecen tanto los límites de generación de informes como los de acceso dentro de DefectDojo. Dado que las integraciones, los permisos de RBAC, la propiedad, las métricas y los modelos de deduplicación heredan con frecuencia la estructura de las Organizaciones, diseñar límites claros desde el principio ayuda a evitar una jerarquía excesiva y la fragmentación de los informes más adelante.

### Hallazgos y automatización

Aunque las integraciones normalmente se configuran en objetos de nivel inferior, como Activos, Compromisos o Hallazgos, las Organizaciones siguen definiendo los límites de propiedad, generación de informes y acceso dentro de los cuales operan dichas integraciones.

Los permisos se propagan en cascada hacia abajo, lo que significa que el acceso a una Organización otorga automáticamente acceso a todos los objetos dentro de esa Organización (por ejemplo, Activos, Compromisos, Tests y Hallazgos).

El modelo de RBAC de DefectDojo se puede usar para controlar el acceso de usuarios humanos, pero también puede restringir el acceso de los tokens de API a Organizaciones concretas.

Para obtener más información sobre los roles de usuario, consulte nuestro artículo [Permisos](/admin/user_management/os__authorized_users/).

### Propiedad

Al ser objetos de nivel superior, las Organizaciones también implican la propiedad de los objetos secundarios que contienen. El seguimiento de SLA, los flujos de trabajo de remediación, el enrutamiento de tickets y la gobernanza general fluyen con mayor facilidad cuando las Organizaciones se configuran para reflejar con precisión a los responsables de las mismas.

### Métricas/Informes

Los paneles de métricas, los mosaicos y las vistas se pueden filtrar por Organización, lo que las convierte en un componente fundamental de cómo se calculan, visualizan y finalmente exportan sus datos de seguridad.

Para fines de generación de informes, en general resulta más sencillo combinar varias Organizaciones en un solo documento que subdividir una única Organización en documentos independientes. Por ello, recomendamos configurar las Organizaciones con el nivel de granularidad que tenga sentido para los informes de su equipo. Por ejemplo, no es necesario representar una gran división de negocio como una Organización si, en su mayor parte, va a generar informes para departamentos individuales dentro de esa división.

Estructurar de forma eficaz sus Organizaciones para reflejar sus necesidades de generación de informes es fundamental para evaluar con precisión su postura de seguridad. Para obtener más información sobre Métricas, haga clic [aquí](/metrics_reports/dashboards/introduction_dashboard/).

### Deduplicación

La deduplicación en DefectDojo se produce a nivel de Activo y no se ve afectada por la Organización principal.
