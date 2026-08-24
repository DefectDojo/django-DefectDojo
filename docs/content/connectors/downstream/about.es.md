---
title: Conectores descendentes
weight: 1
audience: pro
aliases:
- /es/en/share_your_findings/integrations
- /es/issue_tracking/pro_integration/integrations/
---

**Disponibilidad:** Los Conectores descendentes están disponibles de forma general y activados para todas las instancias de DefectDojo Pro, tanto en la nube (Cloud) como On-Premise. No hay nada que habilitar, y ya no aparecen en la página de Feature Flags.

Los Conectores descendentes le permiten enviar sus Hallazgos y Grupos de hallazgos a sistemas de seguimiento de tickets para integrar fácilmente la remediación de seguridad con el flujo de trabajo de desarrollo ya existente de su equipo.

Conectores descendentes admitidos:
- Azure Devops
- Bitbucket
- Freshservice
- GitHub
- GitLab Boards
- Jira
- Linear
- Opsgenie
- PagerDuty
- ServiceDesk Plus
- ServiceNow
- ServiceNow SecOps / Vulnerability Response
- Shortcut
- Zendesk

## Cómo abrir la página de Conectores descendentes

La página de Conectores descendentes se encuentra en **Import > Connectors > Downstream Connectors**, en la barra lateral.

![image](images/integrators_3.png)

## Configuración de un Conector descendente

Un Conector descendente se configura con tres componentes clave:

- **Instancia de integración**: es el método de conexión principal que DefectDojo utilizará con un sistema de terceros. La instancia incluirá detalles como una etiqueta, ubicación y credenciales de conexión, junto con cualquier otra información que pueda requerir el proveedor.
- **Mapeo de seguimiento de incidencias**: aquí es donde se almacena la información de mapeo, que define los detalles necesarios para conectarse a un "proyecto" determinado dentro del proveedor. Estos detalles incluyen el nombre o ID del "proyecto", y los mapeos entre la Severidad y el estado de los Hallazgos de DefectDojo y el campo correspondiente en el "ticket" del proveedor. Puede tener configurados varios mapeos si desea enviar Hallazgos a varias ubicaciones de "proyecto".
- **Asignación de seguimiento de incidencias**: aquí es donde los Productos y Compromisos de DefectDojo se asignan a un Mapeo de seguimiento de incidencias determinado, con opciones por Producto/Compromiso para definir cómo se enviará un Hallazgo a un sistema del proveedor.

Estos componentes son jerárquicos: cada **Instancia** tiene uno o más **Mapeos**, que a su vez tienen una o más **Asignaciones de seguimiento**.

![image](images/integrators_2.png)

## Envío de Hallazgos y Grupos de hallazgos

Una vez configurados estos componentes, los Hallazgos y Grupos de hallazgos se pueden enviar a un sistema de seguimiento de incidencias determinado de dos maneras: manual o automáticamente.

- **Manualmente**: los Hallazgos y Grupos de hallazgos contenidos en un Producto/Compromiso con un **Mapeo de seguimiento de incidencias** asignado tendrán una opción "Push to Integrator". Esto creará una incidencia (Issue) en el sistema de seguimiento con la información del Hallazgo/Grupo de hallazgos correspondiente. "Push to Integrator" también se puede usar para actualizar una incidencia existente.

### Envío automático de Hallazgos

Los Hallazgos también se pueden enviar automáticamente; la **Asignación de seguimiento de incidencias** determina cómo se enviarán esos objetos. Estas son las cuatro opciones:

- **Publicar cambios en el destino solo de forma explícita**: esta opción desactiva cualquier comportamiento automático en el Producto o Compromiso asignado. La única forma de enviar un Hallazgo o Grupo de hallazgos será de forma explícita, como se mencionó anteriormente.
- **Vincular automáticamente los Hallazgos nuevos con el destino**: cuando se **crean** nuevos Hallazgos o Grupos de hallazgos en el Producto o Compromiso asignado, DefectDojo enviará automáticamente el objeto al sistema de seguimiento de incidencias. Una vez creados, estos Hallazgos o Grupos de hallazgos no se actualizarán sin una acción manual de "Push to Integrator".
- **Actualizar automáticamente el vínculo existente al editar el Hallazgo**: cuando los Hallazgos o Grupos de hallazgos se **actualizan** en el Producto o Compromiso asignado, el objeto se envía automáticamente al sistema de seguimiento de incidencias si ya se había creado manualmente un vínculo existente.
- **Vincular los nuevos y actualizar el vínculo existente al editar el Hallazgo**: cuando los Hallazgos o Grupos de hallazgos se crean **o** se actualizan en el Producto o Compromiso asignado, el objeto se envía automáticamente al sistema de seguimiento de incidencias.

#### Filtros de envío

Cada Asignación de seguimiento de incidencias puede, opcionalmente, restringir qué Hallazgos se envían **automáticamente**:

- **Severidad mínima**: solo crea tickets automáticamente para los Hallazgos con una Severidad igual o superior a la seleccionada. Déjelo en blanco para incluir todas las severidades.
- **Solo hallazgos activos**: solo crea tickets automáticamente para los Hallazgos activos, omitiendo aquellos que ya estén Mitigados, sean Falso positivo o tengan Riesgo aceptado en el momento en que la asignación los detecta por primera vez.

Estos filtros se aplican únicamente a la **creación** automática. Las actualizaciones de un Hallazgo que ya tiene un ticket vinculado siempre se envían, por lo que los cambios de estado (incluidos los cierres) se siguen propagando. Un **Push to Integrator** manual siempre ignora los filtros. Si deja ambos valores en su configuración predeterminada, se conserva el comportamiento original de enviar todos los Hallazgos.

#### Asignación de varios Productos

Una Asignación de seguimiento de incidencias apunta a un único Producto o Compromiso. Para cubrir varios activos, cree una Asignación por Producto (o Compromiso). Si además necesita que los campos del proveedor sean distintos para cada activo — por ejemplo, un **Assignment group** o **Assigned to** diferente en ServiceNow, o un proyecto de Jira distinto — cree un Mapeo de seguimiento de incidencias independiente (con sus propios Mapeos de campos personalizados) para cada activo y apunte cada Asignación al Mapeo correspondiente.

## Representación de tickets del sistema de seguimiento de incidencias

Los tickets del sistema de seguimiento de incidencias se representan mediante una serie de iconos en la columna "Integrator Tickets" al ver y listar
Hallazgos y Grupos de hallazgos

Iconos de izquierda a derecha:

- **Tipo de integración**: el tipo de sistema de seguimiento de incidencias con el que está asociado el ticket
- **ID del ticket**: el ID del ticket, tal como lo define el sistema de seguimiento de incidencias
- **Enlace del ticket**: el enlace directo al ticket, tal como lo define el sistema de seguimiento de incidencias
- **Registro de cambios**: indica cuándo se asoció el ticket del sistema de seguimiento de incidencias con un Hallazgo o Grupo de hallazgos, así como la última vez que DefectDojo realizó un cambio en el ticket

![image](images/integrators_1.png)

## Requisitos específicos de cada proveedor

Cada proveedor tiene requisitos distintos sobre cómo debe interactuar DefectDojo con él. Esto puede consistir en un mecanismo de autenticación, campos adicionales por "proyecto", o mapeos de severidad/estado.

Para consultar la lista completa de requisitos, abra a continuación las páginas específicas de cada proveedor:

- [Azure Devops](/connectors/toolreference/azure_devops_boards/)
- [Bitbucket](/connectors/toolreference/bitbucket/#downstream-connector)
- [Freshservice](/connectors/toolreference/freshservice/)
- [GitHub](/connectors/toolreference/github/#downstream-connector)
- [GitLab Boards](/connectors/toolreference/gitlab/#downstream-connector)
- [Jira](/connectors/toolreference/jira/)
- [Linear](/connectors/toolreference/linear/)
- [Opsgenie](/connectors/toolreference/opsgenie/)
- [PagerDuty](/connectors/toolreference/pagerduty/)
- [ServiceDesk Plus](/connectors/toolreference/servicedesk_plus/)
- [ServiceNow](/connectors/toolreference/servicenow/)
- [ServiceNow SecOps / Vulnerability Response](/connectors/toolreference/servicenow_secops/)
- [Shortcut](/connectors/toolreference/shortcut/)
- [Zendesk](/connectors/toolreference/zendesk/)

## Manejo de errores y depuración

Los Conectores descendentes pueden generar errores por diversos motivos, como conectividad, autenticación, permisos, etc.. Para ayudar
a depurar estos errores, cada Mapeo de seguimiento de incidencias cuenta con una tabla de errores que indica cuándo ocurrió el error, el motivo por el que
ocurrió, y el Hallazgo o Grupo de hallazgos que no se pudo enviar.

Estos errores se pueden consultar en la página All Issue Tracker Mappings & Assignments, en la columna ⚠️ Total Errors.

![image](images/integrators_4.png)

Al hacer clic en la entrada de Total Errors, accederá a una página con descripciones más detalladas de los errores asociados con este Conector descendente.

### Cómo ver todos los fallos en un solo lugar

La tabla de errores por mapeo cubre un único Conector descendente. [Diagnostics](/admin/diagnostics/pro__diagnostics/) los cubre todos, junto con cualquier otro intento de integración en la instancia — conectores ascendentes, importaciones, Jira, SSO y el motor de reglas — con el mismo filtrado y ordenamiento sobre todo el conjunto.

Utilícelo cuando la pregunta sea más amplia que un único mapeo:

* un intento que **nunca se completó** en lugar de fallar, algo que ninguna tabla de errores refleja, porque no se produjo ningún error
* si un fallo es específico de una integración o está ocurriendo en varias a la vez
* quién o qué inició un intento, y contra qué configuración

Las credenciales citadas en un error se eliminan antes de almacenar la fila, y el detalle técnico completo está restringido a los superusuarios.

## Diseño de la página de Conectores descendentes

Los Conectores descendentes se muestran en dos secciones, **Configured Connectors** y **Available Connectors**, cada una ordenada alfabéticamente con un recuento junto a su encabezado. Una herramienta puede tener varias configuraciones; cada una es su propio mosaico, titulado `<Tool> - <label>`, ordenado por etiqueta. El mosaico **Request Downstream Connector** en DefectDojo Pro Cloud no se incluye en el recuento.
