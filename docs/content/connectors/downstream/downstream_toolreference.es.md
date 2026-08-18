---
title: Referencia de herramientas de Downstream Connectors
description: Guías de configuración detalladas para Downstream Connectors
weight: 1
audience: pro
aliases:
- /es/en/share_your_findings/integrations_toolreference
- /es/issue_tracking/pro_integration/integrations_toolreference/
---

Estas son las instrucciones específicas que detallan cómo configurar un Downstream Connector de DefectDojo con un rastreador de incidencias (Issue Tracker) de un tercero.

## Azure DevOps Boards

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en su URL de Azure - por ejemplo `https://dev.azure.com/{your organization}`
- **Token** debe establecerse en un token de acceso personal de Azure.

La autenticación con Azure DevOps requiere un [token de acceso personal](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
con permisos establecidos en "Read, Write and Manage" para "Work Items" en el proyecto de Azure con el que desea trabajar.

### Mapeo del Issue Tracker

Estos detalles determinan cómo DefectDojo mapeará los atributos de un Hallazgo o Grupo de Hallazgos a un Proyecto dado en Azure DevOps:

#### Detalles del mapeo del Issue Tracker

El campo `Project ID` corresponde al nombre o al ID del proyecto en Azure.

#### Detalles del mapeo de severidad

Los atributos del formulario se proporcionan como valores predeterminados y son los siguientes:

- **Severity Field Name**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

#### Detalles del mapeo de estado

Los atributos del formulario se proporcionan como valores predeterminados y son los siguientes:

- **Status Field Name**: `/fields/System.State`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

## Bitbucket

La integración de Bitbucket le permite enviar incidencias al [rastreador de incidencias](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) de un repositorio de Bitbucket Cloud.

El rastreador de incidencias es opcional en Bitbucket y debe habilitarse en el repositorio antes de que DefectDojo pueda crear incidencias en él. Para habilitarlo, abra el repositorio en Bitbucket y seleccione **Repository settings**, luego habilite el rastreador de incidencias en **Features**.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://bitbucket.org`.
- **Email** debe ser la dirección de correo electrónico de la cuenta de Atlassian a la que pertenece el token de la API.
- **API Token** debe establecerse en un token de API de Atlassian con alcance limitado (scoped).

Atlassian ha declarado obsoletas las contraseñas de aplicación de Bitbucket y no funcionarán con esta integración. Para crear un token de API:

1. Abra la [configuración de la cuenta de Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens) y elija **Security**, luego **Create and manage API tokens**.
2. Elija **Create API token with scopes**, asigne un nombre al token y establezca una fecha de vencimiento.
3. Seleccione **Bitbucket** como la aplicación.
4. Otorgue al token permiso para leer repositorios y para leer y escribir incidencias.

### Mapeo del Issue Tracker

- **Workspace** debe ser el slug del espacio de trabajo que contiene el repositorio, tal como aparece en las URL de bitbucket.org.
- **Repository Slug** debe ser el slug del repositorio en el que desea crear incidencias.

### Detalles del mapeo de severidad

Esto se mapea al campo Priority de la incidencia de Bitbucket. Los atributos del formulario se proporcionan como valores predeterminados, y cada valor debe ser una de las prioridades de Bitbucket: `trivial`, `minor`, `major`, `critical` o `blocker`.

- **Severity Field Name**: `priority`
- **Info Mapping**: `trivial`
- **Low Mapping**: `minor`
- **Medium Mapping**: `major`
- **High Mapping**: `critical`
- **Critical Mapping**: `blocker`

### Detalles del mapeo de estado

Esto se mapea al campo State de la incidencia de Bitbucket. Cada valor debe ser uno de los estados de incidencia de Bitbucket: `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` o `closed`.

- **Status Field Name**: `state`
- **Active Mapping**: `new`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `invalid`
- **Risk Accepted Mapping**: `wontfix`

## GitHub

La integración de GitHub le permite añadir incidencias a un [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects), que también abre incidencias en un Repo asociado. Estos Repos/Proyectos pueden asociarse tanto a una organización de GitHub como a una cuenta personal de GitHub.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en la URL de su usuario u organización de GitHub, según dónde desee crear las incidencias. por ejemplo `https://github.com/{your-organization}`
- **Token** debe establecerse en un token de acceso personal de GitHub.

Los tokens de acceso personal para GitHub pueden crearse en https://github.com/settings/tokens. El token debe tener los alcances (scopes) Repo y Project.

### Mapeo del Issue Tracker

- **Issue Tracker Mapping Label** debe establecerse para identificar el Proyecto o Repo en el que desea crear incidencias.
- **Project Number** debe ser el ID de un proyecto de GitHub al que desea enviar los elementos. Puede obtenerlo de la URL al ver un Proyecto, por ejemplo `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** debe ser el nombre de un repositorio asociado a su organización (o usuario) al que desea enviar las incidencias.


### Detalles del mapeo de severidad

**Para configurar la integración, el proyecto DEBE tener un campo personalizado creado para representar la prioridad de la incidencia; de lo contrario, la severidad no se mapeará correctamente y las incidencias no se enviarán a GitHub.**

Siga esta guía para crear un [campo personalizado](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority).
Cada severidad necesitará tener una opción de selección única correspondiente disponible. Por ejemplo, de forma predeterminada DefectDojo sugiere P0, P1, P2, P3, P4 como posibles valores de Priority, y cada uno de ellos deberá añadirse al campo personalizado Priority.

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P0`
- **Low Mapping**: `P1`
- **Medium Mapping**: `P2`
- **High Mapping**: `P3`
- **Critical Mapping**: `P4`

### Detalles del mapeo de estado

De forma predeterminada, los nuevos proyectos de GitHub tendrán estados para las incidencias de "In Progress" y "Done". Se pueden añadir estados adicionales al proyecto para rastrear el estado Falso positivo o Riesgo aceptado si lo desea. Una de las formas de hacerlo es añadiendo una nueva columna de estado al tablero del proyecto.

- **Status Field Name**: `Status`
- **Active Mapping**: `In Progress`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

## GitLab

La integración de GitLab le permite añadir incidencias a un [Proyecto de GitLab](https://docs.gitlab.com/ee/user/project/).

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en el enlace de su servidor de GitLab, por ejemplo `https://gitlab.com/`.
- **Token** debe establecerse en un token de acceso personal de GitLab. El token debe tener alcances de API. Consulte la [guía de GitLab para crear un token de acceso personal](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Mapeo del Issue Tracker

- **Project Name**: el nombre del proyecto en GitLab al que desea enviar incidencias.

### Detalles del mapeo de severidad

Esto se mapea al campo Priority de GitLab.
- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `2`
- **Medium Mapping**: `3`
- **High Mapping**: `4`
- **Critical Mapping**: `5`

### Detalles del mapeo de estado

De forma predeterminada, GitLab tiene los estados 'opened' y 'closed'. Se pueden añadir etiquetas de estado adicionales si desea rastrear el estado Falso positivo o Riesgo aceptado. Consulte la [documentación de GitLab](https://docs.gitlab.com/user/work_items/status/) para más detalles.

- **Status Field Name**: `Status`
- **Active Mapping**: `opened`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `closed`

## Jira

La integración de Jira envía los Hallazgos y Grupos de Hallazgos de DefectDojo a un proyecto de Jira como incidencias, mantiene sincronizado el estado de cada incidencia con el Hallazgo y enlaza el Hallazgo de vuelta a la incidencia creada. Se admiten tanto Jira **Cloud** como **Data Center / Server**. Jira Service Management no es compatible.

### Elegir un método de autenticación

Establezca primero **Jira Deployment**, luego elija un **Authentication Method**:

**Jira Cloud**
- **API Token (email + token)** — autenticación HTTP Basic usando un correo electrónico de cuenta de Atlassian y un [token de API](https://id.atlassian.com/manage-profile/security/api-tokens). Las llamadas se dirigen directamente a la URL de su sitio.
- **OAuth 2.0 (recomendado)** — un consentimiento del navegador de una sola vez; DefectDojo obtiene y renueva los tokens por usted.
- **Service Account Token** — un token de API con alcance limitado creado para una [cuenta de servicio](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/) de Atlassian.

**Jira Data Center / Server**
- **Personal Access Token (recomendado)**
- **Username + Password**

> **Cómo llega la autenticación de Cloud a Jira:** tanto OAuth 2.0 como Service Account se autentican como un token Bearer contra la puerta de enlace de Atlassian — `https://api.atlassian.com/ex/jira/{cloudId}` —, que es un *host distinto* de la URL de su sitio `https://your-site.atlassian.net`. DefectDojo usa la puerta de enlace para cada llamada a la API, pero siempre construye el enlace del ticket que se muestra en un Hallazgo a partir de la **URL de su sitio**, de modo que el enlace en el que hace clic un usuario es un enlace normal y navegable `.../browse/{ISSUE-KEY}`. (La autenticación de API Token y Data Center llama directamente a la URL del sitio, por lo que no existe esa división.)

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en la **URL del sitio** de Jira, por ejemplo `https://your-organization.atlassian.net`. Esto se usa para los enlaces de ticket navegables y, para la autenticación de API Token y Data Center, como URL base de la API.
- Los campos restantes dependen del método elegido anteriormente (email + token de API, credenciales de cliente OAuth, token de cuenta de servicio, PAT, o nombre de usuario + contraseña).

### Configuración de OAuth 2.0 (Cloud)

Cree una aplicación dedicada en la [consola de desarrolladores de Atlassian](https://developer.atlassian.com/console/myapps/) y luego conéctese desde DefectDojo.

1. Elija **Create → OAuth 2.0 integration**. Debe ser una *integración OAuth 2.0* — una aplicación Connect o Forge no puede usar el grant de código de autorización 3LO (obtendría `grant_type is not enabled for client`).
2. Cuando se le solicite el **Access type**, elija **Resource-level**. Esto limita el token al único sitio de Jira que autoriza el usuario, que es exactamente lo que apunta una conexión de DefectDojo. (**Account-level** otorga acceso a todos los sitios de la cuenta de Atlassian — más amplio de lo necesario.)
3. En **Permissions**, añada la **Jira platform REST API** y otorgue los alcances listados a continuación. Nota: `offline_access` *no* aparece aquí — es un alcance OAuth estándar que DefectDojo solicita en la URL de autorización, no algo que se añada en esta pantalla.
4. En **Authorization**, junto a **OAuth 2.0 (3LO)**, haga clic en **Configure** y establezca la **Callback URL** en `https://<your-defectdojo-host>/integrators/jira/oauth/callback` — debe coincidir exactamente con la URL de su sitio de DefectDojo. Habilitar esto es lo que activa el grant de código de autorización y los tokens de renovación; omitirlo provoca los errores `grant_type is not enabled` / `Client is not allowed to use offline_access`.
5. Copie el **Client ID** y el **Client Secret** en el formulario de DefectDojo y haga clic en **Submit** para guardar la conexión.
6. Haga clic en **Connect with Jira** y apruebe la pantalla de consentimiento. Atlassian redirige de vuelta a DefectDojo, que almacena los tokens y resuelve su `cloudId` automáticamente. Aparece un indicador "Connected" cuando tiene éxito.

> El host de callback es su `SITE_URL` de DefectDojo. Atlassian debe poder redirigir el navegador allí, y el valor debe coincidir exactamente con lo que envía DefectDojo — así que use el nombre de host real al que sus usuarios acceden a DefectDojo, no un valor solo alcanzable desde dentro de la red.

#### Alcances mínimos de OAuth

DefectDojo solicita estos cuatro alcances clásicos de forma predeterminada, y también son el **mínimo absoluto** requerido — cada uno respalda un comportamiento específico:

| Alcance | Requerido para |
|-------|--------------|
| `read:jira-work` | Leer el proyecto, las incidencias y las transiciones disponibles (validación de conexión y sincronización de estado). |
| `write:jira-work` | Crear y editar incidencias, y ejecutar transiciones de estado. |
| `read:jira-user` | La verificación de identidad de la conexión — DefectDojo llama a `/myself` al validar el acceso. |
| `offline_access` | Emitir un **token de renovación**. Sin él, el token de acceso expira (~1 hora después de conectarse) y la conexión deja de funcionar, porque DefectDojo ya no puede renovarlo. |

Atlassian recomienda los alcances clásicos sobre los granulares; los cuatro anteriores mantienen mínima la huella de la aplicación y son suficientes para todo lo que hace la integración.

##### Alternativa de alcances granulares

Si su organización requiere alcances **granulares** en lugar de clásicos, el conjunto mínimo equivalente es:

| Alcance granular | Requerido para |
|----------------|--------------|
| `read:user:jira` | La verificación de identidad `/myself`. |
| `read:project:jira` | Validar que el proyecto objetivo existe. |
| `read:issue:jira` | Leer el estado actual de una incidencia durante la sincronización. |
| `write:issue:jira` | Crear y editar incidencias **y ejecutar transiciones de estado** — no existe un alcance de escritura de transición separado; una transición es una escritura en la incidencia. |
| `read:issue.transition:jira` | Listar las transiciones disponibles en una incidencia. |
| `offline_access` | El token de renovación (igual que en el clásico). |

Dependiendo de la configuración de campos de su sitio, un endpoint también puede requerir alcances de lectura complementarios para expandir campos — lo más común es `read:status:jira` y `read:field:jira` (y `read:issue-meta:jira` para la creación). Si un envío falla con un error `403` de "scope does not match", añada el alcance exacto indicado en el error. Esta proliferación de alcances complementarios es precisamente la razón por la que se recomiendan los alcances clásicos.

Para el método **Service Account Token**, otorgue al token `read:jira-work` y `write:jira-work` (además de `read:jira-user`) — o los equivalentes granulares anteriores sin `offline_access`. `offline_access` no aplica — un token de cuenta de servicio es de larga duración y DefectDojo no lo renueva.

### Mapeo del Issue Tracker

- **Project Key**: la clave del proyecto de Jira en el que se crearán las incidencias, por ejemplo `SEC`.
- **Issue Type**: el tipo de incidencia a crear, por ejemplo `Bug` o `Task`. El valor predeterminado es `Bug`.

### Detalles del mapeo de severidad

Los valores predeterminados coinciden con el esquema de prioridad predeterminado de Jira. Edítelos para que coincidan con los nombres de prioridad de su proyecto:

- **Severity Field Name**: `priority`
- **Info Mapping**: `Lowest`
- **Low Mapping**: `Low`
- **Medium Mapping**: `Medium`
- **High Mapping**: `High`
- **Critical Mapping**: `Highest`

### Detalles del mapeo de estado

Los estados varían según el flujo de trabajo de cada proyecto, por lo que estos valores predeterminados están pensados para editarse con los nombres de estado de **su** flujo de trabajo:

- **Status Field Name**: `status`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

### Campos personalizados (opcional)

Puede mapear campos adicionales de Jira — por ejemplo, un `resolution` requerido al cerrar, o `labels` — en el paso **Custom Fields** del mapeo. Cada mapeo de campo personalizado tiene cuatro partes:

- **Source** — de dónde proviene el valor: un atributo del **Finding**, **Test**, **Engagement** o **Asset** que se está enviando, o un **Static value**.
- **Value** — para un origen de objeto, el atributo específico a leer, elegido de una lista de los campos de ese objeto con etiquetas legibles (por ejemplo *Severity*, *CVE*, *Mitigation*). Para un origen **Static value**, esto es un cuadro de texto libre en el que escribe el valor literal.
- **Vendor Field** — el campo de Jira en el que se escribe. Como DefectDojo puede leer el catálogo de campos de Jira, este es un selector con búsqueda que lista cada campo por su **nombre de visualización** y lo resuelve al id interno por usted — así que selecciona *DD Close Justification* y DefectDojo almacena `customfield_10255`. El selector se llena a partir de la conexión, por lo que funciona una vez que la conexión se ha guardado y validado.
- **Application point** — *cuándo* enviar el campo: en la **creación del ticket**, en **cada actualización**, o como parte de una **transición** de estado específica (Active / Closed / False Positive / Risk Accepted). Un campo con alcance de transición se envía como parte de la edición de esa transición — así es como se proporciona un valor que Jira solo acepta en una pantalla de transición, más comúnmente un `resolution` que su flujo de trabajo requiere cuando se resuelve una incidencia.

### Plantillas de ticket (opcional)

De forma predeterminada, las incidencias de Jira usan el título y el cuerpo integrados de DefectDojo. Para personalizarlos, adjunte una **Ticket Template** al mapeo en su paso **Ticket Template**. Una plantilla define cuatro piezas independientemente opcionales — el resumen y la descripción del **Finding**, y el resumen y la descripción del **Finding Group**. Cualquier pieza que se deje en blanco recurre al valor predeterminado integrado, por lo que puede anular solo el título, solo el cuerpo, o los cuatro. Use **Test render** en el editor de plantillas para previsualizar la salida renderizada con datos de muestra — detectando errores como marcadores de posición desconocidos o valores que exceden el límite de longitud de un campo — antes de guardar. Si una plantilla se elimina posteriormente, los mapeos que la usaban vuelven automáticamente a los valores predeterminados integrados.

### Cómo funciona

- **Crear / Actualizar / Eliminar:** crear envía una nueva incidencia y registra el enlace en el Hallazgo; actualizar edita la incidencia existente; eliminar un Hallazgo fuerza el cierre de su incidencia (nada se elimina en Jira). Los envíos pueden ser manuales ("Push to Integrator") o automáticos según la asignación del Issue Tracker.
- **Reconciliación de estado:** después de crear (y en cada actualización) DefectDojo lee el estado actual de la incidencia y, si difiere del objetivo mapeado, busca una única transición del flujo de trabajo que lo alcance y la aplica. Si no existe tal transición, el mapeo registra un error en lugar de fallar silenciosamente. Cualquier campo personalizado con alcance de transición se envía con esa transición.
- **Enlace del ticket:** el enlace que se muestra en el Hallazgo es `https://your-site.atlassian.net/browse/{ISSUE-KEY}` — siempre la URL pública de su sitio, nunca la puerta de enlace interna.
- **Ciclo de vida del token (OAuth):** DefectDojo gestiona todo el flujo — realiza el intercambio de código de autorización, almacena los tokens de acceso y de renovación, y renueva bajo demanda antes de un envío, guardando el nuevo token de renovación cada vez (Atlassian lo rota en cada renovación).
- **Almacenamiento de credenciales:** todas las credenciales de la conexión (contraseñas, tokens, secretos de cliente, tokens OAuth) se cifran en reposo y nunca se devuelven a través de la API — editar una conexión muestra un marcador de posición "leave blank to keep" para los secretos almacenados.

## Linear

La integración de Linear le permite enviar los Hallazgos de DefectDojo como incidencias de [Linear](https://linear.app/). Las incidencias se crean en un equipo (Team) de su espacio de trabajo de Linear.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://api.linear.app/graphql`.
- **API Key** debe establecerse en una clave de API personal de Linear. Las claves pueden generarse en Linear en Settings, luego Security & access, luego [API](https://linear.app/settings/account/security). La clave se envía a la API GraphQL de Linear en el encabezado `Authorization`.

### Mapeo del Issue Tracker

- **Team (Group) ID** debe establecerse en el ID del equipo de Linear para el que se crearán las incidencias. Puede listar sus equipos y sus ID llamando a la API GraphQL de Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Detalles del mapeo de severidad

Una incidencia de Linear lleva una **priority** numérica en lugar de un campo de severidad. Cada severidad de DefectDojo se mapea a una prioridad de Linear, donde `1` es Urgent y `4` es Low:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

### Detalles del mapeo de estado

Cada valor de estado debe establecerse en el ID de un estado de flujo de trabajo (Workflow State) en su equipo de Linear. Los ID de estado de flujo de trabajo son únicos para cada espacio de trabajo, por lo que no hay valores predeterminados. Puede listar los estados de flujo de trabajo y sus ID llamando a la API GraphQL de Linear:

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping**: el ID de un estado started o unstarted, por ejemplo `Todo` o `In Progress`.
- **Closed Mapping**: el ID de un estado completed, por ejemplo `Done`. Cuando se elimina un Hallazgo en DefectDojo, su incidencia se mueve a este estado.

## Opsgenie

La integración de Opsgenie le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como alertas de Opsgenie, opcionalmente enrutadas a un equipo de Opsgenie como responsable.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://api.opsgenie.com`. Si su cuenta de Opsgenie está alojada en la región de servicio de la UE, use `https://api.eu.opsgenie.com` en su lugar. Si sus alertas residen en Jira Service Management Operations (Atlassian está integrando Opsgenie en JSM), use `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** debe establecerse en una clave de **integración API** de Opsgenie. Un administrador de la cuenta puede crear una en la aplicación web de Opsgenie en **Settings > Integrations**: añada una integración de tipo **API** y otórguele *Create and Update Access* (y *Read Access* para que DefectDojo pueda verificar la conexión). Tenga en cuenta que esto es una clave de integración, no una clave de API personal - DefectDojo se autentica con autorización `GenieKey`, que solo admiten las claves de integración.

### Mapeo del Issue Tracker

- **Team Name** *(opcional)* debe ser el nombre del equipo de Opsgenie que se añadirá como responsable en las alertas creadas. Puede dejarlo vacío: si la clave de integración de la API tiene alcance de equipo, las alertas se enrutan automáticamente a ese equipo, y en caso contrario las propias reglas de enrutamiento de su cuenta deciden los responsables.

### Detalles del mapeo de severidad

Las severidades se mapean al campo **Priority** de la alerta de Opsgenie, que usa la escala fija de Opsgenie de `P1` (crítica) a `P5` (informativa):

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P5`
- **Low Mapping**: `P4`
- **Medium Mapping**: `P3`
- **High Mapping**: `P2`
- **Critical Mapping**: `P1`

Si una severidad se mapea a un valor no reconocido, se omite la prioridad y Opsgenie aplica su propio valor predeterminado (`P3`).

### Detalles del mapeo de estado

Las alertas de Opsgenie son `open` o `closed`, y una alerta abierta puede además estar `acknowledged`:

- **Status Field Name**: `Status`
- **Active Mapping**: `open`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `acknowledged`

Tenga en cuenta que `closed` es un estado final en Opsgenie - una alerta cerrada no se puede reabrir, y su alias queda liberado. A diferencia de otras herramientas, Opsgenie sí permite editar el contenido después de la creación, así que enviar un Hallazgo actualizado sincroniza su mensaje, descripción y prioridad junto con el estado.

DefectDojo establece el **alias** de cada alerta con una clave estable derivada del Hallazgo o Grupo de Hallazgos, y Opsgenie deduplica las alertas abiertas por alias - así que reenviar el mismo Hallazgo actualiza la alerta abierta existente en lugar de crear un duplicado.

## PagerDuty

La integración de PagerDuty le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como incidentes de PagerDuty, abiertos en un servicio de PagerDuty de su elección.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desea usar para identificar esta integración.
- **Location** debe establecerse en `https://api.pagerduty.com`. Si su cuenta de PagerDuty está alojada en la región de servicio de la UE, use `https://api.eu.pagerduty.com` en su lugar.
- **API Token** debe establecerse en una clave de la API REST de PagerDuty. Un administrador de la cuenta puede crear una en la aplicación web de PagerDuty en **Integrations > API Access Keys > Create New API Key**. Deje sin marcar "Read-only" - DefectDojo necesita crear y actualizar incidentes.
- **From Email** debe ser la dirección de correo electrónico de un usuario válido de su cuenta de PagerDuty. PagerDuty requiere esta dirección al crear o actualizar incidentes, y se mostrará como el solicitante del incidente.

### Mapeo del Issue Tracker

- **Service ID** debe ser el ID del servicio de PagerDuty en el que se abrirán los incidentes. Puede encontrarlo al final de la URL al ver el servicio en PagerDuty, por ejemplo `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Detalles del mapeo de severidad

De forma predeterminada, esto se mapea al campo **Urgency** del incidente de PagerDuty, que solo acepta `high` o `low`:

- **Severity Field Name**: `Urgency`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `low`
- **High Mapping**: `high`
- **Critical Mapping**: `high`

Alternativamente, si su cuenta de PagerDuty tiene habilitadas las [Priorities](https://support.pagerduty.com/main/docs/incident-priority), puede mapear las severidades a nombres de Priority en su lugar. Establezca **Severity Field Name** en `Priority` y use los nombres de Priority de su cuenta (por ejemplo `P1` a `P5`) como valores de mapeo. Al mapear a Priority, la Urgency del incidente queda a cargo de las propias reglas de urgencia de su servicio.

### Detalles del mapeo de estado

Los incidentes de PagerDuty tienen tres estados: `triggered`, `acknowledged` y `resolved`.

- **Status Field Name**: `Status`
- **Active Mapping**: `triggered`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `resolved`
- **Risk Accepted Mapping**: `acknowledged`

Tenga en cuenta que `resolved` es un estado final en PagerDuty - un incidente resuelto no se puede reabrir. Tenga en cuenta también que PagerDuty no permite editar el título o la descripción de un incidente después de su creación, así que enviar un Hallazgo actualizado sincronizará su estado, urgencia y prioridad, pero no los cambios de contenido.

## ServiceNow

La integración con ServiceNow le permite enviar los Hallazgos de DefectDojo como Incidentes de ServiceNow.

### Configuración de la instancia

DefectDojo se autentica ante ServiceNow mediante OAuth 2.0. La forma de crear las credenciales de OAuth depende de la versión de ServiceNow: las versiones más recientes (Zurich y posteriores) usan una concesión de Client Credentials, mientras que las versiones anteriores usan un token de actualización (refresh token).

#### ServiceNow Zurich y posteriores (client credentials)

Las versiones recientes de ServiceNow han descontinuado la opción clásica "Create an OAuth API endpoint for external clients" en favor de la **New Inbound Integration Experience**, que emite una concesión OAuth de **Client Credentials** vinculada a una cuenta de servicio:

1. En la barra de navegación izquierda, busque "Application Registry" y selecciónela.
2. Haga clic en **New** y luego elija **New Inbound Integration Experience**.
3. Seleccione **New Integration → OAuth - Client credentials grant**.
4. Configure **OAuth Application User** con la cuenta de servicio que creará los Incidentes. Los roles de esa cuenta determinan lo que DefectDojo puede escribir.
5. Guarde el registro. ServiceNow genera automáticamente el **Client ID** y el **Client Secret** (deje esos campos en blanco al crear el registro).

Luego, en DefectDojo:

- **Instance Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su servidor ServiceNow, por ejemplo `https://your-organization.service-now.com/`.
- **Client ID** debe ser el Client ID del registro de OAuth.
- **Client Secret** debe ser el Client Secret del registro de OAuth.

Deje vacíos los campos Refresh Token, Username y Password: DefectDojo solicita un token nuevo mediante client credentials en cada sincronización.

#### Versiones anteriores de ServiceNow (refresh token)

En las versiones que aún ofrecen el registro clásico, obtenga un Refresh Token asociado al Usuario o a la cuenta de servicio que enviará los Incidentes a ServiceNow:

1. En la barra de navegación izquierda, busque "Application Registry" y selecciónela.
2. Haga clic en "New".
3. Elija "Create an OAuth API endpoint for external clients".
4. Complete los campos obligatorios:
    * Name: proporcione un nombre significativo para su aplicación (por ejemplo, Vulnerability Integration Client).
    * (Opcional) Ajuste la vigencia del token:
    * Access Token Lifespan: el valor predeterminado es 1800 segundos (30 minutos).
    * Refresh Token Lifespan: el valor predeterminado es 8640000 segundos (aproximadamente 100 días).
5. Haga clic en Submit para crear el registro de la aplicación.
6. Después de enviarlo, seleccione la aplicación en la lista y anote los campos **Client ID y Client Secret**.

Luego deberá usar este registro para obtener un Refresh Token, que solo se puede obtener a través de la API de ServiceNow. Abra una ventana de terminal y pegue lo siguiente (sustituyendo las variables entre `{{}}` por la información real de su usuario)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Si sus credenciales de ServiceNow son correctas y permiten acceso de nivel administrador a ServiceNow, debería recibir una respuesta con un RefreshToken. Necesitará ese token para completar la integración con DefectDojo.

- **Instance Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su servidor ServiceNow, por ejemplo `https://your-organization.service-now.com/`.
- **Refresh Token** es donde debe introducirse el Refresh Token.
- **Client ID** debe ser el Client ID configurado en el OAuth App Registration.
- **Client Secret** debe ser el Client Secret configurado en el OAuth App Registration.

### Detalles del mapeo de severidad

Esto se corresponde con el campo Impact de ServiceNow.
- **Mapeo de Informativa**: `1`
- **Mapeo de Baja**: `1`
- **Mapeo de Media**: `2`
- **Mapeo de Alta**: `3`
- **Mapeo de Crítica**: `3`

### Detalles del mapeo de estado

- **Nombre del campo de estado**: `State`
- **Mapeo de Activo**: `New`
- **Mapeo de Cerrado**: `Closed`
- **Mapeo de Falso positivo**: `Resolved`
- **Mapeo de Riesgo aceptado**: `Resolved`

Cada mapeo acepta una etiqueta de estado estándar (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) o un valor de estado numérico. En instancias con estados de Incidente personalizados, o cuando se apunta a una tabla distinta de `incident`, use el **valor de estado** numérico de la lista de opciones de su instancia; un valor numérico fuera del conjunto estándar se envía a ServiceNow exactamente como se configuró. El valor predeterminado integrado del código de resolución solo acompaña a los estados estándar de resuelto/cerrado, así que combine los valores de estado personalizados con los mapeos de campos de cierre y resolución que se describen a continuación.

### Campos de cierre y resolución

Algunas instancias de ServiceNow aplican una Data Policy que hace obligatorios campos como el **Resolution code** (`close_code`) cada vez que un Incidente pasa a un estado resuelto o cerrado. Si DefectDojo cierra un Incidente sin ellos, ServiceNow rechaza la escritura con un HTTP 403 *"Data Policy Exception"* y el motivo queda registrado en la vista de Errores de la integración.

Asocie los campos requeridos al cambio de estado mediante **Custom Field Mappings**, configurando **Apply On** con la disposición que debe incluirlos:

- **Transition to Closed**: se envía cuando un Hallazgo se mitiga o se cierra.
- **Transition to False Positive**: se envía cuando un Hallazgo se marca como falso positivo.
- **Transition to Risk Accepted**: se envía cuando un Hallazgo tiene el riesgo aceptado.

Por ejemplo, para satisfacer un Resolution code obligatorio:

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Notas:

- Field Name es el nombre de columna de ServiceNow: `close_code`, `close_notes`, o un campo personalizado `u_...`.
- Los mapeos de transición se disparan cuando el estado del registro realmente cambia: un Hallazgo que ya está cerrado cuando se envía por primera vez, una actualización que cierra o reabre el registro, y el cierre forzado cuando se elimina un enlace de ticket. No se vuelven a enviar en actualizaciones rutinarias de un registro sin cambios, por lo que los campos de bitácora como `work_notes` reciben una entrada por cada transición.
- Los campos de referencia como `assignment_group` y `assigned_to` esperan un **sys_id**, no un nombre para mostrar.
- Los valores que se interpretan como JSON se envían tipados: `true`, `42`, `[...]`, `{...}`, y `null`, que borra el campo. Para enviar ese texto como una cadena literal, enciérrelo entre comillas dobles (por ejemplo, `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` y `priority` pertenecen a la plantilla de descripción y a los mapeos de severidad/estado, por lo que no se pueden configurar mediante un mapeo de campo personalizado.
- En tablas distintas de `incident`, los valores de estado que coinciden con el conjunto estándar de Incidente (`1`, `2`, `3`, `6`, `7`, `8`) se siguen interpretando con la semántica de Incidente, incluido el valor predeterminado automático de Resolution code en `6`/`7`/`8`. Prefiera valores de estado fuera de ese rango en tablas personalizadas, o proporcione explícitamente los campos de cierre como se indicó anteriormente.

## ServiceNow SecOps

La integración de ServiceNow SecOps (también conocida como **ServiceNow SecOps / Vulnerability Response**) envía los Hallazgos y Grupos de Hallazgos de DefectDojo a una tabla de seguridad de ServiceNow —un **Security Incident** (`sn_si_incident`) o un **Vulnerable Item** (`sn_vul_vulnerable_item`)— y la mantiene sincronizada a medida que el Hallazgo cambia (creación, actualización y resolución/cierre). Es la contraparte de operaciones de seguridad de la integración de ServiceNow como sistema de tickets descrita arriba; use ServiceNow SecOps cuando ejecute las aplicaciones Security Incident Response (SIR) o Vulnerability Response (VR).

### Configuración de la instancia

- **Instance Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su servidor ServiceNow, por ejemplo `https://your-organization.service-now.com/`.

ServiceNow SecOps admite tres métodos de autenticación; proporcione **uno**:

- **OAuth 2.0**: introduzca un **Client ID**, un **Client Secret** y un **Refresh Token**. Obténgalos exactamente como se describe en la sección [ServiceNow](#servicenow) anterior (cree un endpoint de API OAuth en el Application Registry y luego intercambie sus credenciales en `/oauth_token.do` por un refresh token). Alternativamente, proporcione el **Client ID** y el **Client Secret** junto con un **Username** y un **Password** para usar la concesión de contraseña de OAuth en lugar de un refresh token.
- **API Key**: introduzca una **API Key**, que se envía como el encabezado `x-sn-apikey`. La clave no autentica nada hasta que se le asocie un Inbound Authentication Profile y una REST API Access Policy en la instancia.
- **HTTP Basic**: introduzca el **Username** y el **Password** de la cuenta de servicio.

La cuenta de servicio (o el cliente OAuth) necesita acceso de escritura a la tabla de destino.

### Mapeo del sistema de tickets

- **Target Table** selecciona la tabla de ServiceNow en la que se escriben los registros: **Security Incident** (`sn_si_incident`, el valor predeterminado) o **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Detalles del mapeo de severidad

Para un Security Incident, esto se corresponde con el campo **Impact**; ServiceNow deriva la Priority del incidente a partir de Impact y Urgency, por lo que Urgency refleja el Impact mapeado a menos que lo mapee usted mismo. Para un Vulnerable Item, mapee la severidad al campo de riesgo que use su instancia. Los valores predeterminados a continuación coinciden con la escala estándar de Impact de SIR (`1` Alta, `2` Media, `3` Baja) y son editables.

- **Nombre del campo de severidad**: `impact`
- **Mapeo de Informativa**: `3`
- **Mapeo de Baja**: `3`
- **Mapeo de Media**: `2`
- **Mapeo de Alta**: `1`
- **Mapeo de Crítica**: `1`

### Detalles del mapeo de estado

Esto se corresponde con el campo **State** del registro. Los valores de State son códigos numéricos que difieren entre las tablas Security Incident y Vulnerable Item y pueden personalizarse por instancia, así que revíselos contra su propia configuración. Los valores predeterminados a continuación usan los códigos de estado estándar de SIR (`16` Analysis, `3` Closed).

- **Nombre del campo de estado**: `state`
- **Mapeo de Activo**: `16`
- **Mapeo de Cerrado**: `3`
- **Mapeo de Falso positivo**: `3`
- **Mapeo de Riesgo aceptado**: `3`

Cuando se cierra un registro, DefectDojo también configura el **Close Code** y las **Close Notes** de ServiceNow (`Resolved` para los Hallazgos cerrados, `False positive` y `Risk accepted` para los estados correspondientes).

### Comportamientos específicos de ServiceNow SecOps

- **Deduplicación**: cada registro se etiqueta con el identificador de DefectDojo del Hallazgo o del Grupo de Hallazgos en su `correlation_id`. Antes de crear un registro, DefectDojo busca uno existente por `correlation_id`; si hay coincidencia, se adopta y se actualiza en lugar de duplicarse, de modo que las resincronizaciones son idempotentes.
- Las **actualizaciones** se publican en la bitácora **Work notes** del registro (interna), nunca en los Comments visibles para el cliente.
- **Resolver al eliminar**: eliminar un Hallazgo en DefectDojo resuelve/cierra el registro de ServiceNow (State + Close Code) en lugar de eliminarlo; los registros nunca se eliminan de forma permanente.
- **Campos de referencia**: los valores opcionales `cmdb_ci`, `assignment_group` y `assigned_to` pueden proporcionarse como nombres para mostrar; DefectDojo resuelve cada uno a su `sys_id`. Un nombre que no se resuelve se descarta con una advertencia en lugar de hacer fallar el envío.

## Shortcut

La integración con Shortcut le permite enviar los Hallazgos de DefectDojo como Stories de [Shortcut](https://www.shortcut.com/). Las Stories se crean con el tipo de story Bug y se asignan a un Team de su espacio de trabajo de Shortcut.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse como `https://api.app.shortcut.com`.
- **API Token** debe configurarse con un token de API de Shortcut. Los tokens pueden generarse en Shortcut en Settings, luego Your Account, luego [API Tokens](https://app.shortcut.com/settings/account/api-tokens).

### Mapeo del sistema de tickets

- **Team (Group) ID** debe configurarse con el UUID del Team de Shortcut para el que se crearán las Stories. Puede encontrar este UUID abriendo la página del Team en Shortcut y copiando el identificador de la URL, o llamando a la API de Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Detalles del mapeo de severidad

Cada valor de severidad se aplica a la Story como una etiqueta. Las etiquetas se crean automáticamente en Shortcut si aún no existen, por lo que los valores predeterminados a continuación pueden usarse tal cual, o sustituirse por nombres de etiqueta de su elección. Cuando cambia la severidad de un Hallazgo, la etiqueta de severidad anterior se elimina de la Story y se añade la nueva.

- **Nombre del campo de severidad**: `Label`
- **Mapeo de Informativa**: `sev-info`
- **Mapeo de Baja**: `sev-low`
- **Mapeo de Media**: `sev-medium`
- **Mapeo de Alta**: `sev-high`
- **Mapeo de Crítica**: `sev-critical`

### Detalles del mapeo de estado

Cada valor de estado debe configurarse con el ID numérico de un Workflow State en su espacio de trabajo de Shortcut. Los ID de Workflow State son únicos para cada espacio de trabajo, por lo que no hay valores predeterminados. Puede listar los Workflow States y sus ID llamando a la API de Shortcut:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Nombre del campo de estado**: `Workflow State ID`
- **Mapeo de Activo**: el ID del estado para trabajo abierto, por ejemplo un estado de Backlog o To Do.
- **Mapeo de Cerrado**: el ID de un estado de tipo Done. Cuando se elimina un Hallazgo en DefectDojo, su Story se mueve a este estado.
- **Mapeo de Falso positivo**: el ID del estado que se usará para los Hallazgos marcados como Falso positivo.
- **Mapeo de Riesgo aceptado**: el ID del estado que se usará para los Hallazgos con Riesgo aceptado.

## Freshservice

La integración con Freshservice le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como tickets de Freshservice, asignados a un Group de agentes de su elección.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con su URL de Freshservice: `https://yourcompany.freshservice.com`.
- **API Key** debe ser una clave de API de Freshservice. Encuéntrela haciendo clic en su foto de perfil (arriba a la derecha) > **Profile settings**: la clave aparece a la derecha, debajo de la sección **Delegate Approvals**, después de completar el captcha. Si no aparece ninguna clave ahí, es posible que el acceso a la API esté deshabilitado a nivel de cuenta y un administrador deba habilitarlo primero.
- **Requester Email** debe ser la dirección de correo en cuyo nombre se solicitan los tickets. Freshservice exige un solicitante en cada ticket, por lo que DefectDojo crea los tickets con esta dirección como solicitante.

### Mapeo del sistema de tickets

- **Group ID** debe ser el ID numérico del Group de agentes de Freshservice al que se asignarán los tickets. Encuéntrelo en la URL al ver el grupo en **Admin > Agent Groups**.
- **Workspace ID** (opcional) enruta los tickets a un espacio de trabajo específico en cuentas con varios espacios de trabajo. Déjelo vacío para usar el espacio de trabajo principal.

### Detalles del mapeo de severidad

Esto se corresponde con el campo **Priority** del ticket de Freshservice, que usa códigos numéricos (`1` Low, `2` Medium, `3` High, `4` Urgent). También se aceptan los nombres de prioridad:

- **Nombre del campo de severidad**: `Priority`
- **Mapeo de Informativa**: `1`
- **Mapeo de Baja**: `1`
- **Mapeo de Media**: `2`
- **Mapeo de Alta**: `3`
- **Mapeo de Crítica**: `4`

### Detalles del mapeo de estado

Esto se corresponde con el campo **Status** del ticket, que usa códigos numéricos (`2` Open, `3` Pending, `4` Resolved, `5` Closed). También se aceptan los nombres de estado:

- **Nombre del campo de estado**: `Status`
- **Mapeo de Activo**: `2`
- **Mapeo de Cerrado**: `5`
- **Mapeo de Falso positivo**: `5`
- **Mapeo de Riesgo aceptado**: `3`

Algunos comportamientos específicos de Freshservice que debe tener en cuenta:

- Las actualizaciones sincronizan el contenido completo del ticket: Freshservice permite editar el asunto y la descripción después de la creación.
- Los tickets se cierran en lugar de eliminarse cuando se elimina un Hallazgo; los tickets ya Resolved o Closed se dejan sin modificar. Se adjunta automáticamente una nota de resolución al cerrar, por lo que las cuentas que exigen una (una regla de negocio habitual) aceptan el cierre.
- Algunas cuentas calculan la prioridad de un ticket a partir de una matriz de Impact/Urgency o de una regla de negocio, e ignoran la prioridad enviada en la creación. DefectDojo detecta esto y vuelve a aplicar la prioridad mapeada con una actualización posterior, de modo que el mapeo sigue teniendo efecto.

## ServiceDesk Plus

La integración con ManageEngine ServiceDesk Plus le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como solicitudes (requests) de ServiceDesk Plus, asignadas a un Group de soporte de su elección. La misma integración admite tanto la edición **cloud** (ServiceDesk Plus OnDemand) como la **on-premises**; las credenciales que proporcione determinan qué modo se usa.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con su URL de ServiceDesk Plus: `https://sdpondemand.manageengine.com` para la edición cloud (o su equivalente regional), o la dirección de su servidor para instalaciones on-premises.

Luego proporcione **uno** de los dos conjuntos de credenciales:

#### On-premises: Technician Key

- **Technician Key** debe ser una clave de API generada para un técnico en su servidor, en **Admin > General Settings > API**. Deje vacíos los campos de OAuth de Zoho.

#### Cloud: Zoho OAuth

La edición cloud se autentica mediante Zoho Accounts OAuth:

1. Abra la [Zoho API Console](https://api-console.zoho.com/) y cree un **Self Client**.
2. Anote el **Client ID** y el **Client Secret**.
3. En la pestaña "Generate Code" del Self Client, introduzca el alcance `SDPOnDemand.requests.ALL`, elija una duración y genere el código.
4. Intercambie el código por un refresh token:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Introduzca el **Client ID**, el **Client Secret** y el **Refresh Token** obtenido en el formulario de la instancia. Si su cuenta está alojada fuera del centro de datos de EE. UU., configure **Token URL** con el endpoint regional de Zoho Accounts correspondiente (por ejemplo, `https://accounts.zoho.eu/oauth/v2/token`).

### Mapeo del sistema de tickets

- **Group Name** debe ser el nombre del grupo de soporte de ServiceDesk Plus al que se asignarán las solicitudes, exactamente como aparece en **Admin > Users > Support Groups**.

### Detalles del mapeo de severidad

Esto se corresponde con el campo **Priority** de la solicitud de ServiceDesk Plus por nombre, usando los nombres de prioridad de su cuenta:

- **Nombre del campo de severidad**: `Priority`
- **Mapeo de Informativa**: `Low`
- **Mapeo de Baja**: `Normal`
- **Mapeo de Media**: `Medium`
- **Mapeo de Alta**: `High`
- **Mapeo de Crítica**: `High`

### Detalles del mapeo de estado

Esto se corresponde con el campo **Status** de la solicitud por nombre. Los valores predeterminados usan los estados integrados:

- **Nombre del campo de estado**: `Status`
- **Mapeo de Activo**: `Open`
- **Mapeo de Cerrado**: `Closed`
- **Mapeo de Falso positivo**: `Closed`
- **Mapeo de Riesgo aceptado**: `On Hold`

Algunos comportamientos específicos de ServiceDesk Plus que debe tener en cuenta:

- Las actualizaciones sincronizan el contenido completo de la solicitud: a diferencia de la mayoría de los sistemas de tickets, ServiceDesk Plus permite editar el asunto y la descripción después de la creación.
- Las solicitudes se cierran en lugar de eliminarse cuando se elimina un Hallazgo; las solicitudes ya Closed o Resolved se dejan sin modificar.
- Si su cuenta hace obligatorios ciertos campos al cerrar (por ejemplo, una resolución), un cierre enviado desde DefectDojo puede ser rechazado por esas reglas y aparecerá en la tabla de errores de la integración.

## Zendesk

La integración con Zendesk le permite enviar los Hallazgos y Grupos de Hallazgos de DefectDojo como tickets de Zendesk, asignados a un Group de Zendesk de su elección.

### Configuración de la instancia

- **Label** debe ser la etiqueta que desee usar para identificar esta integración.
- **Location** debe configurarse con la URL de su cuenta de Zendesk, por ejemplo `https://your-subdomain.zendesk.com`.
- **Email** debe ser la dirección de correo del agente de Zendesk al que pertenece el token de API.
- **API Token** debe configurarse con un token de API de Zendesk. Un administrador puede crear uno en el Zendesk Admin Center, en **Apps and integrations > APIs > Zendesk API** (debe habilitarse el acceso por token).

### Mapeo del sistema de tickets

- **Group ID** debe ser el ID numérico del Group de Zendesk al que se asignarán los tickets. Puede encontrarlo en el Admin Center, en **People > Team > Groups**, o en la URL al ver el grupo.

### Detalles del mapeo de severidad

Esto se corresponde con el campo **Priority** del ticket de Zendesk, que acepta `low`, `normal`, `high` y `urgent`:

- **Nombre del campo de severidad**: `Priority`
- **Mapeo de Informativa**: `low`
- **Mapeo de Baja**: `low`
- **Mapeo de Media**: `normal`
- **Mapeo de Alta**: `high`
- **Mapeo de Crítica**: `urgent`

### Detalles del mapeo de estado

Los tickets de Zendesk admiten los estados `new`, `open`, `pending`, `hold` y `closed`, así como `solved`. Tenga en cuenta que `hold` debe estar habilitado en su cuenta antes de poder usarse.

- **Nombre del campo de estado**: `Status`
- **Mapeo de Activo**: `new`
- **Mapeo de Cerrado**: `solved`
- **Mapeo de Falso positivo**: `solved`
- **Mapeo de Riesgo aceptado**: `pending`

Algunos comportamientos específicos de Zendesk que debe tener en cuenta:

- La descripción del ticket es el primer comentario en Zendesk y no se puede editar después de la creación, por lo que enviar un Hallazgo actualizado sincronizará el asunto, la prioridad y el estado del ticket, pero no los cambios de descripción.
- Los tickets se marcan como `solved` en lugar de eliminarse cuando se elimina un Hallazgo; Zendesk cierra automáticamente los tickets resueltos después de un período de tiempo.
- `closed` es un estado final: los tickets cerrados no se pueden actualizar en absoluto, y enviar un Hallazgo cuyo ticket esté cerrado generará un error.
