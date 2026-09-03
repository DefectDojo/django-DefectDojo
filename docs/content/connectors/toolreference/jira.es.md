---
title: "Jira"
description: "Cómo configurar el Conector Downstream de Jira para DefectDojo"
weight: 82
audience: pro
---
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
