---
title: Referencia de nodos
description: Todos los nodos con los que se distribuye Rules Engine 2.0, y qué hace
  cada uno
weight: 3
audience: pro
aliases:
- /es/automation/rules_engine_v2/node_reference/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 es una función exclusiva de DefectDojo Pro.</span>

Rules Engine 2.0 se distribuye con 25 nodos en cuatro categorías. Esta página los documenta todos.

A menos que se indique lo contrario, un nodo recibe una entrada, produce una salida llamada `out`, y pasa cada elemento que recibió a esa salida. Esto importa cuando se encadenan nodos: un nodo de Hallazgos modifica el Hallazgo y luego pasa el elemento hacia adelante, de modo que varios de ellos en fila se aplican todos.

## Triggers

Cada grafo tiene exactamente un disparador, y solo un disparador puede iniciar una ejecución. Los tres producen elementos de Hallazgo y los tres reciben un **Scope** que restringe qué Hallazgos producen. Consulte [Building Rules](../building_rules/) para saber cómo funciona el alcance.

### Ante un evento de Hallazgo

`trigger.finding`

Se ejecuta cuando se crean, actualizan, cierran o reabren Hallazgos.

| Setting | Default | Notes |
|---------|---------|-------|
| **Event** | `created` | Qué cambio de Hallazgo activa esta regla: `created`, `updated`, `closed`, `reopened`, o `any` para las cuatro. |
| **Scope** | vacío | Qué Hallazgos considera esta regla. Vacío significa todos los Hallazgos que el propietario de la regla puede ver. |

Los Hallazgos identificados por el evento se comparan con el alcance antes de entrar en el grafo, de modo que el evento decide *cuándo* y el alcance decide *cuáles*.

### Según una programación

`trigger.schedule`

Recorre todos los Hallazgos dentro del alcance según una programación. La programación se configura en la regla y está limitada a marcas de cuarto de hora.

| Setting | Default | Notes |
|---------|---------|-------|
| **Scope** | vacío | Qué Hallazgos considera esta regla. |

### Ejecución manual

`trigger.manual`

Recorre todos los Hallazgos dentro del alcance cuando se presiona **Run** en la regla.

| Setting | Default | Notes |
|---------|---------|-------|
| **Scope** | vacío | Qué Hallazgos considera esta regla. |

## Lógica

### Si / Filtro

`filter.if`

Enruta cada elemento hacia la rama **true** o la rama **false**, según condiciones. Este es el único nodo con dos salidas, y es la forma en que un grafo se ramifica.

| Setting | Default | Notes |
|---------|---------|-------|
| **Conditions** | vacío | Cada fila es una ruta, un operador y un valor. Consulte [Conditions](../building_rules/#conditions). |
| **Match** | `all` | Si todas las condiciones deben cumplirse (`all`), o basta con una de ellas (`any`). |

Una lista de condiciones vacía pasa todo por la rama true. Ambas ramas son opcionales: dejar la rama false sin conectar simplemente descarta los elementos que fallaron.

### Límite

`flow.limit`

Pasa los primeros N elementos y descarta el resto. Es útil como válvula de seguridad mientras se prueba una regla, y para limitar cuántos tickets o mensajes puede producir una sola ejecución.

| Setting | Default | Notes |
|---------|---------|-------|
| **Keep First** | `100` | Cuántos elementos dejar pasar. |

### Deduplicar dentro de la ejecución

`flow.dedupe_batch`

Mantiene el primer elemento por clave y descarta los posteriores que llevan la misma clave. Está limitado a la ejecución, de modo que deduplica dentro de una sola ejecución y no entre ejecuciones.

| Setting | Default | Notes |
|---------|---------|-------|
| **Key Path** | `finding.hash_code` | La ruta del elemento cuyo valor identifica un duplicado. |

Un uso común es `finding.component_name`, para notificar una vez por componente afectado en lugar de una vez por Hallazgo.

## Hallazgos

Estos nodos modifican Hallazgos. Cada cambio se atribuye a la regla, la ejecución y el nodo que lo realizó, y aparece en la línea de tiempo de procedencia del Hallazgo.

### Establecer severidad

`finding.set_severity`

Establece la severidad, y recalcula con ella la fecha del SLA y la prioridad.

| Setting | Options |
|---------|---------|
| **Severity** | `Critical`, `High`, `Medium`, `Low`, `Info` |

### Establecer un campo

`finding.set_field`

Establece, agrega al final de, o antepone a un campo de texto.

| Setting | Default | Notes |
|---------|---------|-------|
| **Field** | ninguno | Uno de `component_name`, `component_version`, `cvssv3`, `cwe`, `description`, `file_path`, `impact`, `mitigation`, `service`, `title`. |
| **Mode** | `set` | `set`, `append` o `prepend`. Un vector CVSSv3 solo puede reemplazarse. |
| **Value** | ninguno | El texto que se escribirá. Admite marcadores de posición del estilo `{{finding.title}}`. |

### Establecer estado

`finding.set_status`

Mueve el Hallazgo a un estado.

| Setting | Default | Notes |
|---------|---------|-------|
| **Status** | ninguno | `active`, `inactive`, `verified`, `unverified`, `false_positive`, `mitigated`, `reopen`. |
| **Note** | vacío | Una nota opcional registrada junto con el cambio de estado. |

### Agregar etiquetas

`finding.add_tags`

Agrega etiquetas al Hallazgo. Las etiquetas existentes se conservan.

| Setting | Notes |
|---------|-------|
| **Tags** | Separadas por comas. Admite marcadores de posición del estilo `{{product.name}}`, de modo que se puede etiquetar con datos del Hallazgo. |

### Agregar una nota

`finding.add_note`

Agrega una nota al Hallazgo.

| Setting | Notes |
|---------|-------|
| **Note** | El texto de la nota. Admite marcadores de posición. |

### Establecer propietarios

`finding.set_owners`

Hace que un grupo sea responsable del Hallazgo.

| Setting | Notes |
|---------|-------|
| **Group** | El grupo propietario de estos Hallazgos. |

### Establecer revisores

`finding.set_reviewers`

Pone el Hallazgo en revisión por los usuarios seleccionados.

| Setting | Notes |
|---------|-------|
| **Reviewers** | Uno o más usuarios que deben revisar estos Hallazgos. |

### Aceptar riesgo

`finding.risk_accept`

Acepta el riesgo del Hallazgo de forma simple, o lo agrega a un registro de aceptación de riesgo.

| Setting | Default | Notes |
|---------|---------|-------|
| **How** | `simple` | `simple` establece la aceptación de riesgo simple en el Hallazgo. `acceptance` lo agrega a un registro de aceptación de riesgo. |
| **Accepted** | activado | Se muestra para `simple`. Desactive para anular la aceptación del riesgo. |
| **Risk Acceptance** | ninguno | Se muestra para `acceptance`. A qué aceptación de riesgo agregar estos Hallazgos. |

### Establecer política de mitigación

`finding.set_mitigation_policy`

Establece la política de mitigación bajo la cual se remedia el Hallazgo.

| Setting | Notes |
|---------|-------|
| **Mitigation Policy** | La política que se aplicará. |

### Cambiar prioridad

`finding.set_priority`

Establece la prioridad, o la ajusta aritméticamente. Esto anula la prioridad calculada.

| Setting | Default | Notes |
|---------|---------|-------|
| **Operation** | `set` | `set`, `add`, `subtract`, `multiply`, `divide`. |
| **Value** | ninguno | La prioridad que se establecerá, o la cantidad por la que ajustar. |

### Establecer riesgo

`finding.set_risk`

Establece el riesgo, anulando el calculado.

| Setting | Options |
|---------|---------|
| **Risk** | `Low`, `Medium`, `Needs Action`, `Urgent` |

## Salida

Los nodos de salida son los nodos que salen de DefectDojo. Cada uno de ellos registra una [Delivery](../deliveries/) antes de que se envíe nada, y cada uno respeta el modo **Simulate** o **Live** de la regla.

Varios de ellos ofrecen la misma opción **Un mensaje por hallazgo**. Desactivada, el nodo envía un mensaje que describe todo el lote, con un desglose por severidad y una lista limitada de Hallazgos. Activada, envía un mensaje por Hallazgo.

Un nodo que envía un mensaje por Hallazgo se detiene después de 1000 envíos en una sola ejecución de forma predeterminada, y registra una omisión visible que indica cuántos Hallazgos quedaron sin enviar. Consulte [Configuration](../configuration/#per-finding-send-ceiling).

### Cuando un canal no está disponible

Un nodo de salida depende de algo externo a la regla: un token de Slack, un webhook de Microsoft Teams, una configuración de JIRA, un conector con licencia. Cuando eso falta o está desactivado, el nodo no puede funcionar, y Rules Engine 2.0 lo indica en tres momentos distintos en lugar de fallar en silencio:

* **En la paleta**, un nodo no disponible se marca como tal, con el motivo, antes de que se arrastre al lienzo.
* **Al guardar**, se rechaza un grafo que contenga un nodo no disponible. Ese es el momento en que alguien está presente para elegir uno diferente.
* **En tiempo de ejecución**, la entrega se **omite** con el motivo adjunto, no falla. Una regla guardada mientras Slack estaba activo no debería empezar a generar errores el día que alguien desactive Slack. El registro honesto es una entrega omitida que indica que Slack está desactivado.

### Crear una incidencia de JIRA

`ticket.jira`

Crea o actualiza la incidencia de JIRA para el Hallazgo.

| Setting | Default | Notes |
|---------|---------|-------|
| **Skip Findings That Already Have an Issue** | activado | Deja intactos los Hallazgos que ya tienen una incidencia de JIRA. |
| **Update an Existing Issue** | desactivado | Se muestra cuando la opción anterior está desactivada. Envía los Hallazgos que ya tienen una incidencia, de modo que JIRA se actualiza. |

El resumen, la descripción y la prioridad provienen de la configuración de JIRA del producto, no de este nodo. Por lo tanto, un ticket creado por una regla es idéntico a uno creado por push all issues.

### Crear un ticket downstream

`ticket.downstream`

Crea o actualiza un ticket mediante un [Downstream Connector](/connectors/downstream/about/).

| Setting | Default | Notes |
|---------|---------|-------|
| **Issue Trackers** | `auto` | `auto` usa los rastreadores de incidencias asignados al Compromiso o al Producto. `mapping` apunta a una asignación específica. |
| **Issue Tracker Mapping** | ninguno | Se muestra para `mapping`. A qué asignación enviar. |
| **Operation** | `create` | `create` un ticket, o `update` el que ya existe. Una actualización sin ticket existente lo crea. |
| **Skip Findings That Already Have a Ticket** | activado | Deja intactos los Hallazgos que ya tienen un ticket en la asignación de destino. |

La regla reemplaza los ajustes automáticos de envío de la asignación: los filtros de severidad y de solo activos no se aplican una segunda vez aquí. Un Hallazgo cuyo ticket ya existe se omite sin importar cómo se haya creado ese ticket.

### Enviar un mensaje de Slack

`notify.slack`

Publica en un canal de Slack a través de un Messaging Connector. La conexión lleva el token del bot; los ajustes de Slack a nivel de instancia en **System Settings** no se usan y no sirven como respaldo.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | ninguno | Un [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) de este tipo. Obligatorio. |
| **Destination** | vacío | Se muestra una vez elegida una conexión. Los campos dependen del proveedor de la conexión. |
| **One Message per Finding** | desactivado | Desactivado envía un mensaje sobre el lote. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Se renderiza por Hallazgo. |
| **Findings Listed in the Digest** | `10` | Se muestra para mensajes por lote. Cuántos Hallazgos enumera el mensaje antes de indicar cuántos más había. |

### Enviar un mensaje de Microsoft Teams

`notify.msteams`

Publica una tarjeta a través de un Messaging Connector. La conexión lleva la URL del flujo de trabajo de Power Automate; el webhook de Teams a nivel de instancia en **System Settings** no se usa y no sirve como respaldo.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | ninguno | Un [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) de este tipo. Obligatorio. |
| **Destination** | vacío | Se muestra una vez elegida una conexión. Los campos dependen del proveedor de la conexión. |
| **One Message per Finding** | desactivado | Desactivado envía una tarjeta sobre el lote. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Se renderiza por Hallazgo. |
| **Findings Listed in the Digest** | `10` | Se muestra para mensajes por lote. |

### Enviar un correo electrónico

`notify.email`

Envía un correo electrónico a una lista fija de direcciones a través de un Messaging Connector. Los destinatarios son el destino de la conexión.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | ninguno | Un [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) de este tipo. Obligatorio. |
| **Destination** | vacío | Se muestra una vez elegida una conexión. Los campos dependen del proveedor de la conexión. |

| **Subject** | `[DefectDojo] {{ctx.count}} finding(s) from rule {{ctx.rule_name}}` | Se renderiza una vez por mensaje. |
| **Body** | un cuerpo HTML que contiene `{{ctx.findings_html}}` | HTML. `{{ctx.findings_html}}` renderiza la lista de Hallazgos. |
| **One Message per Finding** | desactivado | Desactivado envía un correo electrónico sobre el lote. |
| **Findings Listed in the Body** | `25` | Cuántos Hallazgos enumera `{{ctx.findings_html}}` antes de indicar cuántos más había. |

### Llamar a un webhook

`notify.webhook`

Envía un POST con JSON a un endpoint de webhook.

| Setting | Default | Notes |
|---------|---------|-------|
| **Webhook Endpoint** | ninguno | Un [notification webhook](/automation/api/notification_webhooks/) configurado. Su encabezado personalizado se envía con la solicitud. |
| **URL** | vacío | Se muestra cuando no se selecciona ningún endpoint. Adónde enviar el POST. |
| | | Se requiere uno de los dos anteriores. |
| **Signing Secret** | vacío | Firma el cuerpo como `X-DefectDojo-Signature: sha256=HMAC`. |
| **One Message per Finding** | desactivado | Desactivado publica todo el lote en una sola solicitud. |

Dos cosas que conviene saber. Un secreto de firma escrito aquí se almacena junto con la regla, así que para cualquier cosa sensible es preferible un endpoint configurado con su propio encabezado. Y un webhook llamado por una regla nunca cambia el estado de salud propio de ese endpoint, de modo que una regla no puede deshabilitar sus webhooks de notificación al fallar.

Las URL de texto libre se validan al guardar. Consulte [Configuration](../configuration/#outbound-destination-validation) para saber qué se rechaza y cómo permitir direcciones privadas.

### Generar una alerta en la aplicación

`notify.alert`

Crea una alerta en la aplicación sobre el lote.

| Setting | Default | Notes |
|---------|---------|-------|
| **Title** | `Rules Engine 2.0: {{ctx.rule_name}}` | Se renderiza una vez para todo el lote. |
| **Description** | `{{ctx.count}} finding(s) matched the rule {{ctx.rule_name}}.` | Se renderiza una vez para todo el lote. |
| **Recipients** | vacío | Nombres de usuario, separados por comas. Vacío alerta a los administradores. |

Los destinatarios igualmente controlan esto mediante su propio ajuste de notificación **Rules Engine Match**, de modo que una alerta no puede eludir las preferencias de notificación de un usuario.

### Generar un informe

`report.generate`

Genera un informe a partir de una plantilla, limitado a los Hallazgos que llegaron a este nodo, y puede anunciar el enlace de descarga.

| Setting | Default | Notes |
|---------|---------|-------|
| **Report Template** | ninguno | A partir de qué plantilla generar. Obligatorio. |
| **Format** | `pdf` | `pdf` o `html`. |
| **Findings Included** | `batch_findings` | `batch_findings` limita el informe a los Hallazgos que llegaron a este nodo. `template_default` permite que la plantilla use sus propios filtros. |
| **Announce Over** | ninguno | Un [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) mediante el cual publicar el enlace de descarga una vez generado el informe. Déjelo vacío para no anunciar. |
| **Announce To** | vacío | Se muestra una vez elegida una conexión. Adónde envía esa conexión: un ID de canal de Slack, direcciones de correo electrónico, etcétera. |
| **Announcement** | `Report ready: {{ctx.report_url}}` | Se muestra al anunciar. `{{ctx.report_url}}` es el enlace de descarga. |

`batch_findings` es lo que una regla puede hacer y un informe programado no: generar un informe exactamente sobre los Hallazgos que acaban de coincidir.

El anuncio se registra como una entrega propia, separada de la generación del informe, de modo que se puede ver que el informe tuvo éxito y que el anuncio falló de forma independiente.
