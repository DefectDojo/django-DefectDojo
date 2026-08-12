---
title: Conectores de mensajería
description: Envíe alertas desde DefectDojo a Slack, Microsoft Teams, correo electrónico
  o Amazon SNS.
weight: 4
audience: pro
---

**Disponibilidad:** los Conectores de mensajería son una función en beta. Active **Messaging Connectors** en la página Feature Flags. Como las alertas se enrutan mediante reglas, **Rules Engine 2.0** también debe estar activado.

Los Conectores de mensajería envían alertas desde DefectDojo a un servicio de chat, a una dirección de correo electrónico o a un topic de Amazon SNS. Se ubican junto a los conectores de tickets y de gestión de incidentes en la misma página **Downstream Connectors**, y se configuran de la misma manera: cree una conexión una vez y luego decida qué se debe enviar a ella.

Los conectores de tickets y los conectores de mensajería responden preguntas distintas. Un conector de tickets crea y actualiza un ticket que hace seguimiento de un Hallazgo a lo largo del tiempo. Un conector de mensajería publica un mensaje sobre algo que acaba de ocurrir, como una importación que trajo nuevos Hallazgos de severidad Alta y Crítica. Un mensaje no tiene un estado que transicionar ni un ticket que mantener sincronizado, por lo que ambos se configuran por separado y ninguno afecta al otro.

## Qué puede enviar

Las alertas se enrutan mediante Rules Engine 2.0. Una regla decide **cuándo** enviar (un disparador), **qué** Hallazgos califican (condiciones) y **adónde** va el mensaje (un nodo de notificación que direcciona su conexión y canal).

Esto significa que los filtros disponibles para una alerta son los mismos que están disponibles para una regla: severidad, alcance, etiquetas, estado y cualquier otra cosa que una condición de regla pueda expresar. Varias alertas distintas que van a varios canales distintos son, simplemente, varias reglas.

## Los cuatro proveedores

| Vendor | What you provide | How many destinations per connection |
| --- | --- | --- |
| Slack | Un token de bot de una app de Slack | Varios. Cada destino especifica un ID de canal. |
| Microsoft Teams | Una URL de flujo de trabajo de Power Automate | Uno. La URL determina el canal. |
| Email | Nada. Se usa el servidor de correo de la instancia. | Varios. Cada destino especifica destinatarios. |
| Amazon SNS | Una clave de acceso de AWS con permiso para publicar | Varios. Cada destino especifica un ARN de topic. |

Cada uno se configura de la misma manera: agregue la conexión en **Connect > Downstream** y luego cree una alerta que lo tenga como destino.

## Configurar una conexión de Slack

Necesita una app de Slack con un token de bot. Si su workspace ya tiene una para DefectDojo, puede reutilizarla.

### 1. Crear una app de Slack

1. Vaya a [https://api.slack.com/apps](https://api.slack.com/apps) y seleccione **Create New App**, luego **From scratch**.
2. Asigne un nombre a la app (por ejemplo, DefectDojo) y elija el workspace en el que debe publicar.
3. Abra **OAuth & Permissions** y agregue estos **Bot Token Scopes**:
   - `chat:write` (obligatorio): permite que la app publique mensajes.
   - `chat:write.public` (opcional): permite que la app publique en cualquier canal público sin necesidad de invitarla primero. Sin este scope, debe invitar al bot a cada canal que quiera usar.
4. Seleccione **Install to Workspace** y apruebe la app.
5. Copie el **Bot User OAuth Token**. Comienza con `xoxb-`.

### 2. Agregar la conexión en DefectDojo

1. Vaya a **Connect > Downstream**.
2. En la sección **Messaging**, busque el bloque de Slack y seleccione **Add Configuration**.
3. Ingrese:
   - **Location**: la URL de su workspace de Slack, por ejemplo `https://your-workspace.slack.com`. Se usa solo para mostrarla y para enlaces.
   - **Identifier**: una etiqueta que distingue esta conexión de las demás, por ejemplo `Security workspace`.
   - **Bot Token**: el token `xoxb-` que copió.
4. Guarde. DefectDojo valida el token contra Slack de inmediato, de modo que un token incorrecto o revocado se reporta aquí en lugar de la primera vez que se dispare una alerta.

Puede agregar tantas conexiones de Slack como necesite. Usar conexiones separadas es la forma de llegar a más de un workspace.

### 3. Encontrar el ID del canal

Los destinos de Slack usan el **ID** del canal, no su nombre.

1. En Slack, abra el canal y seleccione su nombre en la parte superior.
2. Desplácese hasta la parte inferior de la pestaña **About**.
3. Copie el **Channel ID**. Se ve así: `C0123456789`.

Si la app no tiene el scope `chat:write.public`, también deberá invitarla al canal: escriba `/invite @your-app-name` en el canal.

## Configurar una conexión de Microsoft Teams

Teams usa una **URL de flujo de trabajo de Power Automate**. Los conectores clásicos de Office 365 quedaron obsoletos, y esta vía no requiere registrar una app ni el consentimiento del administrador del tenant: alguien con permisos sobre el canal crea el flujo y pega la URL que este devuelve.

**Una conexión publica en un solo canal.** La URL del flujo de trabajo determina adónde va el mensaje, de modo que un segundo canal implica una segunda conexión y no un segundo destino.

### 1. Crear el flujo de trabajo

1. En Teams, abra el canal en el que quiere publicar, seleccione el menú **...** junto al nombre del canal y luego **Workflows**.
2. Elija la plantilla **Post to a channel when a webhook request is received**.
3. Confirme el equipo y el canal, y luego seleccione **Add workflow**.
4. Copie la URL que le entrega el flujo de trabajo. Es una dirección `https://` larga en un host de Microsoft Power Automate.

Trate esta URL como si fuera una contraseña. Cualquiera que la tenga puede publicar en ese canal.

### 2. Agregar la conexión en DefectDojo

1. Vaya a **Connect > Downstream**.
2. En la sección **Messaging**, busque el bloque de Microsoft Teams y seleccione **Add Configuration**.
3. Ingrese:
   - **Location**: su URL de Teams o Microsoft 365. Se usa solo para mostrarla y para enlaces.
   - **Instance Label**: una etiqueta que nombra el canal al que llega esta conexión, por ejemplo `Security / Alerts`.
   - **Workflow URL**: la URL que copió.
4. Guarde.

DefectDojo verifica el formato de la URL al guardar (debe ser `https://` y estar en un host de flujo de trabajo de Microsoft), pero no publica en ella. No hay otra forma de probar una URL de flujo de trabajo que no sea enviando un mensaje, y un mensaje sorpresa en un canal al momento de guardar es peor que descubrirlo más tarde. Use **Send test message** cuando esté listo.

Un destino de Teams tiene un campo opcional, una etiqueta de canal, que solo etiqueta el registro de entrega. La URL del flujo de trabajo ya determina el destino.

## Configurar una conexión de correo electrónico

El correo electrónico no necesita credenciales. DefectDojo envía a través del servidor de correo que esta instancia ya usa para las notificaciones, de modo que no hay nada nuevo que configurar ni un segundo lugar donde el SMTP pueda estar mal configurado.

1. Vaya a **Connect > Downstream**.
2. En la sección **Messaging**, busque el bloque de Email y seleccione **Add Configuration**.
3. Ingrese:
   - **Location**: la identidad del remitente que se mostrará, por ejemplo `mailto:defectdojo@example.com`.
   - **Instance Label**: una etiqueta que distingue esta conexión de las demás.
4. Guarde.

Guardar falla si esta instancia no tiene un servidor de correo o una dirección de remitente configurados, porque nada de lo enviado por esta conexión saldría del edificio. Configure el SMTP primero en **Settings > System Settings**.

Los destinatarios se definen en la alerta, no en la conexión, de modo que una sola conexión de Email sirve para todas las alertas. Un destino de correo admite hasta 50 direcciones; por encima de eso, use una dirección de distribución.

## Configurar una conexión de Amazon SNS

SNS es distinto por naturaleza de los otros tres: DefectDojo publica un mensaje en un topic, y AWS lo distribuye a lo que esté suscrito, ya sean direcciones de correo, números de SMS, una función Lambda, un endpoint HTTPS o una cola de SQS. A DefectDojo no le importa ni necesita saber cuál.

### 1. Crear una clave de acceso que pueda publicar

1. En la consola de AWS, cree (o elija) un usuario o rol de IAM para DefectDojo.
2. Adjunte una política que permita `sns:Publish` sobre los topics que piensa usar. Es mejor nombrar explícitamente los ARN de los topics que permitirlos todos.
3. Cree una clave de acceso para ese usuario o rol y copie ambas mitades. AWS muestra la clave de acceso secreta una sola vez.

Si el topic está cifrado con una clave de KMS, ese mismo principal también necesita `kms:GenerateDataKey` y `kms:Decrypt` sobre esa clave, o de lo contrario se rechazará toda publicación.

### 2. Agregar la conexión en DefectDojo

1. Vaya a **Connect > Downstream**.
2. En la sección **Messaging**, busque el bloque de Amazon SNS y seleccione **Add Configuration**.
3. Ingrese:
   - **Location**: una URL solo para mostrarla y para enlaces, por ejemplo la URL de su consola de AWS.
   - **Instance Label**: una etiqueta que distingue esta conexión de las demás, por ejemplo `Production AWS account`.
   - **Access Key ID**: el ID de la clave, que se ve así: `AKIAIOSFODNN7EXAMPLE`.
   - **Secret Access Key**: la mitad secreta.
4. Guarde.

DefectDojo verifica la credencial con AWS de inmediato, de modo que una clave incorrecta o eliminada se reporta aquí en lugar de la primera vez que se dispare una alerta. Esa verificación solo confirma que la credencial es válida; si puede publicar en un topic determinado se comprueba cuando se define el destino.

**No hay una región que ingresar.** La región forma parte del ARN del topic, de modo que una sola conexión puede publicar en topics de más de una región, y no existe una segunda configuración que pueda entrar en conflicto con el ARN.

### 3. Encontrar el ARN del topic

Un destino de SNS usa el ARN del topic.

1. En la consola de SNS, abra el topic.
2. Copie el **ARN** que aparece en la parte superior de la página. Se ve así: `arn:aws:sns:us-east-1:123456789012:security-alerts`.

A diferencia de una URL de flujo de trabajo de Teams, un ARN no es un secreto: identifica un topic, y publicar en él requiere la credencial de la conexión. Por eso una sola conexión de SNS puede servir a muchos topics.

Los topics FIFO (un ARN que termina en `.fifo`) no son compatibles. Requieren un grupo de mensajes y un ID de deduplicación, que son reglas de orden que una alerta no tiene manera de proporcionar. Use un topic estándar.

## Enviar un mensaje de prueba

En cualquier lugar donde se configure un destino de mensajería, **Send test message** entrega un mensaje breve por exactamente la misma vía que usaría una alerta real, y reporta lo que respondió el proveedor.

Úselo para confirmar lo que es fácil equivocar: en Slack, que el ID del canal sea correcto y que el bot pueda publicar allí; en Teams, que la URL del flujo de trabajo siga funcionando; en correo electrónico, que la dirección sea entregable; en SNS, que la clave pueda publicar en ese topic. Se traslada la respuesta propia del proveedor, de modo que una invitación de Slack faltante se lee como un mensaje que le indica invitar al bot, en lugar de un error genérico.

Una prueba exitosa también reactiva una conexión que había sido deshabilitada automáticamente (consulte [Cuando una conexión deja de funcionar](#when-a-connection-stops-working)).

## Crear una alerta

Hay dos formas de hacerlo. Ambas producen lo mismo: una regla de Rules Engine 2.0.

### La página de alertas

La vía corta, para el caso habitual de anunciar nuevos hallazgos de una importación.

1. Vaya a **Connect > Downstream** y seleccione **Create Alert** en una conexión de mensajería, o abra **Messaging Alerts** directamente.
2. Seleccione **New Alert** y complete:
   - **Name**: para qué sirve esta alerta, por ejemplo `New highs to the security channel`.
   - **Alert**: de qué se trata. **New findings from an import** es actualmente la única opción.
   - **Send over**: la conexión de mensajería.
   - **Where it delivers**: el campo de destino propio del proveedor, es decir, un ID de canal de Slack, una etiqueta de canal opcional de Teams, una lista de direcciones de correo o un ARN de topic de SNS.
   - **Severity**: el piso, desde **Critical only** hasta **Every severity**.
   - **Mode**: **Simulate** registra lo que se habría enviado sin enviarlo, **Live** sí envía.
3. Seleccione **Create Alert**.

La página lista las alertas que creó, con el disparador, el piso de severidad y un interruptor para activar o desactivar cada una.

Comience en **Simulate** si quiere ver qué habría detectado una alerta antes de que algún canal se entere. La regla se ejecuta, las entregas quedan registradas y no se envía nada.

Las alertas son reglas, así que también pueden abrirse en el editor de reglas desde la misma lista. Una vez que una regla se edita hasta convertirse en algo que el formulario no puede expresar, como una segunda rama o un segundo mensaje, la lista ofrece el editor de reglas en lugar del formulario, en vez de un formulario que aplanaría silenciosamente el trabajo adicional.

### El editor de reglas

La vía completa, para todo lo que el formulario no cubre.

1. Vaya a **Automation > Rules Engine 2.0** y cree una regla.
2. Agregue un disparador. Para alertas sobre Hallazgos recién importados, use el disparador de eventos de Hallazgo en **created**. Las importaciones se procesan por lotes, de modo que una importación produce una alerta en lugar de una por Hallazgo.
3. Agregue condiciones para lo que debe calificar, por ejemplo una severidad mínima de Alta.
4. Agregue un nodo de mensaje para el proveedor que quiera (**Send a Slack Message**, **Send a Microsoft Teams Message**, **Send an Email** o **Publish to an SNS Topic**) y configure:
   - **Connection**: la conexión de mensajería que creó.
   - **Destination**: el destino propio del proveedor, es decir, un ID de canal para Slack, una etiqueta de canal opcional para Teams, destinatarios para correo electrónico, o un ARN de topic para SNS.
5. Guarde la regla y actívela.

No se envía nada cuando ningún Hallazgo cumple las condiciones, de modo que una regla filtrada a Alta o superior permanece en silencio ante una importación que solo trajo Hallazgos de severidad Baja.

### Reglas escritas antes de los Conectores de mensajería

Un nodo de mensaje envía a través de una conexión, y solo a través de una conexión. Antes, los nodos de Slack, Teams y correo electrónico recurrían a la configuración global de la instancia en **Settings > Notifications** cuando no se elegía una conexión. Ya no lo hacen.

Una regla escrita de esa manera sigue ejecutándose, y su nodo de mensaje registra una entrega omitida indicando que no especifica ninguna conexión. Para solucionarlo, abra la regla, elija una conexión y un destino en el nodo, y guarde. Una entrega que ya quedó registrada puede reproducirse desde la lista de entregas una vez que el nodo especifique una conexión.

La conexión es un campo obligatorio en todos los nodos de mensaje, de modo que el editor de reglas solicita una antes de poder guardar la regla.

## Cuando una conexión deja de funcionar

Un token de bot revocado, un flujo de trabajo eliminado o una clave de acceso de AWS eliminada hacen fallar todas las alertas a las que sirven. En lugar de registrar el mismo fallo para cada evento, DefectDojo cuenta los fallos de credenciales consecutivos por destino y deja de enviar después de unos pocos. La conexión reporta qué destino se deshabilitó y por qué.

Para recuperarla: corrija la credencial (reinstale la app de Slack y pegue el nuevo token, vuelva a crear el flujo de trabajo de Teams y pegue la nueva URL, o cree una nueva clave de acceso de AWS), y luego envíe un mensaje de prueba a ese destino, lo que lo reactivará si tiene éxito, o use directamente la acción de reactivación.

Solo los fallos de credenciales provocan esto. Un mensaje rechazado porque un ID de canal de Slack es incorrecto, el bot no fue invitado, una dirección de correo no existe, o una política de IAM no permite publicar en un topic, no deshabilita nada, porque la credencial está bien y corregir el destino o la política debería funcionar de inmediato.

## Alertas y notificaciones juntas

Los Conectores de mensajería no reemplazan a las notificaciones. La configuración global de Slack, Teams y correo electrónico en **Settings > Notifications**, las notificaciones personales y la matriz de notificaciones siguen funcionando exactamente como están configuradas. Estas son las que anuncian los propios eventos de DefectDojo; un Conector de mensajería es lo que envía una regla que usted escribió.

Algo a tener en cuenta: si una alerta publica en el mismo canal o dirección al que ya anuncia la configuración global, ese destino recibirá ambos mensajes. Configure uno u otro para un destino determinado.

## Limitaciones

- La redacción de los mensajes aún no se puede personalizar. Las alertas usan la redacción integrada de DefectDojo.
- Los mensajes son unidireccionales. DefectDojo no lee las respuestas, y no hay botones ni elementos interactivos en el mensaje.
- No se admiten hilos, edición de mensajes ni mensajes directos a usuarios individuales. Las notificaciones personales siguen usando el sistema de notificaciones existente.
- Una conexión de Teams llega a un solo canal, porque es la URL del flujo de trabajo la que direcciona el canal.
- Los mensajes de SNS son texto plano. Un topic puede distribuir a la vez a suscriptores de correo, SMS, Lambda y HTTPS, de modo que no hay un único formato que les sirva a todos, y no se publica ninguna variante por protocolo.
- Los topics FIFO de SNS no son compatibles.
- Aún no se pueden enviar Informes ni otros adjuntos. Las alertas son mensajes con enlaces de vuelta a DefectDojo.
- La página de alertas cubre los nuevos hallazgos de una importación. Todo lo demás se construye en el editor de reglas.
