---
title: Entregas
description: El registro de todo lo que las reglas envían hacia afuera, y cómo funcionan
  los reintentos y la repetición
weight: 5
audience: pro
aliases:
- /es/automation/rules_engine_v2/deliveries/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 es una función exclusiva de DefectDojo Pro.</span>

Cada efecto secundario saliente que produce una regla es una fila en el registro de entregas. **Rules Engine 2.0 > Entregas** las enumera.

La fila se escribe **antes** de que ocurra cualquier llamada de red, y contiene exactamente lo que se enviaría, o lo que se envió. Eso es lo que hace que el tráfico de salida sea auditable en lugar de una línea de registro que uno espera que alguien haya conservado, y es la razón por la que **Simulate** no es una ruta de código independiente: un envío simulado es la misma fila con el paso de despacho omitido.

## Qué registra una entrega

| Campo | Significado |
|-------|---------|
| **Run** y **Node** | Qué ejecución y qué nodo de salida la produjo. |
| **Finding** | El Hallazgo al que se refiere, para un envío por Hallazgo. Los envíos por lotes registran el grupo en su lugar. |
| **Channel** | Qué tipo de envío es. |
| **Target** | El destino resuelto: una clave de proyecto de JIRA, un canal, una URL, una dirección. |
| **Title** | Una descripción de una línea del envío. |
| **Payload** | Exactamente lo que se enviaría, o lo que se envió. |
| **Mode** | `simulate` o `live`. |
| **Status** | Hasta dónde llegó la entrega. |
| **Attempts** | Cuántos envíos se han intentado, respecto al máximo permitido. |
| **Last error** | Por qué falló el último intento, o por qué se omitió la entrega. |
| **Response** | Qué respondió el destino. |
| **External reference** y **URL** | La clave del ticket, el id del mensaje o la ruta del archivo que devolvió el destino, y un enlace a él cuando existe. |

## Canales

| Channel | Producido por |
|---------|-------------|
| **JIRA** | Crear una incidencia de JIRA |
| **Downstream connector** | Crear un ticket downstream |
| **Slack** | Enviar un mensaje de Slack, y anuncios de informes enviados a Slack |
| **Microsoft Teams** | Enviar un mensaje de Microsoft Teams |
| **Email** | Enviar un correo electrónico, y anuncios de informes enviados por correo electrónico |
| **Webhook** | Llamar a un webhook |
| **Report** | Generar un informe |
| **In-app alert** | Generar una alerta en la aplicación |

## Estados

| Status | Meaning |
|--------|---------|
| `simulated` | La regla estaba en modo Simulate. No se envió nada, y nunca se enviará. |
| `skipped` | Algo ya cubría este envío, o el control de acceso lo rechazó. La razón está en el campo del último error. |
| `pending` | Registrada en modo Live, esperando su tarea de entrega. |
| `dispatched` | Entregada al servicio de integración, esperando confirmación. |
| `sent` | Confirmada como entregada. |
| `failed` | Rechazada permanentemente, por ejemplo un 4xx o un error del proveedor. Se puede repetir. |
| `dead` | Reintentos agotados, o nunca llegó confirmación. Se puede repetir. |

Vale la pena detenerse en `skipped`. Las omisiones se registran en lugar de pasar en silencio, porque "la regla no hizo nada" y "la regla no hizo nada porque este Hallazgo ya tenía un ticket" son respuestas diferentes, y solo una de ellas es un problema.

Hay tres razones comunes para una omisión, y el campo del último error siempre indica cuál:

* **Idempotencia.** Algo ya cubría este envío.
* **El canal está desactivado.** Una regla con un nodo de Slack en una instancia donde Slack está deshabilitado registra una omisión que lo explica, en lugar de fallar. Una regla guardada mientras un canal estaba activo no debería empezar a generar errores cuando alguien lo desactiva. Consulte [disponibilidad de nodos](../node_reference/#when-a-channel-is-unavailable).
* **Se alcanzó el límite de envíos por Hallazgo.** Un nodo que envía un mensaje por Hallazgo se detiene después de 1000 en una sola ejecución de forma predeterminada, y registra cuántos quedaron sin enviar.

### Fidelidad del payload

El registro es transparente sobre cuán cercano está el payload registrado al cuerpo real transmitido, porque eso varía según el canal.

| Fidelity | Meaning |
|----------|---------|
| `exact` | Equivalente byte a byte a lo que se envió. |
| `rendered` | Renderizado por los helpers reales, pero el control de acceso en el momento del envío aún puede recortarlo. |
| `dojo request` | La solicitud exacta entregada al servicio de integración. El payload específico del proveedor se compone más adelante (downstream). |
| `summary` | Una descripción del envío en lugar de una reproducción de este. Un informe generado es el ejemplo: el archivo se construye a partir de datos en vivo en el momento del envío, por lo que una copia almacenada de él sería incorrecta en cuanto algo cambiara. |

## La protección contra doble envío

Solo puede existir una entrega **activa** por clave de idempotencia, lo cual se aplica en la base de datos y no por convención. Activa significa `pending`, `dispatched` o `sent`.

Un segundo envío que colisionaría con uno activo se convierte en una fila `skipped` con su razón registrada. Nunca es una operación silenciosa sin efecto, y nunca es un ticket duplicado.

Dado que las filas `simulated`, `skipped`, `failed` y `dead` no retienen una reserva, una entrega fallida puede repetirse en el mismo lugar sin que una segunda fila compita por la misma clave.

## Reintentos

Una entrega en vivo se reintenta automáticamente. Cada fila lleva su propio contador de intentos y su propio límite, seis intentos de forma predeterminada, de modo que un destino que falla no puede arrastrar consigo a sus filas hermanas. Los reintentos aplican un retroceso entre intentos.

Cuando se agota el último reintento, la fila se marca como `dead` en lugar de dejarla estancada en `pending`. El agotamiento es visible, no silencioso.

Si un worker se interrumpe a mitad de un envío, el mensaje se vuelve a entregar. La fila se bloquea y se vuelve a comprobar su estado antes de enviar nada de nuevo, de modo que una reentrega no puede convertirse en un doble envío.

Las entregas transferidas al servicio de integración pasan a `dispatched` y esperan un callback de confirmación. Si no llega ningún callback en un plazo de seis horas, la fila se marca como `dead` para que pueda repetirse. Esa ventana es deliberadamente generosa: que una cola downstream se acumule durante una hora es normal, y marcar una fila como agotada demasiado pronto convertiría una repetición en un ticket duplicado.

## Repetir una entrega

Una entrega `failed` o `dead` puede reenviarse desde la página Entregas. El registro anota cuándo se repitió y por quién.

Repetir requiere **Rule Edit**.

Repetir reenvía el payload registrado. Para un informe, eso regenera el informe a partir de los datos actuales, porque el payload es una descripción de lo que se debe generar y no el archivo en sí.

## Simulate

En modo Simulate, cada nodo de salida escribe su fila de entrega con estado `simulated`, el payload completo y el destino resuelto, y luego se detiene. No se registra ningún despacho, de modo que nada puede enviarse más tarde sin importar cómo se resuelva la ejecución. Preview se comporta de la misma manera, y ni siquiera inserta las filas.

Esta es la forma prevista de revisar una regla antes de ponerla en producción: habilítela en Simulate, déjela ejecutarse contra Hallazgos reales, y luego lea los payloads que registró.

Recuerde que Simulate retiene **únicamente** los envíos salientes. Los nodos de Hallazgos siguen modificando los Hallazgos.

## Retención

Las entregas se conservan durante **180 días** de forma predeterminada, después de lo cual un trabajo de retención las elimina.

Esta es la tabla que crece más rápido en la función, porque un nodo que envía un mensaje por Hallazgo escribe una fila por Hallazgo, tanto en modo Simulate como en Live. El valor predeterminado es una ventana real en lugar de "conservar todo", de modo que el crecimiento no se convierta silenciosamente en su problema.

Se le informa al respecto en lugar de dejar que lo descubra por sí mismo. El detalle de una entrega muestra la ventana de retención y la fecha en que esa fila se eliminará, y la fecha se recalcula en cada lectura, de modo que cambiar la ventana surte efecto de inmediato.

Establezca una ventana más larga si necesita un registro de auditoría de salida más extenso, o `0` para conservar todo. Consulte [Configuración](../configuration/#retention).
