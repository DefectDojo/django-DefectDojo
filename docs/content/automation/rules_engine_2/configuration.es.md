---
title: Configuración
description: Ajustes a nivel de despliegue para Rules Engine 2.0
weight: 7
audience: pro
aliases:
- /es/automation/rules_engine_v2/configuration/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 es una función exclusiva de DefectDojo Pro.</span>

Rules Engine 2.0 funciona de fábrica. Los ajustes de esta página son para despliegues que necesitan afinar el rendimiento, la retención o la política de red saliente. Todos se aplican de la misma manera que cualquier otro ajuste de DefectDojo (consulte [Configuración](/get_started/open_source/configuration/)).

Rules Engine 2.0 se configura por separado del Rules Engine original. Los dos motores no comparten ningún ajuste, de modo que un ajuste `DD_RULES_ENGINE_*` no afecta a Rules Engine 2.0 y un ajuste `DD_RULES_V2_*` no afecta al motor original.

```python
DD_RULES_V2_EVENT_BATCH=(int, 500),
DD_RULES_V2_CHUNK_SIZE=(int, 1000),
DD_RULES_V2_STALLED_AFTER_MINUTES=(int, 30),
DD_RULES_V2_RUN_TIME_LIMIT_MINUTES=(int, 360),
DD_RULES_V2_ALLOW_PRIVATE_EGRESS=(bool, False),
DD_RULES_V2_DELIVERY_RETENTION_DAYS=(int, 180),
DD_RULES_V2_RUN_RETENTION_DAYS=(int, 180),
DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS=(int, 8000),
DD_RULES_V2_MAX_PER_ITEM_SENDS=(int, 1000),
```

## Rendimiento

### Hallazgos por evento (`DD_RULES_V2_EVENT_BATCH`)

**Predeterminado: 500.**

Cuántos ids de Hallazgo lleva un único evento. Los eventos cruzan un límite asíncrono, por lo que se mantienen lo bastante pequeños para seguir siendo un mensaje económico. Una escritura más grande se reparte en varios eventos, cada uno de los cuales se convierte en su propia ejecución.

Aumentar este valor produce menos ejecuciones, más grandes. Reducirlo produce más ejecuciones, más pequeñas.

### Hallazgos por bloque (`DD_RULES_V2_CHUNK_SIZE`)

**Predeterminado: 1000.**

Cuántos Hallazgos mantiene en memoria una ejecución a la vez. Una ejecución se procesa en bloques, así que este es un control de memoria y **no** un límite de lo que una regla maneja: una regla siempre procesa todo lo que coincide con su alcance.

Un envelope ocupa aproximadamente 2,7 KB por Hallazgo, de modo que el valor predeterminado mantiene unos pocos megabytes a la vez. Aumentarlo cambia memoria por menos idas y vueltas. Reducirlo hace lo contrario.

### Límite de texto del envelope (`DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS`)

**Predeterminado: 8000. Establézcalo en 0 para desactivarlo.**

Cuántos caracteres de `description`, `mitigation` e `impact` lleva un elemento.

Esos tres campos son la mayor parte del tamaño de un envelope. El límite existe para el caso inusual de un Hallazgo con una descripción muy extensa, en el que un bloque completo de ellos sería mucho más grande de lo que sugiere el tamaño del bloque. Es lo bastante generoso como para que una instancia habitual nunca lo note.

Tenga en cuenta que esto afecta a lo que las condiciones y las plantillas pueden ver. Una condición que compare contra el final de una descripción muy larga no verá el texto que sobrepase el límite.

## Ciclo de vida de la ejecución

### Ventana de estancamiento (`DD_RULES_V2_STALLED_AFTER_MINUTES`)

**Predeterminado: 30.**

Cuánto tiempo puede pasar una ejecución sin una señal de actividad antes de considerarse abandonada, marcarse como errónea y liberar su bloqueo por regla.

Una ejecución registra una señal de actividad después de cada bloque, de modo que esto se mide desde la última señal de actividad y no desde el inicio. Un barrido largo que sigue avanzando nunca se confunde con un worker caído, que es lo que permite que la ventana se mantenga corta.

### Límite de tiempo de ejecución (`DD_RULES_V2_RUN_TIME_LIMIT_MINUTES`)

**Predeterminado: 360, es decir, seis horas.**

El tiempo máximo que puede tardar una sola ejecución antes de que el worker la termine.

Esto es una protección contra una regla que nunca terminaría mientras ocupa un slot de worker y el bloqueo de ejecución de su regla. Es deliberadamente generoso, porque un barrido en bloques sobre un alcance muy grande es exactamente la carga de trabajo para la que está construido este motor.

## Retención

Dos tareas acotan las tres tablas que hace crecer esta función. Ambas tienen como valor predeterminado **180 días**, y ambas aceptan `0` para desactivar por completo la depuración.

La retención se muestra en el producto en lugar de dejarse implícita: la API entrega tanto la ventana como la fecha en que se eliminará un registro determinado, y las páginas que muestran una ejecución o una entrega lo indican en una frase. La fecha se calcula al leer, de modo que cambiar la ventana surte efecto de inmediato en lugar de aplicarse solo a los registros nuevos.

### `DD_RULES_V2_DELIVERY_RETENTION_DAYS`

**Predeterminado: 180.**

Cuántos días se conserva una entrega finalizada.

Esta es la tabla que más rápido crece de la función. Un nodo de salida por Hallazgo escribe hasta un bloque entero de filas por ejecución, incluso en modo Simulación. Auméntelo si necesita un rastro de auditoría saliente más largo, y redúzcalo si el volumen es un problema.

### `DD_RULES_V2_RUN_RETENTION_DAYS`

**Predeterminado: 180.**

Cuántos días se conserva una ejecución finalizada, junto con sus filas por nodo y la procedencia de sus Hallazgos.

El lado de las ejecuciones crece más rápido que el de las entregas, porque la procedencia es una fila por Hallazgo, por nodo de mutación, por ejecución. Una regla horaria sobre un alcance grande genera una gran cantidad.

Una ejecución que todavía tiene entregas asociadas se conserva hasta que estas se depuran, de modo que establecer una ventana de ejecución más corta que la de entrega no deja nada huérfano.

## Validación del destino saliente

Dos ajustes de nodo toman un destino como texto libre en lugar de a partir de un objeto configurado: la **URL** en Llamar a un webhook, y el **Para** en Enviar un correo electrónico. Ambos se validan al guardar la regla.

Para las URL de webhook:

* Solo se aceptan `http` y `https`. Los demás esquemas se rechazan de inmediato.
* La URL debe tener un host.
* De forma predeterminada, se rechaza un host que resuelva a una dirección loopback, link-local, privada, reservada o multicast.

Para las direcciones de correo electrónico, se rechaza una dirección vacía, así como una que contenga un salto de línea, lo cual es una inyección de cabeceras.

La razón de la comprobación de red es que el worker que envía la solicitud normalmente se encuentra dentro de su clúster y puede alcanzar mucha más red interna que la persona que redacta la regla. Sin esta comprobación, una URL en texto libre es un primitivo de falsificación de solicitudes: apúntela a un servicio de metadatos o a un puerto administrativo interno y la respuesta vuelve a través del registro de entregas.

Esto es defensa en profundidad, no el único control. Rule Edit ya es de por sí casi un permiso administrativo. Vale la pena tenerlo para que el radio de impacto de un rol concedido en exceso no sea "leer cualquier endpoint HTTP interno", y para que una errata falle al guardar con un mensaje claro en lugar de al enviar con un error de conexión.

### Permitir direcciones privadas (`DD_RULES_V2_ALLOW_PRIVATE_EGRESS`)

**Predeterminado: desactivado.**

Desactiva la comprobación de direcciones de red, de modo que los webhooks pueden publicar en direcciones loopback, link-local y privadas. La validación de esquema y de forma sigue aplicándose.

Actívelo si realmente necesita enviar un webhook a algo en una dirección privada, que es lo habitual en un receptor de chat o de webhooks autoalojado.

## Límite de envíos por Hallazgo

### `DD_RULES_V2_MAX_PER_ITEM_SENDS`

**Predeterminado: 1000. Establézcalo en 0 para eliminar el límite.**

El máximo de envíos por Hallazgo que un solo nodo de salida registrará en una ejecución.

Un nodo con **Un mensaje por Hallazgo** activado produce una fila de entrega y una tarea en cola por Hallazgo. Como una ejecución no tiene límite de elementos, una regla con un alcance muy amplio y el envío por Hallazgo activado supondría, de lo contrario, un número ilimitado de ambas cosas.

Superado este límite, el nodo registra una **omisión visible** que indica sobre cuántos Hallazgos no envió nada. No hace fallar la ejecución, ni se detiene en silencio.

## Ajustes relacionados

Algunos nodos de Rules Engine 2.0 usan la configuración de integración de todo el sistema en lugar de la propia:

* **Enviar un mensaje de Slack** usa el token de Slack del sistema, y recurre al canal de Slack del sistema cuando el nodo no indica ninguno.
* **Enviar un mensaje de Microsoft Teams** usa el webhook de Microsoft Teams de los ajustes del sistema.
* **Crear un issue de JIRA** usa la configuración de JIRA del producto para el resumen, la descripción y la prioridad.
* **Generar una alerta en la aplicación** respeta el ajuste de notificación **Coincidencia de Rules Engine** propio de cada destinatario.
