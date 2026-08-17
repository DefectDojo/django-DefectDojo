---
title: Ejecuciones
description: Cómo se ejecuta una regla, qué registra una ejecución y cómo se limita
  el encadenamiento
weight: 4
audience: pro
aliases:
- /es/automation/rules_engine_v2/runs/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 es una función exclusiva de DefectDojo Pro.</span>

Una **ejecución** es una instancia de ejecución de una regla. Cada ejecución se registra, tanto si tuvo éxito como si falló, y cada nodo dentro de ella deja un rastro. **Rules Engine 2.0 > Runs** las enumera.

## Qué registra una ejecución

| Field | Meaning |
|-------|---------|
| **Rule** | La regla que se ejecutó. |
| **Trigger** | El evento que la inició, por ejemplo `finding.created`, `schedule` o `manual`. |
| **Triggered by** | La persona que la desencadenó, cuando fue una persona: quien presionó Run, o quien guardó el Hallazgo que la disparó. Vacío en el caso de una programación, y en el de un cambio en el que no hubo nadie presente, como una importación o una llamada a la API sin usuario. Esto es distinto del propietario de la regla, que es la identidad **con la que** se ejecutó la ejecución. |
| **Status** | `Running`, `Success` o `Error`. |
| **Started** y **Finished** | Cuándo se ejecutó. Finished solo está vacío mientras sigue en ejecución. |
| **Error** | El error que la finalizó, si falló. |
| **Stats** | Totales por nodo, eventos en cascada y trabajo diferido. |
| **Depth** | A cuántos saltos de cascada está esta ejecución del evento de origen. |
| **Source run** | La ejecución cuyo evento emitido disparó esta, en el caso de una ejecución en cascada. |

### El rastro del nodo

Dentro de una ejecución, cada nodo registra su propia fila:

| Field | Meaning |
|-------|---------|
| **Order** | La posición del nodo en el orden de ejecución. |
| **Node** | Su id, su tipo y su etiqueta, si le asignó una. |
| **Status** | Si el nodo se completó o generó un error. |
| **Items in** | Cuántos elementos entraron. |
| **Items out** | Cuántos salieron, desglosados por controlador de salida, de modo que un nodo If / Filter muestra sus recuentos de verdadero y falso por separado. |
| **Summary** | Los contadores que reportó el nodo, por ejemplo cuántos Hallazgos cambió. |
| **Error** | El error que generó, si falló. |

El rastro es lo que se lee cuando una regla no hizo lo que se esperaba. Un nodo If / Filter que reporta 400 elementos de entrada y 0 por la rama verdadera indica que las condiciones están mal, sin necesidad de adivinar.

## Modelo de ejecución

Los nodos se ejecutan en orden topológico: un nodo se ejecuta una vez que todo lo que lo alimenta se ha ejecutado. Un nodo con varios bordes entrantes recibe todas sus salidas concatenadas. Un nodo sin nada que lo alimente igual se ejecuta, con una lista de entrada vacía.

### Una ejecución fallida no cambia nada

Una ejecución es atómica. Si algún nodo genera un error, se revierten todos los cambios de Hallazgos que hizo la ejecución.

El rastro no se revierte junto con ella. Las filas de nodos y el estado `Error` se escriben después, de modo que una ejecución fallida indica exactamente qué nodo falló sin dejar ediciones aplicadas a medias. Esta es la garantía más importante a tener en cuenta al leer la página de Runs: una ejecución con error es una ejecución que no hizo nada.

La salida (egress) sigue la misma regla. Las entregas se registran dentro de la transacción de la ejecución y solo se despachan después de que esta se confirme, de modo que una ejecución que se revierte no envía nada.

### Una ejecución por regla a la vez

Una regla solo puede tener una ejecución en curso. Un segundo disparador para la misma regla mientras aún está en ejecución no compite con ella. Espera y reintenta.

Las reglas diferentes se ejecutan de forma totalmente concurrente, de modo que una regla lenta nunca retrasa a las demás.

Si una ejecución queda abandonada de alguna forma, por ejemplo porque se mató al worker que la ejecutaba, su bloqueo se libera tras una ventana de estancamiento (30 minutos de forma predeterminada) para que la regla no quede atascada para siempre. Una ejecución que se acerca a esa ventana se detiene primero por sí sola, desenrollándose de forma limpia, de modo que una ejecución simplemente lenta nunca termina ejecutándose junto con su propio reemplazo.

## Encadenamiento

Una regla que cambia un Hallazgo produce exactamente el tipo de evento sobre el que otra regla puede activarse. Rules Engine 2.0 permite esto, de modo que las cadenas `A -> B -> C` funcionan, y lo limita de dos formas independientes:

* **Depth.** Un evento puede viajar como máximo **3** saltos en cascada desde el cambio que lo originó.

* **Chain membership.** Cada evento lleva la lista de reglas ya recorridas en su cadena, y una regla nunca se ejecuta dos veces en la misma cadena. Así, una regla no puede volver a activarse a sí misma, y dos reglas no pueden rebotar entre sí.

Los campos **Depth** y **Source run** de una ejecución permiten rastrear una cadena hasta el cambio que la inició. **Triggered by** se traslada a lo largo de toda la cadena, de modo que una cascada que una persona inició sigue siéndole atribuible en cada salto.

Los cambios hechos *por* una regla en ejecución se atribuyen a la propia cascada de esa regla en lugar de parecer actividad nueva de un usuario, de modo que una regla que delega trabajo internamente no infla la cadena.

## Escala y límites

**Una ejecución no tiene un tope.** Una regla procesa todo lo que coincide con su alcance, sin importar cuán grande sea. Una regla que se detuviera silenciosamente en los primeros N Hallazgos sería una regla en la que no se podría confiar.

En cambio, una ejecución se procesa en **bloques (chunks)**, de 1000 Hallazgos a la vez de forma predeterminada. Solo el bloque se mantiene en memoria, de modo que un barrido sobre un alcance muy grande está limitado por la memoria y no por la cobertura. La única excepción es **Preview**, que sí tiene un tope, y lo indica en su rastro cuando trunca.

Otros dos números determinan cómo se divide el trabajo:

* **Findings per event**, 500 de forma predeterminada. Un cambio masivo se divide en varios eventos, cada uno convirtiéndose en su propia ejecución. El efecto práctico para una importación grande es un número manejable de ejecuciones en lugar de una ejecución por Hallazgo.

* **Per-Finding send ceiling**, 1000 de forma predeterminada. Un nodo de salida configurado para enviar un mensaje por Hallazgo se detiene en esta cantidad dentro de una sola ejecución y registra una omisión visible que indica cuántos no se enviaron. Esto limita las filas de entregas y las tareas en cola, algo que una ejecución dividida en bloques ya no limita por sí sola.

Los tres son parámetros de implementación, documentados en [Configuration](../configuration/).

### Cuánto puede durar una ejecución

Una ejecución registra un **heartbeat** (latido) después de cada bloque. La detección de estancamiento lee ese heartbeat en lugar de la hora de inicio, de modo que un barrido largo que sigue avanzando nunca se confunde con un worker caído.

Se aplican dos ventanas, ambas configurables:

* Una ejecución que pasa 30 minutos sin un heartbeat se trata como abandonada, se marca con error y se libera su bloqueo.

* Una ejecución se termina directamente después de seis horas, como resguardo contra una que nunca terminaría.

## Retención

Las ejecuciones se conservan durante **180 días** de forma predeterminada, junto con sus filas por nodo y su procedencia de Hallazgos. Las entregas se conservan durante 180 días por separado.

El producto lo indica en lugar de dejarlo implícito: el detalle de una ejecución muestra la ventana de retención y la fecha en que esa ejecución se eliminará. Una ejecución que todavía contiene entregas se conserva hasta que estas se depuran.

Ambas ventanas son configurables, y cualquiera de las dos puede establecerse para conservar los registros indefinidamente. Consulte [Configuration](../configuration/#retention).

## Ejecutar una regla manualmente

Una regla cuyo disparador es **Manual Run** se ejecuta con la acción **Run** en la lista de reglas. Las reglas con otros disparadores se ejecutan cuando su disparador se activa.

**Preview**, en el editor, es la otra forma de ejecutar un grafo. Ejecuta el motor real y luego revierte todo, no registra ninguna ejecución y fuerza a la salida a simular. Use preview mientras construye, y runs para ver qué ocurrió realmente.

## Procedencia en un Hallazgo

Las ejecuciones responden "¿qué hizo esta regla?". La procedencia responde la pregunta opuesta: "¿por qué cambió este Hallazgo?".

Cada cambio que hace una regla se registra contra el Hallazgo junto con la regla, la ejecución y el nodo responsables, y aparece como una línea de tiempo en el propio Hallazgo. Las acciones registradas son:

| Action | Meaning |
|--------|---------|
| `created`, `updated`, `closed`, `reopened` | Cambió el ciclo de vida del Hallazgo. |
| `duplicate`, `status_change` | Cambiaron sus indicadores de duplicado o de estado. |
| `notified` | Se envió una notificación sobre él. |
| `delivered` | Una entrega saliente lo cubrió. |

Las ediciones de campos registran lo que cambió, incluido el valor anterior y posterior de cada campo. Los valores muy largos se truncan en el registro, de modo que la línea de tiempo sigue siendo un registro del cambio y no una segunda copia del Hallazgo.

Las notificaciones y las entregas también se registran aquí. Esto es intencional: una regla que enviara un mensaje pero no cambiara ningún campo, de lo contrario, no dejaría ningún rastro en el Hallazgo.

La procedencia sobrevive a la regla. Eliminar una regla o una ejecución conserva las entradas de la línea de tiempo y simplemente las desvincula, de modo que el historial no desaparece cuando alguien hace limpieza.

## Eliminar reglas con historial

Una regla que ha producido entregas no se puede eliminar dejándolas huérfanas. Elimine primero las entregas, o conserve la regla y desactívela. Esto es intencional: las entregas contienen el registro de lo que realmente se envió a sistemas externos, y una eliminación en cascada se llevaría consigo los envíos en curso.
