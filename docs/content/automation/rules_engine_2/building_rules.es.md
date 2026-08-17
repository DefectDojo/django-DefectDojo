---
title: Creación de reglas
description: El editor de grafos, los disparadores, el alcance, las condiciones y
  las plantillas de mensajes
weight: 2
audience: pro
aliases:
- /es/automation/rules_engine_v2/building_rules/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 es una función exclusiva de DefectDojo Pro.</span>

Una regla se construye en un lienzo. Se arrastran nodos desde una paleta, se conectan entre sí y cada uno se configura en un panel lateral. Esta página cubre las partes de ese proceso que son iguales sea cual sea el nodo que se use. Los propios nodos están en la [Referencia de nodos](../node_reference/).

## El editor

Abra **Rules Engine 2.0 > Todas las reglas** y elija **Nueva regla**, o abra una regla existente para editarla.

La paleta está agrupada en cuatro categorías, que también es el orden en que los elementos fluyen a través de un grafo típico:

| Categoría | Qué hacen los nodos |
|----------|-------------------|
| **Disparadores** | Deciden cuándo se activa la regla y qué Hallazgos entran en ella. Exactamente uno por grafo. |
| **Lógica** | Enrutan, limitan y deduplican los elementos que fluyen. |
| **Hallazgos** | Modifican los Hallazgos. |
| **Salida** | Envían algo hacia el exterior: un ticket, un mensaje, un informe. |

La paleta se genera a partir del propio motor, de modo que lo que se ve en el editor es siempre exactamente lo que el motor puede ejecutar.

### Reglas del grafo

Un grafo se valida al guardarlo, y de nuevo antes de cada ejecución. Debe cumplir todo lo siguiente:

* Tiene al menos un nodo.
* Tiene **exactamente un** nodo disparador.
* Cada nodo tiene un id único y no vacío de 100 caracteres o menos.
* Cada nodo es de un tipo que el motor conoce.
* Cada arista conecta dos nodos que existen.
* No contiene ningún ciclo.

Un nodo sin nada conectado a su entrada es válido. Se ejecuta con una lista de entrada vacía, lo que normalmente significa que no hace nada.

Un nodo con varias aristas entrantes recibe todas sus salidas concatenadas.

### Vista previa antes de guardar

**Vista previa** ejecuta en seco el grafo que se tiene actualmente en el lienzo y muestra la traza por nodo que produciría: cuántos elementos entraron en cada nodo, cuántos salieron por cada salida, y qué habría cambiado cada nodo.

La vista previa ejecuta el motor real, no una simulación de él, y luego revierte todo. No se escribe nada, no se registra ninguna ejecución, y la salida se fuerza a simular lo que indique el modo de la regla. Es la forma más rápida de comprobar que las condiciones coinciden con lo esperado.

La vista previa es la única ejecución que limita cuántos Hallazgos examina, para mantenerse rápida. Cuando trunca, lo indica en la traza. Una ejecución real no tiene ese límite.

## Disparadores y alcance

Todo grafo empieza con uno de tres disparadores.

* **Ante un evento de Hallazgo** activa la regla cuando se crean, actualizan, cierran o reabren Hallazgos. Elija cuál de esos en el ajuste **Evento** del nodo, o `any` para los cuatro.
* **Según una programación** recorre los Hallazgos con una periodicidad recurrente.
* **Ejecución manual** recorre los Hallazgos cuando se pulsa **Ejecutar** en la regla.

### Alcance

Los tres disparadores admiten un **Alcance**, y el alcance es la forma de acotar lo que la regla considera. Es el mismo vocabulario de filtros que usa el Rules Engine original, alrededor de sesenta filtros que abarcan los Hallazgos y los objetos a su alrededor, de modo que un filtro que ya se sepa escribir allí significa lo mismo aquí.

Vale la pena entender dos cosas sobre el alcance:

* **El alcance se aplica por encima de la autorización, nunca en su lugar.** La regla se ejecuta como su propietario, de modo que el alcance acota un conjunto de Hallazgos ya autorizado. Dejar el alcance vacío no significa "todos los Hallazgos de la instancia", significa "todos los Hallazgos que el propietario de la regla puede ver".
* **Un alcance inválido hace fallar la ejecución en lugar de ampliarla.** Si una clave de filtro no existe, o un valor es uno que el filtro descartaría silenciosamente, la ejecución termina en error. Una regla que no hace nada es recuperable. Una regla que edita silenciosamente todos los Hallazgos de la instancia no lo es.

Para un disparador de evento, el alcance actúa como una segunda puerta: los Hallazgos nombrados en el evento se comparan con él, y solo los que la superan entran en el grafo.

### Programación

Una regla cuyo disparador es **Según una programación** se programa desde la propia regla. Establecer la programación requiere Rule Edit, el mismo permiso que editar la regla, porque una regla activada por programación no hace nada en absoluto hasta que tiene una.

Las programaciones están limitadas a marcas de cuarto de hora. El campo de minutos de una expresión cron debe ser `0`, `15`, `30` o `45`.

Ejemplos válidos:

```
0 * * * *     every hour, on the hour
15 9 * * *    every day at 09:15
0 15 * * 1    every Monday at 15:00
30 2 * * *    every day at 02:30
```

## Cómo hacer referencia a los datos de un Hallazgo

Hay dos lugares en una regla que leen valores del elemento que pasa por ella: las **condiciones** y las **plantillas**. Ambos usan las mismas rutas con puntos.

```
finding.severity
finding.title
finding.vulnerability_ids.0
product.name
product_type.name
test.scan_type
ctx.rule_name
```

Una ruta que no se resuelve no produce ningún valor, en lugar de un error.

### Campos disponibles

Cada elemento lleva un conjunto fijo de campos de Hallazgo. Esta lista es un contrato, así que solo cambia de forma deliberada.

| Grupo | Campos |
|-------|--------|
| Identidad | `id`, `title`, `hash_code`, `unique_id_from_tool` |
| Severidad y puntuación | `severity`, `numerical_severity`, `cvssv3`, `cvssv3_score`, `epss_score`, `epss_percentile`, `priority`, `risk`, `risk_score` |
| Texto | `description`, `mitigation`, `impact` |
| Estado | `active`, `verified`, `false_p`, `duplicate`, `is_mitigated`, `out_of_scope`, `risk_accepted`, `under_review` |
| Fechas | `date`, `mitigated`, `last_status_update`, `sla_expiration_date` |
| Ubicación | `file_path`, `line`, `component_name`, `component_version`, `service` |
| Clasificación | `cwe`, `vulnerability_ids`, `tags` |

Además de `finding`, cada elemento lleva `test` (`id`, `title`, `scan_type`), `engagement` (`id`, `name`), `product` (`id`, `name`), `product_type` (`id`, `name`), y `ctx`.

Las fechas son cadenas ISO-8601. Eso es deliberado: significa que `gt` y `lt` las ordenan correctamente como texto, de modo que `2026-07-28` es correctamente mayor que `2026-01-01`.

`priority`, `risk` y `risk_score` provienen de la priorización de Pro. Un Hallazgo que aún no se ha puntuado no lleva ningún valor para ellos.

### Condiciones

Un nodo **Si / Filtro** contiene una lista de filas de condición. Cada fila es una ruta, un operador y un valor. **Coincidencia** decide si todas las filas deben cumplirse (`all`) o basta con una (`any`).

| Operador | Significado |
|----------|---------|
| `eq` | es igual a |
| `neq` | no es igual a |
| `contains` | contiene |
| `not_contains` | no contiene |
| `in` | es uno de |
| `not_in` | no es uno de |
| `gt` | es mayor que |
| `gte` | es mayor o igual que |
| `lt` | es menor que |
| `lte` | es menor o igual que |
| `startswith` | comienza con |
| `endswith` | termina con |
| `exists` | está definido |
| `not_exists` | no está definido |

Las comparaciones son **flexibles**. Primero se intenta como número, y si eso falla, los valores se comparan como texto recortado e insensible a mayúsculas/minúsculas. Así, una condición escrita como `finding.severity eq high` coincide con un Hallazgo cuya severidad es `High`, que es casi siempre lo que el autor quiso decir.

#### Transformaciones

Una fila de condición puede procesar el valor leído antes de compararlo.

| Transformación | Efecto |
|-----------|--------|
| `int` | número entero |
| `float` | número decimal |
| `str` | texto |
| `first` | primer elemento de una lista |
| `list` | como lista |
| `join` | unido con comas |
| `upper` | MAYÚSCULAS |
| `lower` | minúsculas |
| `strip` | recortado |
| `cwe_int` | número de CWE |
| `severity` | severidad normalizada, de modo que valores de estilo `critical`, `error` y `warning` de distintos escáneres se convierten en los cinco niveles de DefectDojo |
| `numerical_severity` | código de severidad ordenable, para comparaciones de orden |

### Plantillas

Cualquier ajuste etiquetado como mensaje, nota, título o valor acepta marcadores `{{ path }}`, resueltos por elemento:

```
{{finding.severity}}: {{finding.title}} ({{product.name}})
```

Una ruta sin valor se representa como una cadena vacía. Una lista se representa unida con comas.

Las plantillas también ven un bloque `ctx` con detalles sobre la propia ejecución. Las claves disponibles dependen del nodo, pero las habituales son:

| Marcador | Significado |
|-------------|---------|
| `{{ctx.rule_name}}` | El nombre de la regla |
| `{{ctx.count}}` | Cuántos Hallazgos cubre el mensaje |
| `{{ctx.trigger}}` | El evento que inició la ejecución |
| `{{ctx.findings_html}}` | La lista de Hallazgos renderizada, en el nodo de correo electrónico |
| `{{ctx.report_url}}` | El enlace de descarga, en el nodo de informe |
| `{{ctx.template_name}}` | El nombre de la plantilla de informe, en el nodo de informe |

Las plantillas son sustitución simple. No hay evaluación de expresiones, ni ejecución de código, ni acceso a atributos de objetos en ninguna parte de la configuración de una regla.

## Cómo probar una regla de forma segura

El orden recomendado para una regla que envía algo:

1. Construya el grafo y use **Vista previa** hasta que los recuentos de elementos parezcan correctos.
2. Guárdela. Las reglas nuevas se crean desactivadas.
3. Deje el modo en **Simulación** y active la regla.
4. Déjela ejecutarse, luego revise **Entregas** y compruebe que los payloads registrados son los previstos.
5. Cambie el modo a **En vivo**.

Simulación no es una ejecución parcial. Cada edición de Hallazgo del grafo ocurre de verdad en modo simulación. Solo se retienen los envíos salientes.
