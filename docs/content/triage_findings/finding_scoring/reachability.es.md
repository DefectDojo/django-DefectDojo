---
title: Alcanzabilidad
description: Cómo DefectDojo Pro registra si el código vulnerable de un Hallazgo es
  realmente alcanzable, y cómo ese veredicto ajusta la prioridad
audience: pro
weight: 3
---

Un CVE con severidad Crítica en código que su aplicación nunca invoca no supone
el mismo riesgo que ese mismo CVE en una ruta de solicitud activa.
**Alcanzabilidad** capta esa diferencia: DefectDojo Pro registra si el código
vulnerable de cada Hallazgo puede alcanzarse realmente, le muestra de dónde
proviene esa conclusión, y la incorpora a la **prioridad** calculada del
Hallazgo.

Alcanzabilidad es una función en **beta** y está **desactivada de forma
predeterminada**. Un superusuario puede activarla en **Settings > Feature
Flags**. Mientras esté desactivada, no se registra ningún veredicto, la
prioridad no se ve afectada y no aparece ninguna interfaz de alcanzabilidad.

## Veredictos

Todo veredicto se normaliza a los mismos cinco valores, sin importar qué lo
haya generado:

| Veredicto | Significado |
|---|---|
| **Reachable (runtime)** | Se observó que el código vulnerable se ejecutaba. |
| **Reachable (static)** | Existe una ruta de llamada hacia el código vulnerable desde un punto de entrada de la aplicación. |
| **Potentially reachable** | Evidencia parcial — por ejemplo, se usa el paquete vulnerable, pero no se pudo confirmar la función específica. |
| **Unreachable** | El análisis no encontró ninguna ruta hacia el código vulnerable. |
| **Unknown** | Todavía ningún análisis de alcanzabilidad cubre este Hallazgo. |

Normalizar importa porque las herramientas no coinciden en su terminología:
el "no se encontró ninguna ruta" de un escáner y el "no está en uso" de otro
significan cosas distintas, y DefectDojo registra ambos como veredictos que
puede comparar, en lugar de reducirlos a un simple sí/no.

## Las reglas que sigue la alcanzabilidad

Estos comportamientos son deliberados y no cambian según la herramienta:

- **Unknown nunca juega en contra de un Hallazgo.** La mayoría de las
  instancias comienzan con poca o ninguna cobertura de alcanzabilidad. Un
  Hallazgo que nada ha analizado se puntúa exactamente igual que si la
  función estuviera desactivada.
- **Unreachable reduce la prioridad. Nunca cierra un Hallazgo.** Un
  veredicto "unreachable" atenúa la puntuación para que los problemas
  realmente activos se ordenen por encima, pero el Hallazgo permanece
  abierto y visible. El análisis de alcanzabilidad no es perfecto, y un
  "unreachable" incorrecto que ocultara silenciosamente una Crítica activa
  sería el peor fallo posible.
- **Cada veredicto muestra su origen.** Ningún veredicto aparece sin la
  herramienta que lo produjo, su nivel de confianza y, cuando se conoce, el
  commit que analizó.
- **Los veredictos siguen la deduplicación.** Cuando varios escáneres
  reportan la misma vulnerabilidad y solo uno de ellos informa
  alcanzabilidad, el veredicto se aplica a todo ese grupo de duplicados, de
  modo que no pierde la señal al importar otra herramienta.

## De dónde provienen los veredictos

No es necesario adoptar un nuevo escáner para obtener valor aquí: DefectDojo
lee la alcanzabilidad que ya producen las herramientas que quizás ya esté
usando:

- **Escáneres que la reportan en su salida.** Varios parsers admitidos
  incluyen alcanzabilidad, ya sea como datos estructurados o en el texto de
  su informe. No se requiere ninguna configuración adicional más allá de
  importar el informe como de costumbre.
- **Conectores.** Un conector que admite alcanzabilidad envía veredictos
  para los Productos que sincroniza, actualizados según su programación
  normal.

La cobertura normalmente es parcial, y eso es lo esperado. Las herramientas
que no reportan alcanzabilidad simplemente dejan sus Hallazgos en
**Unknown**.

## Cómo la alcanzabilidad cambia la prioridad

Alcanzabilidad es una entrada más para la puntuación de prioridad descrita en
[Puntuación y priorización](../). Los veredictos Reachable aumentan la
prioridad de un Hallazgo, Unreachable la reduce en proporción a la confianza
de la fuente, y Unknown la deja sin cambios.

La intensidad de ese ajuste se puede configurar por motor de priorización,
igual que cualquier otro factor: establezca el escalar de alcanzabilidad en
`0` para registrar los veredictos sin que estos muevan las puntuaciones en
absoluto, o auméntelo para dar más peso a la alcanzabilidad. Puede
previsualizar el efecto con el simulador de priorización antes de
aplicarlo.

Como habilitar la alcanzabilidad modifica las puntuaciones, revise los
umbrales de riesgo de su motor después de activarla, para que los Hallazgos
queden en los rangos que espera.

### Reglas de riesgo de alcanzabilidad

Ese ajuste es proporcional a la severidad del Hallazgo, lo que significa que
no puede expresar dos cosas que quizás desee. Un Hallazgo de severidad Baja
cuyo código se confirma como reachable solo recibe un pequeño aumento y
permanece en una banda baja; una Crítica reportada como unreachable puede
seguir estando en la parte superior de la cola. En su lugar, dos reglas
opcionales del motor de priorización fijan una banda directamente:

- **Reachable risk floor** — la banda de Riesgo mínima para los Hallazgos
  cuyo código vulnerable se confirma como reachable. Solo puede elevar una
  banda.
- **Unreachable risk ceiling** — la banda de Riesgo máxima para los
  Hallazgos reportados como unreachable. Solo puede bajar una banda, y
  nunca cierra ni oculta un Hallazgo; solo limita dónde se ordena.

Ambas están vacías de forma predeterminada, por lo que nada cambia hasta que
las configure. El ceiling también tiene una **confianza mínima**: solo se
aplica cuando el veredicto unreachable alcanza al menos ese nivel de
confianza, porque limitar una banda a partir de un veredicto de baja
confianza es la forma en que una Crítica activa termina enterrada.

Un Hallazgo cuyo CVE se reporta como explotado activamente en el mundo real
nunca queda limitado por el ceiling — la evidencia de explotación tiene
precedencia sobre la afirmación de ausencia de ruta.

## Qué verá

**En un Hallazgo** — una insignia de alcanzabilidad, y un panel de
**Reachability Sources** que enumera cada fuente que informó sobre él, el
veredicto y la confianza de cada fuente, y cuál se aplica actualmente.
Cuando una herramienta proporciona una ruta de llamada, la evidencia de
respaldo se muestra junto a ella.

**En la lista de Hallazgos** — una columna y un filtro de Reachability, para
que pueda crear vistas como "Crítica y reachable" y guardarlas.

**En un activo** — un panel de **Reachability Coverage** que muestra el
desglose de veredictos para ese activo, cuántos de sus Hallazgos tienen
algún veredicto, y cuántas Críticas la alcanzabilidad ha degradado o
confirmado. Cada cifra enlaza a los Hallazgos correspondientes. La
proporción que sigue en Unknown se muestra junto al resto: indica cuánto del
activo puede cubrir actualmente la alcanzabilidad.
