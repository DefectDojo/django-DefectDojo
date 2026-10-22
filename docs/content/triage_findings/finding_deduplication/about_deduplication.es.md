---
title: Acerca de la deduplicación
description: Fundamentos y conceptos clave de la deduplicación
weight: 1
aliases:
- /es/en/working_with_findings/finding_deduplication/about_deduplication
- /es/en/working_with_findings/finding_deduplication/delete_deduplicates
- /es/en/working_with_findings/findings_workflows/manage_duplicate_findings
---

DefectDojo está diseñado para ingerir informes masivos procedentes de herramientas, creando uno o más Hallazgos según el contenido del informe. Al usar DefectDojo, lo más probable es que esté ingiriendo informes de la misma herramienta de forma periódica, lo que hace muy probable la aparición de Hallazgos duplicados.

Aquí es donde entra en juego la Deduplicación, una función inteligente que puede configurar para gestionar automáticamente los Hallazgos duplicados.

## Cómo gestiona DefectDojo los duplicados

1. Primero, importa **Test 1\.** Su informe contiene una vulnerabilidad que se registra como Hallazgo A.
2. **Más adelante, importa Test 2, que contiene la misma vulnerabilidad. Esto se registrará como Hallazgo B, y el Hallazgo B se marcará como duplicado del Hallazgo A.**
3. Más tarde aún, importa **Test 3**, que también contiene esa vulnerabilidad. Esto se registrará como Hallazgo C, que se marcará como duplicado del Hallazgo A.

Al crear y marcar los Duplicados de esta manera, DefectDojo garantiza que todo el trabajo relacionado con la vulnerabilidad "original" se centralice en la página del Hallazgo original, sin crear contextos separados ni dar a su equipo la impresión de que existen varias vulnerabilidades distintas que deben abordarse.

### Qué Hallazgo se convierte en el original

La Deduplicación siempre trata el Hallazgo **creado más antiguo** de una cadena de duplicados como el original canónico, por lo que un Hallazgo de una importación anterior nunca se degrada a duplicado de uno más reciente: un original ya establecido no cambia de manos.

Dentro de un *único* informe, el orden en que el escáner enumera sus hallazgos no decide cuál gana. Los Hallazgos de una misma importación se crean en un orden estable derivado del contenido, por lo que un informe que contiene varios hallazgos que coinciden en la misma clave de deduplicación produce **siempre el mismo original cada vez que se importa**. Volver a escanear y reimportar los mismos resultados no cambiará el Hallazgo con el que su equipo ha estado trabajando.

De forma predeterminada, estos Tests deben estar anidados bajo el mismo Producto para que se aplique la Deduplicación. Si lo desea, puede limitar aún más el alcance de la Deduplicación a un único Compromiso.

![Deduplicación a nivel de producto y compromiso](images/deduplication.png)

Los Hallazgos duplicados se establecen como Inactivos de forma predeterminada. Esto no significa que el propio Hallazgo duplicado esté inactivo. Más bien, esto permite que su equipo tenga un único Hallazgo activo en el que trabajar y remediar, lo que implica que, una vez que el Hallazgo original se Mitigue, los Duplicados también se Mitigarán.

## Deduplicación de Reimportación

La Deduplicación y la Reimportación son procesos similares, pero utilizan algoritmos diferentes para identificar coincidencias entre Hallazgos.

* Cuando reimporta a un Test, el proceso de Reimportación examina los Hallazgos entrantes, **compara los códigos hash y luego descarta cualquier coincidencia**. Esas coincidencias nunca se crearán como Hallazgos ni como Duplicados de Hallazgos.

Sin embargo, los Hallazgos que permanecen después de la Deduplicación de Reimportación siguen sujetos a la Deduplicación de la misma herramienta. Por lo tanto, si utiliza un alcance más estrecho para la Deduplicación de la misma herramienta, puede terminar con Duplicados dentro de un flujo de Reimportación.

### Ejemplo

A continuación se muestra una herramienta cuyo algoritmo de Deduplicación de Reimportación es diferente del algoritmo de Deduplicación de la misma herramienta.

| Algoritmo de deduplicación | Campos de código hash |
| ----- | ---- |
| Reimportación | Título, CWE, Severidad, Descripción, Número de línea |
| Misma herramienta | Título, CWE, Severidad, Descripción |

Supongamos que tiene un Hallazgo en DefectDojo con un número de línea determinado. Vuelve a escanear su entorno y el número de línea de esa vulnerabilidad cambia. Reimporta al mismo Test. Esto es lo que sucederá durante la reimportación y la deduplicación:

* Durante la Reimportación, el Hallazgo no coincidirá con ningún Hallazgo ya existente, porque el número de línea es diferente. Por lo tanto, se creará un nuevo Hallazgo en el Test.
* Una vez completada la Reimportación, se ejecutará el algoritmo de Deduplicación de la misma herramienta. La Deduplicación de la misma herramienta no considera el número de línea en esta configuración, por lo que el nuevo Hallazgo se etiquetará como duplicado.

La Reimportación puede descartar por completo los Hallazgos antes de que se registren, por lo que la configuración de Deduplicación de Reimportación debe ajustarse con precaución.

## ¿Cuándo son apropiados los duplicados?

Los duplicados son útiles cuando se trata de contextos de Test compartidos pero independientes. Por ejemplo, si su Producto está subiendo resultados de Test para dos repositorios diferentes que deben compararse, resulta útil saber qué vulnerabilidades son comunes a ambos repositorios.

Sin embargo, si DefectDojo está creando un exceso de duplicados, esto también puede ser una señal de que necesita ajustar sus pipelines o procesos de importación.

## ¿Qué indican mis duplicados?

* **La misma vulnerabilidad, pero encontrada en un contexto diferente:** esta es la forma adecuada de usar los Hallazgos duplicados. Si tiene muchos componentes afectados por la misma vulnerabilidad, probablemente querrá saber cuáles están afectados para comprender el alcance del problema.
​
* **La misma vulnerabilidad, encontrada en el mismo contexto**: para este caso existen mejores opciones. Si el Hallazgo duplicado no le aporta ningún contexto nuevo sobre la vulnerabilidad, o si se encuentra ignorando o eliminando con frecuencia sus Hallazgos duplicados, esto es una señal de que su proceso puede mejorarse. Por ejemplo, la Reimportación le permite gestionar eficazmente los informes entrantes de un pipeline de CI/CD. En lugar de crear un objeto Hallazgo completamente nuevo para cada duplicado, la Reimportación tomará nota del duplicado entrante sin llegar a crear el Hallazgo duplicado.

## Resumen

DefectDojo Open Source admite cuatro algoritmos de deduplicación que se pueden seleccionar por analizador (tipo de test):

- **ID único de la herramienta**: utiliza el identificador único proporcionado por el escáner.
- **Código hash**: utiliza un conjunto configurado de campos para calcular un hash.
- **ID único de la herramienta o código hash**: prioriza el ID único de la herramienta; si no se encuentra un ID único coincidente, recurre al hash.
- **Heredado**: algoritmo histórico con múltiples condiciones; solo disponible en la versión Open Source.

**DefectDojo Pro añade más opciones.** Dos algoritmos adicionales realizan coincidencias en **todos los Productos** de la instancia, en lugar de dentro de un único Producto o Compromiso: **Componente global** (por nombre y versión del componente) y **ID de vulnerabilidad global** (por CVE, GHSA, …). Ambos están desactivados de forma predeterminada y los habilita el equipo de soporte de DefectDojo. Pro también permite que el algoritmo de Código hash trate los ID de vulnerabilidad y los CWE de un Hallazgo como **conjuntos**, haciendo coincidir el conjunto exacto, cualquier valor compartido (`_partial`) o que uno sea un subconjunto del otro (`_subset`). Consulte [Ajuste de la deduplicación (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/) para ver la lista completa, los campos de coincidencia por conjuntos y las reglas que los rigen.

### Una alternativa a la Deduplicación: Historial de falsos positivos

Las instancias que deliberadamente **no** deduplican pueden usar en su lugar el [Historial de falsos positivos](/triage_findings/finding_deduplication/false_positive_history/), que marca automáticamente un Hallazgo entrante como falso positivo cuando un Hallazgo coincidente del mismo Producto ya fue triado de esa manera. Es **mutuamente excluyente con la Deduplicación** (DefectDojo no permite habilitar ambas a la vez) y todavía está marcado como experimental.

## Cómo se evalúan los endpoints según el algoritmo

Los endpoints pueden influir en la deduplicación de diferentes maneras según el algoritmo y la configuración.

### ID único de la herramienta

- La deduplicación usa `unique_id_from_tool` (o `vuln_id_from_tool`).
- **Los endpoints se ignoran** para la coincidencia de duplicados.
- El hash de un hallazgo puede seguir calculándose para otras funciones, pero no afecta a la deduplicación bajo este algoritmo.

### Código hash

- La deduplicación usa un hash calculado a partir de los campos especificados en `HASHCODE_FIELDS_PER_SCANNER` para el analizador correspondiente.
- El hash también incluye los campos de `HASH_CODE_FIELDS_ALWAYS` (consulte la sección sobre el campo Service más abajo).
- Los endpoints pueden afectar a la deduplicación de dos maneras:
  - Si los campos hash del escáner incluyen `endpoints`, estos forman parte del hash y deben coincidir en consecuencia.
- Si los campos hash del escáner no incluyen `endpoints`, se puede habilitar la coincidencia opcional basada en endpoints mediante `DEDUPE_ALGO_ENDPOINT_FIELDS` (configuración de OS). Cuando está configurado:
    - Establézcalo en una lista vacía `[]` para ignorar los endpoints por completo.
    - Establézcalo en una lista de atributos de endpoint (por ejemplo, `["host", "port"]`). Si al menos un par de endpoints entre los dos hallazgos coincide en todos los atributos indicados, puede producirse la deduplicación.

### ID único de la herramienta o código hash
Un hallazgo es duplicado de otro si comparten el mismo unique_id_from_tool O el mismo hash_code.

Los endpoints también deben coincidir para que los hallazgos se consideren duplicados; consulte el algoritmo de Código hash anterior.

### Heredado (solo Open Source)

- La deduplicación considera múltiples atributos, incluidos los endpoints.
- El comportamiento difiere entre hallazgos estáticos y dinámicos:
  - **Hallazgos estáticos**: el nuevo hallazgo debe contener todos los endpoints del original. Se permiten endpoints adicionales en el nuevo hallazgo.
  - **Hallazgos dinámicos**: los endpoints deben coincidir estrictamente (habitualmente por host y puerto); los endpoints diferentes impiden la deduplicación.
- Si no hay endpoints y tanto `file_path` como `line` están vacíos, normalmente no se produce la deduplicación.

## Procesamiento en segundo plano

- La deduplicación se activa durante la importación/reimportación y durante ciertas actualizaciones que se ejecutan en segundo plano mediante Celery.

### Modo de ejecución de la deduplicación en importación/reimportación

Para la importación y la reimportación puede controlar cómo se despacha el posprocesamiento de la deduplicación y si la respuesta de la API espera a que termine. Configúrelo por usuario en la página de perfil (**Modo de ejecución de la deduplicación**), o anúlelo por solicitud con el campo `deduplication_execution_mode` en los endpoints de importación/reimportación (el valor de la solicitud tiene prioridad sobre el del perfil).

- `async` (predeterminado): la deduplicación y el resto del posprocesamiento se ejecutan en segundo plano y la respuesta se devuelve de inmediato. Es el comportamiento histórico; la respuesta se produce antes de que los hallazgos se dedupliquen.
- `async_wait`: el posprocesamiento se sigue despachando en segundo plano, pero la solicitud espera a que termine la deduplicación antes de responder. La notificación `scan_added` y las estadísticas de la respuesta reflejan entonces el estado ya deduplicado (los hallazgos que resultaron ser duplicados ya no se cuentan ni se listan como nuevos). El envío a JIRA, la calificación del producto y otras tareas ajenas a la deduplicación siguen siendo asíncronas y no se esperan. La espera está limitada por `DD_DEDUPLICATION_ASYNC_WAIT_TIMEOUT` (predeterminado `60` segundos); si ningún worker toma el trabajo a tiempo, la solicitud responde de todos modos en lugar de quedarse bloqueada.
- `sync`: la deduplicación de la importación se ejecuta en línea dentro de la solicitud web.

La respuesta de importación/reimportación incluye un booleano `deduplication_complete` que indica si la deduplicación había terminado en el momento en que se produjo la respuesta (`true` para `sync` y para un `async_wait` completado, `false` para `async`).

Esto es independiente del indicador global de perfil `block_execution`, que fuerza **todas** las tareas asíncronas de un usuario (notificaciones, envío a JIRA, calificación de producto, deduplicación, ...) a ejecutarse en primer plano. Cuando no se establece ningún modo de ejecución, `block_execution=True` recurre a `sync`.

## El campo Service y su impacto

- De forma predeterminada, `HASH_CODE_FIELDS_ALWAYS = ["service"]`, lo que significa que el `service` asociado a un hallazgo se añade al hash para todos los escáneres.
- Implicaciones prácticas:
  - Dos hallazgos por lo demás idénticos con valores de `service` diferentes producirán hashes distintos y no se deduplicarán en las rutas basadas en hash.
  - Durante la importación/reimportación, el campo `Service` introducido en la interfaz puede sobrescribir el servicio proporcionado por el analizador. Cambiarlo puede modificar el hash y, por lo tanto, afectar a los resultados de la deduplicación.
  - Si desea que el servicio no tenga ningún impacto en la deduplicación, configure `HASH_CODE_FIELDS_ALWAYS` en consecuencia (consulte la página de ajuste de OS). Quitar `service` de la lista de inclusión permanente hará que deje de afectar a los hashes.

## Eliminar Hallazgos duplicados

Si tiene una cantidad excesiva de Hallazgos duplicados que desea eliminar, puede activar la opción **Eliminar Hallazgos duplicados** en la **Configuración del sistema**.

**Eliminar Hallazgos duplicados**, combinado con el campo **Máximo de duplicados**, permite a DefectDojo limitar la cantidad de Hallazgos duplicados almacenados. Cuando este campo está habilitado, DefectDojo solo conservará un número determinado de Hallazgos duplicados.

### ¿Qué duplicados se eliminarán?

El Hallazgo original nunca se eliminará automáticamente de DefectDojo, pero una vez superado el umbral del Máximo de duplicados, DefectDojo eliminará automáticamente el Hallazgo duplicado más antiguo.

Por ejemplo, supongamos que tiene el campo Máximo de duplicados establecido en "1".

1. Primero, importa **Test 1\.** Su informe contiene una vulnerabilidad que se registra como Hallazgo A.
2. **Más adelante, importa Test 2, que contiene la misma vulnerabilidad. Esto se registrará como Hallazgo B, y el Hallazgo B se marcará como duplicado del Hallazgo A.**
3. Más tarde aún, importa **Test 3**, que también contiene esa vulnerabilidad. Esto se registrará como Hallazgo C, que se marcará como duplicado del Hallazgo A. En este momento, el Hallazgo B se eliminará de DefectDojo, ya que se ha superado el umbral del máximo de duplicados.

### Aplicación de esta configuración

Al aplicar **Eliminar Hallazgos duplicados** se iniciará un proceso de eliminación de inmediato. Esta configuración se puede aplicar en la página de **Configuración del sistema**. Consulte Habilitar la deduplicación para obtener más información.

## Solución de problemas de la deduplicación

A veces, la deduplicación no funciona como se espera. A continuación se muestran algunos ejemplos de casos en los que la deduplicación podría no estar funcionando correctamente, junto con posibles soluciones.

| Lo que observa | Causa más probable | Qué ajustar |
| --- | --- | --- |
| La Reimportación cierra un Hallazgo antiguo y crea uno nuevo cuando solo cambió el número de línea | La coincidencia de la Reimportación usa campos inestables (por ejemplo, el número de línea) | <strong>Deduplicación de Reimportación</strong> (priorice ID estables o campos hash estables) |
| Se crean varios Hallazgos en el mismo Test que usted cree que deberían ser duplicados | La coincidencia de deduplicación no está configurada para esa herramienta o alcance | <strong>Deduplicación de la misma herramienta</strong> (y considere el comportamiento de "Eliminar Hallazgos duplicados") |
| Se crean duplicados entre distintas herramientas | La coincidencia entre herramientas está desactivada o es demasiado estricta | <strong>Deduplicación entre herramientas (solo Pro)</strong> (coincidencia basada en hash) |
| La misma dependencia SCA importada en varios Productos crea Hallazgos independientes en lugar de duplicados | La deduplicación se limita a cada Producto de forma predeterminada | <strong>Deduplicación de componente global (solo Pro)</strong> ([habilítela para sus herramientas SCA](/triage_findings/finding_deduplication/pro__global_component_deduplication/)), o bien, bajo el modelo de datos de ubicaciones, <strong>Deduplicación de ubicaciones globales (solo Pro)</strong> ([coincidencia por ubicación compartida](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| La misma URL / Hallazgo web importado en varios Productos crea Hallazgos independientes en lugar de duplicados | La deduplicación se limita a cada Producto de forma predeterminada, y el Componente global solo hace coincidir componentes | <strong>Deduplicación de ubicaciones globales (solo Pro)</strong> ([coincidencia de Hallazgos DAST/URL entre Productos](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| Se están creando duplicados en exceso del mismo Hallazgo, entre Tests | La jerarquía de activos no está configurada correctamente | [Considere la Reimportación para pruebas continuas](/triage_findings/finding_deduplication/avoid_excess_duplicates/) |

Cuando la deduplicación automática pasa por alto Hallazgos que usted cree que deberían estar vinculados, puede enlazarlos manualmente desde la página Ver Hallazgo. Consulte Hallazgos similares para saber cómo descubrir Hallazgos relacionados y marcarlos como duplicados manualmente ([Open Source](/triage_findings/finding_deduplication/os__similar_findings/) | [Pro](/triage_findings/finding_deduplication/pro__similar_findings/)).
