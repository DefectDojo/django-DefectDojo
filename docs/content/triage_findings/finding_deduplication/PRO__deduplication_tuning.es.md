---
title: Ajuste de la deduplicación
description: Configure cómo DefectDojo identifica y gestiona los hallazgos duplicados
weight: 4
audience: pro
aliases:
- /es/en/working_with_findings/finding_deduplication/tune_deduplication
---

El ajuste de la deduplicación es una función de DefectDojo Pro que le brinda un control detallado sobre cómo se deduplican los hallazgos, lo que le permite optimizar la detección de duplicados para su flujo de trabajo específico de pruebas de seguridad.

## Configuración de deduplicación

En DefectDojo Pro, puede acceder al ajuste de la deduplicación desde:
**Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** en las instancias que todavía usan el diseño de menú anterior)

![image](images/deduplication_tuning.png)

La página de configuración de deduplicación ofrece tres áreas clave de configuración:
- Deduplicación de la misma herramienta
- Deduplicación entre herramientas
- Deduplicación de reimportación

## Deduplicación de la misma herramienta

La deduplicación de la misma herramienta está habilitada de forma predeterminada para todos los parsers de herramientas de seguridad. Esto garantiza que los hallazgos de escaneos consecutivos con la misma herramienta se deduplican correctamente.

Para ajustar la deduplicación de la misma herramienta:

1. Seleccione una **Herramienta de seguridad** específica en el menú desplegable
2. Elija un **Algoritmo de deduplicación** entre las opciones disponibles

![image](images/same_tool_deduplication.png)

### Algoritmos de deduplicación disponibles

DefectDojo Pro ofrece los siguientes métodos de deduplicación para la deduplicación de la misma herramienta:

#### Código hash
Utiliza una combinación de campos seleccionados para generar un hash único. Al seleccionarlo, aparecerá un tercer menú desplegable que muestra los campos utilizados para calcular el hash.

##### Huella de contenido

**Huella de contenido** es un campo de hash seleccionable (disponible en las tres áreas de configuración) que proporciona una identidad *invariante a la ubicación* para los hallazgos de análisis estático. Se deriva del fragmento de código vulnerable que una herramienta incluye en el hallazgo, normalizado de modo que la indentación, las anotaciones de número de línea y las diferencias de formato no lo modifiquen. Dos hallazgos sobre el mismo código vulnerable generan el mismo hash aunque el código se haya movido a otra línea o archivo.

La huella de contenido se calcula para herramientas que incluyen un fragmento de código en la descripción del hallazgo, entre ellas **Bandit**, **Gosec**, **Brakeman**, **Checkmarx One**, y cualquier herramienta cuya descripción contenga un bloque de código con cercas o un fragmento SARIF.

> **Antes de seleccionar Huella de contenido como campo de hash**, complete las huellas de los hallazgos existentes ejecutando `./manage.py backfill_fingerprints`. Los hallazgos importados después de que la función esté disponible obtienen huellas automáticamente, pero los hallazgos preexistentes no tienen ninguna; seleccionar el campo sin completar antes las huellas hace que los hallazgos existentes y los entrantes generen hashes distintos, rompiendo cada coincidencia hasta que se ejecute el proceso de relleno.

La huella de contenido combina bien con **CWE** para herramientas que incrustan rutas de archivo o números de línea dentro de sus títulos, donde otros campos de identidad cambian cada vez que el código se mueve. Consulte [Coincidencia por desplazamiento de ubicación](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools).

#### ID único de la herramienta
Aprovecha el identificador interno propio de la herramienta de seguridad para los hallazgos, garantizando una deduplicación perfecta cuando el escáner proporciona IDs únicos confiables.

Este algoritmo puede ser útil al trabajar con escáneres SAST, o en situaciones en las que un hallazgo puede "desplazarse" dentro del código fuente a medida que avanza el desarrollo.

#### ID único de la herramienta o código hash
Intenta usar primero el ID único de la herramienta y, si no hay ninguno disponible, recurre al código hash. Esto ofrece la opción de deduplicación más flexible.

#### Componente global
Hace coincidir los hallazgos por nombre y versión de componente en **todos los Productos** de la instancia, en lugar de dentro de un único Producto o Compromiso. Está pensado para herramientas de SCA en las que la misma dependencia vulnerable aparece en muchos Productos. Este algoritmo está desactivado de forma predeterminada y debe habilitarlo el soporte de DefectDojo. Consulte [Deduplicación de componente global](/triage_findings/finding_deduplication/pro__global_component_deduplication/) para más información.

#### ID de vulnerabilidad global
Hace coincidir los hallazgos por sus **IDs de vulnerabilidad** (CVE, GHSA, …) en **todos los Productos** de la instancia, en lugar de dentro de un único Producto o Compromiso. Está pensado para herramientas que reportan el mismo CVE en muchos Productos. Desactivado de forma predeterminada y habilitado por el soporte de DefectDojo.

> **Dos herramientas con el mismo algoritmo a nivel de instancia se convierten en candidatas mutuas de deduplicación.** Cuando dos herramientas *distintas* están configuradas con un algoritmo a nivel de instancia (Componente global o ID de vulnerabilidad global), sus hallazgos comparten un hash de agrupación constante, de modo que un hallazgo de cualquiera de las dos herramientas se considera para deduplicación frente a la otra en esa dimensión compartida (componente o ID de vulnerabilidad). Este es el comportamiento entre herramientas previsto: actívelo solo cuando desee que esas herramientas se deduplican entre sí.

### Campos de código hash basados en conjuntos (IDs de vulnerabilidad y CWEs)

Dos atributos de los hallazgos contienen un *conjunto* de valores en lugar de un único valor: los IDs de vulnerabilidad (CVE, GHSA, …) y los CWEs. Al usar el algoritmo de **Código hash** (misma herramienta o entre herramientas), puede añadir los siguientes campos a **Campos de código hash** para controlar cómo se comparan esos conjuntos:

| Campo | Los hallazgos son duplicados cuando… |
|-------|-------------------------------|
| `vulnerability_ids` | tienen **exactamente el mismo conjunto** de IDs de vulnerabilidad |
| `vulnerability_ids_partial` | comparten **al menos un** ID de vulnerabilidad |
| `vulnerability_ids_subset` | los IDs de vulnerabilidad de un hallazgo son un **subconjunto** de los del otro |
| `cwes` | tienen **exactamente el mismo conjunto** de CWEs |
| `cwes_partial` | comparten **al menos un** CWE |
| `cwes_subset` | los CWEs de un hallazgo son un **subconjunto** de los del otro |

Los campos `_partial` y `_subset` se comparan por par de hallazgos en lugar de incorporarse al hash: el resto de los Campos de código hash agrupa a los hallazgos candidatos, y la comparación de conjuntos luego reduce ese grupo. (La coincidencia exacta —`vulnerability_ids` y `cwes`— se incorpora directamente al hash).

**Valores vacíos.** Si un hallazgo no tiene IDs de vulnerabilidad (o CWEs) para el comparador configurado:

- Si los Campos de código hash también incluyen un campo ordinario (por ejemplo, `title`), ese campo aporta la identidad: el comparador de conjuntos se omite para ese par y los hallazgos aún pueden coincidir en el resto del hash.
- Si un comparador de conjuntos es el **único** campo, un hallazgo sin valores no coincide con nada: al no haber ningún otro elemento que lo identifique, un conjunto vacío no se trata como coincidente con todos los demás.

**Reglas de configuración** (aplicadas al guardar la configuración):

- Un campo de IDs de vulnerabilidad (`vulnerability_ids`, `vulnerability_ids_partial` o `vulnerability_ids_subset`) puede usarse por sí solo: un CVE o GHSA identifica una instancia de vulnerabilidad específica.
- Los campos de CWE (`cwes`, `cwes_partial`, `cwes_subset`) **no** pueden ser el único criterio. Un CWE es una *clase* de debilidad, no una instancia específica, por lo que hacer coincidir solo por CWE fusionaría hallazgos no relacionados. Combine un comparador de CWE con un campo identificador como `title` o `file_path`.

## Deduplicación entre herramientas

La deduplicación entre herramientas está deshabilitada de forma predeterminada, ya que la deduplicación entre distintas herramientas de seguridad requiere una configuración cuidadosa debido a las variaciones en cómo cada herramienta reporta las mismas vulnerabilidades.

![image](images/cross_tool_deduplication.png)

Para habilitar la deduplicación entre herramientas:

1. Seleccione una **Herramienta de seguridad** en el menú desplegable
2. Cambie el **Algoritmo de deduplicación** de "Disabled" a "Hash Code"
3. Seleccione qué campos deben usarse para generar el hash en el menú desplegable **Campos de código hash**

La deduplicación entre herramientas admite el algoritmo de Código hash, que es adecuado para la mayoría de los flujos de trabajo, ya que distintas herramientas rara vez comparten identificadores únicos compatibles. Para herramientas de SCA que reportan las mismas dependencias, [Deduplicación de componente global](/triage_findings/finding_deduplication/pro__global_component_deduplication/) también está disponible como opción entre herramientas (desactivada de forma predeterminada).

Tenga en cuenta que la deduplicación entre herramientas también se limita únicamente a Assets individuales.

## Deduplicación de reimportación

**⚠️ Los procesos de reimportación pueden descartar por completo los Hallazgos antes de que se registren. Esto puede provocar pérdida de datos si se configura incorrectamente, por lo que la configuración de deduplicación de reimportación debe ajustarse con precaución.**

La configuración de deduplicación de reimportación puede usarse para establecer un algoritmo para los Universal Parsers, o para un Generic Findings Import Parser.

La deduplicación de reimportación no puede ajustarse para otras herramientas de forma predeterminada. Los usuarios que deseen ajustar el algoritmo de deduplicación de reimportación para otras herramientas en su instancia deben ponerse en contacto con el [soporte de DefectDojo](mailto:support@defectdojo.com) para obtener ayuda.

![image](images/reimport_deduplication.png)

Al configurar la deduplicación de reimportación:

1. Seleccione la **Herramienta de seguridad** (Universal o Generic Parser)
2. Elija el **Algoritmo de deduplicación** adecuado

Las siguientes opciones de algoritmo están disponibles para la deduplicación de reimportación:
- Código hash
- ID único de la herramienta
- ID único de la herramienta o código hash

La reimportación puede descartar por completo los Hallazgos antes de que se registren, por lo que la configuración de deduplicación de reimportación debe ajustarse con precaución.

### Seguimiento de hallazgos al cambiar de ubicación

Cuando el algoritmo de deduplicación de reimportación de una herramienta es **Código hash**, aparece un interruptor adicional: **Track findings as locations change**. Con él habilitado, un hallazgo cuya ubicación se movió entre reimportaciones —un desplazamiento de línea o un cambio de nombre de archivo, un cambio de URL, o un aumento de versión de dependencia— se trata como el *mismo* hallazgo, incluso si la herramienta volvió a puntuar su severidad. Se mantiene un único hallazgo en su lugar y se conserva su historial de ubicación, en lugar de cerrar el hallazgo anterior y crear uno idéntico nuevo.

El interruptor está desactivado de forma predeterminada y solo se aplica al algoritmo de reimportación de Código hash (las herramientas con un ID único de la herramienta confiable ya rastrean el movimiento mediante sus IDs estables). Habilitarlo vuelve a calcular automáticamente el hash de los hallazgos existentes de la herramienta en segundo plano, de modo que los datos históricos participan de inmediato.

Consulte [Coincidencia por desplazamiento de ubicación](/triage_findings/finding_deduplication/pro__location_drift_matching/) para saber cómo funciona la coincidencia, qué se conserva y las recomendaciones para habilitarla en instancias grandes.

## Ejecutar la deduplicación de forma retroactiva sobre datos existentes

Una situación habitual al activar por primera vez el ajuste de la deduplicación es tener una gran acumulación de Hallazgos que se importaron *antes* de que cambiara la configuración de deduplicación. En DefectDojo Pro, no es necesario ejecutar un comando aparte para deduplicar estos datos históricos: **cambiar la configuración de deduplicación de una herramienta desencadena automáticamente un recálculo de hash en segundo plano de todos los Hallazgos existentes asociados a ese tipo de test**.

Esto significa en la práctica:

- Cuando cambia el **Algoritmo de deduplicación** o los **Campos de código hash** de una herramienta, DefectDojo pone en cola un trabajo en segundo plano para recalcular los hashes de cada Hallazgo de esa herramienta ya presente en la instancia.
- El trabajo se ejecuta de forma asíncrona. En instancias grandes (millones de Hallazgos), esto puede tardar un tiempo en completarse y no verá cambios inmediatos en la tabla de Hallazgos.
- Los hashes recién calculados se aplican a las decisiones de deduplicación posteriores en toda la acumulación.

Si realiza varios cambios de configuración en rápida sucesión, cada uno pone en cola su propio trabajo de recálculo de hash. Deje que el trabajo anterior termine antes de evaluar los resultados, especialmente al comparar el número de Hallazgos antes y después del cambio.

> **Nota para Pro autoalojado:** El trabajo en segundo plano se ejecuta en el pool de workers de Celery. Si sus workers están saturados o con trabajos acumulados, el recálculo de hash puede tardar más de lo esperado; verifique el estado de los workers si los resultados no aparecen en el plazo que esperaría para el tamaño de su instancia.

> **Los feature flags no bloquean una configuración ya existente.** La configuración de deduplicación guardada de una herramienta permanece vigente mientras esté configurada; desactivar un feature flag relacionado **no** revierte retroactivamente esa herramienta a la deduplicación predeterminada. Para cambiar o detener el comportamiento de deduplicación de una herramienta, actualice directamente su configuración de deduplicación (lo que también pone en cola el recálculo de hash en segundo plano descrito anteriormente).

## Prácticas recomendadas de deduplicación

Para obtener resultados óptimos con el ajuste de la deduplicación:

- **Empiece con los valores predeterminados**: la configuración de deduplicación preconfigurada funciona bien en la mayoría de los escenarios
- **Pruebe los cambios con cuidado**: después de ajustar la configuración de deduplicación, supervise algunas importaciones para garantizar un comportamiento correcto.
- **Planifique los recálculos retroactivos**: cambiar la configuración de deduplicación recalcula el hash de cada Hallazgo existente de esa herramienta en segundo plano. Consulte [Ejecutar la deduplicación de forma retroactiva sobre datos existentes](#running-deduplication-retroactively-on-existing-data) más arriba.
- **Use Código hash para la deduplicación entre herramientas**: al habilitar la deduplicación entre herramientas, seleccione campos que identifiquen de forma confiable el mismo hallazgo en distintas herramientas (como el nombre de la vulnerabilidad, la ubicación y la severidad). **IMPORTANTE** cada herramienta habilitada para la deduplicación entre herramientas **DEBE** tener seleccionados los mismos campos.
- **Mantenga las fuentes entre herramientas en el mismo Asset**: la deduplicación entre herramientas está limitada por Asset. Los hallazgos repartidos entre Assets distintos no se deduplican aunque coincidan los campos de hash. Consulte [Deduplicación entre herramientas](#cross-tool-deduplication) más arriba.
- **Evite una deduplicación demasiado amplia**: la deduplicación entre herramientas con muy pocos campos de hash puede provocar falsos duplicados
- **Complete las huellas antes de seleccionar Huella de contenido**: ejecute primero `./manage.py backfill_fingerprints` y luego seleccione el campo; así el recálculo de hash desencadenado ya tendrá huellas con las que trabajar. Consulte [Huella de contenido](#content-fingerprint) más arriba.
- **Habilite el seguimiento de ubicación entre ejecuciones de escaneo**: el recálculo automático del interruptor cubre toda la acumulación de la herramienta; en instancias grandes, deje que termine antes de la próxima reimportación programada. Consulte [Coincidencia por desplazamiento de ubicación](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades).

Ajustando la configuración de deduplicación según sus herramientas específicas, puede reducir significativamente el ruido de duplicados.

## Hallazgos bloqueados

Cada vez que se cambia la configuración de deduplicación de una herramienta determinada, los hashes de deduplicación se recalculan para esa herramienta en toda la instancia de DefectDojo.
