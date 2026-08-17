---
title: Historial de falsos positivos
description: Marca automáticamente los Hallazgos nuevos como falso positivo cuando
  un Hallazgo coincidente ya fue triado de esa manera
weight: 7
---

**El Historial de falsos positivos** evita que su equipo tenga que triar el mismo falso positivo una y otra vez. Cuando está habilitado y se importa un Hallazgo, DefectDojo busca Hallazgos existentes en el mismo Producto que coincidan con él, y si alguno de ellos ya está marcado como **Falso positivo**, el Hallazgo entrante también se marca como Falso positivo.

> **Esta función está marcada como EXPERIMENTAL en el producto** y **no se puede usar al mismo tiempo que la Deduplicación.** Lea [Cuándo puede usarla](#when-you-can-use-it) antes de activarla.

## Qué hace

Supongamos que un escáner informa de un hallazgo que su equipo investiga y marca como falso positivo. En cada escaneo posterior, ese mismo hallazgo vuelve a aparecer. Normalmente, alguien tiene que descartarlo cada vez. Con el Historial de falsos positivos activado, DefectDojo reconoce el hallazgo recurrente y lo marca automáticamente como falso positivo.

Los Hallazgos marcados de esta manera también se establecen como **inactivos** y **no verificados**, no solo como Falso positivo. Esto es intencional (el hallazgo desaparece por completo de su cola activa), pero sorprende a quienes esperan que solo cambie el indicador de Falso positivo.

La regla que mantiene DefectDojo es: *dentro de un Producto, si un Hallazgo es un falso positivo, todos los Hallazgos coincidentes también lo son.*

### Modo retroactivo

**El Historial retroactivo de falsos positivos** aplica la misma regla en sentido inverso. Cuando marca un Hallazgo como falso positivo, todos los demás Hallazgos coincidentes que estén **activos** en ese Producto también se marcan como Falso positivo.

Esto reescribe datos existentes. No hay vista previa ni solicitud de confirmación: el cambio simplemente se aplica en todo el Producto. Actívelo de forma deliberada.

## Cuándo puede usarlo

**El Historial de falsos positivos y la Deduplicación son mutuamente excluyentes.** Ambos resuelven problemas que se solapan, por lo que DefectDojo no permite ejecutar ambos a la vez: en la Configuración del sistema, habilitar uno deshabilita visualmente el otro, y activar la Deduplicación borra la configuración del Historial de falsos positivos.

Esto es lo más importante que hay que entender sobre esta función. La mayoría de las instancias ejecutan la Deduplicación, y para ellas el Historial de falsos positivos no está disponible. Está pensado para instancias que han decidido deliberadamente no deduplicar.

## Cómo habilitarlo

Ambas opciones se encuentran en la **Configuración del sistema**, en el bloque de deduplicación, y ambas están **desactivadas** de forma predeterminada:

| Opción | Qué hace |
| --- | --- |
| **Habilitar historial de falsos positivos** | Activa la función para la instancia. |
| **Habilitar historial retroactivo de falsos positivos** | También aplica la regla en sentido inverso, como se describió anteriormente. Requiere la opción anterior. |

Estas opciones son **de alcance para toda la instancia**. No existe una anulación por Producto o por Herramienta: habilitarlas afecta a todos los Productos de la instancia.

## Qué cuenta como coincidencia

El Historial de falsos positivos decide si dos Hallazgos son "el mismo" utilizando **el algoritmo de deduplicación configurado para la herramienta que los reportó**, aunque la propia función de Deduplicación deba estar desactivada.

| Algoritmo de deduplicación de la herramienta | Los Hallazgos coinciden cuando comparten |
| --- | --- |
| **Código hash** | el mismo código hash, generado a partir de los Campos de código hash configurados de esa herramienta |
| **ID único de la herramienta** | el mismo ID único de la herramienta |
| **ID único de la herramienta o código hash** | cualquiera de los dos |
| **Heredado** | el mismo título (sin distinguir mayúsculas y minúsculas) y la misma severidad |

Por lo tanto, la precisión de esta función depende por completo de lo bien configurada que esté la deduplicación de esa herramienta. **Ajuste el algoritmo y los campos hash de la herramienta antes de habilitar el Historial de falsos positivos**: consulte [Ajuste de la deduplicación](/triage_findings/finding_deduplication/pro__deduplication_tuning/) (Pro) o [Ajuste de la deduplicación](/triage_findings/finding_deduplication/os__deduplication_tuning/) (Open Source).

La coincidencia se limita **a un Producto**. Nunca se extiende entre Productos, ni se aplica a toda la instancia.

### Coincidencia basada en conjuntos (Pro)

En DefectDojo Pro, la coincidencia también respeta los **Campos de código hash basados en conjuntos**: los comparadores de ID de vulnerabilidad y CWE (`vulnerability_ids_partial`, `vulnerability_ids_subset`, `cwes_partial`, `cwes_subset`, y sus formas de coincidencia exacta), con el mismo significado que tienen en la deduplicación.

Esto hace que la coincidencia de Pro sea **más estrecha** que la de Open Source, y ese es precisamente el objetivo: sin ella, el Historial de falsos positivos podría replicar un falso positivo a Hallazgos que la deduplicación de la misma herramienta ni siquiera habría considerado duplicados. Este refinamiento solo puede reducir el conjunto de Hallazgos que se marcan; habilitar Pro nunca hará que se marquen automáticamente *más* Hallazgos.

En Open Source, la coincidencia usa solo el código hash, por lo que es más amplia. Téngalo en cuenta al ajustarla.

## Riesgos que conviene entender antes de habilitarlo

Esta función marca los Hallazgos como falso positivo sin que una persona los revise. Su radio de impacto lo determina su configuración de deduplicación, por lo que una configuración laxa es peligrosa.

* **Una clave de coincidencia laxa puede descartar Hallazgos no relacionados sin que nadie lo note.** El algoritmo **Heredado** solo hace coincidir el título y la severidad, por lo que una sola decisión de falso positivo podría marcar como falso positivo a todos los Hallazgos con el mismo título y la misma severidad en el Producto, incluidos los genuinos. Lo mismo se aplica a un conjunto de Campos de código hash demasiado amplio. Ajuste primero el algoritmo.
* **El modo retroactivo reescribe los Hallazgos existentes** sin vista previa, sin solicitud de confirmación y sin un resumen de lo que cambió.
* **Los Hallazgos se desactivan y quedan no verificados**, no solo se marcan.
* **La actualización masiva omite el procesamiento habitual que se ejecuta al guardar**, por lo que la automatización que reacciona a la actualización de Hallazgos podría no activarse para los Hallazgos modificados de esta manera.
* **Sigue estando etiquetada como EXPERIMENTAL** en el propio DefectDojo.

Un patrón más seguro para la mayoría de los equipos es mantener la Deduplicación activada y dejar que los duplicados hereden el estado de su Hallazgo original, en lugar de cambiar al Historial de falsos positivos. Consulte [Acerca de la deduplicación](/triage_findings/finding_deduplication/about_deduplication/).
