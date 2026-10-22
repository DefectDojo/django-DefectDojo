---
title: EPSS / KEV
description: Cómo DefectDojo Pro enriquece los Hallazgos con datos de EPSS y CISA
  KEV, cuándo se sincroniza y cómo influye en la prioridad
audience: pro
weight: 2
aliases:
- /es/triage_findings/epss_kev/
---

DefectDojo Pro enriquece automáticamente sus Hallazgos con dos fuentes externas de inteligencia de amenazas — **EPSS** y **CISA KEV** — de modo que la priorización refleje qué tan probable es que se explote una vulnerabilidad, y no solo su severidad CVSS. Ambas fuentes coinciden con los Hallazgos por **CVE**, se actualizan según una **programación diaria** y alimentan directamente la puntuación de **prioridad** calculada de cada Hallazgo.

Los datos de enriquecimiento se almacenan **una vez por vulnerabilidad** y luego se aplican a todos los Hallazgos que la referencian. Esto significa que un CVE presente en diez mil Hallazgos se consulta una sola vez, y puede inspeccionar sus valores de EPSS y KEV directamente en Vulnerability Explorer — no solo Hallazgo por Hallazgo.

En DefectDojo Cloud, el enriquecimiento está totalmente gestionado: DefectDojo mantiene los datos de inteligencia de amenazas subyacentes y los entrega a su instancia. No hay nada que instalar, ninguna URL de feed que configurar y ningún trabajo diario que programar — se ejecuta por usted.

## Las dos fuentes

### EPSS — Exploit Prediction Scoring System

[EPSS](https://www.first.org/epss/) es un modelo basado en datos publicado por FIRST que estima la probabilidad de que un CVE determinado sea explotado en el mundo real durante los próximos 30 días. DefectDojo Pro almacena dos valores de EPSS en cada Hallazgo coincidente:

| Campo | Significado |
| --- | --- |
| **EPSS Score** | Probabilidad de explotación en los próximos 30 días, de `0.0` a `1.0` (por ejemplo, `0.94` = 94%). |
| **EPSS Percentile** | La posición de este CVE frente a todos los CVE puntuados, de `0.0` a `1.0` (por ejemplo, `0.99` = entre el 1% con mayor probabilidad de ser explotado). |

Cuando un solo Hallazgo tiene **varios CVE**, DefectDojo conserva la **puntuación EPSS más alta** entre ellos y la empareja con el percentil de ese mismo CVE. El percentil siempre pertenece al mismo CVE que la puntuación — nunca se combinan valores de CVE distintos, porque un percentil solo tiene sentido junto a su propia puntuación.

### KEV — CISA Known Exploited Vulnerabilities

El [catálogo CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) es la lista oficial del gobierno de EE. UU. de vulnerabilidades confirmadas como explotadas en el mundo real. A diferencia de EPSS (una predicción), KEV es una constatación de explotación real y observada. DefectDojo Pro almacena tres valores de KEV en cada Hallazgo coincidente:

| Campo | Significado |
| --- | --- |
| **Known Exploited** | `True` cuando el CVE aparece en el catálogo CISA KEV. |
| **Ransomware Used** | `True` cuando CISA indica que el CVE se ha utilizado en campañas de ransomware. |
| **KEV Date** | La fecha en que la vulnerabilidad se agregó al catálogo KEV. |

Cuando un Hallazgo tiene **varios CVE**, se marca como **Known Exploited** si **alguno** de sus CVE está en el catálogo, como **Ransomware Used** si alguno cumple esa condición, y la **KEV Date** corresponde a la fecha de incorporación al catálogo más temprana entre ellos.

Una señal de KEV nunca queda suprimida por otro CVE con un EPSS más alto. Si un Hallazgo tiene un CVE con una puntuación EPSS alta que *no* está en el catálogo KEV, y otro con una puntuación EPSS baja que *sí* lo está, el Hallazgo toma la puntuación EPSS alta **y** se marca como Known Exploited — cada campo refleja de forma independiente el peor caso entre los CVE del Hallazgo.

> **Los Hallazgos sin CVE no se enriquecen.** Ambas fuentes coinciden estrictamente por identificador CVE (`CVE-YYYY-NNNNN`). Un Hallazgo sin CVE — o con solo un identificador específico del proveedor o de tipo GHSA — no recibe datos de EPSS ni de KEV.

## Cuándo se sincroniza

El enriquecimiento se ejecuta **una vez al día, de forma automática**. Cada ejecución ocurre en dos etapas:

1. **Actualizar los datos de vulnerabilidad.** Cada CVE que conoce DefectDojo se vuelve a verificar contra los datos más recientes de EPSS y KEV, y se actualiza el registro correspondiente a esa vulnerabilidad.
2. **Aplicar los cambios a los Hallazgos.** Solo las vulnerabilidades cuyos valores realmente *cambiaron* se propagan a los Hallazgos que las referencian, y solo esos Hallazgos se vuelven a puntuar.

Como la segunda etapa depende de lo que haya cambiado, un día sin novedades resulta económico: si ninguna de las dos fuentes publicó nada nuevo, la ejecución finaliza sin reescribir sus Hallazgos. Cuando sí hay un cambio — una puntuación EPSS varía, o se agrega un CVE al catálogo KEV — cada Hallazgo afectado lo recibe en la siguiente ejecución.

Algunas consecuencias que vale la pena entender:

- **Los Hallazgos normalmente se enriquecen en el momento de la importación.** Desde la **v3.2.0**, el enriquecimiento de EPSS/KEV se aplica en el momento de la importación, por lo que un Hallazgo con un CVE recién importado normalmente no necesita esperar al siguiente ciclo diario para mostrar valores. Qué tan inmediato sea esto depende de si DefectDojo ya había consultado ese CVE antes — consulte [Qué cubre "enriquecido en el momento de la importación"](#what-enriched-at-import-time-covers) más abajo. La ejecución diaria se sigue realizando igualmente, y mantiene esos valores actualizados a medida que cambian las puntuaciones de EPSS y el catálogo KEV. Si un Hallazgo que esperaba ver enriquecido no lo está, puede [ejecutar una sincronización bajo demanda](#running-a-sync-on-demand).
- **Los valores se mantienen actualizados, no quedan congelados.** Un CVE que se agrega al catálogo KEV hará que un Hallazgo existente pase a **Known Exploited** en la siguiente ejecución, sin necesidad de volver a importar.
- **Las eliminaciones del catálogo KEV se respetan.** Si los CVE de un Hallazgo dejan de estar en el catálogo KEV, la ejecución borra los valores obsoletos de **Known Exploited** / **Ransomware Used** / **KEV Date** en lugar de dejarlos activos.

### Qué cubre "enriquecido en el momento de la importación"

Como los datos de enriquecimiento se almacenan una vez por vulnerabilidad, una importación solo puede aplicar de forma instantánea lo que DefectDojo ya haya consultado antes. Hay tres casos:

| En el momento de la importación, el CVE… | Cuándo el Hallazgo muestra EPSS/KEV |
| --- | --- |
| **Ya está enriquecido** — DefectDojo ya había consultado este CVE antes, para cualquier Hallazgo de cualquier Producto | **De inmediato**, como parte de la importación. Este es el caso habitual: los CVE se repiten entre escaneos y entre equipos, por lo que la mayoría de los CVE de una importación típica ya son conocidos. |
| **Es nuevo para DefectDojo**, y la importación incorpora solo una cantidad moderada de CVE nuevos | **Poco después de la importación**, en segundo plano. Todavía no hay nada almacenado que aplicar, así que la importación solicita una consulta solo para esos CVE y aplica los resultados cuando la recibe. |
| **Es nuevo para DefectDojo**, y la importación incorpora una gran cantidad de CVE nuevos — una primera importación, o una carga masiva retroactiva | **En la siguiente ejecución diaria**, o en la siguiente [sincronización bajo demanda](#running-a-sync-on-demand). Consultar miles de CVE completamente nuevos mientras la importación aún está en curso duplicaría el trabajo de la ejecución diaria, por lo que deliberadamente se deja para esa ejecución. |

En todos los casos, los valores llegan sin necesidad de volver a importar, y la ejecución diaria sigue siendo la red de seguridad — nada se omite de forma permanente.

> **Las sincronizaciones de conectores se enriquecen de la misma manera**, con una excepción: una **sincronización de conector muy grande se importa en bloques (chunks)**, y las sincronizaciones en bloques no se enriquecen en el momento de la importación. Esos Hallazgos obtienen sus valores de EPSS/KEV en la siguiente ejecución diaria, o mediante una sincronización bajo demanda.

## Visualizar KEV/EPSS en Vulnerability Explorer

Vulnerability Explorer muestra una fila por cada ID de vulnerabilidad, con las mismas cinco columnas de KEV/EPSS que aparecen en la tabla de Hallazgos — **EPSS Score**, **EPSS Percentile**, **Known Exploited**, **Ransomware Used** y **KEV Date**:

![imagen](images/Pro_EPSS_KEV_Explorer_Columns.png)

Estos valores describen la propia vulnerabilidad, por lo que son idénticos sin importar cuántos Hallazgos la referencien. EPSS Score, EPSS Percentile, Known Exploited y KEV Date se pueden ordenar, lo que convierte esto en la forma más rápida de responder "¿qué vulnerabilidades de mi entorno se están explotando realmente?" — ordene por **EPSS Score** de forma descendente, o por **Known Exploited** para llevar los CVE listados en el catálogo a la parte superior.

El número de **Total Findings** de cada fila enlaza a la lista de Hallazgos filtrada por esa vulnerabilidad, de modo que puede pasar de "este CVE está en el catálogo KEV" a "esto es todo lo que afecta" con un solo clic.

## Distinguir entre "sin datos" y "no explotado"

Una columna de KEV/EPSS en blanco y una ✗ roja significan cosas distintas:

- **✗ roja o una puntuación** — esta vulnerabilidad *sí* fue verificada. Una ✗ en Known Exploited significa que CISA no la incluye en su catálogo.
- **En blanco** — esta vulnerabilidad **nunca se ha enriquecido**, por lo que simplemente se desconoce su estado de explotación.

Aquí, el mismo Vulnerability Explorer nunca se ha sincronizado, por lo que todas las columnas de KEV/EPSS aparecen en blanco en lugar de mostrar ceros o marcas ✗:

![imagen](images/Pro_EPSS_KEV_Explorer_Unenriched.png)

La misma distinción aparece en el propio Hallazgo. Un Hallazgo cuyos CVE aún no se han enriquecido lo indica claramente, y enlaza a Vulnerability Explorer donde puede iniciar una sincronización:

![imagen](images/Pro_EPSS_KEV_Not_Enriched.png)

Una vez que se ha ejecutado el enriquecimiento, ese mismo panel informa lo que realmente se encontró:

![imagen](images/Pro_EPSS_KEV_Finding_Panel.png)

Esto importa porque, de otro modo, "todavía no lo hemos verificado" y "lo verificamos y no está siendo explotado" serían indistinguibles, y solo uno de esos dos casos es motivo para estar tranquilo.

## Ejecutar una sincronización bajo demanda

No es necesario esperar al ciclo diario. El botón **Sync KEV/EPSS data**, en la parte superior de Vulnerability Explorer, inicia una sincronización de inmediato:

![imagen](images/Pro_EPSS_KEV_Sync_Started.png)

Mientras una sincronización está en curso, el botón se deshabilita y en su lugar aparece una barra de progreso, junto con una estimación del tiempo restante una vez que se ha completado suficiente trabajo como para proyectarla. La línea de estado que aparece encima informa lo que está sucediendo — primero, que DefectDojo está verificando qué vulnerabilidades cambiaron, y luego, cuántos Hallazgos se han actualizado hasta el momento. Cuando la ejecución finaliza, la línea informa el resultado: cuántos Hallazgos cambiaron, que todo ya estaba actualizado, o bien — si no hay ninguna fuente configurada — que la sincronización no se ejecutó.

Solo se ejecuta una sincronización a la vez. Si presiona el botón mientras ya hay una en curso, simplemente se conecta a la ejecución que ya está en marcha en lugar de iniciar una segunda, por lo que es seguro presionarlo si no está seguro de si hay una sincronización en curso. También es seguro repetir una sincronización: si no hubo cambios desde la última ejecución, no se reescribe nada.

Esta es la forma más rápida de incorporar los cambios de EPSS y KEV publicados desde el último ciclo diario, y de completar los Hallazgos que todavía no muestran datos de enriquecimiento.

## Cómo influye en la prioridad y el riesgo

EPSS y KEV no son solo distintivos informativos: son entradas directas del **motor de priorización** de DefectDojo Pro. La puntuación `priority` de cada Hallazgo combina varios componentes (severidad, exposición, contexto del activo y más); EPSS y KEV determinan el componente de **puntuación externa**, que favorece a las vulnerabilidades que probablemente sean explotadas, o que se sabe que lo son.

La puntuación externa se deriva de la señal **más fuerte** entre las siguientes:

- **EPSS** contribuye en proporción a su puntuación — una mayor probabilidad de explotación contribuye más.
- **La inclusión en KEV** aporta un peso fijo: estar marcado como **Known Exploited** *o* usarse en **ransomware** aplica un aumento significativo, y un CVE que **tanto** es Known Exploited **como** se usa en ransomware aplica el mayor aumento.

Gana la señal mayor de las dos, de modo que un Hallazgo recibe el crédito completo ya sea por una puntuación EPSS alta o por estar en el catálogo KEV, sin verse penalizado por carecer de la otra. Esta puntuación externa se combina luego con la prioridad general del Hallazgo, junto con su severidad y exposición. El efecto neto: **un Hallazgo listado en KEV o con un EPSS alto se sitúa por encima de otro Hallazgo comparable que no tiene ninguna de las dos señales**, enfocando la remediación en lo que realmente tiene más probabilidades de ser atacado.

> **EPSS y KEV son la base — [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/) la amplía.** Con Threat Intelligence Enrichment habilitado, esa misma puntuación externa también reconoce exploits públicos armados, plantillas de detección de Nuclei, código de prueba de concepto y explotación activa confirmada, cada uno actuando como un *piso* en la escala de EPSS. Además, agrega el [Actively-Exploited Risk Floor](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor), que evita que un Hallazgo que está siendo explotado activamente en el mundo real quede en una banda de Riesgo baja solo porque su severidad base es Baja. Al igual que EPSS y KEV, estas señales solo pueden aumentar una puntuación.

Esto ocurre de forma automática — la prioridad se recalcula exactamente para los Hallazgos actualizados por cada ejecución de enriquecimiento, de modo que la priorización se mantiene alineada con la inteligencia de amenazas más reciente.

> **Nota:** EPSS y KEV influyen en la puntuación de **prioridad**. No modifican el campo **Severidad** de un Hallazgo. Sin embargo, sí pueden afectar el plazo del **SLA**: si su configuración de SLA tiene habilitado **Cap by KEV due date**, la fecha límite de SLA de un Hallazgo listado en KEV se adelanta a la fecha límite de remediación que fija CISA para ese CVE. Cuando un Hallazgo tiene varios CVE listados en KEV, se aplica la fecha límite más temprana.

## Filtrar y visualizar Hallazgos enriquecidos

Una vez que los Hallazgos están enriquecidos, los valores de EPSS y KEV están disponibles en toda la interfaz de Pro:

- **En el Hallazgo** — EPSS score, EPSS percentile, Known Exploited, Ransomware Used y KEV Date se muestran en el detalle del Hallazgo.
- **Ordenamiento** — las tablas de Hallazgos se pueden ordenar por EPSS score / percentile para mostrar primero los Hallazgos con mayor probabilidad de ser explotados.
- **Filtrado** — la lista de Hallazgos ofrece los filtros **Known Exploited** y **Ransomware Used**, de modo que puede crear vistas o informes limitados a vulnerabilidades con explotación real confirmada.

Un flujo de trabajo habitual consiste en filtrar por **Known Exploited = true**, y luego ordenar por prioridad, para generar una cola de "arreglar esto primero" respaldada por explotación confirmada.

## Configuración

En **DefectDojo Cloud**, el enriquecimiento de EPSS y KEV está habilitado y se mantiene automáticamente: no hay que activar fuentes, configurar URLs de feeds ni definir umbrales, y la sincronización diaria la gestiona DefectDojo. Las ponderaciones que traducen EPSS y KEV en prioridad están integradas en el motor de priorización.

Si los datos de EPSS o KEV no aparecen en los Hallazgos donde los espera (y esos Hallazgos sí tienen CVE), comience por revisar la línea de estado en Vulnerability Explorer: informa el resultado de la sincronización más reciente, incluido el caso en que no hay ninguna fuente configurada. Si eso se ve correcto y los datos siguen faltando, comuníquese con el soporte de DefectDojo, que puede confirmar si la sincronización diaria está entregando datos a su instancia.

> *Las instalaciones on-premise* configuran el enriquecimiento de otra manera — cada fuente se puede habilitar o deshabilitar y apuntar a una URL de feed personalizada en la configuración de enriquecimiento de Hallazgos del Tuner. Esa configuración no se aplica a Cloud, donde los datos los entrega DefectDojo.
