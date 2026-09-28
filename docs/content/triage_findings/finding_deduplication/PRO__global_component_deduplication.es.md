---
title: Deduplicación de componente global
description: Deduplique los Hallazgos de Análisis de Composición de Software por nombre
  y versión de componente en todos los Productos
weight: 5
audience: pro
---

La deduplicación de componente global es un algoritmo de DefectDojo Pro que identifica Hallazgos duplicados en **todos los Productos** según el nombre y la versión del componente al que hacen referencia. Está pensado para herramientas de Análisis de Composición de Software (SCA), donde la misma dependencia vulnerable (por ejemplo, `timespan@2.3.0`) puede aparecer en muchos Productos, y usted desea que DefectDojo trate esas apariciones como duplicados de un único Hallazgo original.

A diferencia de los demás algoritmos de deduplicación, la coincidencia por Componente global **no está limitada a un único Producto o Compromiso**. Un Hallazgo importado en el Producto B puede marcarse como duplicado de un Hallazgo más antiguo en el Producto A, incluso si los dos Productos no están relacionados.

> **Componente global frente a Ubicaciones globales:** Componente global solo hace coincidir por nombre y versión de componente. Si su instancia usa el modelo de datos de Ubicaciones, [Deduplicación de ubicaciones globales](/triage_findings/finding_deduplication/pro__global_locations_deduplication/) es el sucesor más preciso: identifica las dependencias por la Package URL completa y, además, deduplica Hallazgos de URL/DAST entre Productos. Consulte la tabla comparativa de esa página para saber cuál elegir.

## Habilitar el algoritmo de Componente global

La deduplicación de componente global está controlada por un feature flag y está **desactivada de forma predeterminada**. Un superusuario puede activarla desde **Settings > Feature Flags** tanto en instancias Cloud como On-Premise. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una vez habilitada la función, **Global Component** estará disponible como opción en el menú desplegable **Algoritmo de deduplicación**, tanto en la configuración de deduplicación de la misma herramienta como entre herramientas del Tuner.

## Configurar la deduplicación de componente global

Componente global puede aplicarse a la deduplicación de la misma herramienta, a la deduplicación entre herramientas, o a ambas, y se configura por herramienta de seguridad desde **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** en las instancias que todavía usan el diseño de menú anterior; consulte [El menú de configuración](/navigation/pro__settings_menu/)).

### Misma herramienta

Use la deduplicación de la misma herramienta con el algoritmo de Componente global cuando desee deduplicar hallazgos de una única herramienta de SCA en varios Productos.

1. Abra la pestaña **Same Tool Deduplication**.
2. Seleccione la herramienta de SCA en el menú desplegable **Security Tool** (por ejemplo, `Dependency Track Finding Packaging Format (FPF) Export`).
3. Establezca el **Deduplication Algorithm** en **Global Component**.
4. Envíe el formulario.

Este algoritmo no usa Campos de código hash, y estos se ocultan cuando se selecciona.

### Entre herramientas

Use la deduplicación entre herramientas con el algoritmo de Componente global cuando desee deduplicar hallazgos del mismo componente entre distintas herramientas de SCA y Productos.

La coincidencia entre herramientas requiere que Componente global esté configurado en **cada** herramienta que deba participar.

1. Abra la pestaña **Cross Tool Deduplication**.
2. Para cada herramienta a incluir: selecciónela en el menú desplegable **Security Tool**, establezca el algoritmo en **Global Component** y envíe.

## Cómo funciona la coincidencia

Un Hallazgo nuevo se marca como duplicado de un Hallazgo existente cuando:

- El nombre y la versión del componente coinciden exactamente, **y**
- Existe un Hallazgo más antiguo con el mismo nombre y versión de componente en cualquier lugar de la instancia de DefectDojo, en cualquier Producto o Compromiso.

La coincidencia de versión de componente es exacta. Un Hallazgo para `timespan@2.3.0` **no** se deduplicará frente a uno para `timespan@2.3.1`.

La configuración de deduplicación limitada al Compromiso se ignora para este algoritmo; la coincidencia siempre es global.

## Ejemplo

Suponga que Componente global está habilitado en `Dependency Track Finding Packaging Format (FPF) Export` (misma herramienta) y en una herramienta Generic Findings Import (entre herramientas):

| Paso | Importación | En el Producto | Resultado |
| --- | --- | --- | --- |
| 1 | Escaneo de Dependency Track para `timespan@2.3.0` | Application 0 | Se crea 1 Hallazgo activo |
| 2 | Mismo escaneo de Dependency Track | Application 1 | Se crea 1 Hallazgo, marcado como duplicado del Hallazgo de Application 0 |
| 3 | Generic Findings Import para `timespan@2.3.0` | Application 2 | Se crea 1 Hallazgo, marcado como duplicado del Hallazgo de Application 0 (coincidencia entre herramientas) |
| 4 | Escaneo de Dependency Track para `timespan@2.3.1` | Application 3 | Se crea 1 Hallazgo activo: versión distinta, sin coincidencia |

Cada Hallazgo duplicado muestra su original en la parte inferior de la página del Hallazgo, dentro de la cadena de duplicados.

## Visibilidad entre Productos

Dado que la coincidencia por Componente global cruza los límites entre Productos, el Hallazgo original de una cadena de duplicados puede estar en un Producto al que el usuario que visualiza el duplicado no tiene permiso de acceso.

En ese caso, el Hallazgo es visible y se etiqueta como duplicado, pero el usuario no podrá abrir ni navegar al original. Tenga esto en cuenta antes de habilitar Componente global en herramientas cuyos Hallazgos sean sensibles a los controles de acceso a nivel de Producto.

## Revertir

Para dejar de usar Componente global en una herramienta determinada, abra su configuración de deduplicación y cambie el algoritmo de nuevo a una de las opciones con alcance limitado.

Para la deduplicación de la **misma herramienta**:

- Código hash
- ID único de la herramienta
- ID único de la herramienta o código hash

Para la deduplicación **entre herramientas**:

- Código hash
- Deshabilitado

Cambiar el algoritmo desencadena un recálculo en segundo plano de los hashes de deduplicación para los Hallazgos existentes de la herramienta.
