---
title: Deduplicación de ubicaciones globales
description: Deduplique Hallazgos por ubicación compartida (URL o dependencia) en
  todos los Productos
weight: 6
audience: pro
---

La deduplicación de ubicaciones globales es un algoritmo de DefectDojo Pro que identifica Hallazgos duplicados en **todos los Productos** basándose exclusivamente en una **ubicación compartida**: una URL, o una dependencia (identificada por su Package URL). Dos Hallazgos que comparten una ubicación de un tipo seleccionado se tratan como duplicados independientemente de su título, severidad, CWE o IDs de vulnerabilidad; la ubicación por sí sola es la identidad.

Es la contraparte consciente de la ubicación de [Deduplicación de componente global](/triage_findings/finding_deduplication/pro__global_component_deduplication/), aplicada al modelo de datos de Ubicaciones de DefectDojo. Mientras que Componente global solo coincide por nombre y versión de componente, Ubicaciones globales coincide por la misma dependencia **mediante la Package URL completa** *y* por **URLs** compartidas, por lo que puede deduplicar Hallazgos de DAST/web entre Productos, algo que Componente global no puede hacer.

A diferencia de los algoritmos con alcance limitado, la coincidencia por Ubicaciones globales **no está limitada a un único Producto o Compromiso**. Un Hallazgo importado en el Producto B puede marcarse como duplicado de un Hallazgo más antiguo en el Producto A, incluso si los dos Productos no están relacionados.

## Requisitos

Ubicaciones globales se define sobre el modelo de datos de **Ubicaciones** de DefectDojo y solo se ofrece cuando la función **Ubicaciones** está habilitada. En instancias donde Ubicaciones está desactivada, el feature flag de Ubicaciones globales aparece bloqueado ("Requires Locations to be enabled") y el algoritmo no aparece en el Tuner.

## Habilitar el algoritmo de Ubicaciones globales

La deduplicación de ubicaciones globales está controlada por un feature flag y está **desactivada de forma predeterminada**. Una vez habilitada Ubicaciones, un superusuario puede activarla desde **Settings > Feature Flags** tanto en instancias Cloud como On-Premise. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una vez habilitada la función, **Global Locations** estará disponible como opción en el menú desplegable **Algoritmo de deduplicación**, tanto en la configuración de deduplicación de la misma herramienta como entre herramientas del Tuner.

## Configurar la deduplicación de ubicaciones globales

Ubicaciones globales puede aplicarse a la deduplicación de la misma herramienta, a la deduplicación entre herramientas, o a ambas, y se configura por herramienta de seguridad desde **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** en las instancias que todavía usan el diseño de menú anterior; consulte [El menú de configuración](/navigation/pro__settings_menu/)).

Al seleccionar **Global Locations**, el selector de Campos de código hash se oculta (no se aplica) y en su lugar aparece un selector de **Location Types**.

### Tipos de ubicación

Elija qué tipos de ubicación participan en la coincidencia:

- **URLs**: dos Hallazgos coinciden cuando comparten una URL (comparada según los campos de endpoint configurados, `DEDUPE_ALGO_ENDPOINT_FIELDS`).
- **Dependencies**: dos Hallazgos coinciden cuando hacen referencia a la misma dependencia, por identidad de Package URL completa.

Debe seleccionarse al menos un tipo; ambos están seleccionados de forma predeterminada. Una herramienta configurada solo con **URLs** ignora las dependencias compartidas, y una configurada solo con **Dependencies** ignora las URLs compartidas.

### Misma herramienta

Use la deduplicación de la misma herramienta con el algoritmo de Ubicaciones globales cuando desee deduplicar Hallazgos de una única herramienta en varios Productos por ubicación compartida.

1. Abra la pestaña **Same Tool Deduplication**.
2. Seleccione la herramienta en el menú desplegable **Security Tool**.
3. Establezca el **Deduplication Algorithm** en **Global Locations**.
4. Elija los **Location Types** con los que hacer coincidir.
5. Envíe el formulario.

### Entre herramientas

Use la deduplicación entre herramientas con el algoritmo de Ubicaciones globales cuando desee deduplicar Hallazgos que comparten una ubicación entre **distintas** herramientas y Productos.

La coincidencia entre herramientas lee la selección de tipo de ubicación de la herramienta que realiza la importación, así que configure Ubicaciones globales en **cada** herramienta que deba participar, con los mismos Location Types.

1. Abra la pestaña **Cross Tool Deduplication**.
2. Para cada herramienta a incluir: selecciónela en el menú desplegable **Security Tool**, establezca el algoritmo en **Global Locations**, elija los Location Types y envíe.

## Cómo funciona la coincidencia

Un Hallazgo nuevo se marca como duplicado de un Hallazgo existente en cualquier lugar de la instancia cuando ambos comparten **al menos una ubicación concreta de un tipo seleccionado**:

- **Una URL** cuyos campos de endpoint configurados (`DEDUPE_ALGO_ENDPOINT_FIELDS`) coinciden todos, **o**
- **Una dependencia** con la misma Package URL (una coincidencia exacta de purl, por lo que `pkg:npm/timespan@2.3.0` **no** coincide con `pkg:npm/timespan@2.3.1`).

La coincidencia es **estricta y no vacía**: dos Hallazgos que no tienen ninguna ubicación de un tipo seleccionado **nunca** se deduplican (a diferencia de la coincidencia por ubicación con alcance limitado, "ambos vacíos" no es una coincidencia). Si la comparación de campos de endpoint está deshabilitada (`DEDUPE_ALGO_ENDPOINT_FIELDS = []`), las URLs no pueden establecer ninguna coincidencia; solo puede hacerlo una dependencia compartida.

La coincidencia de la misma herramienta se mantiene dentro de una única herramienta (tipo de test). La coincidencia entre herramientas cruza herramientas intencionalmente. La configuración de deduplicación limitada al Compromiso se ignora para este algoritmo; la coincidencia siempre es global, y el campo `service` sigue particionando la deduplicación igual que en los demás algoritmos globales.

## Ejemplo

Suponga que Ubicaciones globales (ambos tipos de ubicación) está habilitado en una herramienta DAST (misma herramienta) y, para la fila entre herramientas, en una segunda herramienta DAST:

| Paso | Importación | En el Producto | Resultado |
| --- | --- | --- | --- |
| 1 | Hallazgo DAST en `https://shared.example.com/login` | Application 0 | Se crea 1 Hallazgo activo |
| 2 | Misma URL, vulnerabilidad **distinta** (título + severidad) | Application 1 | Se crea 1 Hallazgo, marcado como duplicado del Hallazgo de Application 0 (coincide solo por ubicación) |
| 3 | Segunda herramienta DAST, misma URL | Application 2 | Se crea 1 Hallazgo, marcado como duplicado del Hallazgo de Application 0 (coincidencia entre herramientas) |
| 4 | Hallazgo DAST en `https://other.example.com/admin` | Application 3 | Se crea 1 Hallazgo activo: URL distinta, sin ubicación compartida |
| 5 | Hallazgo sin URL ni dependencia | Application 4 | Se crea 1 Hallazgo activo: no hay ubicación que compartir |

Cada Hallazgo duplicado muestra su original en la parte inferior de la página del Hallazgo, dentro de la cadena de duplicados.

## Componente global frente a Ubicaciones globales

Ambos son algoritmos globales (entre Productos) que ignoran el alcance del Compromiso y hacen coincidir por una única identidad en lugar de por los campos de hash. Elija según qué identifica un duplicado para su herramienta:

| | Componente global | Ubicaciones globales |
| --- | --- | --- |
| Coincide por | **Nombre y versión** de componente | Una **ubicación** compartida: una URL y/o una dependencia |
| Identidad de dependencia | Nombre y versión | **Package URL** completa (tipo, namespace, nombre, versión, calificadores) |
| Hallazgos de URL / DAST | No coincide | Coincide (según los campos de endpoint configurados) |
| Configurable | No | Sí: elija URLs, Dependencies, o ambos por herramienta |
| Modelo de datos | Funciona con o sin Ubicaciones | Requiere **Ubicaciones** (Pro) |
| Ideal para | Herramientas de SCA donde un nombre+versión de paquete es la identidad | Herramientas web/DAST y SCA bajo el modelo de Ubicaciones, donde la URL o la dependencia exacta es la identidad |

Para una instancia nueva que use el modelo de datos de Ubicaciones, Ubicaciones globales es el sucesor más preciso de Componente global: identifica las dependencias por la Package URL exacta y, además, deduplica Hallazgos basados en URL. Componente global sigue estando disponible sin cambios para herramientas en las que el nombre y la versión del componente sean la identidad que se desea usar.

## Visibilidad entre Productos

Dado que la coincidencia por Ubicaciones globales cruza los límites entre Productos, el Hallazgo original de una cadena de duplicados puede estar en un Producto al que el usuario que visualiza el duplicado no tiene permiso de acceso.

En ese caso, el Hallazgo es visible y se etiqueta como duplicado, pero el usuario no podrá abrir ni navegar al original. Tenga esto en cuenta antes de habilitar Ubicaciones globales en herramientas cuyos Hallazgos sean sensibles a los controles de acceso a nivel de Producto.

## Revertir

Para dejar de usar Ubicaciones globales en una herramienta determinada, abra su configuración de deduplicación y cambie el algoritmo de nuevo a una de las opciones con alcance limitado.

Para la deduplicación de la **misma herramienta**:

- Código hash
- ID único de la herramienta
- ID único de la herramienta o código hash

Para la deduplicación **entre herramientas**:

- Código hash
- Deshabilitado

Cambiar el algoritmo desencadena un recálculo en segundo plano de los hashes de deduplicación para los Hallazgos existentes de la herramienta.
