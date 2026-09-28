---
title: Reimportación
description: Aprenda a importar datos manualmente, mediante la API o a través de un
  conector
weight: 2
aliases:
- /es/en/connecting_your_tools/import_scan_files/using_reimport
---

Cuando se crea un Test en DefectDojo (ya sea de antemano o al importar un archivo de escaneo), el Test puede extenderse con nuevos datos de Hallazgos.

Por ejemplo, supongamos que tiene una canalización de CI/CD diseñada para enviar un nuevo informe a DefectDojo todos los días. En lugar de crear un nuevo Test o Compromiso para cada "ejecución" de la canalización, podría hacer que cada informe fluya hacia el mismo Test usando **Reimport**.

## Reimport: resumen del proceso

La reimportación de datos no reemplaza ningún dato antiguo en el Test; en cambio, compara el archivo de escaneo entrante con los datos de escaneo existentes en un test para tomar decisiones informadas:

* Según el archivo más reciente, ¿qué vulnerabilidades siguen presentes?
* ¿Qué vulnerabilidades ya no están presentes?
* ¿Qué vulnerabilidades se habían resuelto anteriormente, pero han vuelto a aparecer?

El Test hará un seguimiento y separará cada versión de escaneo mediante el **Historial de importación**, para que pueda revisar los cambios en los Hallazgos de su Test a lo largo del tiempo.

![image](images/using_reimport.png)

## Lógica de Reimport: crear, ignorar, cerrar o reabrir

Al usar Reimport, DefectDojo comparará los datos de escaneo entrantes con los datos de escaneo existentes, y luego aplicará cambios a los Hallazgos contenidos en su Test de la siguiente manera:

### Crear Hallazgos

Cualquier vulnerabilidad que no estuviera incluida en la importación anterior se agregará automáticamente al Test como un nuevo Hallazgo.

### Ignorar Hallazgos existentes

Si algún Hallazgo entrante coincide con Hallazgos ya existentes, los Hallazgos entrantes se descartarán en lugar de registrarse como Duplicados. Estos Hallazgos ya han sido registrados, no es necesario agregar un nuevo objeto Hallazgo. La página del Test mostrará estos Hallazgos como **Left Untouched**.

### Campos fix_available y fix_version

Si algún Hallazgo entrante coincide con Hallazgos ya existentes, se verifica si los campos `fix_available` y `fix_version` del Hallazgo entrante difieren, y se actualizan en caso afirmativo. Estos Hallazgos ya han sido registrados, no es necesario agregar un nuevo objeto Hallazgo. La página del Test mostrará estos Hallazgos como **Left Untouched**.

### Cerrar Hallazgos

Si existen Hallazgos que ya están presentes en el Test pero que no aparecen en el informe entrante, puede optar por establecer automáticamente esos Hallazgos como Inactivo y Mitigado (suponiendo que esas vulnerabilidades se hayan resuelto desde la importación anterior). La página del Test mostrará estos Hallazgos como **Closed**.

Si **no** desea que se cierre ningún Hallazgo antiguo, puede deshabilitar este comportamiento en Reimport:

* Desmarque la casilla **Close Old Findings** si usa la interfaz
* Configure `close_old_findings` en `False` si usa la API (en este endpoint, `close_old_findings` es `True` de forma predeterminada)

**Nota sobre el alcance:** A diferencia de Import, Reimport nunca puede examinar otros Tests del Compromiso al considerar qué Hallazgos cerrar. El alcance del cierre de Hallazgos siempre se limita al Test de destino.

La función `close_old_findings` también respeta el campo `service`: solo se considerarán para el cierre los Hallazgos con un valor de `service` idéntico (o sin valor de `service`, si no se especificó ninguno).

### Reabrir Hallazgos

* Si algún Hallazgo Cerrado vuelve a aparecer en una Reimportación, se Reabrirá automáticamente. Se asume que estas vulnerabilidades han vuelto a producirse, a pesar de la mitigación anterior. La página del Test hará seguimiento de estos Hallazgos como **Reactivated**.

Si está usando un escáner sin triage, o si por algún otro motivo no desea que los Hallazgos Cerrados se reactiven, puede deshabilitar este comportamiento en Reimport:

* Configure **do_not_reactivate** en **True** si usa la API
* Marque la casilla **Do Not Reactivate** si usa la interfaz

### Comportamiento de Force Active y Force Verified

Configurar `active=true` (interfaz: **Force Active**) o `verified=true` (interfaz: **Force Verified**) en una Reimportación establecerá el estado correspondiente en todos los Hallazgos coincidentes, **incluidos los hallazgos que de otro modo estarían Inactivos por haber sido Mitigados**. Este es el mismo comportamiento de reactivación descrito anteriormente, solo que se hace explícito en cada Hallazgo entrante.

Force Active y Force Verified **no** anulan los estados que representan una decisión explícita de un usuario o del sistema sobre por qué un Hallazgo no debería estar Activo:

| Status | Does Force Active reactivate it? | Why |
|---|---|---|
| Mitigated / Closed | Sí | Igual que el comportamiento de reactivación predeterminado |
| Risk Accepted | No | El Hallazgo está Inactivo porque un usuario aceptó explícitamente el riesgo; la reimportación no debe revocar esa decisión de forma silenciosa |
| Duplicate | No | El Hallazgo está Inactivo porque la deduplicación lo marcó como duplicado de otro Hallazgo; el Hallazgo original (no el duplicado) es el que debe estar activo |
| False Positive | No | El mismo razonamiento que Risk Accepted: una decisión de triage explícita |
| Out of Scope | No | El mismo razonamiento que Risk Accepted: una decisión de triage explícita |

Si desea que un Hallazgo marcado como Risk Accepted o Duplicate vuelva a estar Activo, primero debe eliminar la Aceptación de riesgo o el marcador de Duplicado. Force Active por sí solo no lo hará.

## Cómo abrir el formulario de Reimport

Se puede acceder al formulario **Re-Import Findings** desde cualquier página de Test, en el menú desplegable **⚙️Gear**.

![image](images/using_reimport_2.png)

El **Formulario** de **Re-import Findings** **no** le permitirá importar un tipo de escaneo diferente, ni cambiar el destino de los Hallazgos que intenta cargar. Si necesita hacer alguna de esas dos cosas, deberá usar el **Import Scan Form**.

## Trabajar con el Historial de importación

El Historial de importación de un test determinado aparece bajo el encabezado **Test Overview** en la página del **Test**.

Esta tabla muestra cada Import o Reimport como una sola línea con una **marca de tiempo (Timestamp)**, junto con las columnas **Branch Tag, Build ID, Commit Hash** y **Version** si se especificaron.

![image](images/using_reimport_3.png)

### Actions

Este encabezado indica las acciones realizadas por un Import/Reimport.

* **\# created indica la cantidad de nuevos Hallazgos creados en el momento del Import/Reimport**
* **\# closed muestra la cantidad de Hallazgos que fueron cerrados por una Reimportación (por no existir en el informe entrante).**
* **\# left untouched muestra la cantidad de Hallazgos Abiertos que no cambiaron con una Reimportación (porque también existían en el informe entrante).**
* **\#** **reactivated** muestra los Hallazgos Cerrados que fueron reabiertos por una Reimportación entrante.

## Deduplicación en Reimport

Reimport decide si un elemento entrante coincide con un Hallazgo existente usando la configuración de **[Reimport Deduplication](/triage_findings/finding_deduplication/about_deduplication/)**. Esto es independiente de la "Deduplicación de la misma herramienta" y la "Deduplicación entre herramientas", que operan después de que los Hallazgos ya existen.

Si observa que Reimport cierra Hallazgos antiguos y crea Hallazgos nuevos cuando solo cambia un atributo menor (por ejemplo, un desplazamiento en el número de línea), ajuste la **Deduplicación en Reimport** de esa herramienta para usar identificadores estables que ignoren esos atributos (como Unique ID From Tool).

**DefectDojo Pro** puede resolver esto directamente para herramientas sin IDs únicos confiables: al habilitar **[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/)**, Reimport reconoce un Hallazgo cuya ubicación cambió (un desplazamiento de línea, un cambio de nombre de archivo, un cambio de URL o una actualización de versión de dependencia) como el *mismo* Hallazgo, actualizándolo en el lugar y conservando su historial de ubicación.

## Reimport mediante API - nota especial

Tenga en cuenta que el endpoint de la API /reimport puede tanto **extender un Test existente** (aplicando el método descrito en este artículo) **como crear un nuevo Test** con datos nuevos; no es necesario hacer una llamada inicial a `/import`, ni configurar un Test de antemano.

Para obtener más información sobre cómo crear una canalización de CI/CD automatizada usando DefectDojo, consulte nuestra guía [aquí](/automation/api/api-v2-docs/).
