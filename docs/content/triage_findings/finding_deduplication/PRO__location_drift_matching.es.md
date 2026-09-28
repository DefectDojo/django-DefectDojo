---
title: Coincidencia por desplazamiento de ubicación
description: 'Rastree los hallazgos a medida que sus ubicaciones cambian entre reimportaciones:
  los desplazamientos de línea, los renombrados de archivo, los cambios de URL y los
  cambios de versión de dependencias ya no cierran ni recrean hallazgos'
weight: 6
audience: pro
---

**Coincidencia por desplazamiento de ubicación** permite que la reimportación reconozca un hallazgo cuya *ubicación* cambió como el **mismo hallazgo**. Sin ella, la reimportación compara los hallazgos mediante un hash de identidad exacto que incluye campos de ubicación, de modo que cualquier cambio de ubicación cierra el hallazgo anterior y crea uno nuevo idéntico:

- Un commit desplaza el código y cambia el **número de línea** del hallazgo.
- Una refactorización **renombra o mueve el archivo**.
- La **URL, el puerto o el host** de una aplicación web cambian entre escaneos DAST.
- Un **cambio de versión** de una dependencia modifica la versión del paquete vulnerable que reporta una herramienta SCA.

Cada uno de estos casos producía antes un hallazgo cerrado más un hallazgo "nuevo" — perdiendo el estado, las notas, el reloj de SLA, la aceptación de riesgo y el vínculo con JIRA del original, y generando ruido falso de "nuevo hallazgo crítico". Con la coincidencia por desplazamiento de ubicación habilitada, se mantiene un único hallazgo en su lugar: su ubicación se actualiza a partir del último escaneo y se conserva su historial.

> La coincidencia por desplazamiento de ubicación es una función de DefectDojo Pro. Está **deshabilitada de forma predeterminada** y se habilita por herramienta de seguridad.

## Habilitación del seguimiento de ubicación

El seguimiento de ubicación se configura por herramienta en:
**Configuración > Flujo de trabajo de hallazgos > Deduplicación en reimportación** (**Configuración > Configuración de Pro > Configuración de deduplicación > Deduplicación en reimportación** en instancias que aún usan el diseño de menú anterior)

1. Seleccione la **Herramienta de seguridad**.
2. Establezca el **Algoritmo de deduplicación** en **Hash Code**. El seguimiento de ubicación se aplica únicamente al algoritmo Hash Code: las herramientas con un **Unique ID From Tool** confiable ya rastrean el movimiento mediante sus ID estables y no lo necesitan.
3. Habilite **Rastrear hallazgos a medida que cambian las ubicaciones**.

Guardar la configuración activa automáticamente un nuevo cálculo de hash en segundo plano para los hallazgos existentes de la herramienta (consulte [Habilitación en datos existentes](#enabling-on-existing-data-upgrades) más abajo), de modo que los hallazgos importados antes de activar la opción participan de inmediato.

## Cómo funciona la coincidencia

Con el seguimiento habilitado, la coincidencia de reimportación ocurre en dos etapas:

1. **Identidad estable.** El hash de reimportación se calcula *sin* los campos de ubicación volátiles (línea, ruta del archivo, descripción, nombre/versión del componente, endpoints), de modo que la identidad de un hallazgo captura *qué* es el hallazgo, no *dónde* se encuentra actualmente. Los hallazgos que no se movieron siguen coincidiendo de forma exacta, primero, y nunca se ven alterados.
2. **Emparejamiento por evidencia.** Dentro de cada grupo de hallazgos que comparten una identidad estable, un comparador de ubicación empareja los hallazgos entrantes con los existentes usando evidencia de ubicación, en pasadas deterministas de la más fuerte a la más débil. Cada hallazgo se dirige exactamente a un comparador según los datos de ubicación que contenga.

### Hallazgos de código (SAST)

| Pass | Pairs when | Notes |
|------|-----------|-------|
| Exacta | Mismo archivo y línea | Siempre gana; un vecino que se movió nunca puede "robar" la coincidencia de un hallazgo que no se movió |
| Flujo de datos | Mismos objetos de origen/destino (`sast_source_object` / `sast_sink_object`) | Para herramientas que reportan flujo de datos; inmune a la renumeración de líneas |
| Línea más cercana | Mismo archivo, número de línea más cercano | Codiciosa, de la más cercana en adelante; solo dentro del mismo archivo |
| Renombrado de archivo | Archivo distinto | Solo cuando queda exactamente **un** hallazgo entrante y **uno** existente: la ambigüedad falla de forma segura |

### Hallazgos de URL (DAST)

| Pass | Pairs when |
|------|-----------|
| Exacta | Conjunto de endpoints idéntico |
| Desplazamiento del conjunto de endpoints | Conjuntos de endpoints superpuestos (endpoints agregados/eliminados) |
| Cambio de puerto | Mismo host y ruta, puerto distinto |
| Desplazamiento de ruta | Mismo host, ruta similar (similitud de segmento mutuamente óptima) |
| Cambio de host | Host distinto: solo como emparejamiento 1×1 sin ambigüedad, con una protección para DNS comodín |

### Hallazgos de dependencias (SCA)

| Pass | Pairs when |
|------|-----------|
| Exacta | Mismo paquete, versión y manifiesto |
| Cambio de versión | Mismo paquete, versión distinta |
| Cambio de manifiesto | Mismo paquete, ruta de lockfile/manifiesto distinta |

Cuando el mismo paquete vulnerable aparece en **varios manifiestos**, el hallazgo de cada manifiesto se rastrea de forma independiente: un cambio de versión en un lockfile nunca absorbe el hallazgo de otro.

### Recalificaciones de severidad

Las herramientas de seguridad recalifican las severidades a medida que evolucionan sus motores de reglas. Con el seguimiento habilitado, un cambio de severidad reportado por la herramienta **no** divide la identidad del hallazgo: el hallazgo coincide y su severidad se actualiza a partir del escaneo, a menos que una persona haya vuelto a triar la severidad manualmente, en cuyo caso el valor humano siempre prevalece (ver más abajo).

## Qué se conserva y qué se actualiza

Un hallazgo emparejado por desplazamiento conserva todo lo importante de su ciclo de vida: estado, notas, aceptación de riesgo, fechas de SLA, vínculo con JIRA y su ID de hallazgo.

Sus **campos de ubicación** (ruta del archivo, línea, campos de flujo de datos, endpoints, versión del componente) se actualizan a partir del escaneo entrante.

Sus **campos descriptivos** (título, descripción, severidad, versión del componente) se actualizan a partir del escaneo *solo cuando el escaneo todavía es su propietario*: DefectDojo registra un resumen (digest) de cada campo tal como lo escribió por última vez la importación o reimportación. Si el valor actual todavía coincide con ese digest, fue la herramienta quien lo escribió y el escaneo puede actualizarlo; si una persona editó el campo después, el valor humano se conserva de forma permanente. Los hallazgos creados antes de esta función no tienen digests y se tratan como de propiedad humana: la reimportación nunca sobrescribirá sus campos descriptivos. La única excepción es la **versión del componente**, que es telemetría del escaneo que las personas prácticamente nunca editan a mano: se actualiza incluso sin un digest, de modo que los hallazgos SCA migrados siguen recibiendo actualizaciones de versión.

### La identidad siempre sigue el reporte de la herramienta

Cuando se actualiza un hallazgo emparejado, sus hashes de identidad almacenados se **adoptan a partir de los valores del escaneo entrante**, nunca se recalculan a partir de los campos actuales del hallazgo. Esta distinción importa: los campos del hallazgo después de una actualización son una *combinación* de valores del escaneo y ediciones humanas, y un hash calculado a partir de esa combinación contendría valores que ningún escaneo volverá a reportar jamás, rompiendo silenciosamente toda futura reimportación de ese hallazgo. La adopción garantiza que una persona que renombra un hallazgo, vuelve a triar su severidad o edita su descripción nunca pueda romper su capacidad de coincidir con el próximo escaneo.

## Historial de ubicación

En **Ubicaciones** (Beta), cada coincidencia por desplazamiento registra dónde solía vivir el hallazgo: la ubicación de código fuente, URL o versión de dependencia reemplazada se conserva como referencia en el hallazgo, marcada con el momento y el motivo del movimiento. La línea de tiempo de ubicación del hallazgo ("este hallazgo vivió en `auth.py:42`, luego en `auth.py:57`, luego en `session.py:31`") es visible en la página del hallazgo. Consulte [Ubicaciones de código fuente](/asset_modelling/locations/pro__source_code_locations/).

La coincidencia por desplazamiento de ubicación en sí funciona **con o sin** la función Ubicaciones: el emparejamiento se basa en los propios campos y endpoints del hallazgo, de modo que los hallazgos sobreviven al movimiento en cualquier caso. Ubicaciones añade el historial registrado y visible como complemento. El historial comienza a registrarse desde el momento en que se habilita Ubicaciones: los movimientos anteriores se aplicaron pero no se registraron.

## Habilitación en datos existentes (actualizaciones)

La función está diseñada para automigrarse:

- **Nada cambia hasta que usted lo active.** Con la opción desactivada, los hashes de reimportación se calculan exactamente como antes.
- **Guardar la opción vuelve a calcular el hash de los hallazgos existentes.** El trabajo en segundo plano recalcula los hashes de reimportación almacenados de la herramienta con la nueva identidad (sin ubicación) y crea los registros de hallazgos Pro que falten para los datos migrados desde open-source. Una vez que finaliza, los hallazgos antiguos y nuevos hablan el mismo lenguaje de identidad: un hallazgo importado hace meses se rastrea exactamente igual que uno importado ayer.
- **Habilítelo entre ejecuciones de escaneo en instancias grandes.** El nuevo cálculo de hash es un trabajo en segundo plano sobre toda la población de hallazgos de la herramienta. Una reimportación que llegue mientras está en curso puede ver una mezcla de hashes antiguos y nuevos y agitar una vez la porción no procesada. Active la opción en un momento tranquilo y deje que el trabajo termine antes de la próxima reimportación programada.
- **Títulos editados a mano.** El nuevo cálculo de hash por activación se realiza a partir de los valores actuales de la base de datos. Todo campo comúnmente editado queda excluido de la identidad rastreada (las ediciones de severidad de hecho se *sanan* con el nuevo cálculo), pero si una persona renombró el **título** de un hallazgo (y el título es un campo de hash para esa herramienta), ese hallazgo en particular se agitará una vez en su próxima reimportación antes de estabilizarse.

## Elección de los campos de hash para herramientas rastreadas

El seguimiento de ubicación elimina automáticamente los campos de ubicación volátiles del hash de reimportación: usted no necesita quitar `line` ni `file_path` de la configuración de hash de una herramienta manualmente. Dos configuraciones merecen atención:

- **Configuraciones totalmente volátiles.** Si los campos de hash de una herramienta son *enteramente* campos de ubicación (por ejemplo, solo `file_path` + `line`), al eliminarlos no queda nada y el hash recae en la identidad heredada de título+CWE. La coincidencia sigue funcionando (las pasadas de evidencia aportan la discriminación), pero la identidad es mucho más burda. Prefiera configuraciones que conserven al menos un campo de contenido estable.
- **Ubicación incrustada en campos estables.** Las exclusiones de campos no ayudan cuando los datos de ubicación se ocultan *dentro* de un campo que debe permanecer en el hash. Una herramienta que titula los hallazgos "SQL Injection in queries.py:42" cambia su título en cada movimiento de línea: la identidad se divide y el seguimiento no puede ver el par. Para esas herramientas, elija campos de hash que eviten el campo filtrador; **CWE + Content Fingerprint** es la combinación más sólida (consulte [Content Fingerprint](/triage_findings/finding_deduplication/pro__deduplication_tuning/#content-fingerprint)).

## Interacción con la deduplicación

El seguimiento de ubicación es una función de **reimportación**: la deduplicación de la misma herramienta y la deduplicación entre herramientas no cambian: sus hashes se calculan exactamente como antes, y las exclusiones nunca se les aplican. Dos integraciones deliberadas:

- **Los cambios de versión ya no bloquean la deduplicación de dependencias.** La barrera de ubicación de la deduplicación normalmente exige que dos hallazgos SCA hagan referencia a la *misma* versión de paquete. Para las herramientas con seguimiento habilitado, basta con una identidad de paquete compartida (ecosistema + nombre del paquete, comparando el espacio de nombres cuando ambos lados lo tienen), coherente con el hecho de que la reimportación trata un cambio de versión como el mismo hallazgo. Esto se aplica únicamente a la deduplicación de la misma herramienta bajo Ubicaciones.
- **Entradas de identidad limpias.** Debido a que los hallazgos emparejados adoptan los hashes reportados por el escaneo, los valores que consume la deduplicación siempre reflejan lo último reportado por la herramienta: las ediciones humanas ya no pueden contaminarlos.

## Consolidación de la rotación histórica

Las instancias que operaron durante años sin seguimiento acumulan cadenas de cierre y recreación: el mismo hallazgo cerrado y reabierto como un registro nuevo cada vez que se movía. Un comando de administración encuentra esas cadenas (enlazadas paso a paso por los mismos comparadores, con una protección de superposición de tiempo de vida para que los hallazgos que realmente coexistieron nunca se fusionen) y consolida cada cadena en su hallazgo más reciente, marcando las copias más antiguas como duplicados del superviviente:

```bash
# Dry run — reports what would be consolidated, changes nothing
./manage.py consolidate_location_churn --product <id>

# Apply, with a confirmation prompt
./manage.py consolidate_location_churn --product <id> --apply
```

El comando es dry-run de forma predeterminada, nunca se ejecuta automáticamente y puede acotarse con `--test` o `--product`. Bajo Ubicaciones, el historial de ubicación del superviviente se reconstruye a partir de la cadena.

## Salvaguardas y límites

- **Las coincidencias exactas siempre ganan.** Un hallazgo que no se movió se empareja de forma exacta antes de que se ejecute cualquier pasada difusa; los que se movieron nunca pueden robarle su coincidencia.
- **La ambigüedad falla de forma segura.** Los renombrados de archivo y los cambios de host se emparejan solo cuando queda exactamente un candidato en cada lado. Dos hallazgos que desaparecieron mientras aparecían dos nuevos permanecen sin emparejar en lugar de adivinar.
- **Los grupos muy grandes se degradan de forma controlada.** Si un único bucket de identidad supera el límite de emparejamiento (40,000 comparaciones), la coincidencia se degrada a solo exacta para ese bucket en lugar de consumir tiempo ilimitado.
- **Compensación aceptada:** las pasadas 1×1 de renombrado/cambio de host pueden crear una falsa continuidad cuando un hallazgo desaparece y aparece un hallazgo no relacionado con la misma identidad estable en la misma reimportación. Este es el precio deliberado de rastrear renombrados; la identidad estable (misma herramienta, título, CWE, severidad...) acota cuán equivocado puede ser el emparejamiento.

## Actualización de ubicación sin la opción activada

Independientemente del seguimiento de ubicación, la reimportación mantiene actualizada la ubicación de todo hallazgo emparejado en **todos** los algoritmos: un hallazgo emparejado por Unique ID From Tool (o cualquier otro algoritmo) actualiza sus campos `line`, `file_path`, los campos de flujo de datos y `component_version` a partir del reporte entrante, y los endpoints reportados se adjuntan mientras que los que desaparecieron se mitigan. Los valores que un escaneo omite nunca sobrescriben los datos existentes, y una versión de componente fijada manualmente se conserva. Esto cierra la brecha de larga data en la que los hallazgos SAST emparejados por uid mostraban para siempre el número de línea de su primera importación. Puede deshabilitarse en toda la instancia con `DD_REIMPORT_REFRESH_LOCATION_FIELDS=False`.
