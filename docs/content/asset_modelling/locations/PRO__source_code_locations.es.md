---
title: Ubicaciones de código fuente
description: Las ubicaciones de código modelan dónde vive en el código fuente un hallazgo
  de análisis estático, y registran su historial de movimiento a medida que el código
  evoluciona
weight: 6
audience: pro
---

Las **Source Code Locations** amplían el modelo de Locations al análisis estático: junto con las URLs (DAST) y las Dependencies (SCA), una ubicación de tipo **Code** describe dónde vive en el código fuente un hallazgo SAST, identificada por su **ruta de archivo y número de línea**.

> Source Code Locations requiere la función Locations (Beta). Para habilitar Locations en su instancia, comuníquese con [support@defectdojo.com](mailto:support@defectdojo.com).

## Qué modelan

Todo hallazgo estático que reporte una ruta de archivo obtiene una ubicación de tipo Code. El valor canónico de la ubicación es `path/to/file.py:42` (o solo la ruta del archivo cuando la herramienta no reporta una línea). Como todas las Locations, las ubicaciones de código son objetos compartidos: dos Hallazgos en el mismo archivo y línea hacen referencia a la misma ubicación, y esta lleva estados de referencia por Hallazgo y por Asset.

Las ubicaciones de código están **gestionadas por el escaneo**: se crean y actualizan mediante importaciones y reimportaciones, no manualmente. No existe una acción "New Source Code Location": el escáner es la fuente de verdad de dónde viven los Hallazgos de código.

## Dónde encontrarlas

- **All Source Code** en la barra lateral enumera todas las ubicaciones de código de la instancia, con el mismo filtrado y etiquetado que las URLs y las Dependencies.
- **View Source Code** en el menú de Locations de un Asset limita la lista a ese Asset.
- La página de un Hallazgo muestra su ubicación de código actual y, cuando el Hallazgo se ha movido, su **historial de ubicación**.

## Historial de movimiento

El código fuente se mueve constantemente: los commits desplazan los números de línea, las refactorizaciones renombran archivos. Cuando [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) está habilitado para una herramienta, un Hallazgo que se mueve conserva su identidad, y sus referencias de ubicación de código registran el rastro:

- La referencia del Hallazgo a la ubicación **anterior** se mitiga y se marca con *a dónde se movió el Hallazgo* y *por qué se hizo la coincidencia* (línea más cercana, flujo de datos, cambio de nombre de archivo...).
- Se crea una referencia a la **nueva** ubicación, que permanece activa.

El resultado es una cadena de sustitución navegable — "este Hallazgo vivía en `auth.py:42`, luego en `auth.py:57`, luego en `session.py:31`" — que se representa como una línea de tiempo en la página del Hallazgo. El mismo mecanismo de historial cubre los movimientos de URL y los incrementos de versión de dependencias, de modo que los tres tipos de ubicación comparten una única interfaz de línea de tiempo.

El historial se registra desde el momento en que Locations se habilita en la instancia. Los Hallazgos que se movieron antes de ese momento conservan su ubicación actual: los saltos pasados se aplicaron pero no se registraron. Para instancias con años de historial previo a la función, el [comando de consolidación de churn](/triage_findings/finding_deduplication/pro__location_drift_matching/#consolidating-historical-churn) puede reconstruir los rastros mientras fusiona las antiguas cadenas de cierre y recreación.

## Corrección de estados

Los estados de referencia de las ubicaciones de código se mantienen fieles a la realidad mediante la reimportación en **todos** los algoritmos de coincidencia, esté o no habilitado el drift matching:

- La referencia de código actual de un Hallazgo coincidente se sincroniza en cada reimportación, de modo que un Hallazgo que se movió no deja su referencia anterior activa para siempre.
- La misma sincronización, independiente del interruptor de la función, se aplica a las referencias de dependencias: cuando la versión del paquete de un Hallazgo de SCA cambia, la referencia de la versión anterior se mitiga en lugar de permanecer activa junto a la nueva.

## Relación con los campos del Hallazgo

Los propios campos `file_path` / `line` del Hallazgo siguen siendo los valores escalares autorizados (son los que exponen los filtros, los hashes y la API); la Code Location es la vista compartida y con conteo de referencias de esa misma coordenada. La reimportación actualiza los valores escalares a partir del último escaneo y el mecanismo de ubicaciones deriva las ubicaciones a partir de ellos: los dos no pueden desalinearse.
