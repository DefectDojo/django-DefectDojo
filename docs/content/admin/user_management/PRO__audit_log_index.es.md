---
title: Registro de auditoría
description: Cada acción de creación, actualización y eliminación que DefectDojo registra
  en su registro de auditoría, además de qué se captura y cómo configurar la retención.
draft: false
weight: 4
---

DefectDojo registra un rastro de auditoría de los cambios en sus datos.  Cada objeto rastreado registra automáticamente eventos de **creación**, **actualización** y **eliminación**, y las tablas de relación (muchos a muchos) registran eventos de **agregado** y **eliminación**.

## Cómo funciona

El rastreo de auditoría está impulsado por disparadores de base de datos registrados por modelo. Para cada objeto rastreado, pueden dispararse tres tipos de eventos:

| Tipo de evento | Cuándo se dispara                                                                 | Acción     |
| ------------- | ----------------------------------------------------------------------------- | ---------- |
| `InsertEvent` | Se crea un nuevo registro                                                        | **Creación** |
| `UpdateEvent` | Un registro cambia — solo cuando el valor de un campo real realmente cambia               | **Actualización** |
| `DeleteEvent` | Se elimina un registro                                                            | **Eliminación** |

Las tablas de relación muchos a muchos (etiquetas, revisores, rangos de IP de firewall) rastrean solo **agregado** (`InsertEvent`) y **eliminación** (`DeleteEvent`) — no existe una "actualización" para una fila de relación.

### Qué se captura con cada evento

- **Quién** — el usuario que realiza la acción, tomado del contexto de la solicitud.
- **Cuándo** — una marca de tiempo.
- **IP de origen** — la dirección remota, respetando las cadenas de proxy `X-Forwarded-For`.
- **Instantánea antes/después** — los valores completos de los campos del registro.
- **Contexto / etiqueta** — agrupa los eventos originados en la misma solicitud. La etiqueta `initial_backfill` marca los registros históricos importados cuando se habilitó el rastreo por primera vez.

Los eventos producidos por trabajos en segundo plano se vuelven a vincular al contexto de la solicitud de origen, de modo que una acción completada de forma asíncrona sigue atribuyéndose al usuario que la originó.

## Core (Open Source) — acciones rastreadas

| Objeto                         | Creación | Actualización | Eliminación | Notas                                          |
| ------------------------------ | :----: | :----: | :----: | ---------------------------------------------- |
| Usuario                           |   ✅   |   ✅   |   ✅   | `password` excluido de las instantáneas             |
| Tipo de producto                   |   ✅   |   ✅   |   ✅   |                                                |
| Producto                        |   ✅   |   ✅   |   ✅   |                                                |
| Compromiso                     |   ✅   |   ✅   |   ✅   |                                                |
| Test                            |   ✅   |   ✅   |   ✅   |                                                |
| Hallazgo                        |   ✅   |   ✅   |   ✅   |                                                |
| Grupo de hallazgos                  |   ✅   |   ✅   |   ✅   |                                                |
| Plantilla de hallazgo               |   ✅   |   ✅   |   ✅   |                                                |
| Aceptación de riesgo                |   ✅   |   ✅   |   ✅   |                                                |
| Endpoint                       |   ✅   |   ✅   |   ✅   |                                                |
| Ubicación                       |   ✅   |   ✅   |   ✅   |                                                |
| URL                            |   ✅   |   ✅   |   ✅   |                                                |
| Webhook de notificación           |   ✅   |   ✅   |   ✅   | `header_name` / `header_value` excluidos (secretos) |

### Core — eventos de relación (agregado / eliminación)

| Relación                       | Agregado | Eliminación |
| ---------------------------------- | :-: | :----: |
| Hallazgo → Revisores                | ✅  |   ✅   |
| Hallazgo → Etiquetas                     | ✅  |   ✅   |
| Hallazgo → Etiquetas heredadas           | ✅  |   ✅   |
| Producto → Etiquetas                     | ✅  |   ✅   |
| Compromiso → Etiquetas                  | ✅  |   ✅   |
| Compromiso → Etiquetas heredadas        | ✅  |   ✅   |
| Test → Etiquetas                        | ✅  |   ✅   |
| Test → Etiquetas heredadas              | ✅  |   ✅   |
| Endpoint → Etiquetas                    | ✅  |   ✅   |
| Endpoint → Etiquetas heredadas          | ✅  |   ✅   |
| Plantilla de hallazgo → Etiquetas            | ✅  |   ✅   |
| Análisis de aplicaciones (Tecnología) → Etiquetas   | ✅  |   ✅   |
| Objetos/Producto → Etiquetas             | ✅  |   ✅   |

## Pro — acciones rastreadas

| Objeto                            | Creación | Actualización | Eliminación | Notas                          |
| --------------------------------- | :----: | :----: | :----: | ------------------------------ |
| Hallazgo mejorado                  |   ✅   |   ✅   |   ✅   | Complemento Pro de Hallazgo       |
| Regla                              |   ✅   |   ✅   |   ✅   | Motor de reglas                   |
| Acción de regla                       |   ✅   |   ✅   |   ✅   |                                |
| Condición de acción de regla             |   ✅   |   ✅   |   ✅   |                                |
| Entrada de filtro de regla                 |   ✅   |   ✅   |   ✅   |                                |
| Operación del motor de reglas            |   ✅   |   ✅   |   ✅   |                                |
| Mensaje de operación del motor de reglas    |   ✅   |   ✅   |   ✅   |                                |
| Tarea programada                    |   ✅   |   ✅   |   ✅   |                                |
| Ejecución de tarea programada                |   ✅   |   ✅   |   ✅   |                                |
| Política de mitigación                 |   ✅   |   ✅   |   ✅   |                                |
| Ajuste configurable                   |   ✅   |   ✅   |   ✅   | Cambios de configuración del sistema   |
| Estado de indicador de función                |   ✅   |   ✅   |   ✅   | Activaciones/desactivaciones + fijaciones del sistema |
| Definición de indicador de función           |   ✅   |   ✅   |   ✅   | Metadatos / sincronización de registro |
| Firewall en la nube                    |   ✅   |   ✅   |   ✅   | Campo `locked` excluido        |
| Máscara de IP de firewall                  |   ✅   |   ✅   |   ✅   |                                |

### Pro — RBAC / permisos

| Objeto                        | Creación | Actualización | Eliminación |
| ----------------------------- | :----: | :----: | :----: |
| Grupo                         |   ✅   |   ✅   |   ✅   |
| Rol                           |   ✅   |   ✅   |   ✅   |
| Membresía de grupo              |   ✅   |   ✅   |   ✅   |
| Rol global                   |   ✅   |   ✅   |   ✅   |
| Asignación de grupo a producto      |   ✅   |   ✅   |   ✅   |
| Asignación de grupo a tipo de producto |   ✅   |   ✅   |   ✅   |
| Miembro de producto            |   ✅   |   ✅   |   ✅   |
| Miembro de tipo de producto           |   ✅   |   ✅   |   ✅   |

### Pro — eventos de relación (agregado / eliminación)

| Relación                | Agregado | Eliminación |
| --------------------------- | :-: | :----: |
| Firewall en la nube → Rangos de IP  | ✅  |   ✅   |

## Configuración y retención (controles on-premise)

| Ajuste              | Variable de entorno                  | Predeterminado            | Efecto                                                              |
| -------------------- | ------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Habilitar el registro de auditoría | `DD_ENABLE_AUDITLOG`                  | `True`             | Cuando es `False`, todos los disparadores de historial se deshabilitan y no se registra ningún evento |
| Período de retención     | `DD_AUDITLOG_FLUSH_RETENTION_PERIOD`  | `-1` (nunca purgar) | Meses de historial a conservar; los eventos más antiguos se eliminan por lotes mediante el trabajo de purga  |
| Tamaño de lote de purga     | `DD_AUDITLOG_FLUSH_BATCH_SIZE`        | `1000`             | Filas eliminadas por lote durante la limpieza                              |
| Máximo de lotes de purga    | `DD_AUDITLOG_FLUSH_MAX_BATCHES`       | `100`              | Límite en la cantidad de lotes por ejecución de purga                        |

## Notas y limitaciones

- **Los secretos nunca se capturan.** Las contraseñas de usuario y los valores de encabezado de los webhooks de notificación se excluyen explícitamente de las instantáneas de eventos.
- **Las actualizaciones solo se registran ante un cambio real.** Un guardado que no altera ningún valor de campo no genera ningún evento de actualización; los campos autogestionados, como `last_updated` por sí solo, no disparan uno.
- **Los eventos de autenticación no se capturan aquí.** Solo cambios de datos. El inicio de sesión, el cierre de sesión y los intentos fallidos de inicio de sesión se gestionan por separado y no forman parte de este registro de auditoría.
