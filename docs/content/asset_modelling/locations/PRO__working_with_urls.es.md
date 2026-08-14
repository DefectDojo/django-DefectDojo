---
title: Trabajar con URLs
description: Uso cotidiano de URL Locations como reemplazo de Endpoints
audience: pro
weight: 4
---

Las URL Locations son el reemplazo funcional del modelo heredado de Endpoints. Almacenan los mismos campos con forma de URL a los que está acostumbrado — `protocol`, `host`, `port`, `path`, `query`, `fragment` — y cumplen el mismo rol: identificar *dónde* vive un Hallazgo de aplicación web.

Esta página cubre qué cambia cuando empieza a usar las URL Locations en el día a día, las nuevas superficies de interfaz y los endpoints de la API que debe usar en lugar de la API heredada de Endpoint.

## El subtipo URL

Toda URL es una Location. Eso significa que una URL tiene a la vez:

- Los campos estructurados de la URL (`protocol`, `user_info`, `host`, `port`, `path`, `query`, `fragment`, además de un `hash` usado para la deduplicación).
- Los campos compartidos de Location (`location_type="url"`, una cadena canónica `location_value` para visualización y búsqueda, etiquetas, etiquetas heredadas, metadatos y enlaces de Reference hacia Assets y Findings).

Cuando crea o carga una URL, DefectDojo la analiza en los campos estructurados y escribe tanto la fila de URL como su fila de Location padre en una única transacción. La deduplicación de URL es de coincidencia exacta entre los campos estructurados: dos URLs se consideran iguales si cada componente coincide, con el colapso estándar de puerto predeterminado (`http://example.com:80/` y `http://example.com/` se resuelven en la misma URL).

## En la interfaz de Pro

Cuando la función Locations está habilitada, la navegación expone:

- **Locations / All** — Una lista de todas las Locations de la instancia, tanto del subtipo URL como del subtipo Dependency. Filtre por tipo, estado, Asset, Finding o etiqueta.
- **Locations / URLs** — Una lista limitada solo a las URL Locations. Es el equivalente más cercano a la antigua página de Endpoints.
- **New URL** — Un formulario para crear una única URL con campos estructurados, etiquetas y asociaciones opcionales con Assets/Findings.
- **Locations en un Asset** — Desde cualquier Asset, la pestaña **Locations** muestra las URLs y Dependencies adjuntas a ese Asset, con conteos de estado y acciones rápidas.

Se conservan los flujos de trabajo comunes de la interfaz de Endpoints:

- **Actualizaciones de estado en bloque.** Seleccione varias URL Locations y aplique un estado (Activo, Mitigado, Falso positivo, Riesgo aceptado, Fuera de alcance) a sus referencias de Finding en una sola acción.
- **Agregar URLs existentes a un Asset.** Use **Add Existing** en la pestaña Locations de un Asset para vincular URLs que ya están en el sistema en lugar de crear duplicados.
- **Etiquetas.** Las etiquetas aplicadas a una URL Location se propagan como etiquetas heredadas en los Findings que la referencian, de la misma manera que antes lo hacían las etiquetas de Endpoint.

## Modelo de estados

Las URL Locations usan las mismas etiquetas de estado único que todas las demás Locations:

| Estado | Significado |
| --- | --- |
| **Activo** | El Hallazgo en esta URL está abierto. |
| **Mitigado** | El Hallazgo se ha remediado para esta URL. |
| **Falso positivo** | El Hallazgo no es una vulnerabilidad real para esta URL. |
| **Riesgo aceptado** | El Hallazgo se reconoce pero se acepta en esta URL. |
| **Fuera de alcance** | Esta URL está excluida del Engagement. |

Tenga en cuenta que el antiguo modelo de Endpoint Status permitía múltiples indicadores simultáneamente (por ejemplo, `mitigated=True` y `false_positive=True`). Las Locations aplican un solo estado a la vez. Si migró desde Endpoints, se conservó el indicador más específico (vea la tabla de mapeo en [Migrating from Endpoints](../pro__migrating_from_endpoints)).

Las Asset References usan un estado más simple: solo **Activo** o **Mitigado**, ya que el estado a nivel de Asset no necesita el detalle de auditoría.

## API REST

Use estos endpoints en lugar de la API heredada de Endpoint:

| Tarea | Endpoint |
| --- | --- |
| Listar URLs | `GET /api/v2/urls/` |
| Crear una URL | `POST /api/v2/urls/` |
| Actualizar las etiquetas o metadatos de una URL | `PATCH /api/v2/urls/{id}/` |
| Listar todas las Locations (URLs + Dependencies) | `GET /api/v2/location/?location_type=url` |
| Vincular una URL con un Finding | `POST /api/v2/location_findings/` |
| Vincular una URL con un Asset | `POST /api/v2/location_Assets/` |
| Actualizar el estado de un vínculo de Finding | `PATCH /api/v2/location_findings/{id}/` |
| Eliminar un vínculo de Finding | `DELETE /api/v2/location_findings/{id}/` |

Los filtros en `/api/v2/urls/` incluyen los campos estructurados de la URL además de `tag(s)`, `has_tags`, `Asset`, y ordenación por `host`, `Asset` o conteo de Hallazgos activos.

El endpoint heredado `/api/v2/endpoints/` sigue sirviendo tráfico de **lectura** mediante una capa de compatibilidad — vea [Migrating from Endpoints](../pro__migrating_from_endpoints) para saber qué se conserva y en qué difiere la capa del comportamiento original. Las **escrituras** en los endpoints heredados devuelven `403` y deben moverse a los endpoints anteriores.

## Importar URLs desde escaneos

Las importaciones de escáneres crean URL Locations automáticamente. Cuando un parser emite una URL para un Hallazgo (de la misma manera en que antes emitía un Endpoint), el importador:

1. Busca una URL existente con campos estructurados coincidentes, o crea una.
2. Crea una Finding Reference que vincula el Hallazgo con la URL con estado **Activo**.
3. Crea (o reutiliza) una Asset Reference para que la URL también aparezca en el Asset padre.

Los parsers de DefectDojo que antes creaban Endpoints se han actualizado para crear Locations automáticamente en Pro.

## Comportamientos que difieren

Vale la pena señalar algunos pequeños cambios de comportamiento:

- **Un estado por par URL/Finding.** Como se describió anteriormente, el modelo de múltiples indicadores de Endpoint_Status se reduce a un único estado. Los flujos de trabajo que alternaban indicadores de forma independiente deben elegir una sola transición.
- **Las etiquetas viven en la Location, no en la URL.** El subtipo URL no lleva su propio conjunto de etiquetas; las etiquetas pertenecen a la Location padre. Si lee una URL a través de la API, el campo `tags` proviene de `location.tags`.
- **La deduplicación es por URL canónica, no por Asset.** Dos Assets que tienen la misma URL comparten una única URL Location subyacente y la referencian dos veces (una Asset Reference cada uno). Esto es intencional y es lo que permite la generación de informes entre Assets.
- **El campo `endpoints` en los Findings.** Cuando la función está activada, este campo en la API de Finding sigue devolviendo filas, pero se proyectan a partir de URL Locations en lugar de la tabla de Endpoint. Trátelo como de solo lectura y escriba a través de `/api/v2/location_findings/` en su lugar.
