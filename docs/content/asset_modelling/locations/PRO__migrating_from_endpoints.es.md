---
title: Migración desde Endpoints
description: Qué sucede cuando se migran los datos existentes de Endpoint a Locations
audience: pro
weight: 3
---

Cuando habilita Locations en una instancia existente de DefectDojo Pro, los datos ya almacenados como Endpoints deben trasladarse al nuevo modelo de Locations. Esta página describe la migración, qué conserva y cómo se comporta la API heredada de Endpoint una vez ejecutada la migración.

Tenga en cuenta que la migración es **unidireccional**. No existe una ruta de reversión automatizada que vuelva a crear Endpoints a partir de Locations.

## Qué hace la migración

Para cada Endpoint existente, la migración hará lo siguiente:

1. **Crea una URL Location** (o reutiliza una existente) usando los campos `protocol`, `userinfo`, `host`, `port`, `path`, `query` y `fragment` del Endpoint. La nueva URL se adjunta automáticamente a un objeto `Location` padre.
2. **Traslada las etiquetas.** Cada etiqueta del Endpoint se añade al conjunto de etiquetas de la Location.
3. **Traslada los metadatos.** Cada fila `DojoMeta` adjunta al Endpoint se redirige hacia la nueva Location.
4. **Crea una `LocationProductReference`** para que la URL aparezca bajo el Asset (Product) correcto.
5. **Crea una `LocationFindingReference` para cada `Endpoint_Status`**:

   | Indicador de Endpoint_Status | Estado resultante de la Location |
   | --- | --- |
   | `risk_accepted=True` | **Riesgo aceptado** |
   | `false_positive=True` | **Falso positivo** |
   | `out_of_scope=True` | **Fuera de alcance** |
   | `mitigated=True` | **Mitigado** |
   | (ninguno de los anteriores) | **Activo** |

   El mapeo depende del orden: gana el *primer* indicador que coincida. Esto reduce intencionalmente las antiguas combinaciones de múltiples indicadores a un único estado canónico que usan las Locations.


## Qué no hace la migración

- **No** crea Dependency Locations. Los datos de SBOM y de bibliotecas nunca existieron como Endpoints, por lo que no hay nada que la migración pueda convertir. Para poblar las Dependencies, cargue SBOMs (consulte [Working with SBOMs](../pro__working_with_sboms)) o vuelva a ejecutar los escaneos con parsers que generen datos de dependencias.
- **No** elimina las filas originales de Endpoint o Endpoint_Status. Permanecen en la base de datos para respaldar la API heredada de solo lectura. La nueva interfaz de usuario ni las importaciones las utilizan una vez habilitada la función.

## API de Endpoint después de la migración

Una vez habilitado Locations, la API heredada de Endpoint entra en un modo de **compatibilidad de lectura** diseñado para que las automatizaciones existentes sigan funcionando sin cambios de código, pero solo para el tráfico de lectura.

### Qué sigue funcionando

- `GET /api/v2/endpoints/` — Devuelve filas que *parecen* Endpoints, pero en realidad se proyectan a partir de filas de Location Product Reference combinadas con URL Locations. Los campos habituales (`protocol`, `host`, `port`, `path`, `query`, `fragment`, `tags`, `product`, `active_finding_count`) están todos presentes.
- `GET /api/v2/endpoints/{id}/` — La recuperación de un único Endpoint funciona de la misma manera. El `id` es el ID original del Endpoint y se conserva a través de la migración mediante el mapeo de Asset Reference.
- `GET /api/v2/endpoint_status/` y `GET /api/v2/endpoint_status/{id}/` — Devuelven filas proyectadas a partir de `LocationFindingReference`. Los campos booleanos heredados `mitigated`, `false_positive`, `out_of_scope` y `risk_accepted` se reconstruyen.
- El filtrado por `protocol`, `host`, `port`, `path`, `query`, `fragment`, `product` y `tag(s)` sigue funcionando.
- La acción `generate_report` en Endpoints individuales sigue funcionando.

### Qué devuelve 403

- `POST`, `PUT`, `PATCH` y `DELETE` en `/api/v2/endpoints/` y `/api/v2/endpoint_status/` devuelven todos `HTTP 403` con el cuerpo:

  > Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled

  Los clientes que escriben datos de Endpoint deben migrar a los nuevos endpoints de Reference (`POST /api/v2/location_findings/`, `POST /api/v2/location_products/`) y al endpoint de URL (`POST /api/v2/urls/`).

### Diferencias de comportamiento a tener en cuenta

Algunas cosas se comportan de forma diferente respecto a la API original de Endpoint:

- **Un único estado en lugar de indicadores.** Las Locations tienen un solo estado a la vez. Si su código dependía de que un Hallazgo fuera *a la vez* `mitigated=True` *y* `false_positive=True` simultáneamente en un Endpoint_Status, eso ya no se puede representar: la migración elige el indicador de mayor prioridad (el orden que se muestra en la tabla anterior).
- **Campo `endpoint` en Endpoint_Status.** El campo heredado `endpoint` se reconstruye buscando el Asset Reference correspondiente. En casos excepcionales en los que el Asset de un Hallazgo ya no coincide con los Asset References de su Location, este campo puede ser nulo.
- **Paginación y ordenación.** Los campos de ordenación disponibles en la capa de compatibilidad de lectura son `host`, `product`, `id` y `active_finding_count`. Si su cliente ordena por otro campo, cambie a uno de estos o migre a los nuevos endpoints de Locations.

## Etiquetas y metadatos

Las etiquetas aplicadas a los Endpoints se convierten en etiquetas del objeto Location (no del subtipo URL). Los filtros basados en etiquetas de la API heredada siguen coincidiendo.

Los metadatos del Endpoint se redirigen hacia la Location durante la migración. Las automatizaciones existentes que leen metadatos a través de `/api/v2/endpoint_meta/` deberían seguir funcionando; los metadatos nuevos deben escribirse a través de los endpoints de Location.
