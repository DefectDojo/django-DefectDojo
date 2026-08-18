---
title: Descripción general de Ubicaciones
description: Qué son las Ubicaciones y por qué reemplazan a los Endpoints
audience: pro
weight: 1
---

Las **Ubicaciones** son una nueva herramienta de modelado de activos en DefectDojo Pro. Reemplazan al modelo heredado de **Endpoints** y absorben los datos previos de **Componentes** (bibliotecas), lo que le da a DefectDojo una única forma polimórfica de describir *dónde* vive un Hallazgo — ya sea una URL, una dependencia de software proveniente de un **SBOM** o, en el futuro, un **ID de recurso en la nube**, una **imagen de contenedor** o un **repositorio de código**.

Las Ubicaciones deben habilitarse en su instancia antes de poder usarlas. Puede activarlas usted mismo desde la [página de Feature Flags](/admin/feature_flags/pro__feature_flags/) — no se requiere una solicitud de Soporte. Tenga en cuenta que las Ubicaciones no se pueden desactivar una vez habilitadas.

## ¿Por qué reemplazar los Endpoints?

El modelo original de Endpoints se construyó en torno a URL y direcciones IP — incluía campos de aplicación web como `protocol`, `host`, `port`, `path`, y una tabla de estado fija fuertemente acoplada a los Hallazgos. De esto se derivaron tres problemas:

1. **Fidelidad limitada.** Los Endpoints no podían describir con claridad activos que no fueran URL, como bibliotecas de terceros, imágenes de contenedor o recursos en la nube, aunque los escáneres producen cada vez más hallazgos sobre esos elementos.
2. **Límite de rendimiento.** Las filas de Endpoint_Status por Hallazgo y el esquema con forma de URL no escalaban bien con grandes volúmenes de clientes.
3. **Los Componentes eran de segunda clase.** Las bibliotecas de software existían únicamente como campos desnormalizados en un Hallazgo, por lo que una biblioteca no podía existir independientemente de una vulnerabilidad — lo que hacía imposible una gestión real de SBOM.

Las Ubicaciones resuelven los tres problemas al introducir un **objeto `Location` base** con una carga tipada, además de **subtipos** dedicados para cada forma de activo:

- **Ubicaciones de URL** — equivalente funcional de los antiguos Endpoints, con los mismos campos protocol/host/port/path/query/fragment.
- **Ubicaciones de dependencia** — bibliotecas de software identificadas mediante [Package URL (pURL)](https://github.com/package-url/purl-spec), utilizadas para modelar el contenido de un SBOM.
- **[Ubicaciones de código fuente](/asset_modelling/locations/pro__source_code_locations/)** — dónde vive en el código fuente un hallazgo de análisis estático, identificado por ruta de archivo y número de línea. Gestionadas por el escaneo, y la base para [el seguimiento de hallazgos a medida que su código se mueve](/triage_findings/finding_deduplication/pro__location_drift_matching/).

Entre los futuros tipos de Ubicación en consideración se incluyen los ID de recursos de proveedores en la nube (AWS ARN, Azure Resource ID, GCP Full Resource Name) e imágenes de contenedor (registry/repository:tag y huellas SHA256).

## Conceptos clave

### Ubicaciones y subtipos

Una **Ubicación** es el padre compartido. Contiene:

- Un `Location Type` (p. ej. `"url"`, `"dependency"`)
- Una cadena `Location Value` canónica utilizada para mostrar, buscar y deduplicar
- `Tags` y etiquetas heredadas del Activo padre
- Metadatos (pares clave/valor personalizados)

Un **subtipo** (URL o Dependency) contiene los campos estructurados específicos de ese tipo de ubicación. Las URL y las Dependencies siempre existen junto a un objeto Location padre; el `Location Value` del subtipo se genera a partir de sus campos estructurados.

### Referencias

Las Ubicaciones no están adjuntas directamente a Productos o Hallazgos. En cambio, dos objetos **Reference** las vinculan:

- **Asset References** — relaciones que la Ubicación tiene con los Activos (p. ej., `libFoo` es *propiedad de* Asset 6, *usada por* Asset 9). Cada referencia tiene un estado (`Active` o `Mitigated`) y una **relación** opcional ("Used By" u "Owned By").
- **Finding References** — relaciones que la Ubicación tiene con los Hallazgos. Cada referencia tiene un estado más detallado (`Active`, `Mitigated`, `False Positive`, `Risk Accepted`, `Out of Scope`) además del auditor y el momento de la auditoría.

Esta separación es lo que permite que una biblioteca exista en un Producto *sin* necesitar un Hallazgo — una capacidad ausente en el antiguo modelo de Componentes.

### Asociación automática en el momento de la importación

Cuando un parser produce un Hallazgo que hace referencia a una URL o biblioteca, el importador:

1. Busca una Ubicación existente que coincida con la URL o el pURL; si no existe ninguna, crea una.
2. Crea una Finding Reference que vincula el Hallazgo con la Ubicación con estado `Active`.
3. Crea (o reutiliza) una Asset Reference para que la Ubicación también exista en el Activo padre.

Los parsers existentes se han actualizado para emitir datos de Ubicación cuando el feature flag está activado, y para recurrir al modelo heredado de Endpoint cuando está desactivado. No se necesita ninguna reconfiguración cuando las Ubicaciones están habilitadas — la próxima importación se enrutará automáticamente a través del pipeline de Ubicaciones.

## Qué incluye el MVP

| Capability | Status |
| --- | --- |
| Modelos base `Location`, `URL`, `Dependency` | Disponible |
| API REST para Locations y References | Disponible (`Location` de solo lectura, CRUD completo en References) |
| Shim de compatibilidad de lectura de la API de Endpoint | Disponible |
| Comando de migración unidireccional de Endpoint a URL | Disponible |
| Actualizaciones de parsers (URL y dependencias) | Disponible para los principales parsers |
| Carga de SBOM (CycloneDX, SPDX v2/v3) | Disponible mediante `/api/v2/sbom-import/` |
| Pro UI para Locations, URLs, Dependencies | Disponible |
| Búsqueda/filtro por pURL | Disponible |
| Seguimiento de licencias en dependencias | Parcial (campo `license_expression`) |
| Formato de SBOM SWID Tag | No incluido en el MVP |

## Próximos pasos

- **Habilite la función** — comuníquese con [support@defectdojo.com](mailto:support@defectdojo.com) para activar las Ubicaciones en su instancia.
- **Migre desde Endpoints** — consulte [Migración desde Endpoints](../pro__migrating_from_endpoints) para saber qué preserva la migración y cómo se comporta después la API heredada de Endpoint.
- **Flujos de trabajo diarios de URL** — consulte [Trabajar con URLs](../pro__working_with_urls).
- **SBOM y dependencias** — consulte [Trabajar con SBOMs](../pro__working_with_sboms).
