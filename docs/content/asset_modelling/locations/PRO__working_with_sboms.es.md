---
title: Trabajar con SBOMs
description: Gestione las dependencias de software y los SBOMs como Locations
audience: pro
weight: 5
---

DefectDojo Pro modela las bibliotecas de software como **Dependency Locations**. Una Dependency es un subtipo de Location identificado por una [Package URL (pURL)](https://github.com/package-url/purl-spec) y está pensada para representar una única biblioteca o paquete — `org.apache.logging.log4j:log4j-core@2.17.0`, `pypi/django@5.0.2`, `npm/react@18.2.0`, etcétera.

Las Dependencies reemplazan al modelo anterior de **Components**, que solo se adjuntaba a los Findings. Con Locations, las bibliotecas pueden existir independientemente de cualquier vulnerabilidad: puede cargar un SBOM en un Asset y luego dejar que los Hallazgos se adjunten automáticamente a las dependencias que referencian a medida que llegan los escaneos.

## Qué contiene una Dependency

Cada Dependency se identifica de forma única mediante un pURL, descompuesto en campos atómicos sobre los que puede buscar y filtrar:

| Campo | Significado | Ejemplo |
| --- | --- | --- |
| `purl_type` | Ecosistema de la biblioteca | `npm`, `pypi`, `maven`, `cargo`, `nuget`, `gem` |
| `namespace` | Proveedor u organización | `org.apache.logging` |
| `name` | Nombre de la biblioteca | `log4j-core` |
| `version` | Versión específica | `2.17.0` |
| `qualifiers` *(opcional)* | Detalles de implementación | `arch=amd64` |
| `subpath` *(opcional)* | Ruta dentro de un archivo o monorepo | `src/lib/foo` |
| `artifact_hashes` *(opcional)* | Huellas digitales | sumas SHA256 |
| `license_expression` *(opcional)* | Expresión de licencia SPDX | `Apache-2.0`, `MIT` |
| `file_path` *(opcional)* | Dónde se encontró la biblioteca en el proyecto | `package-lock.json` |

Esta descomposición atómica es lo que hace útil la búsqueda basada en pURL: puede preguntar *"todos los paquetes `pypi` en el namespace `django` en la versión 4.x"* y DefectDojo puede responder sin necesidad de analizar una cadena de texto libre.

## Owned-By vs Used-By

Cuando una Dependency se asocia con un Asset, la Asset Reference lleva una **relationship** opcional que describe *cómo* pertenece la biblioteca al Asset:

- **`owned_by`** — *"esta biblioteca pertenece a este Asset"*. Úselo para bibliotecas propias que un Asset publica o mantiene.
- **`used_by`** — *"esta biblioteca es utilizada por este Asset"*. Úselo para dependencias de terceros que un Asset consume.

La misma biblioteca puede ser `owned_by` de un Asset y `used_by` de varios otros, que es exactamente la relación que necesita para responder *"¿quién consume el paquete que publica mi equipo?"* durante el triage de vulnerabilidades.

## Cargar un SBOM

Para poblar Dependencies en bloque, cargue un archivo SBOM contra un Product. El endpoint es:

```
POST /api/v2/sbom-import/
```

| Campo | Descripción |
| --- | --- |
| `product` | El ID del Product (Asset) de destino |
| `file` | El archivo SBOM |
| `scan_type` | El formato del SBOM — vea los formatos admitidos más abajo |
| `replace` *(opcional)* | Si es `true`, se eliminan las asociaciones de Product obsoletas que no estén respaldadas por una referencia de Finding existente. Predeterminado: `false` (acumulativo) |

El importador analiza el archivo, extrae los registros `Dependency`, los deduplica contra las Locations existentes (creando nuevas según sea necesario) y crea Asset References que vinculan cada Dependency con el Product. La interfaz de Pro expone el mismo flujo de carga — vea la acción **Upload SBOM** en la pestaña de Locations de un Product.

### Formatos admitidos

El MVP incluye parsers para los dos formatos de SBOM dominantes:

- **CycloneDX** — JSON y XML
- **SPDX** — JSON (v2 y v3), XML y tag-value

El formato SWID Tag aún no es compatible.

### Replace vs Append

De forma predeterminada, las cargas repetidas son **aditivas**: las dependencias que ya existen en el Asset se conservan, se agregan las nuevas y no se elimina nada. Esto coincide con el flujo de trabajo típico de actualizaciones incrementales de SBOM.

Configure `replace=true` para depurar. Cuando el modo replace está activado, después de una importación exitosa el importador elimina las asociaciones de Product que no estaban presentes en el nuevo SBOM **y** que no están referenciadas actualmente por un Finding activo. Las referencias vinculadas a Findings activos se conservan incluso en modo replace, de modo que no pierde contexto de vulnerabilidad solo porque un nuevo SBOM omita un paquete.

## Hallazgos que referencian bibliotecas

Cuando un parser ingiere una vulnerabilidad vinculada a una biblioteca — por ejemplo, una herramienta SCA que reporta `CVE-2021-44228` contra `log4j-core@2.14.1` —, el importador:

1. Busca una Dependency Location existente por pURL, o crea una nueva.
2. Crea una `LocationFindingReference` que vincula el Hallazgo con la Dependency con estado **Activo**.
3. Crea una `LocationProductReference` para que la Dependency también aparezca en el Product padre, si aún no está presente.

Dado que los Hallazgos y las cargas de SBOM comparten los mismos objetos Dependency subyacentes, un Hallazgo ingerido *antes* de una carga de SBOM será visible retroactivamente en la vista del SBOM, y viceversa.

## API REST

| Tarea | Endpoint |
| --- | --- |
| Cargar un SBOM | `POST /api/v2/sbom-import/` |
| Listar Dependencies | `GET /api/v2/dependencies/` |
| Crear una Dependency manualmente | `POST /api/v2/dependencies/` |
| Listar Dependency Locations | `GET /api/v2/location/?location_type=dependency` |
| Vincular una Dependency con un Finding | `POST /api/v2/location_findings/` |
| Vincular una Dependency con un Product (con `owned_by` / `used_by`) | `POST /api/v2/location_products/` |

Los filtros en `/api/v2/dependencies/` incluyen los campos componentes del pURL, las etiquetas y la ordenación por `name`, `version` y conteo de Hallazgos activos.

## En la interfaz de Pro

Cuando Locations está habilitado, la navegación expone:

- **Locations / Dependencies** — Lista global de todas las Dependencies de la instancia, con filtros de pURL.
- **Locations en un Product/Asset** — Vista por Asset que muestra tanto las URLs como las Dependencies, con la acción **Upload SBOM** disponible en la pestaña de Dependencies.
- **New Dependency** — Formulario para crear una única biblioteca introduciendo manualmente sus componentes de pURL.
- **Detalle de Hallazgos** — Un Hallazgo que involucra una biblioteca muestra sus Dependency Locations junto con cualquier URL Location, de modo que puede ver *"este CVE afecta a `log4j-core@2.14.1` en el Asset 6 y el Asset 9"* en un solo lugar.

## Qué no incluye el MVP

- **Formato SBOM SWID Tag** — No se analiza. Se requiere CycloneDX o SPDX.
- **Puntuación de riesgo de licencia** — El campo `license_expression` se captura cuando está presente en el SBOM, pero DefectDojo aún no marca Hallazgos por incompatibilidad de licencias. La generación de informes basada en licencias está en la hoja de ruta como seguimiento del MVP de Locations.
- **Locations de imágenes de contenedor y recursos en la nube** — Futuros subtipos de Location. Por ahora, las bibliotecas descubiertas dentro de una imagen de contenedor se registran como Dependencies; la imagen de contenedor en sí aún no es una Location de primera clase.
