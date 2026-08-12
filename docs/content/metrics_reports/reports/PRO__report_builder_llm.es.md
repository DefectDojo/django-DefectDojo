---
title: Creación de informes con un LLM
description: Use Claude u otro LLM para diseñar, crear, ejecutar y descargar informes
  de DefectDojo Pro a través de la API
draft: false
audience: pro
weight: 22
slug: report-builder-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: automatizar el Generador de informes con la API REST y un LLM es una función de DefectDojo Pro, actualmente en beta.</span>

El Generador de informes de DefectDojo Pro (Temas, Bloques y Plantillas) funciona íntegramente a través de la API REST. Esto significa que puede delegar todo el trabajo a un LLM: pegue un único prompt autocontenido en Claude, ChatGPT o cualquier otro modelo capaz, y este consultará el esquema OpenAPI en vivo de su tenant y `field_options`, propondrá un tema junto con una biblioteca reutilizable de bloques y plantillas para las audiencias que usted indique, generará un script de Python ejecutable y luego ejecutará el informe y descargará el archivo terminado.

El patrón es simple. Usted proporciona su URL base, un token de API y una breve descripción de para quién son los informes. El LLM se encarga del descubrimiento, el diseño, la creación, la verificación, la ejecución y la descarga, deteniéndose para pedir su aprobación antes de crear nada en su tenant.

Esta guía complementa la [guía de la API del Generador de informes](../report-builder-api/), que documenta los recursos sin procesar y las estructuras de solicitud con las que trabaja el LLM. Si desea comprender o ajustar manualmente lo que produjo el LLM, esa es la referencia que debe tener abierta.

## Antes de empezar

1. **Obtenga un token de API.** En la interfaz de DefectDojo Pro, vaya a **Configuración de usuario → Clave de API v2** y copie el token. Luego, defínalo como una variable de entorno para que el script generado pueda leerlo sin que el token aparezca nunca en el chat:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Decida sus audiencias.** El LLM le preguntará para quién son los informes. Las opciones más comunes son:

   - **Resumen ejecutivo** — postura general de alto nivel; SLA vencidos, KEV e inventario de activos de un vistazo.
   - **POA&M (Plan de acción e hitos)** — hallazgos abiertos con severidad, fecha límite y remediación recomendada, además del detalle de los hallazgos de severidad Crítica y los hallazgos históricos o cerrados.
   - **Libro de inventario integrado** — activos (antes Productos) en alcance con criticidad, plataforma, ciclo de vida, accesibilidad desde internet y recuento de hallazgos.
   - **Paquete de solicitud de desviación (DRF)** — aceptaciones de riesgo activas, hallazgos etiquetados como DR y candidatos con SLA vencido para nuevas solicitudes de desviación.
   - **Detalle de hallazgos de ingeniería** — descripciones completas por hallazgo (descripción, impacto, mitigación, referencias).
   - **Instantánea de cumplimiento/auditoría** — activos más aceptaciones de riesgo más KEV.

> **💡 Sugerencia:** No tiene que elegir de esta lista. Indíquele al LLM sus audiencias reales en lenguaje sencillo y él las asignará a las entidades y filtros disponibles.

## El prompt

Copie todo el bloque delimitado a continuación y péguelo en Claude, ChatGPT o cualquier otro LLM capaz. El prompt es autocontenido: el modelo le pedirá la URL de su tenant, la variable de entorno del token y las audiencias del informe, y luego lo guiará a través del descubrimiento → diseño → creación → verificación → ejecución → descarga.

```text
You are helping me build, run, and download custom reports in DefectDojo Pro
using its REST API and "Report Generator" (Themes / Blocks / Templates /
Generated Reports).

================================================================================
DATA MODEL
================================================================================

DefectDojo Pro custom reports use these related REST resources (all under
/api/v2/):

  report_themes      visual style
  report_blocks      reusable content units (filters live here)
  report_templates   ordered blocks + a theme
  generated_reports  run a template and download the resulting PDF/HTML

A Template references Blocks by ID and a Theme by ID. A Block carries its own
filters, so reusing a Block reuses its filters identically everywhere. A
Generated Report runs a Template and produces a downloadable file.

================================================================================
THEMES
================================================================================

A Theme controls the visual style applied to a template. Its fields are:

  name              display name for the theme
  primary_color     7-char hex (default #1e3a5f)
  secondary_color   7-char hex (default #4a90a4)
  accent_color      7-char hex (default #e67e22)
  text_color        7-char hex (default #333333)
  background_color  7-char hex (default #ffffff)
  footer_text       text shown in the page footer
  show_page_numbers boolean -- whether to print page numbers
  header_image      optional image for the page header
  footer_image      optional image for the page footer

All color values are 7-character hex strings (e.g. "#1e3a5f").

================================================================================
BLOCK TYPES
================================================================================

A Block's `block_type` is one of: stock | tabular | detail
  - stock    : non-data content (cover_page, table_of_contents, page_break,
               image, text_block). Config goes in `stock_configuration`.
  - tabular  : a table of records from a DefectDojo entity. Config in
               `tabular_configuration`. Required: model_choice, fields[], ordering.
  - detail   : a per-record detail layout (good for long-text fields like
               description, impact, mitigation). Config in
               `detail_configuration`. Same required keys as tabular.

(A `chart` block type is reserved but not yet exposed via the API.)

`model_choice` is locked to one of EXACTLY these seven entities (this is an
enum in the OpenAPI schema -- do not invent others):

    organization | asset | engagement | test | finding | test_type | risk_acceptance

NOTE: Even if the tenant has REST endpoints like /api/v2/location/,
/api/v2/location_findings/, or /api/v2/location_products/, those are NOT
selectable as `model_choice`. Any "location" scoping must flow through asset
(formerly Product), tag, or organization (formerly Product Type) filters on
the supported entities.

================================================================================
FIELDS (columns) -- discover, never invent
================================================================================

For each entity above, the list of valid `fields` (column paths) plus which
paths are allowed for `tabular` vs `detail` blocks is exposed at:

    GET /api/v2/report_blocks/field_options/

You MUST fetch this before designing any block. Use only the `path` values it
returns. Some fields are `detail`-only (description, mitigation, impact,
references, etc.) because they hold long-form / markdown content.

================================================================================
FILTERS -- this is the most error-prone area; READ CAREFULLY
================================================================================

Each tabular/detail block accepts:

    "filter_entries": [
        {"field": "<filter_name>", "value": "<string_value>"},
        ...
    ]

The OpenAPI schema does NOT enumerate valid filter names. The valid vocabulary
is the GET query-parameter vocabulary of the underlying REST endpoint for that
entity. To discover the real filter names for an entity:

    finding         -> GET /api/v2/findings/         (look at `parameters`)
    asset           -> GET /api/v2/assets/          (formerly Products)
    engagement      -> GET /api/v2/engagements/
    test            -> GET /api/v2/tests/
    test_type       -> GET /api/v2/test_types/
    organization    -> GET /api/v2/organizations/   (formerly Product Types)
    risk_acceptance -> GET /api/v2/risk_acceptance/

The fastest way is to load the full OpenAPI schema once:

    GET /api/v2/oa3/schema/?format=json

then, for each entity, read
    schema['paths'][<endpoint>]['get']['parameters']
and use those `name` values as your filter `field` keys.

DO NOT invent UI-style filter names (older docs sometimes mention
`status_any`, `priority_greater_than`, or comma-separated multi-value strings
like "Critical,High"). The DD Pro server SILENTLY DROPS or rewrites any
filter_entry whose `field` does not match a real GET-parameter name on the
underlying endpoint. Examples of names that DO work, from a live 2.58.x
tenant, on findings:

    {"field": "active",          "value": "true"}     boolean
    {"field": "verified",        "value": "true"}     boolean
    {"field": "is_mitigated",    "value": "true"}     boolean
    {"field": "risk_accepted",   "value": "true"}     boolean
    {"field": "duplicate",       "value": "false"}    boolean
    {"field": "false_p",         "value": "false"}    boolean
    {"field": "out_of_scope",    "value": "false"}    boolean
    {"field": "severity",        "value": "Critical"} single value (NOT comma-separated)
    {"field": "known_exploited", "value": "true"}     boolean
    {"field": "ransomware_used", "value": "true"}     boolean
    {"field": "outside_of_sla",  "value": "1"}        NUMERIC (not boolean string)
    {"field": "priority_min",    "value": "800"}      use _min / _max, not _greater_than
    {"field": "priority_max",    "value": "1000"}
    {"field": "tag",             "value": "DR"}       single tag
    {"field": "tags",            "value": "kev,pci"}  multiple tags (any-of)
    {"field": "tags__and",       "value": "kev,pci"}  multiple tags (all-of)
    {"field": "test__engagement__product",         "value": "<product_id>"}
    {"field": "test__engagement__product__prod_type","value": "<prod_type_id>"}
    {"field": "cve",             "value": "CVE-2024-12345"}
    {"field": "cwe",             "value": "79"}
    {"field": "planned_remediation_date_before", "value": "2025-12-31"}
    {"field": "date_before",     "value": "2025-12-31"}
    {"field": "date_after",      "value": "2025-01-01"}

Asset filters (examples confirmed on live tenant):

    {"field": "business_criticality", "value": "very_high"}
    {"field": "internet_accessible",  "value": "true"}
    {"field": "lifecycle",            "value": "production"}
    {"field": "platform",             "value": "web"}
    {"field": "tag",                  "value": "pci"}

Risk-acceptance filters (note: no `tag` filter exists here -- filter by
`decision`, `owner`, or `expiration_date` instead, or push the DR-marking
tag onto the underlying findings):

    {"field": "decision",         "value": "Accept (Transfer)"}
    {"field": "owner",            "value": "<user_id>"}
    {"field": "expiration_date_before", "value": "2025-12-31"}

Operational rules for filter_entries:

  - Single-value strings only. "Critical,High" in one severity entry will NOT
    keep both -- DefectDojo will store only "Critical". To cover multiple
    severities, create separate blocks (one per severity) or compose multiple
    filter rows where the underlying endpoint supports it (e.g. tags__and).
  - Booleans go as the LITERAL string "true" or "false".
  - PATCHing filter_entries REPLACES the whole list. Always send the full
    desired set; never assume merge semantics.
  - After POSTing a block, GET it back and compare the returned filter_entries
    against what you sent. If any entry is missing, the field name was rejected
    -- look it up in `parameters` on the corresponding REST endpoint.

================================================================================
TEMPLATES
================================================================================

A Template ties blocks together in order and binds them to a theme:

    POST /api/v2/report_templates/
    {
        "name":        "<name>",
        "description": "<short description>",
        "theme_id":    <theme_id>,
        "template_blocks_write": [
            {"order": 0, "block_id": <block_id>},
            {"order": 1, "block_id": <block_id>},
            ...
        ]
    }

The same `block_id` can appear multiple times (e.g. a "page break" block
reused several times in the same template).

================================================================================
GENERATED REPORTS -- run a template, then download the file
================================================================================

A Generated Report runs a Template and produces a downloadable file.

1. Kick off a run:

    POST /api/v2/generated_reports/
    {
        "template_id": <template_id>,
        "file_format": "pdf"      // or "html"
    }

   This returns a generated_reports record with an `id` and a `status`.

2. Poll until it finishes:

    GET /api/v2/generated_reports/{id}/

   `status` moves through: pending -> processing -> completed (or failed).
   Poll on an interval until it reaches "completed". If it reaches "failed",
   read `error_message` for the reason and stop.

3. Download the file once completed:

    GET /api/v2/generated_reports/{id}/download/

   This returns the binary PDF/HTML body. It returns 404 until status is
   "completed", so only call it after polling confirms completion. Save the
   response body to a file with the matching extension.

================================================================================
AUTH
================================================================================

Every request needs:

    Authorization: Token <my-api-token>
    Accept:        application/json
    Content-Type:  application/json   (on POST/PATCH)

Get the token from User Settings -> API v2 Key in the DefectDojo Pro UI.

================================================================================
WHAT I WANT YOU TO DO
================================================================================

1. Ask me for:
   - my DefectDojo Pro base URL (e.g. https://<tenant>.cloud.defectdojo.com/api/v2)
   - the env var name that holds my API token (default: DD_IMPORTER_DOJO_API_TOKEN)
   - the audiences/reports I want (e.g. Executive Summary, POA&M,
     Inventory Workbook, Deviation Request package, Engineering Detail,
     Compliance/Audit Snapshot)
   - any specific filters I care about (severity tiers, SLA cutoffs, KEV-only,
     specific assets, tags, etc.)
   - branding for the theme (primary/secondary/accent colors, footer text,
     whether to show page numbers)
   - which output format I want for the run: "pdf" or "html"

2. Discover the live vocabulary BEFORE designing anything:
   - GET /api/v2/oa3/schema/?format=json    and save locally
   - GET /api/v2/report_blocks/field_options/   and save locally
   - For each entity I want to report on, extract the GET parameters from the
     schema and show me the candidate filter names so we agree on vocabulary.

3. Propose a design back to me consisting of:
   - one shared theme (with the branding from step 1)
   - a reusable Block library (cover page, page breaks, intro text blocks,
     and the data tables/details I need)
   - 1+ Templates that compose those blocks for the audiences I named
   For every data block, show me: model_choice, fields[], ordering, and the
   exact filter_entries list. Wait for my approval.

4. Once I approve, generate a SINGLE Python script (stdlib only, urllib --
   no extra dependencies needed) that:
   - reads the token from the env var I named
   - POSTs the theme, then the blocks, then the templates (in that order,
     because templates reference block IDs and a theme ID)
   - prints each returned ID as it goes
   - dumps everything to a created.json file for verification
   - THEN runs and downloads the report (see steps 6-8 below) as part of the
     same script
   Show me the full script before running it.

5. After creating, VERIFY:
   - GET each created block back and confirm filter_entries persisted
     EXACTLY as POSTed. If any entry is missing, that field name was rejected
     by DD -- look it up in `parameters` on the relevant REST endpoint and
     PATCH the block with the corrected vocabulary.
   - GET each template back and confirm the block_id list and order, plus
     theme_id binding, are correct.

6. RUN the report:
   - POST /api/v2/generated_reports/ with
     { "template_id": <template_id>, "file_format": "pdf" }  (or "html")
   - capture the returned generated report `id`.

7. POLL until done:
   - GET /api/v2/generated_reports/{id}/ on a short interval.
   - statuses progress: pending -> processing -> completed/failed.
   - stop polling when status is "completed".
   - if status is "failed", read and print `error_message`, then stop.

8. DOWNLOAD the file:
   - once status is "completed", GET /api/v2/generated_reports/{id}/download/
     (it 404s until completed) and save the response body to a file with the
     correct extension (.pdf or .html).
   - print the saved file path.

9. If I later want to tune a filter, swap a block, or change colors:
   - PATCH the existing resource (do not recreate).
   - When PATCHing filter_entries, send the FULL desired list -- it replaces,
     not merges.
   - Re-run steps 6-8 to regenerate the file.

================================================================================
HARD CONSTRAINTS
================================================================================

- Do NOT invent field paths or filter names. If unsure, GET field_options
  (for column paths) or the entity's GET parameters (for filter names) and
  use only what's there.
- Do NOT use "Critical,High" or other comma-separated values inside a single
  severity/status filter_entry value -- DD will keep only the first match.
  Use one block per value, or use multi-value filters that DD's underlying
  endpoint explicitly supports (e.g. `tags`, `tags__and`).
- Do NOT use the older UI-style filter names like `status_any`,
  `priority_greater_than`, `mitigated_within_sla`, or `severity__in`. They
  are silently dropped.
- Do NOT call the download endpoint before status is "completed" -- it 404s.
- Show me each batch of commands or the full script before running it.
- Stop and ask if anything in the schema is ambiguous rather than guessing.

Start by asking me for the base URL, the env var name holding the token, my
audience goals, theme branding, and my preferred output format.
```

## Cómo usarlo

1. **Pegue el prompt** anterior en Claude, ChatGPT o cualquier otro LLM capaz.
2. **Responda sus preguntas de descubrimiento.** Le pedirá su URL base, la variable de entorno que contiene su token, sus audiencias, cualquier filtro específico que le interese (niveles de severidad, límites de SLA, solo KEV, activos o etiquetas concretos), su branding y el formato de salida que desea.
3. **Revise el diseño propuesto y apruébelo antes de que lo construya.** El modelo debería presentarle un tema compartido, una biblioteca de bloques reutilizable y una o más plantillas, mostrando, para cada bloque de datos, el `model_choice`, los `fields`, el orden y las entradas de filtro exactas. No permita que cree nada en su tenant hasta que usted haya dado el visto bueno.
4. **Deje que genere y ejecute el script.** El único script de Python (solo con la biblioteca estándar) crea el tema, los bloques y las plantillas, y luego ejecuta el informe y descarga el archivo terminado.
5. **Debería verificar antes y después de la ejecución.** Es de esperar que haga GET de cada bloque y plantilla para confirmar que los filtros y el orden se guardaron correctamente, luego haga POST a `generated_reports`, sondee hasta que el estado sea `completed` y descargue el archivo.

> **💡 Sugerencia:** Si el LLM pasa directamente a diseñar bloques sin antes obtener el esquema en vivo de su tenant (`/api/v2/oa3/schema/?format=json`) y `field_options`, deténgalo. Los nombres de filtros y campos varían según la versión, y diseñar de memoria es exactamente la forma en que los bloques terminan con filtros faltantes sin que nadie lo note.

## Solución de problemas

**Un bloque creado vuelve sin los filtros que envió.** El nombre de `field` del filtro no coincidía con un parámetro GET real en la entidad subyacente, por lo que DefectDojo lo descartó. Haga que el LLM obtenga `/api/v2/oa3/schema/?format=json`, lea la lista de `parameters` del endpoint GET de esa entidad (por ejemplo, el endpoint de hallazgos) y use un nombre de parámetro real.

**Los filtros booleanos no surten efecto.** Los valores booleanos deben enviarse como las cadenas `"true"` o `"false"`, no como booleanos JSON reales.

**`outside_of_sla` no filtra.** Ese filtro toma un valor numérico como cadena; use `"1"`, no `"true"`.

**Varias severidades en un mismo bloque no funcionan.** Un solo bloque conserva únicamente la primera severidad. En su lugar, divídalo en un bloque por severidad.

**Los bloques de la plantilla vuelven en el orden incorrecto o faltan.** Asegúrese de que el LLM haya hecho POST a `template_blocks_write` (el campo de solo escritura) y no a `template_blocks` (que es de solo lectura). El campo `order` es obligatorio en cada entrada.

**La ejecución del informe está atascada o falló.** Siga sondeando `GET /api/v2/generated_reports/{id}/`; el estado pasa de `pending` a `processing` y luego a `completed`. Si el estado pasa a `failed`, lea el campo `error_message` para conocer la causa antes de reintentar.

> **⚠️** El endpoint de descarga (`/api/v2/generated_reports/{id}/download/`) devuelve 404 hasta que la ejecución llega a `completed`. Sondee siempre hasta la finalización antes de descargar.

## Próximos pasos

- [Generador de informes (interfaz)](../report-builder/) — diseñe y ejecute informes de forma interactiva en la interfaz de DefectDojo Pro.
- [API del Generador de informes](../report-builder-api/) — los recursos REST sin procesar y las estructuras de solicitud con las que trabaja el LLM, para ajustes manuales o automatización más profunda.
