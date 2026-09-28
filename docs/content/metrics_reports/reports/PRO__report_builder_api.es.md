---
title: Automatización de informes con la API
description: Cree temas, bloques y plantillas, luego ejecute informes y descargue
  los resultados a través de la API REST de DefectDojo Pro
draft: false
audience: pro
weight: 21
slug: report-builder-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: La API REST de Report Builder (temas, bloques, plantillas e informes generados) es una función de DefectDojo Pro, actualmente en beta.</span>

La API REST de Report Builder le permite automatizar los mismos Temas, Bloques y Plantillas que ensambla a mano en la [interfaz de Report Builder](../report-builder/) — y va un paso más allá al permitirle **ejecutar** una plantilla y **descargar** el PDF u HTML terminado. Esta guía recorre el ciclo de vida completo: autenticarse, descubrir el vocabulario de campos y filtros, crear los bloques de construcción y luego generar y recuperar un informe.

> **¿Busca en cambio una exportación rápida de hallazgos?** Si solo necesita una lista plana de hallazgos en JSON, HTML, CSV o Excel — sin temas, bloques ni plantillas que configurar — use el endpoint más simple `generate_report/` documentado en [Generación de informes](/automation/api/api-v2-docs/#generating-reports). La API de Report Builder descrita en esta página es para construir informes diseñados y de varias secciones.

## Autenticación

Cada solicitud se autentica con un token de API personal enviado en el encabezado `Authorization` usando el prefijo `Token` (no `Bearer`).

Obtenga su token desde la interfaz de DefectDojo Pro en **User Settings → API v2 Key**. Guárdelo en una variable de entorno para que nunca termine en el historial de su shell ni en un script confirmado (commit):

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

La URL base para todas las llamadas es la de su instancia más `/api/v2`:

```text
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Encabezados requeridos:

| Encabezado | Valor | Cuándo |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Cada solicitud |
| `Accept` | `application/json` | Cada solicitud |
| `Content-Type` | `application/json` | `POST` / `PATCH` con un cuerpo JSON |

Una solicitud autenticada mínima se ve así:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

Los endpoints de listado se paginan con los parámetros de consulta `limit` y `offset`.

> **⚠️ Aviso de seguridad:** Su token de API otorga acceso completo a sus datos de DefectDojo. Nunca lo pegue en un chat, captura de pantalla, ticket o archivo confirmado (commit). Léalo desde una variable de entorno, rótelo si alguna vez queda expuesto y, cuando sea posible, limite el alcance de los tokens a cuentas de servicio.

## La API de informes de un vistazo

Cuatro recursos conforman la API de Report Builder. Cada uno admite las operaciones estándar de listado (`GET`), creación (`POST`), obtención (`GET {id}/`), actualización (`PATCH {id}/`) y eliminación (`DELETE {id}/`), además de algunas acciones personalizadas.

| Recurso | Ruta | Qué es | Acciones personalizadas |
|----------|------|------------|----------------|
| Temas | `/report_themes/` | Colores, fuentes, imágenes de encabezado/pie de página, números de página | — |
| Bloques | `/report_blocks/` | Una sola pieza de contenido: una portada, una tabla o una sección de detalle | `field_options/`, `preview/`, `{id}/preview/`, `{id}/duplicate/` |
| Plantillas | `/report_templates/` | Una lista ordenada de bloques más un tema | `{id}/duplicate/` |
| Informes generados | `/generated_reports/` | Una ejecución de una plantilla que produce un archivo descargable | `{id}/download/` |

Dos endpoints más le ayudan a descubrir el vocabulario que necesita:

| Endpoint | Propósito |
|----------|---------|
| `GET /report_blocks/field_options/` | Rutas de campos de columna válidas y opciones de ordenamiento para cada modelo |
| `GET /oa3/schema/?format=json` | El esquema OpenAPI completo — se usa para descubrir nombres de filtros válidos |

## Paso 1: descubrir el vocabulario

Hay dos cosas en un bloque que son fáciles de equivocar si se adivinan: los **campos de columna** que enumera y los **filtros** que aplica. La API le ofrece una fuente de verdad para ambos. Obténgalos primero y luego construya sobre lo que el servidor realmente acepta.

### Campos de columna y ordenamiento

`field_options` devuelve los `fields` (rutas de columna) y `ordering_fields` válidos para cada modelo que se puede colocar en un bloque tabular o de detalle:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

La respuesta tiene esta forma (truncada):

```json
{
  "fields": {
    "finding": [
      {"path": "title", "label": "Title"},
      {"path": "severity", "label": "Severity"},
      {"path": "age_days", "label": "Age (days)"}
    ],
    "asset": [ ... ]
  },
  "ordering_fields": {
    "finding": [ ... ]
  }
}
```

Use solo los valores de `path` devueltos aquí para la lista `fields` de un bloque. Algunas rutas son de formato extenso o markdown y están pensadas para bloques de **detalle** en lugar de columnas tabulares estrechas — `field_options` es la lista autorizada, así que confírmelo ahí en lugar de codificar de forma fija un conjunto exhaustivo.

### Nombres de filtros a partir del esquema

Los filtros de un bloque residen en `filter_entries`, donde cada entrada es un par `{field, value}`. Los nombres de `field` válidos son los **nombres de los parámetros de consulta GET** del endpoint REST de la entidad subyacente — *no* las etiquetas que ve en la interfaz. Descúbralos leyendo el esquema OpenAPI:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

Luego lea los parámetros GET de la entidad que está filtrando. Para los hallazgos, busque `paths` → `/api/v2/findings/` → `get` → `parameters`. Los endpoints análogos son `/api/v2/assets/` para **assets** (antes Productos), `/api/v2/organizations/` para **organizations** (antes Tipos de producto), `/api/v2/engagements/`, `/api/v2/tests/`, `/api/v2/test_types/` y `/api/v2/risk_acceptance/`. Cada `name` de parámetro es un `field` de filtro válido.

> **💡 Consejo:** En DefectDojo Pro, los **Assets** antes se llamaban **Productos** y las **Organizations** antes eran **Tipos de producto**. Las rutas de campo de filtro subyacentes en los hallazgos todavía usan la redacción heredada `product` (por ejemplo, `test__engagement__product`), aunque las entidades ahora son Assets y Organizations.

> **🔑 Importante:** El servidor **descarta silenciosamente** cualquier `filter_entry` cuyo `field` no sea un parámetro GET real para ese modelo. No se genera ningún error — el filtro simplemente no existe en el bloque guardado. Siempre haga un GET del bloque después de crearlo y compare los `filter_entries` devueltos con lo que envió.

### Campos de filtro comunes

Las tablas a continuación enumeran filtros verificados y de alto valor. Todos los valores se envían como **cadenas de valor único**; los booleanos son las cadenas literales `"true"` / `"false"`.

**Filtros de hallazgo**

| Campo | Valor de ejemplo | Notas |
|-------|---------------|-------|
| `active` | `"true"` | Cadena booleana |
| `verified` | `"true"` | Cadena booleana |
| `is_mitigated` | `"false"` | Cadena booleana |
| `risk_accepted` | `"false"` | Cadena booleana |
| `duplicate` | `"false"` | Cadena booleana |
| `false_p` | `"false"` | Cadena booleana |
| `out_of_scope` | `"false"` | Cadena booleana |
| `severity` | `"Critical"` | Solo un valor — **no** separado por comas. Use un bloque por severidad. |
| `known_exploited` | `"true"` | Cadena booleana |
| `ransomware_used` | `"true"` | Cadena booleana |
| `outside_of_sla` | `"1"` | Cadena **numérica**, no una cadena booleana |
| `priority_min` | `"800"` | Use `_min`/`_max`, no `_greater_than` |
| `priority_max` | `"1000"` | Use `_min`/`_max` |
| `tag` | `"DR"` | Una sola etiqueta |
| `tags` | `"kev,pci"` | Cualquiera de (coincide con cualquier etiqueta listada) |
| `tags__and` | `"kev,pci"` | Todas (debe coincidir con cada etiqueta listada) |
| `test__engagement__product` | `"42"` | ID del asset (los Assets antes eran Productos) |
| `test__engagement__product__prod_type` | `"3"` | ID de la organización (antes Tipo de producto) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**Filtros de asset** (los Assets antes se llamaban Productos; estos son los parámetros en `/api/v2/assets/`)

| Campo | Valor de ejemplo | Notas |
|-------|---------------|-------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | Cadena booleana |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | Una sola etiqueta |

**Filtros de aceptación de riesgo**

| Campo | Valor de ejemplo | Notas |
|-------|---------------|-------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | ID de usuario |
| `expiration_date_before` | `"2025-12-31"` | No existe un filtro `tag` en este modelo |

Para los bloques de **compromiso**, **test**, **tipo de test** y **organización**, lea los parámetros GET directamente del esquema como se describió antes. Los de mayor valor incluyen `engagement__product` y `status` en los tests, y `name` en los tipos de test — pero siempre confirme el nombre exacto en `schema.json` antes de confiar en él.

> **⚠️** Estos nombres heredados / de estilo de interfaz **se descartan silenciosamente** y NO deben usarse: `status_any`, `priority_greater_than`, `severity__in`, `mitigated_within_sla`, y cualquier valor de **`severity` separado por comas** (por ejemplo, `"Critical,High"`). Use en su lugar los nombres reales de parámetros de consulta del esquema, y divida las necesidades de varias severidades en bloques separados.

> **🔑 Importante:** Un `PATCH` que incluya `filter_entries` **reemplaza toda la lista** — no hay fusión. Envíe siempre el conjunto completo deseado de filtros en cada actualización, o perderá los que omita.

## Paso 2: crear tema, bloques y plantillas

Construya las piezas en orden de dependencia: un **tema**, luego los **bloques**, y luego una **plantilla** que haga referencia a ambos.

### Crear un tema

Los colores son cadenas hexadecimales de 7 caracteres. Cualquier campo que omita vuelve a su valor predeterminado (primario `#1e3a5f`, secundario `#4a90a4`, acento `#e67e22`, texto `#333333`, fondo `#ffffff`).

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/" \
  -d '{
    "name": "Quarterly Review Theme",
    "primary_color": "#1e3a5f",
    "secondary_color": "#4a90a4",
    "accent_color": "#e67e22",
    "text_color": "#333333",
    "background_color": "#ffffff",
    "footer_text": "Confidential — Internal Use Only",
    "show_page_numbers": true
  }'
```

La respuesta incluye el `id` del nuevo tema. Las imágenes de encabezado y pie de página son opcionales y se suben como campos de formulario multipart (`header_image` / `footer_image`); el ejemplo JSON anterior las omite.

### Crear bloques

Un bloque tiene un `name`, un `block_type` y un objeto de configuración correspondiente. Los valores admitidos de `block_type` son `stock`, `tabular` y `detail`. (Existe un tipo `chart` en el modelo de datos, pero aún no está expuesto a través de la API.)

**Una portada de tipo stock.** Los bloques stock contienen contenido fijo. `stock_type` es uno de `cover_page`, `table_of_contents`, `page_break`, `image` o `text_block`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Cover Page",
    "block_type": "stock",
    "header": "Cover",
    "stock_configuration": {
      "stock_type": "cover_page",
      "title": "Quarterly Security Report",
      "subtitle": "Q4 — Active Critical Findings"
    }
  }'
```

**Un bloque tabular de hallazgos con filtros.** Los bloques tabulares renderizan filas de un modelo elegido. `model_choice` es exactamente uno de `organization`, `asset`, `engagement`, `test`, `finding`, `test_type` o `risk_acceptance`. Los `fields` provienen de `field_options` (confirme cada `path`), y `filter_entries` acota las filas.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Active Critical Findings",
    "block_type": "tabular",
    "header": "Active Critical Findings",
    "tabular_configuration": {
      "model_choice": "finding",
      "fields": ["severity", "title", "age_days", "sla_days_remaining"],
      "ordering": "-age_days"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

**Un bloque de detalle de hallazgos.** Los bloques de detalle renderizan una sección expandida por cada registro y pueden incluir campos de formato extenso / markdown que no son adecuados para una columna de tabla estrecha. De nuevo, confirme `fields` contra `field_options`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Critical Finding Detail",
    "block_type": "detail",
    "header": "Critical Findings — Detail",
    "detail_configuration": {
      "model_choice": "finding",
      "fields": ["title", "severity", "description", "mitigation"],
      "ordering": "-severity"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

Cada respuesta de bloque incluye su `id`. Tenga en cuenta que `filter_entries` refleja lo que el servidor realmente almacenó — compárelo con lo que envió (vea [Verifique lo que construyó](#verify-what-you-built)).

### Crear una plantilla

Una plantilla vincula un tema a una lista ordenada de bloques. El campo de solo lectura es `template_blocks`; al crear y actualizar usted **escribe** `template_blocks_write`. Cada entrada necesita un `order` y un `block_id`, y el mismo `block_id` puede aparecer más de una vez.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/" \
  -d '{
    "name": "Quarterly Critical Report",
    "description": "Cover page, critical findings table, then per-finding detail",
    "theme_id": 1,
    "template_blocks_write": [
      {"order": 0, "block_id": 10},
      {"order": 1, "block_id": 11},
      {"order": 2, "block_id": 12}
    ]
  }'
```

Reemplace `theme_id` y cada `block_id` con los IDs devueltos en los pasos anteriores. La respuesta incluye el `id` de la plantilla.

## Paso 3: ejecutar el informe y descargar el resultado

Generar un informe es asíncrono: usted crea una ejecución, consulta su estado y luego descarga el archivo una vez que se completa.

**Iniciar una ejecución.** Haga POST de un `template_id` y un `file_format` de `pdf` o `html`:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/" \
  -d '{
    "template_id": 5,
    "file_format": "pdf"
  }'
```

La respuesta devuelve el nuevo `id` de informe con `status` establecido en `pending`.

**Consultar el estado.** Obtenga el informe hasta que su `status` alcance un estado terminal. El flujo es `pending` → `processing` → `completed`. En caso de `failed`, lea `error_message` para conocer el motivo.

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**Descargar el archivo.** Una vez que `status` sea `completed`, el endpoint de descarga devuelve el archivo como adjunto. Responde con `404` hasta entonces.

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## Uniéndolo todo: un script de ciclo de vida completo

El script a continuación ejecuta todo el flujo usando únicamente la biblioteca estándar de Python 3 — sin `requests`, sin paquetes de terceros. Lee el token desde `DD_IMPORTER_DOJO_API_TOKEN`, crea un tema, tres bloques y una plantilla, inicia un informe, consulta con retroceso hasta que se completa o falla, descarga el resultado y escribe los IDs creados en `created.json`.

Establezca la URL de su instancia y ejecútelo:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_report.py
```

```python
#!/usr/bin/env python3
"""Build and run a DefectDojo Pro report end-to-end using only the stdlib."""

import json
import os
import time
import urllib.error
import urllib.request

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset
FILE_FORMAT = "pdf"  # "pdf" or "html"


def api_request(method, path, body=None, accept_json=True):
    """Make an authenticated request. Returns parsed JSON (or raw bytes)."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
    if accept_json:
        request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        # Surface the server's error body to make debugging easy.
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {path} failed ({error.code}): {detail}")

    if accept_json:
        return json.loads(payload) if payload else {}
    return payload


def main():
    created = {}

    # 1. Create a theme.
    theme = api_request("POST", "/report_themes/", {
        "name": "Quarterly Review Theme",
        "primary_color": "#1e3a5f",
        "secondary_color": "#4a90a4",
        "accent_color": "#e67e22",
        "text_color": "#333333",
        "background_color": "#ffffff",
        "footer_text": "Confidential - Internal Use Only",
        "show_page_numbers": True,
    })
    created["theme_id"] = theme["id"]
    print(f"Created theme id={theme['id']}")

    # 2. Create a stock cover page block.
    cover = api_request("POST", "/report_blocks/", {
        "name": "Cover Page",
        "block_type": "stock",
        "header": "Cover",
        "stock_configuration": {
            "stock_type": "cover_page",
            "title": "Quarterly Security Report",
            "subtitle": "Q4 - Active Critical Findings",
        },
    })
    created["cover_block_id"] = cover["id"]
    print(f"Created stock block id={cover['id']}")

    # 3. Create a tabular finding block scoped to active criticals.
    #    Confirm the chosen fields against /report_blocks/field_options/.
    table = api_request("POST", "/report_blocks/", {
        "name": "Active Critical Findings",
        "block_type": "tabular",
        "header": "Active Critical Findings",
        "tabular_configuration": {
            "model_choice": "finding",
            "fields": ["severity", "title", "age_days", "sla_days_remaining"],
            "ordering": "-age_days",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["table_block_id"] = table["id"]
    print(f"Created tabular block id={table['id']}")

    # 4. Create a detail finding block.
    detail = api_request("POST", "/report_blocks/", {
        "name": "Critical Finding Detail",
        "block_type": "detail",
        "header": "Critical Findings - Detail",
        "detail_configuration": {
            "model_choice": "finding",
            "fields": ["title", "severity", "description", "mitigation"],
            "ordering": "-severity",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["detail_block_id"] = detail["id"]
    print(f"Created detail block id={detail['id']}")

    # 5. Create a template binding the theme to the ordered blocks.
    #    Note: we WRITE template_blocks_write; template_blocks is read-only.
    template = api_request("POST", "/report_templates/", {
        "name": "Quarterly Critical Report",
        "description": "Cover, critical findings table, then per-finding detail",
        "theme_id": created["theme_id"],
        "template_blocks_write": [
            {"order": 0, "block_id": created["cover_block_id"]},
            {"order": 1, "block_id": created["table_block_id"]},
            {"order": 2, "block_id": created["detail_block_id"]},
        ],
    })
    created["template_id"] = template["id"]
    print(f"Created template id={template['id']}")

    # 6. Kick off a report run.
    report = api_request("POST", "/generated_reports/", {
        "template_id": created["template_id"],
        "file_format": FILE_FORMAT,
    })
    report_id = report["id"]
    created["report_id"] = report_id
    print(f"Started report id={report_id} (status={report['status']})")

    # 7. Poll until completed or failed, backing off up to 10 seconds.
    delay = 2
    while True:
        time.sleep(delay)
        report = api_request("GET", f"/generated_reports/{report_id}/")
        status = report["status"]
        print(f"  status={status}")
        if status == "completed":
            break
        if status == "failed":
            raise SystemExit(
                f"Report failed: {report.get('error_message', 'unknown error')}"
            )
        delay = min(delay + 2, 10)  # linear backoff, capped

    # 8. Download the finished file.
    content = api_request(
        "GET",
        f"/generated_reports/{report_id}/download/",
        accept_json=False,
    )
    out_name = f"report.{FILE_FORMAT}"
    with open(out_name, "wb") as handle:
        handle.write(content)
    print(f"Downloaded {out_name} ({len(content)} bytes)")

    # 9. Record the created IDs for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Verifique lo que construyó

Como los filtros inválidos se descartan silenciosamente, la verificación forma parte del flujo de trabajo — no es un paso posterior.

**Confirme que los filtros de un bloque sobrevivieron.** Obtenga cada bloque con GET y compare sus `filter_entries` con lo que envió por POST:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

Si un filtro que envió falta en `filter_entries`, su nombre de `field` no era un parámetro GET válido para ese modelo — vuelva a comprobar el nombre en `schema.json`.

**Confirme el orden de la plantilla y el tema.** Obtenga la plantilla con GET y verifique que `template_blocks` liste los bloques en el `order` esperado y que el tema vinculado coincida:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**Corrija los filtros descartados con PATCH.** Para corregir los filtros de un bloque, haga PATCH del conjunto **completo** deseado — un PATCH reemplaza `filter_entries` por completo:

```bash
curl -s -X PATCH \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/" \
  -d '{
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"},
      {"field": "outside_of_sla", "value": "1"}
    ]
  }'
```

## Próximos pasos

- Construya y previsualice los mismos Temas, Bloques y Plantillas de forma interactiva en la [interfaz de Report Builder](../report-builder/).
- Deje que un LLM ensamble configuraciones de informes por usted con la [integración de Report Builder con LLM](../report-builder-llm/).
