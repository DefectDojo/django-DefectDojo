---
title: Automatización de paneles mediante la API
description: Descubra el catálogo de widgets, cree y actualice diseños de paneles,
  y renderice datos de widgets a través de la API REST de DefectDojo Pro
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: La API REST de Paneles personalizables (diseños, catálogo de widgets y datos de widgets) es una función de DefectDojo Pro. Está desactivada de forma predeterminada: un superusuario puede activar los Paneles personalizables desde **Settings > Feature Flags** tanto en instancias Cloud como On-Premise.</span>

La API REST de Paneles personalizables le permite crear los mismos paneles que ensambla manualmente en la [interfaz de Paneles](../custom-dashboards/), completamente desde código. Puede descubrir el catálogo de widgets, crear y actualizar diseños, establecer su predeterminado, compartir diseños con su equipo e incluso renderizar los datos de un widget bajo demanda sin volver a implementar el filtrado de DefectDojo. La superficie de diseños fue pensada como el punto de entrada principal para los agentes de IA que crean paneles, por lo que las formas de las solicitudes son deliberadamente introspectables.

Esta guía recorre el ciclo de vida completo: autenticarse, descubrir el vocabulario de widgets, crear un diseño y luego verificarlo y renderizarlo.

## Autenticación

Cada solicitud se autentica con un token de API personal enviado en el encabezado `Authorization` usando el prefijo `Token` (no `Bearer`).

Obtenga su token desde la interfaz de DefectDojo Pro en **User Settings → API v2 Key**. Guárdelo en una variable de entorno para que nunca quede en el historial de su shell ni en un script confirmado en el repositorio:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

La URL base para todas las llamadas es su instancia más `/api/v2`:

```
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Encabezados requeridos:

| Encabezado | Valor | Cuándo |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Toda solicitud |
| `Accept` | `application/json` | Toda solicitud |
| `Content-Type` | `application/json` | `POST` / `PATCH` con un cuerpo JSON |

Una solicitud autenticada mínima se ve así:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 Importante:** Toda la API de Paneles depende de la función Paneles personalizables. Hasta que se active, cada endpoint devuelve `403 Dashboards 2.0 is not enabled.` — consulte [Habilitación de los Paneles personalizables](../custom-dashboards/#enabling-customizable-dashboards).

> **⚠️ Aviso de seguridad:** Su token de API otorga acceso completo a sus datos de DefectDojo. Nunca lo pegue en un chat, una captura de pantalla, un ticket o un archivo confirmado en el repositorio. Léalo desde una variable de entorno, rótelo si alguna vez se expone, y limite el alcance de los tokens a cuentas de servicio cuando sea posible.

## La API de paneles de un vistazo

Tres grupos de recursos conforman la API de Paneles, todos bajo `/api/v2/dashboards/`.

| Recurso | Ruta | Qué es | Operaciones |
|----------|------|------------|------------|
| Diseños | `/dashboards/layouts/` | Sus paneles guardados (y las plantillas de equipo compartidas) | `GET` lista, `POST` crear, `GET {id}/`, `PATCH {id}/`, `DELETE {id}/`, además de `{id}/clone/`, `{id}/set_default/`, `shared/`, `for_current_user/` |
| Catálogo de widgets | `/dashboards/widget_catalog/` | El menú de tipos de widget y un ejemplo de configuración para cada uno | `GET` (solo lectura) |
| Datos de widgets | `/dashboards/widget_data/<action>/` | Datos renderizados bajo demanda para un widget | 21 acciones por widget |

Estos endpoints aceptan autenticación por Token, Session o Basic. Toda la autorización por fila y el alcance de los datos siguen el control de acceso basado en roles estándar de DefectDojo: compartir un diseño nunca amplía lo que pueden ver sus espectadores.

> **💡 Consejo:** La interfaz Vue llama a un espejo interno de estos endpoints bajo `/api/vue/dashboard_v2/`. Automatice siempre contra las rutas `/api/v2/dashboards/` estables y orientadas al cliente que se documentan aquí.

## Paso 1: Descubra el vocabulario

Hay tres cosas en un widget que son fáciles de equivocar si se adivinan: el **tipo de widget**, su **dimensión de agrupación** (para los gráficos) y sus **filtros**. La API le proporciona una fuente de verdad para cada uno. Obténgalos primero y luego construya en base a lo que el servidor realmente acepta.

### El catálogo de widgets

`GET /dashboards/widget_catalog/` devuelve cada tipo de widget, la categoría a la que pertenece, el o los endpoints de datos contra los que renderiza y, lo más útil, un `config_example` mínimo y válido que puede copiar como punto de partida:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

La respuesta tiene esta forma (truncada):

```json
{
  "categories": [
    {"id": "numbers", "label": "Numbers", "description": "Single-glance metrics — counts, KPIs, gauges."},
    {"id": "charts",  "label": "Charts",  "description": "Time-series and distribution visualisations."},
    {"id": "lists",   "label": "Lists & Feeds", "description": "Ranked lists, feeds, and embedded tables."},
    {"id": "static",  "label": "Static & Utility", "description": "Notes, shortcuts, and quick actions."}
  ],
  "widgets": [
    {
      "type": "count",
      "label": "Count",
      "category": "numbers",
      "description": "Single number rendered from a filtered queryset...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/count/"],
      "config_example": {
        "model": "finding",
        "filters": {"status_any": "Active", "severity": "Critical"},
        "icon": "fas fa-ban",
        "color": "danger"
      }
    },
    {
      "type": "graph",
      "label": "Graph",
      "category": "charts",
      "description": "Generic chart over any model + group-by dimension...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/aggregate/"],
      "config_example": {
        "model": "finding",
        "filters": {"duplicate": "false"},
        "group_by": "severity",
        "aggregation": "count",
        "chart_type": "pie",
        "time_bucket": null,
        "limit": null,
        "stacked": false
      }
    }
  ]
}
```

Use el `type` de un widget como el `type` del widget, y su `config_example` como punto de partida para el `config` del widget. El catálogo enumera 26 tipos de widget repartidos en las cuatro categorías.

### Dimensiones de agrupación y métricas de registro

Los widgets de gráficos y de clasificación (leaderboard) restringen lo que se puede agrupar o clasificar a una lista permitida seleccionada. Descúbrala por modelo en lugar de adivinar:

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/` devuelve la `key` de cada dimensión (el valor que se pasa como `group_by`), una `label` legible y un `kind`:

```json
{
  "model": "finding",
  "dimensions": [
    {"key": "severity",  "label": "Severity",        "kind": "categorical"},
    {"key": "status",    "label": "Status",          "kind": "banded"},
    {"key": "date",      "label": "Discovered Date", "kind": "time"},
    {"key": "test_type", "label": "Test Type",       "kind": "categorical"}
  ]
}
```

El `kind` importa: una dimensión `time` (como `date`) exige que también envíe un `time_bucket` (`day`/`week`/`month`/`quarter`/`year`); una dimensión `categorical` o `banded` no lo exige. El campo `priority` **no** es intencionalmente una dimensión de agrupación (es una puntuación continua): use la dimensión `risk` para una vista por bandas, o el widget dedicado **Priority Histogram**.

### Filtros

Los `config.filters` de un widget usan **la misma forma de filtro que la vista de lista del objeto**: los valores que la página de lista emite a su URL, no los parámetros de consulta REST en bruto. Por ejemplo, en hallazgos: `{"status_any": "Active"}`, `{"severity": "Critical"}`, `{"duplicate": "false"}`, `{"date_past_days": 7}`, `{"sla_days_remaining_less_than_equal_to": 7}`; en assets: `{"grade": "A,B,C"}`, `{"last_scanned_past_days": 90}`. La forma más rápida de aprender el filtro correcto para una necesidad es aplicarlo en la página de lista correspondiente de la interfaz y leerlo de vuelta desde el cuadro de diálogo de configuración del widget, o copiar los filtros de las plantillas compartidas precargadas.

> **🔑 Importante:** Las **claves de filtro desconocidas se ignoran silenciosamente** — un filtro mal escrito o inexistente no genera un error, simplemente no se aplica, dejando que el widget muestre una población más amplia de la prevista. Los *valores* inválidos para un filtro real devuelven `400`. [Verifique siempre lo que construyó](#verify-what-you-built) leyendo de vuelta el diseño. (Los filtros se validan mediante el mismo FilterSet que usa la vista de lista, por lo que los valores de lista pueden pasarse como arreglos para una coincidencia de tipo "cualquiera de": `{"severity": ["Critical", "High"]}`.)

> **💡 Consejo:** La mayoría de los widgets toman un `model` de `finding`, `product`, `engagement` o `test` — observe el `product` heredado (la interfaz llama a esto **Assets**). El widget **Embedded Table** es la excepción: su `model` usa los nombres más nuevos `finding`, `asset`, `engagement`, `test`, `risk_acceptance`, `organization` o `test_type`.

## Paso 2: Cree un diseño

Un diseño se crea con un `POST` a `/dashboards/layouts/`. Los dos campos que contienen el contenido del panel son `widgets` y `layout`, y deben coincidir entre sí.

### El objeto widget

Cada entrada del arreglo `widgets` tiene esta forma:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** — un UUID que usted genera. Vincula el widget con su posición en la cuadrícula.
- **`type`** — un valor `type` del catálogo de widgets.
- **`title`** — el encabezado que se muestra en el widget (hasta 200 caracteres).
- **`refresh_interval`** — segundos de actualización automática; uno de `0` (desactivado), `30`, `60`, `300` o `900`.
- **`config`** — la configuración específica del tipo. Parta del `config_example` del catálogo y ajústelo. Cada tipo de widget valida su propia configuración en el servidor y devuelve un `400` descriptivo si algo está mal.
- **`title_styling`** *(opcional)* — `{"bold": true, "size": "md"}`, donde `size` es `sm`, `md` o `lg`.

### El mapa de diseño (cuadrícula)

`layout` es un mapa que asocia el `id` de cada widget con su posición en la cuadrícula de 12 columnas:

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`, `y`** — coordenadas de la esquina superior izquierda de la cuadrícula (indexadas desde 0; `x` va de 0 a 11).
- **`w`, `h`** — ancho (en columnas) y alto (en filas).
- **`min_w`, `min_h`** *(opcional, valor predeterminado 1)* y **`max_w`, `max_h`** *(opcional)* — límites de tamaño.

> **🔑 Importante:** El mapa `layout` y la lista `widgets` deben ser consistentes: **cada widget necesita una posición, y cada posición debe hacer referencia a un widget que exista.** Una discrepancia devuelve `400`. El script de ciclo de vida que aparece más abajo construye ambos a la vez para que sus ID siempre coincidan.

### Cree el diseño

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/" \
  -d '{
    "name": "Exec Overview (API)",
    "widgets": [
      {"id": "11111111-1111-4111-8111-111111111111", "type": "count", "title": "Active Critical Findings",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban"}},
      {"id": "22222222-2222-4222-8222-222222222222", "type": "graph", "title": "Findings by Severity",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"duplicate": "false"}, "group_by": "severity", "aggregation": "count", "chart_type": "pie", "time_bucket": null, "limit": null, "stacked": false}}
    ],
    "layout": {
      "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2},
      "22222222-2222-4222-8222-222222222222": {"x": 3, "y": 0, "w": 9, "h": 4, "min_w": 3, "min_h": 3}
    },
    "settings": {}
  }'
```

La respuesta refleja el diseño guardado, incluido su nuevo `id`, además de campos auxiliares de solo lectura (`is_default`, `is_owned`, `is_catalog`, `category`, `icon`, y marcas de tiempo).

### Acciones personalizadas

| Acción | Llamada | Qué hace |
|--------|------|--------------|
| Establecer predeterminado | `POST /dashboards/layouts/{id}/set_default/` | Convierte este diseño en el que carga su página de inicio. Solo puede establecer como predeterminado un diseño que le pertenezca. |
| Clonar | `POST /dashboards/layouts/{id}/clone/` (cuerpo opcional `{"name": "..."}`) | Copia un diseño (propio o una plantilla compartida) a su espacio con nuevos ID de widget. Por defecto usa `"Copy of <name>"`. |
| Listar compartidos | `GET /dashboards/layouts/shared/` | Enumera todos los diseños compartidos: plantillas seleccionadas más las publicadas por el equipo. |
| Bootstrap | `GET /dashboards/layouts/for_current_user/` | Devuelve `{"results": [...your layouts...], "default_id": <id>}`. En la primera llamada, clona automáticamente la plantilla inicial para que siempre reciba al menos un diseño. |

Publicar un diseño compartido (`"is_shared": true` al crear o actualizar) requiere el rol global **Maintainer**.

## Paso 3: Renderice datos de widget (opcional)

Normalmente no necesita renderizar los datos usted mismo: el panel lo hace al mostrar un widget. Pero los mismos endpoints de `widget_data` están disponibles directamente, lo cual es útil para scripts o resúmenes de chat que quieran citar un número en tiempo real. Envíe el `config` del widget (o el subconjunto correspondiente) como cuerpo de la solicitud.

**Un conteo filtrado** (`POST`):

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**Una agregación por agrupación** (`POST`), los datos detrás de un Graph:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/aggregate/" \
  -d '{"model": "finding", "filters": {}, "group_by": "severity", "aggregation": "count"}'
```

```json
{
  "labels": ["Critical", "High", "Medium", "Low", "Info"],
  "series": [{"name": "count", "data": [15, 23, 8, 12, 5]}],
  "group_by": "severity",
  "group_by_label": "Severity",
  "model": "finding",
  "model_label": "Findings",
  "aggregation": "count",
  "time_bucket": null
}
```

El conjunto completo de acciones de `widget_data`:

| Acción | Método | Payload / parámetros clave | Devuelve |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | dimensiones de agrupación válidas |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | métricas válidas del modo de registros |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | series de tasa / numerador / denominador |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy` (1–2 dims) | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | bandas por ventana |
| `risk_matrix` | POST | `filters`, `x_dim?` | celdas EPSS × riesgo (solo finding) |
| `priority_histogram` | POST | `filters`, `bin_count?` | contenedores de histograma (solo finding) |
| `treemap` | POST | `filters`, `metric?` | árbol de portafolio anidado |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | celdas de calendario por día |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | series apiladas de bandas de antigüedad |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | series pareadas de MTTR/MTTD |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | series de creados vs. cerrados |
| `my_work` | GET | `?buckets=`, `?limit=` | sus asignaciones / menciones / revisiones pendientes |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | Hallazgos próximos a incumplir el SLA |
| `recent_activity` | GET | `?model=`, `?limit=` | feed de registros recientes |
| `saved_reports` | GET | `?limit=` | plantillas de informes guardadas *(requiere Reporting)* |
| `usage` | GET | — | desglose de uso de licencia *(requiere Maintainer)* |

## Todo junto: un script de ciclo de vida completo

El siguiente script ejecuta todo el flujo usando solo la biblioteca estándar de Python 3, sin `requests` ni paquetes de terceros. Lee el token desde `DD_IMPORTER_DOJO_API_TOKEN`, descubre el catálogo de widgets, construye un diseño de dos widgets (con la lista `widgets` y el mapa `layout` generados juntos para que sus ID siempre coincidan), lo crea, lo establece como predeterminado, lo lee de vuelta para verificarlo y escribe el ID creado en `created.json`.

Configure la URL de su instancia y ejecútelo:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_dashboard.py
```

```python
#!/usr/bin/env python3
"""Build a DefectDojo Pro dashboard layout end-to-end using only the stdlib."""

import json
import os
import urllib.error
import urllib.request
import uuid

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset


def api_request(method, path, body=None):
    """Make an authenticated request. Returns parsed JSON."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
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

    return json.loads(payload) if payload else {}


def make_widget(widget_type, title, config, *, x, y, w, h, min_w=2, min_h=2):
    """Build a (widget, position) pair sharing a freshly generated UUID."""
    widget_id = str(uuid.uuid4())
    widget = {
        "id": widget_id,
        "type": widget_type,
        "title": title,
        "refresh_interval": 0,
        "config": config,
    }
    position = {"x": x, "y": y, "w": w, "h": h, "min_w": min_w, "min_h": min_h}
    return widget_id, widget, position


def main():
    created = {}

    # 1. Discover the catalog so we build against real widget types.
    #    (We don't strictly need the response here, but fetching it first
    #    is the recommended pattern — copy a config_example as a starting
    #    point instead of guessing the config shape.)
    catalog = api_request("GET", "/dashboards/widget_catalog/")
    known_types = {w["type"] for w in catalog["widgets"]}
    for required in ("count", "graph"):
        if required not in known_types:
            raise SystemExit(f"Widget type {required!r} not in catalog.")
    print(f"Discovered {len(known_types)} widget types.")

    # 2. Build two widgets and their grid positions together.
    widgets = []
    layout = {}

    _id, widget, pos = make_widget(
        "count",
        "Active Critical Findings",
        {
            "model": "finding",
            "filters": {"status_any": "Active", "severity": "Critical"},
            "color": "danger",
            "icon": "fas fa-ban",
        },
        x=0, y=0, w=3, h=2,
    )
    widgets.append(widget)
    layout[_id] = pos

    _id, widget, pos = make_widget(
        "graph",
        "Findings by Severity",
        {
            "model": "finding",
            "filters": {"duplicate": "false"},
            "group_by": "severity",
            "aggregation": "count",
            "chart_type": "pie",
            "time_bucket": None,
            "limit": None,
            "stacked": False,
        },
        x=3, y=0, w=9, h=4, min_w=3, min_h=3,
    )
    widgets.append(widget)
    layout[_id] = pos

    # 3. Create the layout.
    created_layout = api_request("POST", "/dashboards/layouts/", {
        "name": "Exec Overview (API)",
        "widgets": widgets,
        "layout": layout,
        "settings": {},
    })
    layout_id = created_layout["id"]
    created["layout_id"] = layout_id
    print(f"Created layout id={layout_id} with {len(created_layout['widgets'])} widgets")

    # 4. Make it the default landing dashboard.
    api_request("POST", f"/dashboards/layouts/{layout_id}/set_default/")
    print(f"Set layout id={layout_id} as the default")

    # 5. Read it back to verify widgets + positions survived intact.
    verified = api_request("GET", f"/dashboards/layouts/{layout_id}/")
    assert verified["is_default"] is True, "Layout did not become the default"
    assert len(verified["widgets"]) == len(widgets), "Widget count mismatch"
    assert set(verified["layout"]) == {w["id"] for w in verified["widgets"]}, \
        "Layout map and widgets are out of sync"
    print("Verified: default set, widgets and positions consistent")

    # 6. Record the created ID for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Verifique lo que construyó

Debido a que las claves de filtro inválidas se descartan silenciosamente, la verificación es parte del flujo de trabajo, no una idea de último momento.

**Confirme que un diseño se guardó como se esperaba.** Tráigalo de vuelta con `GET` y revise `widgets` y `layout`:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

Para cada widget, compare el `config.filters` devuelto con lo que envió. Si falta un filtro que esperaba, su clave no era un filtro válido para ese modelo: verifíquela nuevamente contra los filtros de la vista de lista del objeto. Confirme que `is_default` sea `true` si lo estableció, y que cada clave en `layout` coincida con un `id` de widget.

**Verifique puntualmente los datos de un widget.** Renderice su endpoint de datos y confirme que el número sea el esperado:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**Corrija un widget con PATCH.** Un `PATCH` a `/dashboards/layouts/{id}/` con los `widgets` y `layout` completos los reemplaza: envíe el conjunto completo deseado, no uno parcial.

## Próximos pasos

- Cree y organice los mismos diseños de forma interactiva en la [interfaz de Paneles personalizables](../custom-dashboards/).
- Deje que un LLM diseñe y construya paneles por usted con la [integración de Paneles con LLM](../custom-dashboards-llm/).
