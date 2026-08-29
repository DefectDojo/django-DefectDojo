---
title: Dashboards über die API automatisieren
description: Entdecken Sie den Widget-Katalog, erstellen und aktualisieren Sie Dashboard-Layouts
  und rendern Sie Widget-Daten über die DefectDojo Pro REST API
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Die REST-API für anpassbare Dashboards (Layouts, Widget-Katalog und Widget-Daten) ist eine DefectDojo-Pro-Funktion. Sie ist standardmäßig deaktiviert – ein Superuser kann anpassbare Dashboards unter **Einstellungen > Feature-Flags** sowohl in Cloud- als auch in On-Premise-Instanzen aktivieren.</span>

Die REST-API für anpassbare Dashboards ermöglicht es Ihnen, dieselben Dashboards, die Sie manuell in der [Dashboard-Benutzeroberfläche](../custom-dashboards/) zusammenstellen, vollständig per Code zu erstellen. Sie können den Widget-Katalog erkunden, Layouts erstellen und aktualisieren, Ihr Standard-Layout festlegen, Layouts mit Ihrem Team teilen und sogar die Daten eines Widgets bei Bedarf rendern, ohne die Filterung von DefectDojo neu zu implementieren. Die Layout-Oberfläche wurde als primärer Einstiegspunkt für KI-Agenten konzipiert, die Dashboards erstellen, weshalb die Anfragestrukturen bewusst introspektierbar gestaltet sind.

Dieser Leitfaden führt Sie durch den gesamten Lebenszyklus: authentifizieren, das Widget-Vokabular erkunden, ein Layout erstellen und es anschließend verifizieren und rendern.

## Authentifizierung

Jede Anfrage authentifiziert sich mit einem persönlichen API-Token, das im `Authorization`-Header mit dem Präfix `Token` (nicht `Bearer`) gesendet wird.

Sie erhalten Ihr Token in der DefectDojo Pro-Benutzeroberfläche unter **Benutzereinstellungen → API v2 Key**. Speichern Sie es in einer Umgebungsvariable, damit es niemals in Ihrem Shell-Verlauf oder einem committeten Skript landet:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

Die Basis-URL für alle Aufrufe ist Ihre Instanz plus `/api/v2`:

```
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Erforderliche Header:

| Header | Wert | Wann |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Bei jeder Anfrage |
| `Accept` | `application/json` | Bei jeder Anfrage |
| `Content-Type` | `application/json` | Bei `POST` / `PATCH` mit JSON-Body |

Eine minimale authentifizierte Anfrage sieht so aus:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 Wichtig:** Die gesamte Dashboards-API hängt von der Funktion für anpassbare Dashboards ab. Solange sie nicht aktiviert ist, liefert jeder Endpunkt `403 Dashboards 2.0 is not enabled.` – siehe [Anpassbare Dashboards aktivieren](../custom-dashboards/#enabling-customizable-dashboards).

> **⚠️ Sicherheitshinweis:** Ihr API-Token gewährt vollständigen Zugriff auf Ihre DefectDojo-Daten. Fügen Sie es niemals in einen Chat, einen Screenshot, ein Ticket oder eine committete Datei ein. Lesen Sie es aus einer Umgebungsvariable, rotieren Sie es, falls es jemals offengelegt wird, und beschränken Sie Tokens nach Möglichkeit auf Service-Konten.

## Die Dashboards-API im Überblick

Die Dashboards-API besteht aus drei Ressourcengruppen, alle unter `/api/v2/dashboards/`.

| Ressource | Pfad | Was es ist | Operationen |
|----------|------|------------|------------|
| Layouts | `/dashboards/layouts/` | Ihre gespeicherten Dashboards (und geteilte Team-Vorlagen) | `GET` list, `POST` create, `GET {id}/`, `PATCH {id}/`, `DELETE {id}/`, plus `{id}/clone/`, `{id}/set_default/`, `shared/`, `for_current_user/` |
| Widget-Katalog | `/dashboards/widget_catalog/` | Das Menü der Widget-Typen + ein Konfigurationsbeispiel für jeden | `GET` (nur lesend) |
| Widget-Daten | `/dashboards/widget_data/<action>/` | Bei Bedarf gerenderte Daten für ein Widget | 21 Aktionen pro Widget |

Diese Endpunkte akzeptieren Token-, Session- oder Basic-Authentifizierung. Die Autorisierung und der Datenumfang pro Zeile folgen der Standard-rollenbasierten Zugriffskontrolle von DefectDojo – das Teilen eines Layouts erweitert niemals, was dessen Betrachter sehen können.

> **💡 Tipp:** Die Vue-Benutzeroberfläche ruft eine interne Spiegelung dieser Endpunkte unter `/api/vue/dashboard_v2/` auf. Automatisieren Sie immer gegen die hier dokumentierten, stabilen und kundenseitig zugänglichen Pfade unter `/api/v2/dashboards/`.

## Schritt 1: Das Vokabular erkunden

Drei Dinge an einem Widget lassen sich leicht falsch raten: der **Widget-Typ**, seine **Gruppierungsdimension** (bei Diagrammen) und seine **Filter**. Die API liefert für jedes davon eine verlässliche Quelle. Rufen Sie diese zuerst ab und bauen Sie dann auf dem auf, was der Server tatsächlich akzeptiert.

### Der Widget-Katalog

`GET /dashboards/widget_catalog/` liefert jeden Widget-Typ, die Kategorie, zu der er gehört, den bzw. die Daten-Endpunkt(e), gegen die er rendert, und – am nützlichsten – ein minimales, funktionierendes `config_example`, das Sie als Ausgangspunkt kopieren können:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

Die Antwort ist folgendermaßen aufgebaut (gekürzt):

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

Verwenden Sie den `type` eines Widgets als `type` des Widgets und dessen `config_example` als Ausgangspunkt für die `config` des Widgets. Der Katalog listet 26 Widget-Typen in den vier Kategorien auf.

### Gruppierungsdimensionen und Datensatzmetriken

Die Diagramm- und Rangliste-Widgets beschränken die Gruppierungs- und Sortiermöglichkeiten auf eine kuratierte Positivliste. Ermitteln Sie diese pro Modell, anstatt sie zu erraten:

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/` liefert für jede Dimension deren `key` (der als `group_by` zu übergebende Wert), ein für Menschen lesbares `label` und eine `kind`:

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

Die `kind` ist wichtig: Eine `time`-Dimension (wie `date`) erfordert, dass Sie zusätzlich ein `time_bucket` (`day`/`week`/`month`/`quarter`/`year`) senden; eine `categorical`- oder `banded`-Dimension benötigt dies nicht. Das Feld `priority` ist bewusst **keine** Gruppierungsdimension (es handelt sich um einen kontinuierlichen Score) – verwenden Sie für eine gebänderte Ansicht die Dimension `risk` oder das eigene Widget **Prioritäts-Histogramm**.

### Filter

Die `config.filters` eines Widgets verwenden **dieselbe Filterstruktur wie die Listenansicht des Objekts** – die Werte, die die Listenseite in ihre URL schreibt, nicht die rohen REST-Query-Parameter. Zum Beispiel bei Befunden: `{"status_any": "Active"}`, `{"severity": "Critical"}`, `{"duplicate": "false"}`, `{"date_past_days": 7}`, `{"sla_days_remaining_less_than_equal_to": 7}`; bei Assets: `{"grade": "A,B,C"}`, `{"last_scanned_past_days": 90}`. Der schnellste Weg, den richtigen Filter für einen Bedarf zu finden, besteht darin, ihn auf der entsprechenden Listenseite in der Benutzeroberfläche anzuwenden und ihn aus dem Widget-Konfigurationsdialog wieder auszulesen, oder die Filter aus den mitgelieferten geteilten Vorlagen zu kopieren.

> **🔑 Wichtig:** Unbekannte Filter-**Schlüssel werden stillschweigend ignoriert** – ein falsch geschriebener oder nicht existierender Filter löst keinen Fehler aus, er wird einfach nicht angewendet, wodurch das Widget eine größere Population anzeigt als beabsichtigt. Ungültige *Werte* für einen echten Filter liefern `400`. Verifizieren Sie immer [was Sie gebaut haben](#verify-what-you-built), indem Sie das Layout zurücklesen. (Filter werden über dasselbe FilterSet validiert, das auch die Listenansicht verwendet, sodass Listenwerte als Arrays für „Any-of"-Abgleich übergeben werden können: `{"severity": ["Critical", "High"]}`.)

> **💡 Tipp:** Die meisten Widgets verwenden ein `model` von `finding`, `product`, `engagement` oder `test` – beachten Sie das veraltete `product` (die Benutzeroberfläche nennt diese **Assets**). Das Widget **Eingebettete Tabelle** ist die Ausnahme: Sein `model` verwendet die neueren Bezeichnungen `finding`, `asset`, `engagement`, `test`, `risk_acceptance`, `organization` oder `test_type`.

## Schritt 2: Ein Layout erstellen

Ein Layout wird mit einem `POST` an `/dashboards/layouts/` erstellt. Die beiden Felder, die den Inhalt des Dashboards tragen, sind `widgets` und `layout`, und sie müssen miteinander übereinstimmen.

### Das Widget-Objekt

Jeder Eintrag im `widgets`-Array hat diese Form:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** – eine von Ihnen generierte UUID. Sie verknüpft das Widget mit seiner Position im Raster.
- **`type`** – ein `type`-Wert aus dem Widget-Katalog.
- **`title`** – die auf dem Widget angezeigte Überschrift (bis zu 200 Zeichen).
- **`refresh_interval`** – automatische Aktualisierung in Sekunden; einer der Werte `0` (aus), `30`, `60`, `300` oder `900`.
- **`config`** – die typspezifische Konfiguration. Beginnen Sie mit dem `config_example` aus dem Katalog und passen Sie es an. Jeder Widget-Typ validiert seine eigene Konfiguration serverseitig und liefert bei einem Fehler ein aussagekräftiges `400`.
- **`title_styling`** *(optional)* – `{"bold": true, "size": "md"}`, wobei `size` `sm`, `md` oder `lg` sein kann.

### Die Layout-(Raster-)Zuordnung

`layout` ist eine Zuordnung von der `id` jedes Widgets zu seiner Position im 12-Spalten-Raster:

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`, `y`** – Rasterkoordinaten oben links (nullbasiert; `x` reicht von 0–11).
- **`w`, `h`** – Breite (in Spalten) und Höhe (in Zeilen).
- **`min_w`, `min_h`** *(optional, Standard 1)* und **`max_w`, `max_h`** *(optional)* – Größenbeschränkungen.

> **🔑 Wichtig:** Die `layout`-Zuordnung und die `widgets`-Liste müssen konsistent sein: **Jedes Widget benötigt eine Position, und jede Position muss auf ein vorhandenes Widget verweisen.** Bei einer Abweichung wird `400` zurückgegeben. Das untenstehende Lifecycle-Skript erstellt beides gemeinsam, sodass die IDs immer übereinstimmen.

### Das Layout erstellen

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

Die Antwort gibt das gespeicherte Layout einschließlich seiner neuen `id` zurück, zusätzlich zu schreibgeschützten Hilfsfeldern (`is_default`, `is_owned`, `is_catalog`, `category`, `icon` und Zeitstempeln).

### Benutzerdefinierte Aktionen

| Aktion | Aufruf | Was sie tut |
|--------|------|--------------|
| Als Standard festlegen | `POST /dashboards/layouts/{id}/set_default/` | Legt dieses Layout als das fest, das Ihre Startseite lädt. Sie können nur ein Layout, das Ihnen gehört, als Standard festlegen. |
| Klonen | `POST /dashboards/layouts/{id}/clone/` (optionaler Body `{"name": "..."}`) | Kopiert ein Layout (Ihr eigenes oder eine geteilte Vorlage) mit neuen Widget-IDs in Ihren Bereich. Standardmäßig `"Copy of <name>"`. |
| Geteilte auflisten | `GET /dashboards/layouts/shared/` | Listet jedes geteilte Layout auf – kuratierte Vorlagen sowie vom Team veröffentlichte. |
| Bootstrap | `GET /dashboards/layouts/for_current_user/` | Liefert `{"results": [...Ihre Layouts...], "default_id": <id>}`. Beim ersten Aufruf wird automatisch die Startvorlage geklont, sodass Sie immer mindestens ein Layout zurückerhalten. |

Das Veröffentlichen eines geteilten Layouts (`"is_shared": true` beim Erstellen oder Aktualisieren) erfordert die globale Rolle **Maintainer**.

## Schritt 3: Widget-Daten rendern (optional)

In der Regel müssen Sie Daten nicht selbst rendern – das Dashboard erledigt dies, wenn es ein Widget anzeigt. Dieselben `widget_data`-Endpunkte stehen jedoch auch direkt zur Verfügung, was praktisch ist für Skripte oder Chat-Zusammenfassungen, die eine aktuelle Zahl zitieren möchten. Senden Sie die `config` des Widgets (oder den relevanten Teil davon) als Payload.

**Eine gefilterte Anzahl** (`POST`):

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**Eine Gruppierungs-Aggregation** (`POST`), die Daten hinter einem Graph:

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

Der vollständige Satz an `widget_data`-Aktionen:

| Aktion | Methode | Wichtige Payload / Parameter | Rückgabe |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | gültige Gruppierungsdimensionen |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | gültige Metriken im Datensatz-Modus |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | Rate-/Zähler-/Nenner-Serien |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy` (1–2 Dimensionen) | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | Bänder pro Zeitfenster |
| `risk_matrix` | POST | `filters`, `x_dim?` | EPSS-×-Risiko-Zellen (nur Befunde) |
| `priority_histogram` | POST | `filters`, `bin_count?` | Histogramm-Bins (nur Befunde) |
| `treemap` | POST | `filters`, `metric?` | verschachtelter Portfolio-Baum |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | Kalenderzellen pro Tag |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | gestapelte Alters-Band-Serien |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | gepaarte MTTR-/MTTD-Serien |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | Serie „Erstellt vs. Geschlossen" |
| `my_work` | GET | `?buckets=`, `?limit=` | Ihre Zuweisungen / Erwähnungen / ausstehende Überprüfungen |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | Befunde, die kurz vor einer SLA-Verletzung stehen |
| `recent_activity` | GET | `?model=`, `?limit=` | Feed der letzten Datensätze |
| `saved_reports` | GET | `?limit=` | gespeicherte Berichtsvorlagen *(erfordert Reporting)* |
| `usage` | GET | — | Aufschlüsselung der Lizenznutzung *(erfordert Maintainer)* |

## Alles zusammenfügen: ein vollständiges Lifecycle-Skript

Das folgende Skript führt den gesamten Ablauf nur mit der Python-3-Standardbibliothek aus – ohne `requests`, ohne Drittanbieter-Pakete. Es liest das Token aus `DD_IMPORTER_DOJO_API_TOKEN`, ermittelt den Widget-Katalog, erstellt ein Layout mit zwei Widgets (wobei die `widgets`-Liste und die `layout`-Zuordnung gemeinsam generiert werden, sodass ihre IDs immer übereinstimmen), legt es an, setzt es als Standard, liest es zur Verifizierung zurück und schreibt die erzeugte ID in `created.json`.

Legen Sie die URL Ihrer Instanz fest und führen Sie es aus:

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

## Verifizieren, was Sie gebaut haben

Da ungültige Filterschlüssel stillschweigend verworfen werden, ist die Verifizierung Teil des Workflows – kein nachträglicher Gedanke.

**Bestätigen Sie, dass ein Layout wie beabsichtigt gespeichert wurde.** Rufen Sie es mit `GET` ab und prüfen Sie `widgets` und `layout`:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

Vergleichen Sie für jedes Widget die zurückgegebenen `config.filters` mit dem, was Sie gesendet haben. Fehlt ein erwarteter Filter, war sein Schlüssel für dieses Modell kein gültiger Filter – überprüfen Sie ihn anhand der Listenansicht-Filter des Objekts. Bestätigen Sie, dass `is_default` `true` ist, falls Sie es gesetzt haben, und dass jeder Schlüssel in `layout` einer Widget-`id` entspricht.

**Prüfen Sie stichprobenartig die Daten eines Widgets.** Rendern Sie dessen Daten-Endpunkt und bestätigen Sie, dass die Zahl Ihren Erwartungen entspricht:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**Korrigieren Sie ein Widget mit PATCH.** Ein `PATCH` an `/dashboards/layouts/{id}/` mit vollständigen `widgets` und `layout` ersetzt diese – senden Sie den vollständigen gewünschten Satz, keinen Teilsatz.

## Nächste Schritte

- Erstellen und ordnen Sie dieselben Layouts interaktiv in der [Benutzeroberfläche für anpassbare Dashboards](../custom-dashboards/) an.
- Lassen Sie ein LLM Dashboards für Sie entwerfen und erstellen mit der [Dashboards-LLM-Integration](../custom-dashboards-llm/).
