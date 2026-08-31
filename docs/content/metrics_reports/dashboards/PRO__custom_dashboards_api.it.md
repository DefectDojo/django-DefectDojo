---
title: Automatizzare le dashboard con l'API
description: Scopri il catalogo dei widget, crea e aggiorna i layout delle dashboard
  e visualizza i dati dei widget tramite la REST API di DefectDojo Pro
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: la REST API delle Dashboard personalizzabili (layout, catalogo widget e dati dei widget) è una funzionalità di DefectDojo Pro. È disattivata per impostazione predefinita: un superuser può attivare le Dashboard personalizzabili da **Impostazioni > Flag delle funzionalità** sia sulle istanze Cloud sia On-Premise.</span>

La REST API delle Dashboard personalizzabili ti permette di creare, interamente da codice, le stesse dashboard che assembleresti a mano nella [UI delle Dashboard](../custom-dashboards/). Puoi scoprire il catalogo dei widget, creare e aggiornare i layout, impostare quello predefinito, condividere i layout con il tuo team e persino visualizzare i dati di un widget su richiesta senza dover reimplementare il filtraggio di DefectDojo. La superficie dei layout è stata progettata come punto di ingresso principale per gli agenti AI che costruiscono dashboard, quindi le forme delle richieste sono deliberatamente introspezionabili.

Questa guida percorre l'intero ciclo di vita: autenticarsi, scoprire il vocabolario dei widget, creare un layout, quindi verificarlo e visualizzarlo.

## Autenticazione

Ogni richiesta si autentica con un token API personale inviato nell'header `Authorization` utilizzando il prefisso `Token` (non `Bearer`).

Ottieni il tuo token dalla UI di DefectDojo Pro in **Impostazioni utente → Chiave API v2**. Salvalo in una variabile d'ambiente in modo che non finisca mai nella cronologia della shell o in uno script sottoposto a commit:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

L'URL di base per tutte le chiamate è la tua istanza seguita da `/api/v2`:

```
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Header richiesti:

| Header | Valore | Quando |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Ogni richiesta |
| `Accept` | `application/json` | Ogni richiesta |
| `Content-Type` | `application/json` | `POST` / `PATCH` con corpo JSON |

Ecco un esempio minimo di richiesta autenticata:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 Important:** L'intera API delle Dashboard dipende dalla funzionalità Dashboard personalizzabili. Finché non viene attivata, ogni endpoint restituisce `403 Dashboards 2.0 is not enabled.` — vedi [Attivare le Dashboard personalizzabili](../custom-dashboards/#enabling-customizable-dashboards).

> **⚠️ Security Notice:** il tuo token API garantisce l'accesso completo ai tuoi dati DefectDojo. Non incollarlo mai in una chat, uno screenshot, un ticket o un file sottoposto a commit. Leggilo da una variabile d'ambiente, ruotalo se viene mai esposto e, quando possibile, assegna i token ad account di servizio con ambito limitato.

## Panoramica dell'API delle dashboard

L'API delle Dashboard è composta da tre gruppi di risorse, tutte sotto `/api/v2/dashboards/`.

| Risorsa | Percorso | Cos'è | Operazioni |
|----------|------|------------|------------|
| Layout | `/dashboards/layouts/` | Le tue dashboard salvate (e i modelli condivisi del team) | `GET` elenco, `POST` creazione, `GET {id}/`, `PATCH {id}/`, `DELETE {id}/`, oltre a `{id}/clone/`, `{id}/set_default/`, `shared/`, `for_current_user/` |
| Catalogo widget | `/dashboards/widget_catalog/` | Il menu dei tipi di widget + un esempio di configurazione per ciascuno | `GET` (sola lettura) |
| Dati widget | `/dashboards/widget_data/<action>/` | Dati resi disponibili su richiesta per un widget | 21 azioni per widget |

Questi endpoint accettano l'autenticazione Token, Session o Basic. L'autorizzazione per singola riga e l'ambito dei dati seguono lo standard controllo degli accessi basato sui ruoli di DefectDojo: condividere un layout non amplia mai ciò che i suoi visualizzatori possono vedere.

> **💡 Tip:** la UI Vue richiama un mirror interno di questi endpoint sotto `/api/vue/dashboard_v2/`. Automatizza sempre facendo riferimento ai percorsi stabili e rivolti al cliente `/api/v2/dashboards/` documentati qui.

## Passaggio 1: scopri il vocabolario

Ci sono tre elementi di un widget facili da sbagliare se li si indovina: il **tipo di widget**, la sua **dimensione di raggruppamento** (per i grafici) e i suoi **filtri**. L'API fornisce una fonte di verità per ciascuno di essi. Recuperali prima, poi costruisci in base a ciò che il server accetta realmente.

### Il catalogo dei widget

`GET /dashboards/widget_catalog/` restituisce ogni tipo di widget, la categoria a cui appartiene, l'endpoint o gli endpoint di dati su cui si basa e — cosa più utile — un `config_example` minimo e funzionante che puoi copiare come punto di partenza:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

La risposta ha questa forma (troncata):

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

Usa il `type` di un widget come `type` del widget, e il suo `config_example` come punto di partenza per il `config` del widget. Il catalogo elenca 26 tipi di widget nelle quattro categorie.

### Dimensioni di raggruppamento e metriche dei record

I widget grafico e classifica limitano ciò per cui puoi raggruppare o classificare a un elenco selezionato di valori consentiti. Scoprili per modello invece di indovinare:

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/` restituisce per ogni dimensione la `key` (il valore da passare come `group_by`), una `label` leggibile e un `kind`:

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

Il `kind` è importante: una dimensione `time` (come `date`) richiede di inviare anche un `time_bucket` (`day`/`week`/`month`/`quarter`/`year`); una dimensione `categorical` o `banded` no. Il campo `priority` non è intenzionalmente una dimensione di raggruppamento (è un punteggio continuo) — usa la dimensione `risk` per una vista a bande, oppure il widget dedicato **Priority Histogram**.

### Filtri

I `config.filters` di un widget usano la **stessa forma dei filtri della vista elenco dell'oggetto** — i valori che la pagina elenco emette nel proprio URL, non i parametri di query REST grezzi. Ad esempio, per i riscontri: `{"status_any": "Active"}`, `{"severity": "Critical"}`, `{"duplicate": "false"}`, `{"date_past_days": 7}`, `{"sla_days_remaining_less_than_equal_to": 7}`; per gli asset: `{"grade": "A,B,C"}`, `{"last_scanned_past_days": 90}`. Il modo più rapido per individuare il filtro giusto per una necessità è applicarlo nella pagina elenco pertinente della UI e rileggerlo dalla finestra di configurazione del widget, oppure copiare i filtri dai modelli condivisi precaricati.

> **🔑 Important:** le chiavi di filtro sconosciute **vengono ignorate silenziosamente** — un filtro scritto male o inesistente non genera un errore, semplicemente non viene applicato, lasciando che il widget mostri una popolazione più ampia del previsto. I *valori* non validi per un filtro reale restituiscono `400`. [Verifica sempre ciò che hai costruito](#verify-what-you-built) rileggendo il layout. (I filtri vengono validati tramite lo stesso FilterSet usato dalla vista elenco, quindi i valori di lista possono essere passati come array per una corrispondenza "any-of": `{"severity": ["Critical", "High"]}`.)

> **💡 Tip:** la maggior parte dei widget accetta un `model` pari a `finding`, `product`, `engagement` o `test` — nota il valore legacy `product` (la UI li chiama **Assets**). Il widget **Embedded Table** è l'eccezione: il suo `model` usa i nomi più recenti `finding`, `asset`, `engagement`, `test`, `risk_acceptance`, `organization` o `test_type`.

## Passaggio 2: crea un layout

Un layout viene creato con una `POST` a `/dashboards/layouts/`. I due campi che contengono il contenuto della dashboard sono `widgets` e `layout`, e devono essere coerenti tra loro.

### L'oggetto widget

Ogni voce nell'array `widgets` ha questa forma:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** — un UUID che generi tu. Collega il widget alla sua posizione nella griglia.
- **`type`** — un valore `type` tratto dal catalogo dei widget.
- **`title`** — l'intestazione mostrata sul widget (fino a 200 caratteri).
- **`refresh_interval`** — secondi di aggiornamento automatico; uno tra `0` (disattivato), `30`, `60`, `300` o `900`.
- **`config`** — la configurazione specifica del tipo. Parti dal `config_example` del catalogo e adattalo. Ogni tipo di widget valida la propria configurazione lato server e restituisce un `400` descrittivo in caso di errore.
- **`title_styling`** *(opzionale)* — `{"bold": true, "size": "md"}`, dove `size` è `sm`, `md` o `lg`.

### La mappa del layout (griglia)

`layout` è una mappa che associa l'`id` di ogni widget alla sua posizione nella griglia a 12 colonne:

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`, `y`** — coordinate della griglia in alto a sinistra (a partire da 0; `x` va da 0 a 11).
- **`w`, `h`** — larghezza (in colonne) e altezza (in righe).
- **`min_w`, `min_h`** *(opzionale, predefinito 1)* e **`max_w`, `max_h`** *(opzionale)* — limiti dimensionali.

> **🔑 Important:** la mappa `layout` e l'elenco `widgets` devono essere coerenti: **ogni widget ha bisogno di una posizione, e ogni posizione deve fare riferimento a un widget esistente.** Una discordanza restituisce `400`. Lo script del ciclo di vita riportato sotto costruisce entrambi insieme, in modo che i loro ID corrispondano sempre.

### Crea il layout

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

La risposta restituisce il layout salvato, incluso il suo nuovo `id`, oltre a campi ausiliari di sola lettura (`is_default`, `is_owned`, `is_catalog`, `category`, `icon` e i timestamp).

### Azioni personalizzate

| Azione | Chiamata | Cosa fa |
|--------|------|--------------|
| Imposta come predefinito | `POST /dashboards/layouts/{id}/set_default/` | Rende questo layout quello caricato dalla tua home page. Puoi impostare come predefinito solo un layout di tua proprietà. |
| Clona | `POST /dashboards/layouts/{id}/clone/` (corpo opzionale `{"name": "..."}`) | Copia un layout (tuo o un modello condiviso) nel tuo spazio con nuovi ID widget. Il valore predefinito è `"Copy of <name>"`. |
| Elenca condivisi | `GET /dashboards/layouts/shared/` | Elenca ogni layout condiviso — modelli curati più quelli pubblicati dal team. |
| Bootstrap | `GET /dashboards/layouts/for_current_user/` | Restituisce `{"results": [...your layouts...], "default_id": <id>}`. Alla prima chiamata, clona automaticamente il modello iniziale in modo che tu riceva sempre almeno un layout. |

Pubblicare un layout condiviso (`"is_shared": true` in creazione o aggiornamento) richiede il ruolo globale **Maintainer**.

## Passaggio 3: visualizza i dati del widget (opzionale)

Di solito non è necessario visualizzare i dati da soli: è la dashboard a farlo quando mostra un widget. Ma gli stessi endpoint `widget_data` sono disponibili direttamente, il che è utile per script o riepiloghi in chat che vogliono citare un numero in tempo reale. Invia il `config` del widget (o il sottoinsieme rilevante) come payload.

**Un conteggio filtrato** (`POST`):

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**Un'aggregazione con raggruppamento** (`POST`), i dati alla base di un grafico:

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

L'insieme completo delle azioni `widget_data`:

| Azione | Metodo | Payload/parametri principali | Restituisce |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | dimensioni di raggruppamento valide |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | metriche valide in modalità record |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | serie di tasso / numeratore / denominatore |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy` (1–2 dimensioni) | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | bande per finestra temporale |
| `risk_matrix` | POST | `filters`, `x_dim?` | celle EPSS × rischio (solo riscontri) |
| `priority_histogram` | POST | `filters`, `bin_count?` | bin dell'istogramma (solo riscontri) |
| `treemap` | POST | `filters`, `metric?` | albero del portafoglio annidato |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | celle calendario per giorno |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | serie impilate per fascia di anzianità |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | serie MTTR/MTTD abbinate |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | serie creati vs chiusi |
| `my_work` | GET | `?buckets=`, `?limit=` | i tuoi incarichi / menzioni / revisioni in sospeso |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | riscontri vicini alla violazione SLA |
| `recent_activity` | GET | `?model=`, `?limit=` | feed dei record recenti |
| `saved_reports` | GET | `?limit=` | modelli di report salvati *(richiede Reporting)* |
| `usage` | GET | — | ripartizione dell'utilizzo della licenza *(richiede Maintainer)* |

## Mettendo tutto insieme: uno script completo del ciclo di vita

Lo script seguente esegue l'intero flusso usando solo la libreria standard di Python 3 — niente `requests`, niente pacchetti di terze parti. Legge il token da `DD_IMPORTER_DOJO_API_TOKEN`, scopre il catalogo dei widget, costruisce un layout a due widget (con l'elenco `widgets` e la mappa `layout` generati insieme in modo che i loro ID corrispondano sempre), lo crea, lo imposta come predefinito, lo rilegge per verificarlo e scrive l'ID creato in `created.json`.

Imposta l'URL della tua istanza ed eseguilo:

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

## Verifica ciò che hai costruito

Poiché le chiavi di filtro non valide vengono scartate silenziosamente, la verifica fa parte del flusso di lavoro, non è un ripensamento.

**Conferma che un layout sia stato salvato come previsto.** Rileggilo con `GET` e controlla `widgets` e `layout`:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

Per ogni widget, confronta i `config.filters` restituiti con quelli inviati. Se manca un filtro che ti aspettavi, la sua chiave non era un filtro valido per quel modello — ricontrollala rispetto ai filtri della vista elenco dell'oggetto. Conferma che `is_default` sia `true` se lo hai impostato, e che ogni chiave in `layout` corrisponda a un `id` di widget.

**Controlla a campione i dati di un widget.** Visualizza il suo endpoint dei dati e conferma che il numero sia quello atteso:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**Correggi un widget con PATCH.** Una `PATCH` a `/dashboards/layouts/{id}/` con i `widgets` e il `layout` completi li sostituisce — invia l'insieme completo desiderato, non uno parziale.

## Prossimi passi

- Crea e disponi gli stessi layout in modo interattivo nella [UI delle Dashboard personalizzabili](../custom-dashboards/).
- Lascia che un LLM progetti e crei le dashboard per te con l'[integrazione LLM per le Dashboard](../custom-dashboards-llm/).
