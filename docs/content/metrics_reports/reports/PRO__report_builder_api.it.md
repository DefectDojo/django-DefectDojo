---
title: Automazione dei report tramite l'API
description: Crea temi, blocchi e modelli, quindi esegui i report e scarica i risultati
  tramite la REST API di DefectDojo Pro
draft: false
audience: pro
weight: 21
slug: report-builder-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: la REST API del Generatore di report (temi, blocchi, modelli e report generati) è una funzionalità di DefectDojo Pro, attualmente in versione beta.</span>

La REST API del Generatore di report ti permette di automatizzare gli stessi Temi, Blocchi e Modelli che assembli manualmente nella [interfaccia del Generatore di report](../report-builder/) — e va un passo oltre, permettendoti di **eseguire** un modello e **scaricare** il PDF o l'HTML finito. Questa guida percorre l'intero ciclo di vita: autenticarsi, scoprire il vocabolario di campi e filtri, creare i blocchi costitutivi, quindi generare e recuperare un report.

> **Cerchi invece un'esportazione rapida dei riscontri?** Se ti serve solo un elenco semplice di riscontri in formato JSON, HTML, CSV o Excel — senza temi, blocchi o modelli da configurare — usa l'endpoint più semplice `generate_report/` documentato in [Generazione dei Report](/automation/api/api-v2-docs/#generating-reports). L'API del Generatore di report descritta in questa pagina serve per costruire report progettati e multi\-sezione.

## Autenticazione

Ogni richiesta si autentica con un token API personale inviato nell'header `Authorization` usando il prefisso `Token` (non `Bearer`).

Ottieni il tuo token dall'interfaccia di DefectDojo Pro in **Impostazioni utente → Chiave API v2**. Salvalo in una variabile d'ambiente in modo che non finisca mai nella cronologia della shell o in uno script sottoposto a commit:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

L'URL base per tutte le chiamate è la tua istanza più `/api/v2`:

```text
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Header richiesti:

| Header | Valore | Quando |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Ogni richiesta |
| `Accept` | `application/json` | Ogni richiesta |
| `Content-Type` | `application/json` | `POST` / `PATCH` con un corpo JSON |

Una richiesta autenticata minima è simile a questa:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

Gli endpoint di elenco sono paginati con i parametri di query `limit` e `offset`.

> **⚠️ Avviso di sicurezza:** il tuo token API garantisce accesso completo ai tuoi dati DefectDojo. Non incollarlo mai in una chat, in uno screenshot, in un ticket o in un file sottoposto a commit. Leggilo da una variabile d'ambiente, ruotalo se viene mai esposto e, dove possibile, assegna i token ad account di servizio.

## Panoramica dell'API di reportistica

Quattro risorse compongono l'API del Generatore di report. Ognuna supporta le operazioni standard di elenco (`GET`), creazione (`POST`), recupero (`GET {id}/`), aggiornamento (`PATCH {id}/`) ed eliminazione (`DELETE {id}/`), oltre ad alcune azioni personalizzate.

| Risorsa | Percorso | Cos'è | Azioni personalizzate |
|----------|------|------------|----------------|
| Temi | `/report_themes/` | Colori, font, immagini di intestazione/piè di pagina, numeri di pagina | — |
| Blocchi | `/report_blocks/` | Un singolo elemento di contenuto: una copertina, una tabella o una sezione di dettaglio | `field_options/`, `preview/`, `{id}/preview/`, `{id}/duplicate/` |
| Modelli | `/report_templates/` | Un elenco ordinato di blocchi più un tema | `{id}/duplicate/` |
| Report generati | `/generated_reports/` | Un'esecuzione di un modello che produce un file scaricabile | `{id}/download/` |

Altri due endpoint ti aiutano a scoprire il vocabolario di cui hai bisogno:

| Endpoint | Scopo |
|----------|---------|
| `GET /report_blocks/field_options/` | Percorsi validi dei campi colonna e opzioni di ordinamento per ogni modello |
| `GET /oa3/schema/?format=json` | Lo schema OpenAPI completo — usato per scoprire i nomi dei filtri validi |

## Passaggio 1: scoprire il vocabolario

In un blocco ci sono due cose facili da sbagliare se si va a intuito: i **campi colonna** che elenchi e i **filtri** che applichi. L'API ti fornisce una fonte di verità per entrambi. Recuperali prima, poi costruisci sulla base di ciò che il server accetta effettivamente.

### Campi colonna e ordinamento

`field_options` restituisce i `fields` (percorsi delle colonne) e gli `ordering_fields` validi per ogni modello che puoi inserire in un blocco tabellare o di dettaglio:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

La risposta ha questa forma (troncata):

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

Usa solo i valori `path` restituiti qui per l'elenco `fields` di un blocco. Alcuni percorsi sono in formato lungo o markdown e sono pensati per i blocchi di **dettaglio** piuttosto che per colonne tabellari strette — `field_options` è l'elenco autorevole, quindi verifica su di esso invece di codificare a priori un insieme esaustivo.

### Nomi dei filtri dallo schema

I filtri di un blocco risiedono in `filter_entries`, dove ogni voce è una coppia `{field, value}`. I nomi `field` validi sono i **nomi dei parametri di query GET** dell'endpoint REST dell'entità sottostante — *non* le etichette che vedi nell'interfaccia. Scoprili leggendo lo schema OpenAPI:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

Poi leggi i parametri GET per l'entità che stai filtrando. Per i riscontri, guarda `paths` → `/api/v2/findings/` → `get` → `parameters`. Gli endpoint analoghi sono `/api/v2/assets/` per gli **asset** (in precedenza Prodotti), `/api/v2/organizations/` per le **organizzazioni** (in precedenza Tipi di prodotto), `/api/v2/engagements/`, `/api/v2/tests/`, `/api/v2/test_types/` e `/api/v2/risk_acceptance/`. Ogni `name` dei parametri è un `field` di filtro valido.

> **💡 Suggerimento:** in DefectDojo Pro, gli **Asset** si chiamavano in precedenza **Prodotti** e le **Organizzazioni** erano in precedenza **Tipi di prodotto**. I percorsi dei campi filtro sottostanti sui riscontri usano ancora la vecchia dicitura `product` (ad esempio, `test__engagement__product`), anche se le entità ora sono Asset e Organizzazioni.

> **🔑 Importante:** il server **elimina silenziosamente** qualsiasi `filter_entry` il cui `field` non sia un parametro GET reale per quel modello. Non viene sollevato alcun errore — il filtro semplicemente non esiste nel blocco salvato. Recupera sempre il blocco con una GET dopo averlo creato e confronta i `filter_entries` restituiti con quelli che hai inviato.

### Campi filtro comuni

Le tabelle seguenti elencano filtri verificati e di alto valore. Tutti i valori vengono inviati come **stringhe a valore singolo**; i booleani sono le stringhe letterali `"true"` / `"false"`.

**Filtri sui riscontri**

| Campo | Valore di esempio | Note |
|-------|---------------|-------|
| `active` | `"true"` | Stringa booleana |
| `verified` | `"true"` | Stringa booleana |
| `is_mitigated` | `"false"` | Stringa booleana |
| `risk_accepted` | `"false"` | Stringa booleana |
| `duplicate` | `"false"` | Stringa booleana |
| `false_p` | `"false"` | Stringa booleana |
| `out_of_scope` | `"false"` | Stringa booleana |
| `severity` | `"Critical"` | Solo valore singolo — **non** separato da virgole. Usa un blocco per ogni gravità. |
| `known_exploited` | `"true"` | Stringa booleana |
| `ransomware_used` | `"true"` | Stringa booleana |
| `outside_of_sla` | `"1"` | Stringa **numerica**, non una stringa booleana |
| `priority_min` | `"800"` | Usa `_min`/`_max`, non `_greater_than` |
| `priority_max` | `"1000"` | Usa `_min`/`_max` |
| `tag` | `"DR"` | Un singolo tag |
| `tags` | `"kev,pci"` | Corrispondenza su almeno uno (any-of) |
| `tags__and` | `"kev,pci"` | Corrispondenza su tutti (all-of, deve corrispondere a ogni tag elencato) |
| `test__engagement__product` | `"42"` | ID dell'asset (gli Asset erano in precedenza Prodotti) |
| `test__engagement__product__prod_type` | `"3"` | ID dell'organizzazione (in precedenza Tipo di prodotto) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**Filtri sugli asset** (gli Asset si chiamavano in precedenza Prodotti; questi sono i parametri su `/api/v2/assets/`)

| Campo | Valore di esempio | Note |
|-------|---------------|-------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | Stringa booleana |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | Un singolo tag |

**Filtri sull'accettazione del rischio**

| Campo | Valore di esempio | Note |
|-------|---------------|-------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | ID utente |
| `expiration_date_before` | `"2025-12-31"` | Su questo modello non esiste alcun filtro `tag` |

Per i blocchi di **engagement**, **test**, **tipo di test** e **organizzazione**, leggi i parametri GET direttamente dallo schema come descritto sopra. Tra quelli di alto valore ci sono `engagement__product` e `status` sui test, e `name` sui tipi di test — ma verifica sempre il nome esatto in `schema.json` prima di affidarti ad esso.

> **⚠️** Questi nomi legacy / in stile interfaccia utente vengono **eliminati silenziosamente** e NON devono essere usati: `status_any`, `priority_greater_than`, `severity__in`, `mitigated_within_sla` e qualsiasi valore di `severity` **separato da virgole** (ad es. `"Critical,High"`). Usa invece i nomi reali dei parametri di query dallo schema, e suddividi le esigenze multi-gravità in blocchi separati.

> **🔑 Importante:** una `PATCH` che include `filter_entries` **sostituisce l'intero elenco** — non esiste alcuna unione (merge). Invia sempre l'insieme completo desiderato di filtri a ogni aggiornamento, altrimenti eliminerai quelli che ometti.

## Passaggio 2: creare tema, blocchi e modelli

Costruisci gli elementi nell'ordine di dipendenza: un **tema**, poi i **blocchi**, quindi un **modello** che fa riferimento a entrambi.

### Creare un tema

I colori sono stringhe esadecimali di 7 caratteri. Qualsiasi campo che ometti torna al suo valore predefinito (primario `#1e3a5f`, secondario `#4a90a4`, accento `#e67e22`, testo `#333333`, sfondo `#ffffff`).

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

La risposta include l'`id` del nuovo tema. Le immagini di intestazione e piè di pagina sono opzionali e vengono caricate come campi di un modulo multipart (`header_image` / `footer_image`); l'esempio JSON sopra le omette.

### Creare blocchi

Un blocco ha un `name`, un `block_type` e un oggetto di configurazione corrispondente. I valori supportati per `block_type` sono `stock`, `tabular` e `detail`. (Nel modello dati esiste un tipo `chart`, ma non è ancora esposto tramite l'API.)

**Una copertina stock.** I blocchi stock contengono contenuto fisso. `stock_type` è uno tra `cover_page`, `table_of_contents`, `page_break`, `image` o `text_block`.

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

**Un blocco tabellare di riscontri con filtri.** I blocchi tabellari rendono righe di un modello scelto. `model_choice` è esattamente uno tra `organization`, `asset`, `engagement`, `test`, `finding`, `test_type` o `risk_acceptance`. I `fields` provengono da `field_options` (verifica ogni `path`), e i `filter_entries` delimitano le righe.

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

**Un blocco di dettaglio dei riscontri.** I blocchi di dettaglio rendono una sezione espansa per ogni record e possono includere campi lunghi / markdown non adatti a una colonna tabellare stretta. Anche qui, verifica i `fields` rispetto a `field_options`.

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

Ogni risposta di blocco include il proprio `id`. Nota che `filter_entries` restituisce ciò che il server ha effettivamente memorizzato — confrontalo con ciò che hai inviato (vedi [Verifica ciò che hai costruito](#verify-what-you-built)).

### Creare un modello

Un modello associa un tema a un elenco ordinato di blocchi. Il campo di sola lettura è `template_blocks`; in creazione e aggiornamento **scrivi** `template_blocks_write`. Ogni voce richiede un `order` e un `block_id`, e lo stesso `block_id` può comparire più di una volta.

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

Sostituisci `theme_id` e ogni `block_id` con gli ID restituiti nei passaggi precedenti. La risposta include l'`id` del modello.

## Passaggio 3: eseguire il report e scaricare il risultato

La generazione di un report è asincrona: crei un'esecuzione, ne controlli periodicamente lo stato, quindi scarichi il file una volta completata.

**Avviare un'esecuzione.** Invia con POST un `template_id` e un `file_format` pari a `pdf` o `html`:

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

La risposta restituisce il nuovo `id` del report con `status` impostato su `pending`.

**Controllare lo stato.** Recupera il report finché il suo `status` non raggiunge uno stato terminale. Il flusso è `pending` → `processing` → `completed`. In caso di `failed`, leggi `error_message` per conoscerne il motivo.

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**Scaricare il file.** Una volta che `status` è `completed`, l'endpoint di download restituisce il file come allegato. Prima di allora risponde con `404`.

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## Mettere tutto insieme: uno script completo per l'intero ciclo di vita

Lo script seguente esegue l'intero flusso usando solo la libreria standard di Python 3 — nessun `requests`, nessun pacchetto di terze parti. Legge il token da `DD_IMPORTER_DOJO_API_TOKEN`, crea un tema, tre blocchi e un modello, avvia un report, esegue il polling con backoff finché non si completa o fallisce, scarica il risultato e scrive gli ID creati in `created.json`.

Imposta l'URL della tua istanza ed eseguilo:

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

## Verifica ciò che hai costruito

Poiché i filtri non validi vengono eliminati silenziosamente, la verifica fa parte del flusso di lavoro — non è un ripensamento successivo.

**Conferma che i filtri di un blocco siano sopravvissuti.** Recupera ogni blocco con una GET e confronta i suoi `filter_entries` con ciò che hai inviato con POST:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

Se un filtro che hai inviato manca da `filter_entries`, il nome del suo `field` non era un parametro GET valido per quel modello — ricontrolla il nome in `schema.json`.

**Conferma l'ordine e il tema del modello.** Recupera il modello con una GET e controlla che `template_blocks` elenchi i blocchi nell'`order` previsto e che il tema associato corrisponda:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**Correggere i filtri eliminati con PATCH.** Per correggere i filtri di un blocco, invia con PATCH l'insieme **completo** desiderato — una PATCH sostituisce interamente `filter_entries`:

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

## Prossimi passi

- Costruisci e visualizza in anteprima gli stessi Temi, Blocchi e Modelli in modo interattivo nella [interfaccia del Generatore di report](../report-builder/).
- Lascia che un LLM assembli le configurazioni dei report per te con l'[integrazione LLM del Generatore di report](../report-builder-llm/).
