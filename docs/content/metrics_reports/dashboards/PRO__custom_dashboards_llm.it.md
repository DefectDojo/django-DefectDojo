---
title: Creare dashboard con un LLM
description: Usa Claude o un altro LLM per progettare, creare e configurare le dashboard
  personalizzabili di DefectDojo Pro tramite l'API
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: automatizzare le Dashboard personalizzabili con la REST API e un LLM è una funzionalità di DefectDojo Pro. È disattivata per impostazione predefinita: un superuser può attivare le Dashboard personalizzabili da **Impostazioni > Flag delle funzionalità** sia sulle istanze Cloud sia On-Premise.</span>

Le Dashboard personalizzabili di DefectDojo Pro sono interamente guidate dalla REST API — e la superficie dei layout è stata progettata pensando agli agenti AI. Questo significa che puoi affidare l'intero lavoro a un LLM: incolla un unico prompt autosufficiente in Claude, ChatGPT o un altro modello capace, descrivi le dashboard che desideri, e interrogherà il catalogo widget in tempo reale del tuo tenant, proporrà i layout, produrrà uno script Python eseguibile, creerà i layout, li verificherà e, facoltativamente, imposterà il tuo predefinito.

Lo schema è semplice. Fornisci il tuo URL di base, un token API e una breve descrizione di chi sono destinate le dashboard. L'LLM si occupa della scoperta, della progettazione, della creazione e della verifica — mettendosi in pausa per la tua approvazione prima di costruire qualsiasi cosa sul tuo tenant.

Questa guida si affianca alla [guida API delle Dashboard](../custom-dashboards-api/), che documenta le risorse grezze e le forme delle richieste con cui lavora l'LLM. Se vuoi capire o modificare manualmente ciò che l'LLM ha prodotto, tieni aperto quel riferimento.

## Prima di iniziare

1. **Ottieni un token API.** Nella UI di DefectDojo Pro, vai su **Impostazioni utente → Chiave API v2** e copia il token. Poi impostalo come variabile d'ambiente in modo che lo script generato possa leggerlo senza che il token compaia mai in chat:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Conferma che la funzionalità sia attiva.** Le Dashboard personalizzabili devono essere attivate per la tua istanza da **Impostazioni > Flag delle funzionalità** — altrimenti ogni chiamata API restituisce `403`.

3. **Decidi le tue dashboard.** L'LLM ti chiederà cosa desideri. Le scelte più comuni sono:

   - **Panoramica esecutiva** — conteggi principali, distribuzione per gravità e conformità SLA a colpo d'occhio.
   - **Triage giornaliero** — critiche/alte attive, istogramma priorità, burndown SLA e la tua coda "Il mio lavoro".
   - **Velocità di remediation** — velocità creati-vs-chiusi, MTTR/MTTD e anzianità.
   - **Efficacia degli scanner** — riscontri per tipo di test, tasso di falsi positivi per strumento e attività di scansione recente.
   - **Salute del portafoglio** — una treemap degli asset per organizzazione, copertura delle scansioni e asset con voto più alto/più basso.

> **💡 Tip:** non devi per forza scegliere da questo elenco. Racconta all'LLM i tuoi obiettivi reali in linguaggio naturale e lui li mapperà sui tipi di widget e sui filtri disponibili.

## Il prompt

Copia l'intero blocco delimitato qui sotto e incollalo in Claude, ChatGPT o un altro LLM capace. Il prompt è autosufficiente — il modello ti chiederà l'URL del tuo tenant, la variabile d'ambiente del token e gli obiettivi delle dashboard, quindi ti guiderà attraverso scoperta → progettazione → creazione → verifica.

```text
You are helping me build customizable dashboards in DefectDojo Pro using its
REST API ("Dashboards 2.0" — layouts of widgets on a grid). Work carefully and
pause for my approval before creating anything against my tenant.

================================================================================
WHAT I WILL GIVE YOU
================================================================================
  - A base URL ending in /api/v2 (e.g. https://my-instance.cloud.defectdojo.com/api/v2)
  - The name of an environment variable holding my API token (default:
    DD_IMPORTER_DOJO_API_TOKEN). NEVER ask me to paste the token itself.
  - A description of the dashboard(s) I want and who they are for.

Authenticate every request with the header:  Authorization: Token <token>
Also send  Accept: application/json  (and Content-Type: application/json on writes).

================================================================================
DATA MODEL
================================================================================
A "layout" is one dashboard: a named set of widgets and their grid positions.
It is created/updated under /api/v2/dashboards/ with these resources:

  /api/v2/dashboards/layouts/         CRUD for layouts + actions:
        POST {id}/clone/        copy a layout (fresh widget IDs)
        POST {id}/set_default/  make a layout my home-page default
        GET  shared/            list curated + team-shared templates
        GET  for_current_user/  my layouts + my default_id (bootstrap)
  /api/v2/dashboards/widget_catalog/  GET: every widget type + a config example
  /api/v2/dashboards/widget_data/<action>/  render a widget's data on demand

A layout's two content fields MUST agree with each other:
  widgets : ordered list of widget objects (see below)
  layout  : map of  widget-id -> {x, y, w, h, min_w?, min_h?, max_w?, max_h?}
Every widget needs a position, and every position must reference a real widget,
or the create returns 400.

A widget object:
  {
    "id": "<uuid you generate>",
    "type": "<a type from the catalog>",
    "title": "<heading>",
    "refresh_interval": 0,        # one of 0, 30, 60, 300, 900 (seconds)
    "config": { ...type-specific... }
  }
Optional: "title_styling": {"bold": true, "size": "md"}  # size: sm | md | lg

The grid is 12 columns wide. x is 0..11; w is the column span; y/h are rows.

================================================================================
STEP 1 — DISCOVER (do this BEFORE designing anything; never invent values)
================================================================================
1. GET /api/v2/dashboards/widget_catalog/ . It returns {categories, widgets}.
   Each widget entry has: type, label, category, description, data_endpoints,
   and a minimal known-good config_example. USE THESE config_examples as the
   starting point for each widget's config — do not guess the config shape.
   There are 26 widget types in four categories: Numbers, Charts,
   Lists & Feeds, Static & Utility.

2. For any chart/leaderboard that groups data, fetch the valid dimensions:
     GET /api/v2/dashboards/widget_data/dimensions/?model=<finding|product|engagement|test>
   Each dimension has key, label, and kind (categorical | boolean | time |
   banded). Pass the key as the widget's group_by. A "time" dimension also
   needs a time_bucket (day|week|month|quarter|year); others do not.
   NOTE: "priority" is NOT a group-by dimension (it is a continuous score).
   Use the "risk" dimension for a banded view, or the priority_histogram widget.

3. For the Top-N widget in "records" mode, fetch valid metrics:
     GET /api/v2/dashboards/widget_data/record_metrics/?model=<product|finding|engagement|test>

================================================================================
MODELS AND FILTERS (the most error-prone area — READ CAREFULLY)
================================================================================
MODEL: most widgets take a config "model" of EXACTLY one of:
       finding | product | engagement | test
   (Note the legacy "product" — the UI calls these "Assets", and
    "engagement"/"test" are unchanged.) Some widgets are finding-only and take
    no model (risk_matrix, priority_histogram). The EMBEDDED TABLE widget is the
    exception: its model uses the newer names and a wider set:
       finding | asset | engagement | test | risk_acceptance | organization | test_type

FILTERS: a widget's config.filters use the SAME shape the object's LIST VIEW
   emits — not raw REST query params. Examples that work:
     finding:  {"status_any": "Active"}        # Active | Mitigated | Risk Accepted | ...
               {"severity": "Critical"}         # single value (or a list for any-of)
               {"duplicate": "false"}           # boolean as a string
               {"date_past_days": 7}
               {"sla_days_remaining_less_than_equal_to": 7}
     asset:    {"grade": "A,B,C"}               # passing; "D,F" = failing
               {"last_scanned_past_days": 90}
   An UNKNOWN filter key is SILENTLY IGNORED (no error) — so a typo leaves the
   widget showing a wider population than intended. An invalid VALUE for a real
   filter returns 400. Because of the silent-drop behavior, you MUST verify
   (Step 4). If unsure of a filter name, prefer the values shown in the catalog
   config_examples, or ask me to read the filter off the relevant list page.

================================================================================
STEP 2 — DESIGN, THEN GET MY APPROVAL
================================================================================
Propose, for each dashboard I asked for: a layout name, and a list of widgets
with their type, title, config, and a sensible 12-column grid arrangement
(x/y/w/h). Show me this plan and the exact JSON you intend to POST. Do NOT
create anything yet. Wait for my explicit "go".

================================================================================
STEP 3 — CREATE
================================================================================
After approval, emit a single Python 3 script using ONLY the standard library
(json, os, urllib, uuid — no requests). It must:
  - read the token from the env var,
  - generate a uuid4 per widget and build the widgets list and layout map
    together so their IDs always match,
  - POST each layout to /api/v2/dashboards/layouts/ and surface any error body,
  - optionally POST {id}/set_default/ for the one I choose as my landing page,
  - print the created layout IDs.

================================================================================
STEP 4 — VERIFY
================================================================================
For each created layout, GET /api/v2/dashboards/layouts/{id}/ and check:
  - every key in "layout" matches a widget "id" (and vice versa),
  - each widget's config.filters contains what we sent (flag any dropped keys),
  - is_default is true for the one I chose.
Report what you verified, and offer to PATCH fixes (a PATCH replaces the full
widgets + layout, so always send the complete set).

================================================================================
NOW START
================================================================================
Ask me for: (1) my base URL, (2) the token env-var name (default
DD_IMPORTER_DOJO_API_TOKEN), and (3) the dashboards I want and their audience.
Then begin at Step 1.
```

## Cosa aspettarsi

Un modello ben istruito farà quanto segue:

1. Chiederà il tuo URL di base, la variabile d'ambiente del token e gli obiettivi delle dashboard.
2. Eseguirà una `GET` del catalogo dei widget (e delle dimensioni/metriche dei record se necessario) e ti dirà quali tipi di widget intende usare.
3. Proporrà ogni layout — nome, widget, filtri e disposizione nella griglia — e **attenderà la tua approvazione**.
4. Produrrà uno script Python che usa solo la libreria standard, che crea i layout, imposta facoltativamente il tuo predefinito e verifica il risultato.
5. Riferirà cosa ha verificato e offrirà di correggere tutto ciò che non si è salvato come previsto.

> **💡 Tip:** se un widget visualizza un numero inatteso, la causa più comune è una chiave di filtro scartata silenziosamente. Chiedi all'LLM di rileggere il layout e confrontare i `config.filters` salvati con quelli inviati — la [guida API](../custom-dashboards-api/#verify-what-you-built) tratta questo passaggio di verifica in dettaglio.

## Prossimi passi

- Consulta la [guida API delle Dashboard](../custom-dashboards-api/) per le risorse grezze, le forme delle richieste e il riferimento completo delle azioni widget-data.
- Crea e disponi le dashboard manualmente nella [UI delle Dashboard personalizzabili](../custom-dashboards/).
