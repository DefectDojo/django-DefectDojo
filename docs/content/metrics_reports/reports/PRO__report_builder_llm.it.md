---
title: Creazione di report con un LLM
description: Usa Claude o un altro LLM per progettare, creare, eseguire e scaricare
  i report di DefectDojo Pro tramite l'API
draft: false
audience: pro
weight: 22
slug: report-builder-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: l'automazione del Report Builder tramite l'API REST e un LLM è una funzionalità di DefectDojo Pro, attualmente in beta.</span>

Il Report Builder di DefectDojo Pro (Temi, Blocchi e Template) è interamente guidato dall'API REST. Questo significa che puoi affidare l'intero lavoro a un LLM: incolla un singolo prompt autonomo in Claude, ChatGPT o un altro modello altrettanto capace, e questo interrogherà lo schema OpenAPI live del tuo tenant e i `field_options`, proponendo un tema più una libreria di blocchi riutilizzabili e template per i destinatari che indichi, produrrà uno script Python eseguibile e infine eseguirà il report e scaricherà il file finito.

Lo schema è semplice. Fornisci il tuo URL di base, un token API e una breve descrizione di chi sono i destinatari dei report. L'LLM si occupa di scoperta, progettazione, creazione, verifica, esecuzione e download, fermandosi per la tua approvazione prima di costruire qualsiasi cosa sul tuo tenant.

Questa guida si affianca alla [guida API del Report Builder](../report-builder-api/), che documenta le risorse grezze e i formati delle richieste con cui lavora l'LLM. Se vuoi capire o mettere a punto manualmente ciò che l'LLM ha prodotto, questo è il riferimento da tenere aperto.

## Prima di iniziare

1. **Ottieni un token API.** Nell'interfaccia di DefectDojo Pro, vai su **User Settings → API v2 Key** e copia il token. Quindi impostalo come variabile d'ambiente in modo che lo script generato possa leggerlo senza che il token compaia mai in chat:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Decidi i destinatari.** L'LLM ti chiederà per chi sono i report. Le scelte più comuni:

   - **Riepilogo esecutivo** — postura di alto livello; SLA scaduti, KEV e inventario degli asset in un colpo d'occhio.
   - **POA&M (Piano d'azione e traguardi)** — riscontri aperti con gravità, scadenza e rimedio consigliato, oltre al dettaglio dei riscontri di gravità Critica e ai riscontri storici/chiusi.
   - **Foglio di lavoro per l'inventario integrato** — asset (in precedenza Prodotti) in ambito con criticità, piattaforma, ciclo di vita, accessibilità da Internet e conteggio dei riscontri.
   - **Pacchetto di richiesta di deroga (DRF)** — accettazioni del rischio attive, riscontri con tag DR e candidati SLA scaduti per nuove richieste di deroga.
   - **Dettaglio dei riscontri ingegneristici** — descrizioni complete per ogni riscontro (descrizione, impatto, mitigazione, riferimenti).
   - **Istantanea di conformità / audit** — asset più accettazioni del rischio più KEV.

> **💡 Suggerimento:** Non devi necessariamente scegliere da questo elenco. Indica all'LLM i tuoi destinatari reali in linguaggio naturale e lui li mapperà sulle entità e sui filtri disponibili.

## Il prompt

Copia l'intero blocco di codice qui sotto e incollalo in Claude, ChatGPT o un altro LLM altrettanto capace. Il prompt è autonomo — il modello ti chiederà l'URL del tuo tenant, la variabile d'ambiente del token e i destinatari dei report, per poi guidarti attraverso scoperta → progettazione → creazione → verifica → esecuzione → download.

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

## Come usarlo

1. **Incolla il prompt** sopra in Claude, ChatGPT o un altro LLM capace.
2. **Rispondi alle sue domande di scoperta.** Ti chiederà l'URL di base, la variabile d'ambiente che contiene il token, i destinatari, eventuali filtri specifici a cui tieni (fasce di gravità, soglie SLA, solo KEV, asset o tag particolari), il tuo branding e il formato di output desiderato.
3. **Rivedi il design proposto e approvalo prima che venga creato.** Il modello dovrebbe presentarti un tema condiviso, una libreria di blocchi riutilizzabili e uno o più template — mostrando, per ogni blocco dati, `model_choice`, `fields`, l'ordinamento e le esatte voci di filtro. Non lasciare che crei nulla sul tuo tenant finché non hai dato l'approvazione.
4. **Lascia che generi ed esegua lo script.** L'unico script Python (solo libreria standard) crea il tema, i blocchi e i template, poi esegue il report e scarica il file finito.
5. **Deve verificare prima e dopo l'esecuzione.** Aspettati che esegua una GET su ogni blocco e template per confermare che filtri e ordinamento siano stati salvati, poi una POST su `generated_reports`, un polling finché lo stato non è `completed`, e infine il download del file.

> **💡 Suggerimento:** Se l'LLM passa direttamente alla progettazione dei blocchi senza prima recuperare lo schema live del tuo tenant (`/api/v2/oa3/schema/?format=json`) e i `field_options`, fermalo. I nomi di filtri e campi variano a seconda della versione, e progettare a memoria è esattamente il motivo per cui i blocchi finiscono per perdere silenziosamente dei filtri.

## Risoluzione dei problemi

**Un blocco creato risulta privo dei filtri che hai inviato.** Il nome del `field` del filtro non corrispondeva a un parametro GET reale sull'entità sottostante, quindi DefectDojo lo ha scartato. Fai recuperare all'LLM `/api/v2/oa3/schema/?format=json`, fagli leggere l'elenco `parameters` per l'endpoint GET di quell'entità (ad esempio l'endpoint dei riscontri), e fagli usare un nome di parametro reale.

**I filtri booleani non hanno effetto.** I valori booleani devono essere inviati come le stringhe `"true"` o `"false"`, non come veri booleani JSON.

**`outside_of_sla` non filtra.** Questo filtro accetta un valore numerico come stringa — usa `"1"`, non `"true"`.

**Più gravità in un unico blocco non funzionano.** Un singolo blocco mantiene solo la prima gravità. Suddividi invece in un blocco per ogni gravità.

**I blocchi del template tornano nell'ordine sbagliato o mancanti.** Assicurati che l'LLM abbia eseguito una POST su `template_blocks_write` (il campo di sola scrittura), non su `template_blocks` (che è di sola lettura). Il campo `order` è obbligatorio per ogni voce.

**L'esecuzione del report è bloccata o fallita.** Continua a eseguire il polling di `GET /api/v2/generated_reports/{id}/` — lo stato passa da `pending` a `processing` a `completed`. Se lo stato diventa `failed`, leggi il campo `error_message` per conoscere la causa prima di riprovare.

> **⚠️** L'endpoint di download (`/api/v2/generated_reports/{id}/download/`) restituisce 404 finché l'esecuzione non raggiunge `completed`. Esegui sempre il polling fino al completamento prima di scaricare.

## Prossimi passi

- [Report Builder (UI)](../report-builder/) — progetta ed esegui report in modo interattivo nell'interfaccia di DefectDojo Pro.
- [Report Builder API](../report-builder-api/) — le risorse REST grezze e i formati delle richieste con cui lavora l'LLM, per la messa a punto manuale o per automazioni più approfondite.
