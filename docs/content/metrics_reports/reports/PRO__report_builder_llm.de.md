---
title: Berichte mit einem LLM erstellen
description: Verwenden Sie Claude oder ein anderes LLM, um DefectDojo Pro-Berichte
  über die API zu entwerfen, zu erstellen, auszuführen und herunterzuladen
draft: false
audience: pro
weight: 22
slug: report-builder-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Die Automatisierung des Report Builders mit der REST-API und einem LLM ist eine DefectDojo Pro-Funktion, die sich derzeit in der Beta-Phase befindet.</span>

Der Report Builder von DefectDojo Pro (Themes, Blocks und Templates) wird vollständig über die REST-API gesteuert. Das bedeutet, Sie können die gesamte Aufgabe einem LLM übergeben: Fügen Sie einen einzigen, in sich geschlossenen Prompt in Claude, ChatGPT oder ein anderes leistungsfähiges Modell ein, und es befragt das live OpenAPI-Schema und die `field_options` Ihres Tenants, schlägt ein Theme sowie eine wiederverwendbare Block-Bibliothek und Templates für die von Ihnen genannten Zielgruppen vor, erzeugt ein lauffähiges Python-Skript und führt anschließend den Bericht aus und lädt die fertige Datei herunter.

Das Muster ist einfach: Sie geben Ihre Basis-URL, ein API-Token und eine kurze Beschreibung an, für wen die Berichte bestimmt sind. Das LLM übernimmt die Recherche, das Design, die Erstellung, die Verifizierung, die Ausführung und den Download — und hält vor jedem Schritt, der etwas in Ihrem Tenant anlegt, für Ihre Freigabe inne.

Dieser Leitfaden ergänzt den [Report Builder API-Leitfaden](../report-builder-api/), der die zugrunde liegenden Ressourcen und Request-Formate dokumentiert, mit denen das LLM arbeitet. Wenn Sie verstehen oder von Hand nachjustieren möchten, was das LLM erzeugt hat, ist das die Referenz, die Sie offen halten sollten.

## Bevor Sie beginnen

1. **Ein API-Token besorgen.** Gehen Sie in der Benutzeroberfläche von DefectDojo Pro zu **Benutzereinstellungen → API v2 Key** und kopieren Sie das Token. Legen Sie es anschließend als Umgebungsvariable ab, damit das generierte Skript es lesen kann, ohne dass das Token jemals im Chat erscheint:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Zielgruppen festlegen.** Das LLM fragt, für wen die Berichte gedacht sind. Gängige Auswahlmöglichkeiten:

   - **Executive Summary** — Sicherheitslage auf hohem Niveau; SLA-Überschreitungen, KEV und Asset-Inventar auf einen Blick.
   - **POA&M (Plan of Action & Milestones)** — offene Befunde mit Schweregrad, Fälligkeitsdatum und empfohlener Behebung, ergänzt um Details zu kritischen sowie historischen/geschlossenen Befunden.
   - **Integrated Inventory Workbook** — Assets (ehemals Produkte) im Geltungsbereich mit Kritikalität, Plattform, Lifecycle, Internet-Erreichbarkeit und Anzahl der Befunde.
   - **Deviation Request (DRF) Package** — aktive Risikoakzeptanzen, mit DR getaggte Befunde und Kandidaten mit SLA-Überschreitung für neue Deviation Requests.
   - **Engineering Findings Detail** — vollständige Beschreibungen je Befund (description, impact, mitigation, references).
   - **Compliance / Audit Snapshot** — Assets plus Risikoakzeptanzen plus KEV.

> **💡 Tipp:** Sie müssen nicht aus dieser Liste auswählen. Beschreiben Sie dem LLM Ihre tatsächlichen Zielgruppen in einfachen Worten, und es ordnet sie den verfügbaren Entitäten und Filtern zu.

## Der Prompt

Kopieren Sie den gesamten Codeblock unten und fügen Sie ihn in Claude, ChatGPT oder ein anderes leistungsfähiges LLM ein. Der Prompt ist in sich geschlossen — das Modell fragt Sie nach Ihrer Tenant-URL, der Umgebungsvariable für das Token und den Zielgruppen der Berichte und führt Sie anschließend durch Discovery → Design → Erstellung → Verifizierung → Ausführung → Download.

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

## So verwenden Sie ihn

1. **Fügen Sie den obigen Prompt** in Claude, ChatGPT oder ein anderes leistungsfähiges LLM ein.
2. **Beantworten Sie seine Rückfragen zur Discovery.** Es fragt nach Ihrer Basis-URL, der Umgebungsvariable mit Ihrem Token, Ihren Zielgruppen, etwaigen speziellen Filtern, die Ihnen wichtig sind (Schweregrad-Stufen, SLA-Grenzwerte, nur KEV, bestimmte Assets oder Tags), Ihrem Branding und dem gewünschten Ausgabeformat.
3. **Prüfen Sie den vorgeschlagenen Entwurf und geben Sie ihn frei, bevor etwas erstellt wird.** Das Modell sollte mit einem gemeinsamen Theme, einer wiederverwendbaren Block-Bibliothek und einem oder mehreren Templates zurückkommen — und dabei für jeden Datenblock `model_choice`, `fields`, die Reihenfolge und die genauen Filtereinträge anzeigen. Lassen Sie es erst dann etwas in Ihrem Tenant anlegen, wenn Sie zugestimmt haben.
4. **Lassen Sie es das Skript generieren und ausführen.** Das einzelne Python-Skript (nur Standardbibliothek) legt Theme, Blocks und Templates an, führt anschließend den Bericht aus und lädt die fertige Datei herunter.
5. **Es sollte vor und nach der Ausführung verifizieren.** Es sollte jeden Block und jedes Template per GET abrufen, um zu bestätigen, dass Filter und Reihenfolge korrekt gespeichert wurden, anschließend per POST an `generated_reports` senden, bis der Status `completed` erreicht ist, und dann die Datei herunterladen.

> **💡 Tipp:** Wenn das LLM direkt mit dem Entwurf von Blocks beginnt, ohne zuvor das aktuelle Schema Ihres Tenants (`/api/v2/oa3/schema/?format=json`) und die `field_options` abzurufen, weisen Sie es zurück. Filter- und Feldnamen unterscheiden sich je nach Version, und ein Entwurf aus dem Gedächtnis führt genau dazu, dass Blocks stillschweigend Filter verlieren.

## Fehlerbehebung

**Ein erstellter Block enthält nicht alle gesendeten Filter.** Der `field`-Name des Filters entsprach keinem echten GET-Parameter der zugrunde liegenden Entität, weshalb DefectDojo ihn verworfen hat. Lassen Sie das LLM `/api/v2/oa3/schema/?format=json` abrufen, die `parameters`-Liste des GET-Endpunkts dieser Entität (zum Beispiel des Findings-Endpunkts) lesen und einen echten Parameternamen verwenden.

**Boolesche Filter wirken nicht.** Boolesche Werte müssen als die Strings `"true"` oder `"false"` gesendet werden, nicht als tatsächliche JSON-Booleans.

**`outside_of_sla` filtert nicht.** Dieser Filter erwartet einen numerischen Wert als String — verwenden Sie `"1"`, nicht `"true"`.

**Mehrere Schweregrade in einem Block funktionieren nicht.** Ein einzelner Block behält nur den ersten Schweregrad. Teilen Sie ihn stattdessen in je einen Block pro Schweregrad auf.

**Template-Blocks kommen in falscher Reihenfolge zurück oder fehlen.** Stellen Sie sicher, dass das LLM `template_blocks_write` (das reine Schreibfeld) per POST gesendet hat und nicht `template_blocks` (das nur lesbar ist). Das Feld `order` ist bei jedem Eintrag erforderlich.

**Der Berichtslauf hängt oder ist fehlgeschlagen.** Fragen Sie weiterhin `GET /api/v2/generated_reports/{id}/` ab — der Status wechselt von `pending` über `processing` zu `completed`. Wird der Status `failed`, lesen Sie das Feld `error_message`, um die Ursache zu ermitteln, bevor Sie es erneut versuchen.

> **⚠️** Der Download-Endpunkt (`/api/v2/generated_reports/{id}/download/`) liefert 404, bis der Lauf `completed` erreicht. Fragen Sie den Status immer bis zum Abschluss ab, bevor Sie herunterladen.

## Nächste Schritte

- [Report Builder (UI)](../report-builder/) — Berichte interaktiv in der Benutzeroberfläche von DefectDojo Pro entwerfen und ausführen.
- [Report Builder API](../report-builder-api/) — die zugrunde liegenden REST-Ressourcen und Request-Formate, mit denen das LLM arbeitet, für manuelles Feintuning oder tiefergehende Automatisierung.
