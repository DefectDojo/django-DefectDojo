---
title: Dashboards mit einem LLM erstellen
description: Verwenden Sie Claude oder ein anderes LLM, um anpassbare DefectDojo Pro-Dashboards
  über die API zu entwerfen, zu erstellen und einzurichten
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Die Automatisierung anpassbarer Dashboards mit der REST-API und einem LLM ist eine DefectDojo-Pro-Funktion. Sie ist standardmäßig deaktiviert – ein Superuser kann anpassbare Dashboards unter **Einstellungen > Feature-Flags** sowohl in Cloud- als auch in On-Premise-Instanzen aktivieren.</span>

Die anpassbaren Dashboards von DefectDojo Pro werden vollständig über die REST-API gesteuert – und die Layout-Oberfläche wurde mit Blick auf KI-Agenten entwickelt. Das bedeutet, dass Sie die gesamte Aufgabe einem LLM übergeben können: Fügen Sie einen einzigen, in sich geschlossenen Prompt in Claude, ChatGPT oder ein anderes leistungsfähiges Modell ein, beschreiben Sie die gewünschten Dashboards, und es wird den Live-Widget-Katalog Ihres Mandanten abfragen, Layouts vorschlagen, ein lauffähiges Python-Skript erzeugen, die Layouts erstellen, verifizieren und optional Ihren Standard festlegen.

Das Muster ist einfach. Sie geben Ihre Basis-URL, ein API-Token und eine kurze Beschreibung an, für wen die Dashboards gedacht sind. Das LLM übernimmt die Erkundung, den Entwurf, die Erstellung und die Verifizierung – und hält vor jeder Aktion gegen Ihren Mandanten inne, um Ihre Zustimmung einzuholen.

Dieser Leitfaden ergänzt den [Dashboards-API-Leitfaden](../custom-dashboards-api/), der die zugrunde liegenden Ressourcen und Anfragestrukturen dokumentiert, mit denen das LLM arbeitet. Wenn Sie verstehen oder von Hand nachjustieren möchten, was das LLM erzeugt hat, halten Sie diese Referenz griffbereit.

## Bevor Sie beginnen

1. **Holen Sie sich ein API-Token.** Gehen Sie in der DefectDojo Pro-Benutzeroberfläche zu **Benutzereinstellungen → API v2 Key** und kopieren Sie das Token. Legen Sie es anschließend als Umgebungsvariable fest, damit das generierte Skript es lesen kann, ohne dass das Token jemals im Chat erscheint:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Bestätigen Sie, dass die Funktion aktiviert ist.** Anpassbare Dashboards müssen für Ihre Instanz unter **Einstellungen > Feature-Flags** aktiviert werden – andernfalls liefert jeder API-Aufruf `403`.

3. **Entscheiden Sie sich für Ihre Dashboards.** Das LLM wird fragen, was Sie möchten. Gängige Optionen:

   - **Übersicht für die Geschäftsführung** – Kennzahlen auf einen Blick, Verteilung nach Schweregrad und SLA-Einhaltung.
   - **Tägliche Triage** – aktive Kritisch-/Hoch-Befunde, Prioritäts-Histogramm, SLA-Burndown und Ihre „Meine Arbeit"-Warteschlange.
   - **Behebungsgeschwindigkeit** – Geschwindigkeit von erstellt vs. geschlossen, MTTR/MTTD und Alterung.
   - **Scanner-Effektivität** – Befunde nach Testtyp, Falsch-positiv-Rate nach Tool und aktuelle Scan-Aktivität.
   - **Portfolio-Zustand** – eine Treemap der Assets nach Organisation, Scan-Abdeckung sowie best- und schlechtest-bewertete Assets.

> **💡 Tipp:** Sie müssen nicht aus dieser Liste auswählen. Beschreiben Sie dem LLM Ihre tatsächlichen Ziele in einfacher Sprache, und es wird sie auf die verfügbaren Widget-Typen und Filter abbilden.

## Der Prompt

Kopieren Sie den gesamten eingerahmten Block unten und fügen Sie ihn in Claude, ChatGPT oder ein anderes leistungsfähiges LLM ein. Der Prompt ist in sich geschlossen – das Modell wird Sie nach der URL Ihres Mandanten, dem Namen der Token-Umgebungsvariable und Ihren Dashboard-Zielen fragen und Sie anschließend durch Erkundung → Entwurf → Erstellung → Verifizierung führen.

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

## Was Sie erwarten können

Ein gut funktionierendes Modell wird:

1. nach Ihrer Basis-URL, der Token-Umgebungsvariable und Ihren Dashboard-Zielen fragen.
2. den Widget-Katalog (sowie bei Bedarf Dimensionen/Datensatzmetriken) per `GET` abrufen und Ihnen mitteilen, welche Widget-Typen es verwenden will.
3. jedes Layout vorschlagen – Name, Widgets, Filter und Rasteranordnung – und **auf Ihre Zustimmung warten**.
4. ein reines Standardbibliotheks-Python-Skript erzeugen, das die Layouts erstellt, optional Ihren Standard festlegt und das Ergebnis verifiziert.
5. berichten, was es verifiziert hat, und anbieten, alles zu korrigieren, was nicht wie beabsichtigt gespeichert wurde.

> **💡 Tipp:** Wenn ein Widget eine unerwartete Zahl anzeigt, liegt das meist an einem Filterschlüssel, der stillschweigend verworfen wurde. Bitten Sie das LLM, das Layout zurückzulesen und die gespeicherten `config.filters` mit dem Gesendeten zu vergleichen – der [API-Leitfaden](../custom-dashboards-api/#verify-what-you-built) behandelt diesen Verifizierungsschritt im Detail.

## Nächste Schritte

- Im [Dashboards-API-Leitfaden](../custom-dashboards-api/) finden Sie die zugrunde liegenden Ressourcen, Anfragestrukturen und die vollständige Referenz der Widget-Daten-Aktionen.
- Erstellen und ordnen Sie Dashboards manuell in der [Benutzeroberfläche für anpassbare Dashboards](../custom-dashboards/) an.
