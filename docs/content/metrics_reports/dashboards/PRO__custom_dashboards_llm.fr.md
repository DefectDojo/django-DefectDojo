---
title: Construire des tableaux de bord avec un LLM
description: Utilisez Claude ou un autre LLM pour concevoir, créer et configurer les
  tableaux de bord personnalisables de DefectDojo Pro via l'API
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : automatiser les tableaux de bord personnalisables avec l'API REST et un LLM est une fonctionnalité de DefectDojo Pro. Elle est désactivée par défaut — un superutilisateur peut activer les tableaux de bord personnalisables depuis **Settings > Feature Flags**, aussi bien sur les instances Cloud que On-Premise.</span>

Les tableaux de bord personnalisables de DefectDojo Pro sont entièrement pilotés par l'API REST — et la surface des mises en page a été conçue en pensant aux agents d'IA. Cela signifie que vous pouvez confier toute la tâche à un LLM : collez un seul prompt autonome dans Claude, ChatGPT ou tout autre modèle compétent, décrivez les tableaux de bord que vous voulez, et il interrogera le catalogue de widgets en direct de votre tenant, proposera des mises en page, produira un script Python exécutable, créera les mises en page, les vérifiera et, en option, définira votre mise en page par défaut.

Le principe est simple. Vous fournissez votre URL de base, un jeton API et une courte description de qui les tableaux de bord sont destinés. Le LLM se charge de la découverte, de la conception, de la création et de la vérification — en marquant une pause pour votre approbation avant de construire quoi que ce soit sur votre tenant.

Ce guide va de pair avec le [guide de l'API des tableaux de bord](../custom-dashboards-api/), qui documente les ressources brutes et les formes de requête avec lesquelles le LLM travaille. Si vous voulez comprendre ou ajuster à la main ce que le LLM a produit, gardez cette référence ouverte.

## Avant de commencer

1. **Récupérez un jeton API.** Dans l'interface de DefectDojo Pro, allez dans **User Settings → API v2 Key** et copiez le jeton. Définissez-le ensuite comme variable d'environnement afin que le script généré puisse le lire sans que le jeton n'apparaisse jamais dans le chat :

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Confirmez que la fonctionnalité est activée.** Les tableaux de bord personnalisables doivent être activés pour votre instance depuis **Settings > Feature Flags** — sinon chaque appel API renvoie `403`.

3. **Décidez de vos tableaux de bord.** Le LLM vous demandera ce que vous voulez. Choix courants :

   - **Executive Overview** — comptages principaux, répartition par sévérité et conformité SLA en un coup d'œil.
   - **Daily Triage** — critiques/élevées actives, histogramme de priorité, burndown SLA, et votre file « My Work ».
   - **Remediation Velocity** — vélocité créé-vs-clôturé, MTTR/MTTD, et vieillissement.
   - **Scanner Effectiveness** — constatations par type de test, taux de faux positifs par outil, et activité de scan récente.
   - **Portfolio Health** — une carte arborescente des assets par organisation, la couverture des scans, et les assets les mieux/moins bien notés.

> **💡 Astuce :** Vous n'êtes pas obligé de choisir dans cette liste. Dites au LLM vos objectifs réels en langage simple, et il les fera correspondre aux types de widgets et aux filtres disponibles.

## Le prompt

Copiez l'intégralité du bloc encadré ci-dessous et collez-le dans Claude, ChatGPT ou tout autre LLM compétent. Le prompt est autonome — le modèle vous demandera l'URL de votre tenant, le nom de la variable d'environnement du jeton et les objectifs des tableaux de bord, puis vous guidera à travers découverte → conception → création → vérification.

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

## À quoi s'attendre

Un modèle bien élevé va :

1. Demander votre URL de base, la variable d'environnement du jeton et les objectifs des tableaux de bord.
2. Faire un `GET` sur le catalogue de widgets (ainsi que les dimensions/métriques d'enregistrement au besoin) et vous indiquer quels types de widgets il compte utiliser.
3. Proposer chaque mise en page — nom, widgets, filtres et disposition dans la grille — et **attendre votre approbation**.
4. Produire un script Python n'utilisant que la bibliothèque standard, qui crée les mises en page, définit éventuellement votre mise en page par défaut, et vérifie le résultat.
5. Rendre compte de ce qu'il a vérifié et proposer de corriger tout ce qui ne s'est pas enregistré comme prévu.

> **💡 Astuce :** Si un widget affiche un nombre inattendu, la cause habituelle est une clé de filtre qui a été abandonnée silencieusement. Demandez au LLM de relire la mise en page et de comparer le `config.filters` enregistré à ce qu'il a envoyé — le [guide de l'API](../custom-dashboards-api/#verify-what-you-built) détaille cette étape de vérification.

## Prochaines étapes

- Consultez le [guide de l'API des tableaux de bord](../custom-dashboards-api/) pour les ressources brutes, les formes de requête et la référence complète des actions widget-data.
- Construisez et organisez des tableaux de bord à la main dans l'[interface des tableaux de bord personnalisables](../custom-dashboards/).
