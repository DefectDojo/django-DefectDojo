---
title: Créer des rapports avec un LLM
description: Utilisez Claude ou un autre LLM pour concevoir, créer, exécuter et télécharger
  des rapports DefectDojo Pro via l'API
draft: false
audience: pro
weight: 22
slug: report-builder-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : l'automatisation du Report Builder avec l'API REST et un LLM est une fonctionnalité de DefectDojo Pro, actuellement en version bêta.</span>

Le Report Builder de DefectDojo Pro (Thèmes, Blocs et Modèles) est entièrement piloté par l'API REST. Cela signifie que vous pouvez confier l'ensemble de la tâche à un LLM : collez une invite autonome unique dans Claude, ChatGPT ou tout autre modèle performant, et celui-ci interrogera le schéma OpenAPI actif de votre tenant ainsi que `field_options`, proposera un thème accompagné d'une bibliothèque de blocs réutilisables et de modèles pour les audiences que vous indiquez, générera un script Python exécutable, puis exécutera le rapport et téléchargera le fichier final.

Le principe est simple. Vous fournissez votre URL de base, un jeton API et une brève description des destinataires des rapports. Le LLM se charge de la découverte, de la conception, de la création, de la vérification, de l'exécution et du téléchargement — en s'arrêtant pour obtenir votre validation avant de créer quoi que ce soit sur votre tenant.

Ce guide complète le [guide de l'API Report Builder](../report-builder-api/), qui documente les ressources brutes et les formats de requêtes utilisés par le LLM. Si vous souhaitez comprendre ou ajuster manuellement ce que le LLM a produit, c'est la référence à garder ouverte.

## Avant de commencer

1. **Obtenez un jeton API.** Dans l'interface de DefectDojo Pro, allez dans **User Settings → API v2 Key** et copiez le jeton. Définissez-le ensuite comme variable d'environnement afin que le script généré puisse le lire sans que le jeton n'apparaisse jamais dans la conversation :

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Définissez vos audiences.** Le LLM vous demandera à qui s'adressent les rapports. Choix courants :

   - **Résumé exécutif** — posture globale ; échéances SLA dépassées, KEV et inventaire des actifs en un coup d'œil.
   - **POA&M (Plan of Action & Milestones)** — constatations ouvertes avec sévérité, date d'échéance et remédiation recommandée, ainsi que le détail des constatations critiques et les constatations historiques/clôturées.
   - **Classeur d'inventaire intégré** — actifs (anciennement Produits) dans le périmètre, avec criticité, plateforme, cycle de vie, accessibilité depuis Internet et nombre de constatations.
   - **Ensemble de demandes de dérogation (DRF)** — acceptations de risque actives, constatations étiquetées DR et candidats en dépassement de SLA pour de nouvelles demandes de dérogation.
   - **Détail technique des constatations** — fiches complètes par constatation (description, impact, atténuation, références).
   - **Instantané de conformité / audit** — actifs, acceptations de risque et KEV.

> **💡 Astuce :** vous n'êtes pas obligé de choisir dans cette liste. Indiquez au LLM vos audiences réelles en langage courant, et il les fera correspondre aux entités et filtres disponibles.

## L'invite

Copiez l'intégralité du bloc ci-dessous et collez-le dans Claude, ChatGPT ou tout autre LLM performant. L'invite est autonome — le modèle vous demandera l'URL de votre tenant, la variable d'environnement du jeton et les audiences des rapports, puis vous guidera à travers la découverte → conception → création → vérification → exécution → téléchargement.

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

## Comment l'utiliser

1. **Collez l'invite** ci-dessus dans Claude, ChatGPT ou un autre LLM performant.
2. **Répondez à ses questions de découverte.** Il vous demandera votre URL de base, la variable d'environnement contenant votre jeton, vos audiences, les filtres spécifiques qui vous intéressent (niveaux de sévérité, seuils de SLA, KEV uniquement, actifs ou étiquettes particuliers), votre habillage graphique et le format de sortie souhaité.
3. **Examinez la conception proposée et validez-la avant toute création.** Le modèle doit revenir avec un thème partagé, une bibliothèque de blocs réutilisables et un ou plusieurs modèles — en indiquant, pour chaque bloc de données, `model_choice`, `fields`, l'ordre et les filtres exacts. Ne le laissez rien créer sur votre tenant tant que vous n'avez pas donné votre accord.
4. **Laissez-le générer et exécuter le script.** L'unique script Python (bibliothèque standard uniquement) crée le thème, les blocs et les modèles, puis exécute le rapport et télécharge le fichier final.
5. **Il doit vérifier avant et après l'exécution.** Attendez-vous à ce qu'il fasse un GET sur chaque bloc et modèle pour confirmer que les filtres et l'ordre ont bien été enregistrés, puis un POST sur `generated_reports`, qu'il interroge le statut jusqu'à `completed`, et qu'il télécharge le fichier.

> **💡 Astuce :** si le LLM se lance directement dans la conception des blocs sans d'abord récupérer le schéma actif de votre tenant (`/api/v2/oa3/schema/?format=json`) et `field_options`, corrigez-le. Les noms de filtres et de champs varient selon la version, et concevoir de mémoire est exactement ce qui fait que des blocs se retrouvent silencieusement privés de filtres.

## Dépannage

**Un bloc créé revient avec des filtres manquants par rapport à ceux envoyés.** Le nom du `field` du filtre ne correspondait à aucun paramètre GET réel de l'entité sous-jacente, donc DefectDojo l'a ignoré. Demandez au LLM de récupérer `/api/v2/oa3/schema/?format=json`, de lire la liste `parameters` du endpoint GET de cette entité (par exemple le endpoint des constatations), et d'utiliser un nom de paramètre réel.

**Les filtres booléens n'ont aucun effet.** Les valeurs booléennes doivent être envoyées sous forme de chaînes `"true"` ou `"false"`, et non de véritables booléens JSON.

**`outside_of_sla` ne filtre pas.** Ce filtre attend une valeur numérique sous forme de chaîne — utilisez `"1"`, et non `"true"`.

**Plusieurs sévérités dans un même bloc ne fonctionnent pas.** Un bloc unique ne conserve que la première sévérité. Créez plutôt un bloc par sévérité.

**Les blocs du modèle reviennent dans le mauvais ordre ou sont manquants.** Assurez-vous que le LLM a bien envoyé un POST sur `template_blocks_write` (le champ en écriture seule), et non sur `template_blocks` (qui est en lecture seule). Le champ `order` est requis pour chaque entrée.

**L'exécution du rapport est bloquée ou a échoué.** Continuez d'interroger `GET /api/v2/generated_reports/{id}/` — le statut passe de `pending` à `processing` puis à `completed`. Si le statut devient `failed`, consultez le champ `error_message` pour connaître la cause avant de recommencer.

> **⚠️** le endpoint de téléchargement (`/api/v2/generated_reports/{id}/download/`) renvoie 404 tant que l'exécution n'a pas atteint `completed`. Attendez toujours la fin de l'exécution avant de télécharger.

## Étapes suivantes

- [Report Builder (interface)](../report-builder/) — concevez et exécutez des rapports de manière interactive dans l'interface de DefectDojo Pro.
- [Report Builder API](../report-builder-api/) — les ressources REST brutes et les formats de requêtes utilisés par le LLM, pour un ajustement manuel ou une automatisation plus poussée.
