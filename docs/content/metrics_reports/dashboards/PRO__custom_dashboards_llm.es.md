---
title: Creación de paneles con un LLM
description: Use Claude u otro LLM para diseñar, crear y configurar los paneles personalizables
  de DefectDojo Pro mediante la API
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Automatizar los Paneles personalizables con la API REST y un LLM es una función de DefectDojo Pro. Está desactivada de forma predeterminada: un superusuario puede activar los Paneles personalizables desde **Settings > Feature Flags** tanto en instancias Cloud como On-Premise.</span>

Los Paneles personalizables de DefectDojo Pro están totalmente impulsados por la API REST, y la superficie de diseños fue pensada teniendo en cuenta a los agentes de IA. Eso significa que puede delegar todo el trabajo a un LLM: pegue un único prompt autocontenido en Claude, ChatGPT o cualquier otro modelo capaz, describa los paneles que desea, y el modelo interrogará el catálogo de widgets en vivo de su tenant, propondrá diseños, generará un script de Python ejecutable, creará los diseños, los verificará y, opcionalmente, establecerá su predeterminado.

El patrón es simple. Usted proporciona su URL base, un token de API y una breve descripción de para quién son los paneles. El LLM se encarga del descubrimiento, el diseño, la creación y la verificación, deteniéndose para pedir su aprobación antes de construir nada contra su tenant.

Esta guía complementa la [guía de la API de Paneles](../custom-dashboards-api/), que documenta los recursos y las formas de solicitud en bruto con los que trabaja el LLM. Si quiere entender o ajustar manualmente lo que produjo el LLM, mantenga esa referencia abierta.

## Antes de comenzar

1. **Obtenga un token de API.** En la interfaz de DefectDojo Pro, vaya a **User Settings → API v2 Key** y copie el token. Luego configúrelo como una variable de entorno para que el script generado pueda leerlo sin que el token aparezca nunca en el chat:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Confirme que la función esté activada.** Los Paneles personalizables deben estar activados para su instancia desde **Settings > Feature Flags**; de lo contrario, cada llamada a la API devuelve `403`.

3. **Decida sus paneles.** El LLM le preguntará qué desea. Las opciones más comunes son:

   - **Panorama ejecutivo** — conteos principales, distribución de severidad y cumplimiento de SLA de un vistazo.
   - **Triage diario** — críticas/altas activas, histograma de prioridad, SLA burndown y su cola "My Work".
   - **Velocidad de remediación** — velocidad de creados vs. cerrados, MTTR/MTTD y antigüedad.
   - **Efectividad de escáneres** — hallazgos por tipo de test, tasa de falsos positivos por herramienta y actividad de escaneo reciente.
   - **Salud del portafolio** — un treemap de assets por organización, cobertura de escaneo y assets con mejor/peor calificación.

> **💡 Consejo:** No tiene que elegir de esta lista. Cuéntele al LLM sus objetivos reales en lenguaje sencillo y él los traducirá a los tipos de widget y filtros disponibles.

## El prompt

Copie todo el bloque delimitado que aparece a continuación y péguelo en Claude, ChatGPT o cualquier otro LLM capaz. El prompt es autocontenido: el modelo le pedirá la URL de su tenant, la variable de entorno del token y los objetivos de los paneles, y luego lo guiará a través de descubrimiento → diseño → creación → verificación.

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

## Qué esperar

Un modelo bien comportado hará lo siguiente:

1. Pedirá su URL base, la variable de entorno del token y los objetivos de los paneles.
2. Hará `GET` al catálogo de widgets (y a dimensions/record-metrics según sea necesario) y le dirá qué tipos de widget planea usar.
3. Propondrá cada diseño (nombre, widgets, filtros y disposición en la cuadrícula) y **esperará su aprobación**.
4. Generará un script de Python que use solo la biblioteca estándar, que cree los diseños, opcionalmente establezca su predeterminado y verifique el resultado.
5. Informará lo que verificó y ofrecerá corregir cualquier cosa que no se haya guardado como se esperaba.

> **💡 Consejo:** Si un widget muestra un número inesperado, la causa habitual es una clave de filtro que se descartó silenciosamente. Pídale al LLM que lea de vuelta el diseño y compare el `config.filters` guardado con lo que envió; la [guía de la API](../custom-dashboards-api/#verify-what-you-built) cubre este paso de verificación en detalle.

## Próximos pasos

- Consulte la [guía de la API de Paneles](../custom-dashboards-api/) para conocer los recursos en bruto, las formas de solicitud y la referencia completa de acciones de widget-data.
- Cree y organice paneles de forma manual en la [interfaz de Paneles personalizables](../custom-dashboards/).
