---
title: Construindo Painéis com uma LLM
description: Use o Claude ou outra LLM para projetar, criar e configurar painéis personalizáveis
  do DefectDojo Pro pela API
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Automatizar Painéis Personalizáveis com a API REST e uma LLM é um recurso do DefectDojo Pro. Ele vem desativado por padrão — um superusuário pode ativar os Painéis Personalizáveis em **Settings > Feature Flags** tanto em instâncias Cloud quanto On-Premise.</span>

Os Painéis Personalizáveis do DefectDojo Pro são totalmente controlados pela API REST — e a superfície de layouts foi projetada com agentes de IA em mente. Isso significa que você pode delegar todo o trabalho a uma LLM: cole um único prompt autocontido no Claude, ChatGPT ou qualquer outro modelo capaz, descreva os painéis que você quer, e ele vai consultar o catálogo de widgets ativo do seu tenant, propor layouts, gerar um script Python executável, criar os layouts, verificá-los e, opcionalmente, definir seu padrão.

O padrão é simples. Você fornece sua URL base, um token de API e uma breve descrição de para quem são os painéis. A LLM faz a descoberta, o design, a criação e a verificação — pausando para sua aprovação antes de construir qualquer coisa no seu tenant.

Este guia complementa o [guia da API de Painéis](../custom-dashboards-api/), que documenta os recursos brutos e os formatos de requisição com os quais a LLM trabalha. Se você quiser entender ou ajustar manualmente o que a LLM produziu, mantenha essa referência aberta.

## Antes de começar

1. **Obtenha um token de API.** Na interface do DefectDojo Pro, acesse **User Settings → API v2 Key** e copie o token. Em seguida, defina-o como uma variável de ambiente para que o script gerado possa lê-lo sem que o token jamais apareça no chat:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Confirme que o recurso está ativado.** Os Painéis Personalizáveis precisam estar ativados na sua instância em **Settings > Feature Flags** — caso contrário, toda chamada de API retorna `403`.

3. **Decida seus painéis.** A LLM vai perguntar o que você quer. Escolhas comuns:

   - **Executive Overview** — contagens principais, distribuição de severidade e conformidade de SLA em uma única visão.
   - **Daily Triage** — críticos/altos ativos, histograma de prioridade, burndown de SLA e sua fila "My Work".
   - **Remediation Velocity** — velocidade de criados vs. fechados, MTTR/MTTD e envelhecimento (aging).
   - **Scanner Effectiveness** — achados por tipo de teste, taxa de falsos positivos por ferramenta e atividade recente de scan.
   - **Portfolio Health** — um treemap de ativos por organização, cobertura de scan e ativos com melhores/piores notas.

> **💡 Dica:** Você não precisa escolher desta lista. Diga à LLM seus objetivos reais em linguagem simples, e ela vai mapeá-los para os tipos de widget e filtros disponíveis.

## O prompt

Copie todo o bloco delimitado abaixo e cole-o no Claude, ChatGPT ou qualquer outra LLM capaz. O prompt é autocontido — o modelo vai pedir a URL do seu tenant, a variável de ambiente do token e os objetivos dos painéis, e então vai conduzir você por descoberta → design → criação → verificação.

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

## O que esperar

Um modelo bem-comportado vai:

1. Pedir sua URL base, a variável de ambiente do token e os objetivos dos painéis.
2. Fazer um `GET` no catálogo de widgets (e em dimensions/record-metrics conforme necessário) e informar quais tipos de widget pretende usar.
3. Propor cada layout — nome, widgets, filtros e organização na grade — e **aguardar sua aprovação**.
4. Gerar um script Python que usa apenas a biblioteca padrão, que cria os layouts, opcionalmente define seu padrão e verifica o resultado.
5. Relatar o que verificou e se oferecer para corrigir qualquer coisa que não tenha sido salva como pretendido.

> **💡 Dica:** Se um widget renderizar um número inesperado, a causa mais comum é uma chave de filtro que foi descartada silenciosamente. Peça à LLM para ler o layout de volta e comparar o `config.filters` salvo com o que foi enviado — o [guia da API](../custom-dashboards-api/#verify-what-you-built) cobre essa etapa de verificação em detalhes.

## Próximos passos

- Veja o [guia da API de Painéis](../custom-dashboards-api/) para os recursos brutos, os formatos de requisição e a referência completa das ações de widget-data.
- Crie e organize painéis manualmente na [interface de Painéis Personalizáveis](../custom-dashboards/).
