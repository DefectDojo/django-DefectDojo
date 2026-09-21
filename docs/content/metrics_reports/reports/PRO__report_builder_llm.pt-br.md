---
title: Construindo relatórios com um LLM
description: Use o Claude ou outro LLM para projetar, criar, executar e baixar relatórios
  do DefectDojo Pro pela API
draft: false
audience: pro
weight: 22
slug: report-builder-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Automatizar o Report Builder com a API REST e um LLM é um recurso do DefectDojo Pro, atualmente em beta.</span>

O Report Builder do DefectDojo Pro (Themes, Blocks e Templates) é totalmente controlado pela API REST. Isso significa que você pode entregar toda a tarefa a um LLM: cole um único prompt autocontido no Claude, ChatGPT ou em qualquer outro modelo capaz, e ele vai consultar o schema OpenAPI ativo do seu tenant e os `field_options`, propor um theme mais uma biblioteca reutilizável de blocks e templates para os públicos que você indicar, gerar um script Python executável e, em seguida, executar o relatório e baixar o arquivo final.

O padrão é simples. Você fornece sua URL base, um token de API e uma breve descrição de para quem os relatórios se destinam. O LLM cuida da descoberta, do design, da criação, da verificação, da execução e do download — pausando para sua aprovação antes de criar qualquer coisa no seu tenant.

Este guia funciona em conjunto com o [guia da API do Report Builder](../report-builder-api/), que documenta os recursos brutos e os formatos de requisição com os quais o LLM está trabalhando. Se você quiser entender ou ajustar manualmente o que o LLM produziu, essa é a referência que vale a pena manter aberta.

## Antes de começar

1. **Obtenha um token de API.** Na interface do DefectDojo Pro, acesse **Configurações do Usuário → Chave da API v2** e copie o token. Em seguida, defina-o como uma variável de ambiente para que o script gerado possa lê-lo sem que o token apareça no chat:

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **Defina seus públicos.** O LLM vai perguntar para quem os relatórios são destinados. Opções comuns:

   - **Executive Summary** — postura de alto nível; SLA vencido, KEV e inventário de ativos em um só relance.
   - **POA&M (Plan of Action & Milestones)** — achados abertos com severidade, data de vencimento e remediação recomendada, além de detalhamento de itens críticos e achados históricos/encerrados.
   - **Integrated Inventory Workbook** — ativos (antigos Products) no escopo com criticidade, plataforma, ciclo de vida, acessibilidade pela internet e contagem de achados.
   - **Deviation Request (DRF) Package** — aceitações de risco ativas, achados marcados com a tag DR e candidatos a SLA vencido para novas solicitações de desvio.
   - **Engineering Findings Detail** — descrições completas por achado (descrição, impacto, mitigação, referências).
   - **Compliance / Audit Snapshot** — ativos, aceitações de risco e KEV.

> **💡 Dica:** Você não precisa escolher desta lista. Diga ao LLM quais são seus públicos reais em linguagem simples, e ele vai mapeá-los para as entidades e filtros disponíveis.

## O prompt

Copie todo o bloco de código abaixo e cole em Claude, ChatGPT, ou qualquer outro LLM capaz. O prompt é autocontido — o modelo vai perguntar a URL do seu tenant, a variável de ambiente do token e os públicos dos relatórios, e então vai conduzi-lo por descoberta → design → criação → verificação → execução → download.

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

## Como usar

1. **Cole o prompt** acima no Claude, ChatGPT ou em outro LLM capaz.
2. **Responda às perguntas de descoberta.** Ele vai pedir sua URL base, a variável de ambiente que contém seu token, seus públicos, filtros específicos que sejam importantes para você (níveis de severidade, cortes de SLA, somente KEV, ativos ou tags específicos), sua identidade visual e o formato de saída desejado.
3. **Revise o design proposto e aprove antes da criação.** O modelo deve retornar com um theme compartilhado, uma biblioteca reutilizável de blocks e um ou mais templates — mostrando, para cada block de dados, o `model_choice`, os `fields`, a ordenação e as entradas de filtro exatas. Não deixe que ele crie nada no seu tenant antes de você dar sua aprovação.
4. **Deixe-o gerar e executar o script.** O único script Python (usando apenas a biblioteca padrão) cria o theme, os blocks e os templates, depois executa o relatório e baixa o arquivo final.
5. **Ele deve verificar antes e depois da execução.** Espere que ele faça um GET de cada block e template para confirmar que os filtros e a ordenação foram persistidos, depois um POST em `generated_reports`, aguarde até o status ficar `completed` e baixe o arquivo.

> **💡 Dica:** Se o LLM for direto para o design dos blocks sem antes buscar o schema ativo do seu tenant (`/api/v2/oa3/schema/?format=json`) e os `field_options`, questione. Os nomes de filtros e campos variam de acordo com a versão, e projetar de memória é exatamente como os blocks acabam ficando silenciosamente sem filtros.

## Solução de problemas

**Um block criado retorna sem os filtros que você enviou.** O nome do `field` do filtro não correspondeu a um parâmetro GET real na entidade subjacente, então o DefectDojo o descartou. Peça ao LLM para buscar `/api/v2/oa3/schema/?format=json`, ler a lista de `parameters` do endpoint GET dessa entidade (por exemplo, o endpoint de findings) e usar um nome de parâmetro real.

**Os filtros booleanos não estão fazendo efeito.** Os valores booleanos devem ser enviados como as strings `"true"` ou `"false"`, e não como booleanos JSON reais.

**`outside_of_sla` não está filtrando.** Esse filtro recebe um valor numérico como string — use `"1"`, não `"true"`.

**Várias severidades em um único block não funcionam.** Um único block mantém apenas a primeira severidade. Em vez disso, divida em um block por severidade.

**Os template blocks retornam na ordem errada ou ausentes.** Verifique se o LLM fez o POST de `template_blocks_write` (o campo somente para escrita), e não de `template_blocks` (que é somente leitura). O campo `order` é obrigatório em cada entrada.

**A execução do relatório está travada ou falhou.** Continue fazendo polling em `GET /api/v2/generated_reports/{id}/` — o status passa de `pending` para `processing` e depois para `completed`. Se o status se tornar `failed`, leia o campo `error_message` para descobrir a causa antes de tentar novamente.

> **⚠️** O endpoint de download (`/api/v2/generated_reports/{id}/download/`) retorna 404 até que a execução chegue a `completed`. Sempre aguarde a conclusão via polling antes de baixar.

## Próximos passos

- [Report Builder (interface)](../report-builder/) — projete e execute relatórios de forma interativa na interface do DefectDojo Pro.
- [Report Builder API](../report-builder-api/) — os recursos REST brutos e os formatos de requisição com os quais o LLM trabalha, para ajuste manual ou automação mais profunda.
