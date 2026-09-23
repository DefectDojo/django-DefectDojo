---
title: Automatizando Relatórios com a API
description: Crie temas, blocos e templates e, em seguida, execute relatórios e baixe
  os resultados pela API REST do DefectDojo Pro
draft: false
audience: pro
weight: 21
slug: report-builder-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: a API REST do Report Builder (temas de relatório, blocos, templates e relatórios gerados) é um recurso do DefectDojo Pro, atualmente em beta.</span>

A API REST do Report Builder permite automatizar os mesmos Temas, Blocos e Templates que você monta manualmente na [interface do Report Builder](../report-builder/) — e vai um passo além, permitindo **executar** um template e **baixar** o PDF ou HTML finalizado. Este guia percorre todo o ciclo de vida: autenticar, descobrir o vocabulário de campos e filtros, criar os blocos de construção e, então, gerar e recuperar um relatório.

> **Procurando algo mais simples para exportar achados?** Se você só precisa de uma lista simples de achados em JSON, HTML, CSV ou Excel — sem temas, blocos ou templates para configurar — use o endpoint mais simples `generate_report/` documentado em [Gerando Relatórios](/automation/api/api-v2-docs/#generating-reports). A API do Report Builder descrita nesta página serve para construir relatórios com design elaborado e múltiplas seções.

## Autenticação

Toda requisição é autenticada com um token de API pessoal enviado no cabeçalho `Authorization` usando o prefixo `Token` (não `Bearer`).

Obtenha seu token na interface do DefectDojo Pro em **User Settings → API v2 Key**. Armazene-o em uma variável de ambiente para que ele nunca fique registrado no histórico do shell ou em um script versionado:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

A URL base para todas as chamadas é a sua instância mais `/api/v2`:

```text
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Cabeçalhos obrigatórios:

| Cabeçalho | Valor | Quando |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Toda requisição |
| `Accept` | `application/json` | Toda requisição |
| `Content-Type` | `application/json` | `POST` / `PATCH` com corpo JSON |

Uma requisição autenticada mínima é assim:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

Os endpoints de listagem são paginados com os parâmetros de consulta `limit` e `offset`.

> **⚠️ Aviso de Segurança:** Seu token de API concede acesso total aos seus dados do DefectDojo. Nunca cole-o em um chat, captura de tela, ticket ou arquivo versionado. Leia-o a partir de uma variável de ambiente, rotacione-o caso ele seja exposto e, quando possível, restrinja tokens a contas de serviço.

## Visão geral da API de relatórios

Quatro recursos compõem a API do Report Builder. Cada um suporta as operações padrão de listagem (`GET`), criação (`POST`), obtenção (`GET {id}/`), atualização (`PATCH {id}/`) e exclusão (`DELETE {id}/`), além de algumas ações personalizadas.

| Recurso | Caminho | O que é | Ações personalizadas |
|----------|------|------------|----------------|
| Temas | `/report_themes/` | Cores, fontes, imagens de cabeçalho/rodapé, números de página | — |
| Blocos | `/report_blocks/` | Um único elemento de conteúdo: uma página de capa, uma tabela ou uma seção de detalhe | `field_options/`, `preview/`, `{id}/preview/`, `{id}/duplicate/` |
| Templates | `/report_templates/` | Uma lista ordenada de blocos mais um tema | `{id}/duplicate/` |
| Relatórios gerados | `/generated_reports/` | Uma execução de um template que produz um arquivo para download | `{id}/download/` |

Mais dois endpoints ajudam você a descobrir o vocabulário necessário:

| Endpoint | Finalidade |
|----------|---------|
| `GET /report_blocks/field_options/` | Caminhos de campo de coluna válidos e opções de ordenação para cada modelo |
| `GET /oa3/schema/?format=json` | O schema OpenAPI completo — usado para descobrir os nomes de filtro válidos |

## Etapa 1: descobrir o vocabulário

Duas coisas em um bloco são fáceis de errar se você apenas chutar: os **campos de coluna** que você lista e os **filtros** que você aplica. A API fornece uma fonte confiável para ambos. Busque-os primeiro e depois construa com base no que o servidor realmente aceita.

### Campos de coluna e ordenação

`field_options` retorna os `fields` (caminhos de coluna) válidos e os `ordering_fields` para cada modelo que pode ser usado em um bloco tabular ou de detalhe:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

A resposta tem este formato (truncada):

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

Use apenas os valores de `path` retornados aqui na lista `fields` de um bloco. Alguns caminhos são de formato longo ou markdown e são destinados a blocos de **detalhe**, não a colunas tabulares estreitas — `field_options` é a lista definitiva, então confirme nela em vez de fixar um conjunto exaustivo no código.

### Nomes de filtro a partir do schema

Os filtros de um bloco ficam em `filter_entries`, onde cada entrada é um par `{field, value}`. Os nomes de `field` válidos são os **nomes dos parâmetros de consulta GET** do endpoint REST da entidade subjacente — *não* os rótulos que você vê na interface. Descubra-os lendo o schema OpenAPI:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

Em seguida, leia os parâmetros GET da entidade que você está filtrando. Para achados, veja `paths` → `/api/v2/findings/` → `get` → `parameters`. Os endpoints análogos são `/api/v2/assets/` para **assets** (antigos Produtos), `/api/v2/organizations/` para **organizations** (antigos Tipos de Produto), `/api/v2/engagements/`, `/api/v2/tests/`, `/api/v2/test_types/`, e `/api/v2/risk_acceptance/`. Cada `name` de parâmetro é um `field` de filtro válido.

> **💡 Dica:** No DefectDojo Pro, **Assets** eram antes chamados de **Produtos** e **Organizations** eram antes **Tipos de Produto**. Os caminhos de campo de filtro subjacentes nos achados ainda usam a nomenclatura legada `product` (por exemplo, `test__engagement__product`), mesmo que as entidades agora sejam Assets e Organizations.

> **🔑 Importante:** O servidor **descarta silenciosamente** qualquer `filter_entry` cujo `field` não seja um parâmetro GET real para aquele modelo. Nenhum erro é gerado — o filtro simplesmente não existe no bloco salvo. Sempre faça um GET do bloco depois de criá-lo e compare os `filter_entries` retornados com o que você enviou.

### Campos de filtro comuns

As tabelas abaixo listam filtros verificados e de alto valor. Todos os valores são enviados como **strings de valor único**; os booleanos são as strings literais `"true"` / `"false"`.

**Filtros de achado**

| Campo | Valor de exemplo | Observações |
|-------|---------------|-------|
| `active` | `"true"` | String booleana |
| `verified` | `"true"` | String booleana |
| `is_mitigated` | `"false"` | String booleana |
| `risk_accepted` | `"false"` | String booleana |
| `duplicate` | `"false"` | String booleana |
| `false_p` | `"false"` | String booleana |
| `out_of_scope` | `"false"` | String booleana |
| `severity` | `"Critical"` | Apenas valor único — **não** separado por vírgulas. Use um bloco por severidade. |
| `known_exploited` | `"true"` | String booleana |
| `ransomware_used` | `"true"` | String booleana |
| `outside_of_sla` | `"1"` | String **numérica**, não uma string booleana |
| `priority_min` | `"800"` | Use `_min`/`_max`, não `_greater_than` |
| `priority_max` | `"1000"` | Use `_min`/`_max` |
| `tag` | `"DR"` | Uma única tag |
| `tags` | `"kev,pci"` | Qualquer-um (corresponde a qualquer tag listada) |
| `tags__and` | `"kev,pci"` | Todos (deve corresponder a todas as tags listadas) |
| `test__engagement__product` | `"42"` | ID do Asset (Assets eram antes Produtos) |
| `test__engagement__product__prod_type` | `"3"` | ID da Organization (antes Tipo de Produto) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**Filtros de Asset** (Assets eram antes chamados de Produtos; estes são os parâmetros em `/api/v2/assets/`)

| Campo | Valor de exemplo | Observações |
|-------|---------------|-------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | String booleana |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | Uma única tag |

**Filtros de aceitação de risco**

| Campo | Valor de exemplo | Observações |
|-------|---------------|-------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | ID do usuário |
| `expiration_date_before` | `"2025-12-31"` | Não existe filtro `tag` neste modelo |

Para blocos de **engagement**, **test**, **test type** e **organization**, leia os parâmetros GET diretamente do schema, conforme descrito acima. Entre os de maior valor estão `engagement__product` e `status` em tests, e `name` em test types — mas sempre confirme o nome exato em `schema.json` antes de confiar nele.

> **⚠️** Estes nomes legados / no estilo da interface são **descartados silenciosamente** e NÃO devem ser usados: `status_any`, `priority_greater_than`, `severity__in`, `mitigated_within_sla`, e qualquer valor de **`severity` separado por vírgulas** (por exemplo, `"Critical,High"`). Use os nomes reais de parâmetro de consulta do schema e divida necessidades de múltiplas severidades em blocos separados.

> **🔑 Importante:** Um `PATCH` que inclui `filter_entries` **substitui a lista inteira** — não há mesclagem. Sempre envie o conjunto completo de filtros desejado em cada atualização, ou você perderá os que forem omitidos.

## Etapa 2: criar tema, blocos e templates

Construa as peças na ordem de dependência: um **tema**, depois os **blocos**, e então um **template** que referencia ambos.

### Criar um tema

As cores são strings hexadecimais de 7 caracteres. Qualquer campo omitido usa seu valor padrão (primary `#1e3a5f`, secondary `#4a90a4`, accent `#e67e22`, text `#333333`, background `#ffffff`).

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

A resposta inclui o `id` do novo tema. As imagens de cabeçalho e rodapé são opcionais e são enviadas como campos de formulário multipart (`header_image` / `footer_image`); o exemplo JSON acima as omite.

### Criar blocos

Um bloco tem um `name`, um `block_type` e um objeto de configuração correspondente. Os valores suportados para `block_type` são `stock`, `tabular` e `detail`. (Existe um tipo `chart` no modelo de dados, mas ele ainda não é exposto pela API.)

**Uma capa fixa (stock).** Blocos stock contêm conteúdo fixo. O `stock_type` é um de `cover_page`, `table_of_contents`, `page_break`, `image` ou `text_block`.

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

**Um bloco tabular de achados com filtros.** Blocos tabulares renderizam linhas de um modelo escolhido. `model_choice` é exatamente um de `organization`, `asset`, `engagement`, `test`, `finding`, `test_type` ou `risk_acceptance`. Os `fields` vêm de `field_options` (confirme cada `path`), e `filter_entries` delimitam as linhas.

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

**Um bloco de detalhe de achados.** Blocos de detalhe renderizam uma seção expandida por registro e podem incluir campos de formato longo / markdown que não cabem em uma coluna de tabela estreita. Novamente, confirme os `fields` em `field_options`.

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

Cada resposta de bloco inclui seu `id`. Note que `filter_entries` reflete o que o servidor realmente armazenou — compare com o que você enviou (veja [Verifique o que você construiu](#verify-what-you-built)).

### Criar um template

Um template vincula um tema a uma lista ordenada de blocos. O campo somente leitura é `template_blocks`; na criação e atualização você **escreve** em `template_blocks_write`. Cada entrada precisa de um `order` e um `block_id`, e o mesmo `block_id` pode aparecer mais de uma vez.

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

Substitua `theme_id` e cada `block_id` pelos IDs retornados nas etapas anteriores. A resposta inclui o `id` do template.

## Etapa 3: executar o relatório e baixar o resultado

Gerar um relatório é assíncrono: você cria uma execução, consulta periodicamente seu status e baixa o arquivo quando ela é concluída.

**Inicie uma execução.** Faça um POST com um `template_id` e um `file_format` de `pdf` ou `html`:

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

A resposta retorna o `id` do novo relatório com `status` definido como `pending`.

**Consulte o status.** Obtenha o relatório até que seu `status` alcance um estado terminal. O fluxo é `pending` → `processing` → `completed`. Em caso de `failed`, leia `error_message` para saber o motivo.

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**Baixe o arquivo.** Quando `status` for `completed`, o endpoint de download retorna o arquivo como um anexo. Até lá, ele responde com `404`.

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## Juntando tudo: um script de ciclo de vida completo

O script abaixo executa todo o fluxo usando apenas a biblioteca padrão do Python 3 — sem `requests`, sem pacotes de terceiros. Ele lê o token de `DD_IMPORTER_DOJO_API_TOKEN`, cria um tema, três blocos e um template, inicia um relatório, consulta o status com backoff até que ele seja concluído ou falhe, baixa o resultado e grava os IDs criados em `created.json`.

Defina a URL da sua instância e execute:

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

## Verifique o que você construiu

Como filtros inválidos são descartados silenciosamente, a verificação faz parte do fluxo de trabalho — não é algo à parte.

**Confirme que os filtros do bloco foram mantidos.** Faça um GET de cada bloco e compare seus `filter_entries` com o que você enviou no POST:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

Se um filtro que você enviou estiver ausente em `filter_entries`, o nome do `field` não era um parâmetro GET válido para aquele modelo — verifique novamente o nome em `schema.json`.

**Confirme a ordem do template e o tema.** Faça um GET do template e verifique se `template_blocks` lista os blocos na `order` esperada e se o tema vinculado corresponde:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**Corrija filtros descartados com PATCH.** Para corrigir os filtros de um bloco, faça um PATCH com o conjunto **completo** desejado — um PATCH substitui `filter_entries` por inteiro:

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

## Próximos passos

- Construa e visualize os mesmos Temas, Blocos e Templates interativamente na [interface do Report Builder](../report-builder/).
- Deixe uma LLM montar configurações de relatório para você com a [integração LLM do Report Builder](../report-builder-llm/).
