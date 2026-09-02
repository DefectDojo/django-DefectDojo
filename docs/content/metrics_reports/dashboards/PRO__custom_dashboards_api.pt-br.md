---
title: Automatizando Painéis com a API
description: Descubra o catálogo de widgets, crie e atualize layouts de painéis e
  renderize dados de widgets pela API REST do DefectDojo Pro
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: A API REST de Painéis Personalizáveis (layouts, catálogo de widgets e dados de widgets) é um recurso do DefectDojo Pro. Ela vem desativada por padrão — um superusuário pode ativar os Painéis Personalizáveis em **Settings > Feature Flags** tanto em instâncias Cloud quanto On-Premise.</span>

A API REST de Painéis Personalizáveis permite criar, inteiramente a partir de código, os mesmos painéis que você monta manualmente na [interface de Painéis](../custom-dashboards/). Você pode descobrir o catálogo de widgets, criar e atualizar layouts, definir seu padrão, compartilhar layouts com sua equipe e até renderizar os dados de um widget sob demanda sem reimplementar a filtragem do DefectDojo. A superfície de layouts foi projetada como o ponto de entrada principal para agentes de IA que constroem painéis, portanto os formatos de requisição são deliberadamente introspectáveis.

Este guia percorre todo o ciclo de vida: autenticar, descobrir o vocabulário de widgets, criar um layout e, em seguida, verificá-lo e renderizá-lo.

## Autenticação

Toda requisição é autenticada com um token de API pessoal enviado no cabeçalho `Authorization` usando o prefixo `Token` (não `Bearer`).

Obtenha seu token na interface do DefectDojo Pro em **User Settings → API v2 Key**. Armazene-o em uma variável de ambiente para que ele nunca fique registrado no histórico do shell ou em um script versionado:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

A URL base para todas as chamadas é a sua instância mais `/api/v2`:

```
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

Cabeçalhos obrigatórios:

| Cabeçalho | Valor | Quando |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Toda requisição |
| `Accept` | `application/json` | Toda requisição |
| `Content-Type` | `application/json` | `POST` / `PATCH` com corpo JSON |

Uma requisição autenticada mínima é semelhante a esta:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 Importante:** Toda a API de Painéis depende do recurso Painéis Personalizáveis. Até que ele seja ativado, todo endpoint retorna `403 Dashboards 2.0 is not enabled.` — veja [Ativando Painéis Personalizáveis](../custom-dashboards/#enabling-customizable-dashboards).

> **⚠️ Aviso de Segurança:** Seu token de API concede acesso total aos seus dados do DefectDojo. Nunca o cole em um chat, captura de tela, chamado ou arquivo versionado. Leia-o a partir de uma variável de ambiente, revogue-o (rotacione) se ele for exposto e restrinja tokens a contas de serviço sempre que possível.

## Visão geral da API de painéis

Três grupos de recursos compõem a API de Painéis, todos sob `/api/v2/dashboards/`.

| Recurso | Caminho | O que é | Operações |
|----------|------|------------|------------|
| Layouts | `/dashboards/layouts/` | Seus painéis salvos (e modelos compartilhados da equipe) | `GET` lista, `POST` cria, `GET {id}/`, `PATCH {id}/`, `DELETE {id}/`, além de `{id}/clone/`, `{id}/set_default/`, `shared/`, `for_current_user/` |
| Catálogo de widgets | `/dashboards/widget_catalog/` | O menu de tipos de widget + um exemplo de configuração para cada um | `GET` (somente leitura) |
| Dados de widget | `/dashboards/widget_data/<action>/` | Dados renderizados sob demanda para um widget | 21 ações por widget |

Esses endpoints aceitam autenticação Token, Session ou Basic. Toda a autorização por registro e o escopo de dados seguem o controle de acesso baseado em função padrão do DefectDojo — compartilhar um layout nunca amplia o que seus visualizadores podem ver.

> **💡 Dica:** A interface Vue chama um espelho interno desses endpoints em `/api/vue/dashboard_v2/`. Sempre automatize usando os caminhos estáveis e voltados ao cliente `/api/v2/dashboards/` documentados aqui.

## Etapa 1: descubra o vocabulário

Três coisas em um widget são fáceis de errar quando você tenta adivinhar: o **tipo do widget**, sua **dimensão de agrupamento** (para gráficos) e seus **filtros**. A API fornece uma fonte de verdade para cada um deles. Busque-os primeiro e depois construa em cima do que o servidor realmente aceita.

### O catálogo de widgets

`GET /dashboards/widget_catalog/` retorna todos os tipos de widget, a categoria a que pertencem, o(s) endpoint(s) de dados sobre os quais são renderizados e — o mais útil — um `config_example` mínimo e válido que você pode copiar como ponto de partida:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

A resposta tem este formato (truncado):

```json
{
  "categories": [
    {"id": "numbers", "label": "Numbers", "description": "Single-glance metrics — counts, KPIs, gauges."},
    {"id": "charts",  "label": "Charts",  "description": "Time-series and distribution visualisations."},
    {"id": "lists",   "label": "Lists & Feeds", "description": "Ranked lists, feeds, and embedded tables."},
    {"id": "static",  "label": "Static & Utility", "description": "Notes, shortcuts, and quick actions."}
  ],
  "widgets": [
    {
      "type": "count",
      "label": "Count",
      "category": "numbers",
      "description": "Single number rendered from a filtered queryset...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/count/"],
      "config_example": {
        "model": "finding",
        "filters": {"status_any": "Active", "severity": "Critical"},
        "icon": "fas fa-ban",
        "color": "danger"
      }
    },
    {
      "type": "graph",
      "label": "Graph",
      "category": "charts",
      "description": "Generic chart over any model + group-by dimension...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/aggregate/"],
      "config_example": {
        "model": "finding",
        "filters": {"duplicate": "false"},
        "group_by": "severity",
        "aggregation": "count",
        "chart_type": "pie",
        "time_bucket": null,
        "limit": null,
        "stacked": false
      }
    }
  ]
}
```

Use o `type` de um widget como o `type` do widget, e seu `config_example` como ponto de partida para o `config` do widget. O catálogo lista 26 tipos de widget distribuídos nas quatro categorias.

### Dimensões de agrupamento e métricas de registro

Os widgets de gráfico e de ranking restringem o que você pode usar para agrupar ou classificar a uma lista de permissões selecionada. Descubra esses valores por modelo em vez de adivinhar:

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/` retorna, para cada dimensão, sua `key` (o valor a ser passado como `group_by`), um `label` legível e um `kind`:

```json
{
  "model": "finding",
  "dimensions": [
    {"key": "severity",  "label": "Severity",        "kind": "categorical"},
    {"key": "status",    "label": "Status",          "kind": "banded"},
    {"key": "date",      "label": "Discovered Date", "kind": "time"},
    {"key": "test_type", "label": "Test Type",       "kind": "categorical"}
  ]
}
```

O `kind` importa: uma dimensão `time` (como `date`) exige que você também envie um `time_bucket` (`day`/`week`/`month`/`quarter`/`year`); uma dimensão `categorical` ou `banded` não exige. O campo `priority` intencionalmente **não** é uma dimensão de agrupamento (é uma pontuação contínua) — use a dimensão `risk` para uma visão em faixas, ou o widget dedicado **Priority Histogram**.

### Filtros

O `config.filters` de um widget usa **o mesmo formato de filtro da visão de lista do objeto** — os valores que a página de lista emite para sua URL, não os parâmetros brutos de consulta REST. Por exemplo, em achados: `{"status_any": "Active"}`, `{"severity": "Critical"}`, `{"duplicate": "false"}`, `{"date_past_days": 7}`, `{"sla_days_remaining_less_than_equal_to": 7}`; em ativos: `{"grade": "A,B,C"}`, `{"last_scanned_past_days": 90}`. A forma mais rápida de descobrir o filtro certo para uma necessidade é aplicá-lo na página de lista correspondente na interface e lê-lo de volta na caixa de diálogo de configuração do widget, ou copiar os filtros dos modelos compartilhados pré-configurados.

> **🔑 Importante:** **Chaves** de filtro desconhecidas **são ignoradas silenciosamente** — um filtro com erro de digitação ou inexistente não gera erro, simplesmente não é aplicado, deixando o widget exibir uma população mais ampla do que o pretendido. *Valores* inválidos para um filtro real retornam `400`. Sempre [verifique o que você construiu](#verify-what-you-built) lendo o layout de volta. (Os filtros são validados pelo mesmo FilterSet usado pela visão de lista, portanto valores de lista podem ser passados como arrays para correspondência do tipo "qualquer um": `{"severity": ["Critical", "High"]}`.)

> **💡 Dica:** A maioria dos widgets recebe um `model` igual a `finding`, `product`, `engagement` ou `test` — observe o legado `product` (a interface chama isso de **Assets**). O widget **Embedded Table** é a exceção: seu `model` usa os nomes mais novos `finding`, `asset`, `engagement`, `test`, `risk_acceptance`, `organization` ou `test_type`.

## Etapa 2: crie um layout

Um layout é criado com um `POST` para `/dashboards/layouts/`. Os dois campos que carregam o conteúdo do painel são `widgets` e `layout`, e eles precisam ser consistentes entre si.

### O objeto de widget

Cada item do array `widgets` tem este formato:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** — um UUID gerado por você. Ele vincula o widget à sua posição na grade.
- **`type`** — um valor de `type` do catálogo de widgets.
- **`title`** — o título exibido no widget (até 200 caracteres).
- **`refresh_interval`** — segundos de atualização automática; um dos valores `0` (desativado), `30`, `60`, `300` ou `900`.
- **`config`** — a configuração específica do tipo. Comece a partir do `config_example` do catálogo e ajuste. Cada tipo de widget valida sua própria configuração no servidor e retorna um `400` descritivo caso algo esteja errado.
- **`title_styling`** *(opcional)* — `{"bold": true, "size": "md"}`, em que `size` é `sm`, `md` ou `lg`.

### O mapa de layout (grade)

`layout` é um mapa do `id` de cada widget para sua posição na grade de 12 colunas:

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`, `y`** — coordenadas da grade no canto superior esquerdo (indexadas a partir de 0; `x` varia de 0 a 11).
- **`w`, `h`** — largura (em colunas) e altura (em linhas).
- **`min_w`, `min_h`** *(opcional, padrão 1)* e **`max_w`, `max_h`** *(opcional)* — limites de tamanho.

> **🔑 Importante:** O mapa `layout` e a lista `widgets` precisam ser consistentes: **todo widget precisa de uma posição, e toda posição precisa referenciar um widget existente.** Uma inconsistência retorna `400`. O script de ciclo de vida abaixo constrói os dois juntos para que seus IDs sempre correspondam.

### Crie o layout

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/" \
  -d '{
    "name": "Exec Overview (API)",
    "widgets": [
      {"id": "11111111-1111-4111-8111-111111111111", "type": "count", "title": "Active Critical Findings",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban"}},
      {"id": "22222222-2222-4222-8222-222222222222", "type": "graph", "title": "Findings by Severity",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"duplicate": "false"}, "group_by": "severity", "aggregation": "count", "chart_type": "pie", "time_bucket": null, "limit": null, "stacked": false}}
    ],
    "layout": {
      "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2},
      "22222222-2222-4222-8222-222222222222": {"x": 3, "y": 0, "w": 9, "h": 4, "min_w": 3, "min_h": 3}
    },
    "settings": {}
  }'
```

A resposta reflete o layout salvo, incluindo seu novo `id`, além de campos auxiliares somente leitura (`is_default`, `is_owned`, `is_catalog`, `category`, `icon` e timestamps).

### Ações personalizadas

| Ação | Chamada | O que faz |
|--------|------|--------------|
| Definir como padrão | `POST /dashboards/layouts/{id}/set_default/` | Torna esse layout o que sua página inicial carrega. Você só pode definir como padrão um layout que você possui. |
| Clonar | `POST /dashboards/layouts/{id}/clone/` (corpo opcional `{"name": "..."}`) | Copia um layout (seu ou um modelo compartilhado) para o seu espaço com novos IDs de widget. Usa como padrão `"Copy of <name>"`. |
| Listar compartilhados | `GET /dashboards/layouts/shared/` | Lista todos os layouts compartilhados — modelos selecionados e os publicados pela equipe. |
| Bootstrap | `GET /dashboards/layouts/for_current_user/` | Retorna `{"results": [...your layouts...], "default_id": <id>}`. Na primeira chamada, ele clona automaticamente o modelo inicial para que você sempre receba pelo menos um layout de volta. |

Publicar um layout compartilhado (`"is_shared": true` na criação ou atualização) requer a função global de **Maintainer**.

## Etapa 3: renderize os dados do widget (opcional)

Normalmente você não precisa renderizar os dados manualmente — o painel faz isso ao exibir um widget. Mas os mesmos endpoints de `widget_data` estão disponíveis diretamente, o que é útil para scripts ou resumos de chat que queiram citar um número em tempo real. Envie o `config` do widget (ou o subconjunto relevante) como payload.

**Uma contagem filtrada** (`POST`):

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**Uma agregação por agrupamento** (`POST`), os dados por trás de um Graph:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/aggregate/" \
  -d '{"model": "finding", "filters": {}, "group_by": "severity", "aggregation": "count"}'
```

```json
{
  "labels": ["Critical", "High", "Medium", "Low", "Info"],
  "series": [{"name": "count", "data": [15, 23, 8, 12, 5]}],
  "group_by": "severity",
  "group_by_label": "Severity",
  "model": "finding",
  "model_label": "Findings",
  "aggregation": "count",
  "time_bucket": null
}
```

O conjunto completo de ações de `widget_data`:

| Ação | Método | Payload / parâmetros principais | Retorna |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | dimensões de agrupamento válidas |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | métricas válidas do modo de registros |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | séries de taxa / numerador / denominador |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy` (1–2 dims) | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | faixas por janela |
| `risk_matrix` | POST | `filters`, `x_dim?` | células de EPSS × risco (somente achados) |
| `priority_histogram` | POST | `filters`, `bin_count?` | compartimentos (bins) de histograma (somente achados) |
| `treemap` | POST | `filters`, `metric?` | árvore de portfólio aninhada |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | células de calendário por dia |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | séries empilhadas de faixas de idade |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | séries pareadas de MTTR/MTTD |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | séries de criados vs. fechados |
| `my_work` | GET | `?buckets=`, `?limit=` | suas atribuições / menções / revisões pendentes |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | achados próximos de violar o SLA |
| `recent_activity` | GET | `?model=`, `?limit=` | feed de registros recentes |
| `saved_reports` | GET | `?limit=` | Modelos de Relatório salvos *(requer Reporting)* |
| `usage` | GET | — | detalhamento de uso de licença *(requer Maintainer)* |

## Juntando tudo: um script de ciclo de vida completo

O script abaixo executa todo o fluxo usando apenas a biblioteca padrão do Python 3 — sem `requests`, sem pacotes de terceiros. Ele lê o token de `DD_IMPORTER_DOJO_API_TOKEN`, descobre o catálogo de widgets, monta um layout com dois widgets (com a lista `widgets` e o mapa `layout` gerados juntos, para que seus IDs sempre correspondam), cria o layout, define-o como padrão, lê-o de volta para verificar e grava o ID criado em `created.json`.

Defina a URL da sua instância e execute:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_dashboard.py
```

```python
#!/usr/bin/env python3
"""Build a DefectDojo Pro dashboard layout end-to-end using only the stdlib."""

import json
import os
import urllib.error
import urllib.request
import uuid

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset


def api_request(method, path, body=None):
    """Make an authenticated request. Returns parsed JSON."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
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

    return json.loads(payload) if payload else {}


def make_widget(widget_type, title, config, *, x, y, w, h, min_w=2, min_h=2):
    """Build a (widget, position) pair sharing a freshly generated UUID."""
    widget_id = str(uuid.uuid4())
    widget = {
        "id": widget_id,
        "type": widget_type,
        "title": title,
        "refresh_interval": 0,
        "config": config,
    }
    position = {"x": x, "y": y, "w": w, "h": h, "min_w": min_w, "min_h": min_h}
    return widget_id, widget, position


def main():
    created = {}

    # 1. Discover the catalog so we build against real widget types.
    #    (We don't strictly need the response here, but fetching it first
    #    is the recommended pattern — copy a config_example as a starting
    #    point instead of guessing the config shape.)
    catalog = api_request("GET", "/dashboards/widget_catalog/")
    known_types = {w["type"] for w in catalog["widgets"]}
    for required in ("count", "graph"):
        if required not in known_types:
            raise SystemExit(f"Widget type {required!r} not in catalog.")
    print(f"Discovered {len(known_types)} widget types.")

    # 2. Build two widgets and their grid positions together.
    widgets = []
    layout = {}

    _id, widget, pos = make_widget(
        "count",
        "Active Critical Findings",
        {
            "model": "finding",
            "filters": {"status_any": "Active", "severity": "Critical"},
            "color": "danger",
            "icon": "fas fa-ban",
        },
        x=0, y=0, w=3, h=2,
    )
    widgets.append(widget)
    layout[_id] = pos

    _id, widget, pos = make_widget(
        "graph",
        "Findings by Severity",
        {
            "model": "finding",
            "filters": {"duplicate": "false"},
            "group_by": "severity",
            "aggregation": "count",
            "chart_type": "pie",
            "time_bucket": None,
            "limit": None,
            "stacked": False,
        },
        x=3, y=0, w=9, h=4, min_w=3, min_h=3,
    )
    widgets.append(widget)
    layout[_id] = pos

    # 3. Create the layout.
    created_layout = api_request("POST", "/dashboards/layouts/", {
        "name": "Exec Overview (API)",
        "widgets": widgets,
        "layout": layout,
        "settings": {},
    })
    layout_id = created_layout["id"]
    created["layout_id"] = layout_id
    print(f"Created layout id={layout_id} with {len(created_layout['widgets'])} widgets")

    # 4. Make it the default landing dashboard.
    api_request("POST", f"/dashboards/layouts/{layout_id}/set_default/")
    print(f"Set layout id={layout_id} as the default")

    # 5. Read it back to verify widgets + positions survived intact.
    verified = api_request("GET", f"/dashboards/layouts/{layout_id}/")
    assert verified["is_default"] is True, "Layout did not become the default"
    assert len(verified["widgets"]) == len(widgets), "Widget count mismatch"
    assert set(verified["layout"]) == {w["id"] for w in verified["widgets"]}, \
        "Layout map and widgets are out of sync"
    print("Verified: default set, widgets and positions consistent")

    # 6. Record the created ID for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Verifique o que você construiu

Como chaves de filtro inválidas são descartadas silenciosamente, a verificação faz parte do fluxo de trabalho — não é uma reflexão tardia.

**Confirme se um layout foi salvo como pretendido.** Faça um `GET` para buscá-lo de volta e verifique `widgets` e `layout`:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

Para cada widget, compare o `config.filters` retornado com o que você enviou. Se um filtro esperado estiver faltando, sua chave não era um filtro válido para aquele modelo — verifique novamente contra os filtros da visão de lista do objeto. Confirme que `is_default` é `true`, se você o definiu, e que toda chave em `layout` corresponde a um `id` de widget.

**Faça uma verificação pontual dos dados de um widget.** Renderize seu endpoint de dados e confirme se o número é o esperado:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**Corrija um widget com PATCH.** Um `PATCH` para `/dashboards/layouts/{id}/` com o conjunto completo de `widgets` e `layout` os substitui — envie o conjunto completo desejado, não um conjunto parcial.

## Próximos passos

- Crie e organize os mesmos layouts de forma interativa na [interface de Painéis Personalizáveis](../custom-dashboards/).
- Deixe uma LLM projetar e construir painéis para você com a [integração de Painéis com LLM](../custom-dashboards-llm/).
