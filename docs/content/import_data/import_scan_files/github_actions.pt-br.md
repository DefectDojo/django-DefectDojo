---
title: Importar do GitHub Actions
description: Importe resultados de scan de um workflow do GitHub Actions com a action
  oficial do DefectDojo
weight: 3
---

A [action oficial do DefectDojo](https://github.com/marketplace/actions/defectdojo) importa um relatório de scan para o DefectDojo a partir de um workflow do GitHub Actions. Ela funciona com o DefectDojo Pro e com a edição Open Source, e lê todos os formatos de relatório compatíveis com o DefectDojo, incluindo SARIF.

Cada execução faz um reimport no mesmo Teste, de modo que os Achados que o scanner deixou de reportar são fechados e cada Achado mantém o seu histórico. A action registra o build, o branch, o commit e o repositório no Teste, e pode fazer a etapa do workflow falhar quando ainda houver Achados ativos na severidade escolhida.

## Antes de começar

1. Crie uma API v2 key para um usuário que possa importar no Ativo (e criá-lo, se você deixar a action criar Ativos). A chave fica em **API v2 Token** no menu do usuário (**API v2 Key** na UI da edição Open Source).
2. No repositório do GitHub, adicione a chave como um secret chamado `DEFECTDOJO_API_TOKEN` em **Settings > Secrets and variables > Actions**.

## Adicione a action a um workflow

Execute o seu scanner e depois passe o relatório dele para a action:

```yaml
name: Security scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` é o nome do formato do relatório como o DefectDojo o lista, por exemplo `SARIF`, `Trivy Scan` ou `Semgrep JSON Report`. Consulte [Ferramentas Compatíveis](/supported_tools/) para ver todos os nomes.

## Para onde vão os Achados

A menos que você os defina, a action usa nomes derivados do repositório e cria os que ainda não existem:

| Objeto do DefectDojo | Padrão | Input |
| --- | --- | --- |
| Organização (Tipo de Produto) | Proprietário do repositório | `organization-name` ou `product-type-name` |
| Ativo (Produto) | Nome do repositório | `asset-name` ou `product-name` |
| Engagement | Nome do branch | `engagement-name` |
| Teste | Tipo de scan | `test-title` |

Quando um mesmo Engagement recebe vários relatórios do mesmo tipo de scan, dê a cada um o seu próprio `test-title` para que cada reimport encontre o seu próprio Teste.

### Branches, pull requests e tags

Cada branch recebe o seu próprio Engagement, de modo que o scan de um pull request nunca fecha nem reabre Achados no branch padrão. Os pull requests usam o branch de origem, as tags usam o nome da tag e a merge queue usa um Engagement por branch base.

Os Engagements que a action cria para qualquer branch diferente do padrão fazem a deduplicação apenas dentro de si mesmos (**Desduplicação apenas dentro deste engajamento**). Sem isso, um Achado visto pela primeira vez em um branch marcaria a cópia do branch padrão como duplicada. Definir `engagement-name` ou `deduplication-on-engagement` por conta própria desativa esse comportamento, então um Engagement que você nomeia faz a deduplicação em todo o Ativo, como de costume. Os Engagements de branch permanecem no DefectDojo depois que o branch é mergeado, portanto execute a importação somente no branch padrão se quiser mantê-los fora das contagens do Ativo.

## Faça o build falhar

Defina `fail-on` como `low`, `medium`, `high` ou `critical` para fazer a etapa falhar quando o Teste tiver, após a importação, Achados ativos nessa severidade ou acima. Duplicados não contam. O resumo do job mostra as contagens por severidade e um link para o Teste.

## Recursos do Pro

No DefectDojo Pro, a action também pode:

- Enviar novos Achados para os Connectors configurados no Ativo (`push-to-connector: true`).
- Importar relatórios grandes em segundo plano (`background-import: true`). A action espera até que o Teste termine de ser processado antes de informar as contagens ou aplicar `fail-on`.
- Avisar quando um Ativo foi renomeado ou movido, para que você possa atualizar os nomes no workflow.

Na edição Open Source, `push-to-connector` e `background-import` são ignorados com um aviso, e a importação continua sendo executada. Defina `strict: true` para fazer a etapa falhar.

## Pull requests de forks

O GitHub não fornece secrets aos workflows executados em pull requests de forks, então a action não consegue se autenticar nesse caso e a etapa falha. Execute a importação em `push`, ou ignore-a nos pull requests de forks:

```yaml
      - name: Import into DefectDojo
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: DefectDojo/defectdojo-action@v1
```

Não use `pull_request_target` para contornar isso: ele é executado com os seus secrets enquanto faz o checkout de código que você não controla.

## Todos os inputs e outputs

O [README da action](https://github.com/DefectDojo/defectdojo-action#inputs) lista todos os inputs e outputs. A maioria dos inputs corresponde a um campo do endpoint **/reimport** descrito em [Importar via API](/import_data/import_scan_files/api_pipeline_modelling/).
