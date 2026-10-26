---
title: Importar do GitHub Actions
description: Importe resultados de scan de um workflow do GitHub Actions com a action
  oficial do DefectDojo
weight: 3
---

A [action oficial do DefectDojo](https://github.com/DefectDojo/defectdojo-action) importa um relatório de scan para o DefectDojo a partir de um workflow do GitHub Actions. Ela funciona com o DefectDojo Pro e com a versão Open Source, e lê todos os formatos de relatório compatíveis com o DefectDojo, incluindo SARIF.

Cada execução faz um Reimport no mesmo Teste, de modo que os Achados que o scanner não reporta mais são fechados e cada Achado mantém seu histórico. A action registra o build, a branch, o commit e o repositório no Teste, e pode fazer a etapa do workflow falhar quando ainda houver Achados ativos em uma severidade escolhida.

## Antes de começar

1. Crie uma chave de API v2 para um usuário que possa importar para o Asset (e criá-lo, caso você permita que a action crie Assets). A chave fica em **API v2 Token** no menu do usuário.
2. No repositório do GitHub, adicione a chave como um secret chamado `DEFECTDOJO_API_TOKEN` em **Settings > Secrets and variables > Actions**.

## Adicione a action a um workflow

Execute seu scanner e depois passe o relatório dele para a action:

```yaml
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

`scan-type` é o nome do formato de relatório como o DefectDojo o lista, por exemplo `SARIF`, `Trivy Scan` ou `Semgrep JSON Report`. Consulte [Ferramentas compatíveis](/supported_tools/) para ver todos os nomes.

## Para onde vão os Achados

A menos que você os defina, a action usa nomes derivados do repositório e cria os que ainda não existem:

| Objeto do DefectDojo | Padrão | Input |
| --- | --- | --- |
| Organização (Tipo de Produto) | Proprietário do repositório | `organization-name` ou `product-type-name` |
| Asset (Produto) | Nome do repositório | `asset-name` ou `product-name` |
| Engajamento | Nome da branch | `engagement-name` |
| Teste | Tipo de scan | `test-title` |

Quando um mesmo Engajamento recebe vários relatórios do mesmo tipo de scan, dê a cada um o seu próprio `test-title` para que cada Reimport encontre o seu próprio Teste.

### Branches, pull requests e tags

Cada branch recebe o seu próprio Engajamento, de modo que o scan de um pull request nunca fecha nem reabre Achados na branch padrão. Os pull requests usam a branch de origem, as tags usam o nome da tag, e a merge queue usa um Engajamento por branch base.

Os Engajamentos que a action cria para qualquer branch que não seja a padrão fazem a desduplicação somente dentro de si mesmos (**Desduplicação apenas dentro deste engajamento**). Sem isso, um Achado visto primeiro em uma branch marcaria a cópia da branch padrão como duplicada. Os Engajamentos de branch permanecem no DefectDojo depois que a branch é mesclada, portanto, execute a importação somente na branch padrão se quiser mantê-los fora das contagens do Asset.

## Faça o build falhar

Defina `fail-on` como `low`, `medium`, `high` ou `critical` para fazer a etapa falhar quando o Teste tiver Achados ativos nessa severidade ou acima dela após a importação. Duplicados não são contados. O resumo do job mostra as contagens por severidade e um link para o Teste.

## Recursos do Pro

No DefectDojo Pro, a action também pode:

- Enviar novos Achados para os Connectors configurados para o Asset (`push-to-connector: true`).
- Importar relatórios grandes em segundo plano (`background-import: true`). A action espera até que o Teste termine de ser processado antes de informar as contagens ou aplicar `fail-on`.
- Avisar quando um Asset foi renomeado ou movido, para que você possa atualizar os nomes no workflow.

Na versão Open Source, esses inputs são ignorados com um aviso, e a importação continua sendo executada. Defina `strict: true` para fazer a etapa falhar em vez disso.

## Pull requests de forks

O GitHub não fornece secrets aos workflows executados em pull requests de forks, portanto a action não consegue se autenticar nesse caso. Execute a importação em `push`, ou em pull requests de branches do mesmo repositório. Não use `pull_request_target` para contornar isso: ele é executado com os seus secrets enquanto faz o checkout de código que você não controla.

## Todos os inputs e outputs

O [README da action](https://github.com/DefectDojo/defectdojo-action#inputs) lista todos os inputs e outputs. A maioria dos inputs corresponde a um campo do endpoint **/reimport** descrito em [Importar via API](/import_data/import_scan_files/api_pipeline_modelling/).
