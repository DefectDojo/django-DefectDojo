---
title: Idiomas e linhas de código
description: Importe dados de composição de linguagens para um Produto usando a ferramenta
  cloc
weight: 3
audience: opensource
aliases:
- /pt-br/en/open_source/languages
---

O DefectDojo pode exibir uma análise das linguagens de programação e das linhas de código de um Produto, preenchida a partir da importação de um relatório da ferramenta [cloc](https://github.com/AlDanial/cloc) (Count Lines of Code) via API.

## Gerando o relatório do cloc

Execute o `cloc` sobre sua base de código usando a flag `--json` para produzir um arquivo JSON no formato correto:

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Importando via API

Envie o relatório JSON para o DefectDojo via API. Ao importar, todos os dados de linguagem existentes para o Produto são substituídos pelo conteúdo do novo arquivo.

O endpoint de importação está documentado em [DefectDojo API v2 docs](../api-v2-docs/).

## Visualizando os resultados

Após a importação, a análise das linguagens é exibida no lado esquerdo da página de detalhes do Produto, mostrando cada linguagem e sua contagem de linhas. As cores de cada linguagem são definidas por entradas na tabela `Language_Type`, pré-preenchida com dados do GitHub.

## Atualizando as cores das linguagens

O GitHub atualiza periodicamente as cores das linguagens conforme surgem novas linguagens. Para obter os dados de cor mais recentes, execute o seguinte comando de gerenciamento:

```bash
./manage.py import_github_languages
```

Isso lê os dados de [ozh/github-colors](https://github.com/ozh/github-colors) e adiciona novas linguagens ou atualiza cores existentes.
