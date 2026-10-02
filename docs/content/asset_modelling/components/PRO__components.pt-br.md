---
title: Componentes
description: Rastreamento de bibliotecas de terceiros e componentes de software no
  DefectDojo Pro
audience: pro
weight: 1
---

No DefectDojo, os Componentes representam bibliotecas de terceiros, componentes de software e módulos que potencialmente possuem vulnerabilidades.


## Visualizações de Componentes

O DefectDojo Pro inclui uma visualização de tabela dedicada para Componentes, que pode ser encontrada na barra lateral.  Essa visualização mostra os Achados Ativos, os Achados Duplicados e o Total de Achados para cada Componente.  Esses números incluem todos os Ativos na instância do DefectDojo.

Os Componentes de um Ativo individual podem ser vistos na visualização do Ativo.

## A Tabela de Componentes

A Tabela de Componentes exibe as seguintes colunas:

* **Componente** — o nome do componente, preenchido a partir dos dados do scan.
* **Versão** — a versão do componente, preenchida a partir dos dados do scan.
* **Achados Ativos** — contagem de Achados Ativos associados ao componente.
* **Achados Duplicados** — contagem de Achados Duplicados associados ao componente.
* **Total de Achados** — contagem total de todos os Achados associados ao componente.

Clicar no Nome do Componente ou nos valores de Achados Ativos, Achados Duplicados ou Total de Achados abre uma lista filtrada de Achados para o respectivo campo.

Um Componente **Nenhum** é exibido na tabela, mostrando todos os Achados que não estão associados a nenhum Componente.

Os Componentes importados permanecem na tabela mesmo que todos os seus Achados associados estejam Mitigados. Quando Achados são importados para um Componente específico, a Tabela de Componentes é atualizada para refletir corretamente os novos totais de Achados.


### Exemplo

Um Componente importado de um scan do Dependency-Check em uma aplicação com uma dependência vulnerável do `lodash` pode aparecer na tabela como:

| Componente | Versão | Achados Ativos | Achados Duplicados | Total de Achados |
| --- | --- | --- | --- | --- |
| npm:lodash | 4.17.15 | 3 | 1 | 5 |

Clicar em `npm:lodash` abre a lista de todos os Achados que referenciam esse Componente. Clicar em `3` abre a mesma lista filtrada apenas para Achados Ativos.

## Adicionando Componentes

Os Componentes podem ser extraídos de uma importação de scan ou por meio da edição manual de um Achado. Assim que um Nome de Componente é associado a um Achado, uma entrada correspondente é adicionada automaticamente à Tabela de Componentes. Se o Componente já estiver associado a outros Achados no DefectDojo, os totais de Achados Ativos, Achados Duplicados e Total de Achados são atualizados de acordo.

### Como os Componentes são Extraídos dos Dados do Scan

Quando um scan é importado, os parsers preenchem os campos **Component Name** e **Component Version** de cada Achado a partir da saída do scan. A Tabela de Componentes é então construída a partir desses valores. O nível de detalhe e a convenção de nomenclatura dependem da ferramenta que gerou o scan:

* **Ferramentas de Software Composition Analysis (SCA)** normalmente informam um nome de pacote e uma versão exata. Por exemplo, o OWASP Dependency-Check deriva o Componente a partir da [Package URL](https://github.com/package-url/purl-spec) em seu identificador — um purl `pkg:npm/lodash@4.17.15` se torna `Component Name: npm:lodash`, `Component Version: 4.17.15`.
* **Scanners de contêiner e de pacotes do SO** como Trivy, Anchore Grype e Anchore Engine informam o pacote do SO ou da linguagem afetado — por exemplo, `Component Name: curl`, `Component Version: 7.68.0`.
* **Scanners de dependências específicos de linguagem** como npm Audit, pip-audit, bundler-audit, Retire.js, Govulncheck e OSV-Scanner preenchem o pacote e a versão problemáticos a partir dos respectivos manifestos do ecossistema.

Scanners focados em configuração, infraestrutura ou lógica de código-fonte (como ferramentas SAST e IaC) geralmente não preenchem os campos de Componente, e seus Achados aparecem sob o Componente **Nenhum**.

Para adicionar ou alterar um Componente manualmente, edite o Achado e defina os campos **Component Name** e **Component Version** diretamente. A Tabela de Componentes é atualizada assim que o Achado é salvo.

## Atualizando Componentes

Para atualizar um Nome ou Versão de Componente, todos os Achados associados ao Componente devem ter seu campo Component Name ou Component Version atualizado.

## Removendo Componentes

Para remover um Componente da Tabela de Componentes, todos os Achados associados ao Componente devem ser atualizados para remover seus campos Component Name e Component Version. Os Componentes também são removidos se todos os seus Achados associados forem excluídos.

Se todos os Achados de um Componente estiverem Mitigados, o Componente permanece na tabela, mas seu valor de Achados Ativos é definido como 0.
