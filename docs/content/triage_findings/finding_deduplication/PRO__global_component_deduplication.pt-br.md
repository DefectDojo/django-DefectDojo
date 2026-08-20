---
title: Global Component Deduplication
description: Deduplique achados de Software Composition Analysis (SCA) por nome e
  versão do componente em todos os Produtos
weight: 5
audience: pro
---

Global Component Deduplication é um algoritmo do DefectDojo Pro que identifica achados duplicados em **todos os Produtos** com base no nome e na versão do componente que eles referenciam. Destinado a ferramentas de Software Composition Analysis (SCA), em que a mesma dependência vulnerável (por exemplo, `timespan@2.3.0`) pode aparecer em muitos Produtos, e você deseja que o DefectDojo trate essas ocorrências como duplicatas de um único achado original.

Diferente dos demais algoritmos de deduplicação, a correspondência do Global Component **não tem escopo limitado a um único Produto ou Engajamento**. Um achado importado no Produto B pode ser marcado como duplicata de um achado mais antigo no Produto A, mesmo que os dois Produtos não tenham relação alguma.

> **Global Component vs. Global Locations:** o Global Component corresponde apenas por nome e versão do componente. Se sua instância usa o modelo de dados Locations, o [Global Locations Deduplication](/triage_findings/finding_deduplication/pro__global_locations_deduplication/) é o sucessor mais preciso — ele identifica dependências pela Package URL completa e também deduplica achados de URL/DAST entre Produtos. Veja a tabela comparativa dessa página para saber qual escolher.

## Enabling the Global Component Algorithm

O Global Component Deduplication fica atrás de uma feature flag e vem **desativado por padrão**. Um superusuário pode habilitá-lo em **Settings > Feature Flags**, tanto em instâncias Cloud quanto On-Premise. Veja [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Uma vez habilitado o recurso, **Global Component** passa a estar disponível como opção no menu suspenso **Deduplication Algorithm**, tanto para as configurações de Same Tool Deduplication quanto de Cross Tool Deduplication no Tuner.

## Configuring Global Component Deduplication

O Global Component pode ser aplicado ao Same-Tool Deduplication, ao Cross-Tool Deduplication, ou a ambos, e é configurado por ferramenta de segurança em **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** em instâncias que ainda usam o layout de menu anterior; veja [The Settings Menu](/navigation/pro__settings_menu/)).

### Same-Tool

Use o Same Tool Deduplication com o algoritmo Global Component quando quiser deduplicar achados de uma única ferramenta SCA em múltiplos Produtos.

1. Abra a aba **Same Tool Deduplication**.
2. Selecione a ferramenta SCA no menu suspenso **Security Tool** (por exemplo, `Dependency Track Finding Packaging Format (FPF) Export`).
3. Defina o **Deduplication Algorithm** como **Global Component**.
4. Envie o formulário.

Os Hash Code Fields não são usados por esse algoritmo e ficam ocultos quando ele é selecionado.

### Cross-Tool

Use o Cross Tool Deduplication com o algoritmo Global Component quando quiser deduplicar achados do mesmo componente entre diferentes ferramentas SCA e Produtos.

A correspondência cross-tool exige que o Global Component esteja configurado em **cada** ferramenta que deva participar.

1. Abra a aba **Cross Tool Deduplication**.
2. Para cada ferramenta a incluir: selecione-a no menu suspenso **Security Tool**, defina o algoritmo como **Global Component** e envie.

## How Matching Works

Um novo achado é marcado como duplicata de um achado existente quando:

- O nome e a versão do componente correspondem exatamente, **e**
- Existe um achado mais antigo com o mesmo nome e versão de componente em qualquer lugar da instância do DefectDojo — em qualquer Produto ou Engajamento.

A correspondência de versão do componente é exata. Um achado para `timespan@2.3.0` **não** será deduplicado com um para `timespan@2.3.1`.

A configuração de deduplicação com escopo de Engajamento é ignorada por esse algoritmo; a correspondência é sempre global.

## Example

Suponha que o Global Component esteja habilitado no `Dependency Track Finding Packaging Format (FPF) Export` (Same Tool) e em uma ferramenta Generic Findings Import (Cross Tool):

| Etapa | Importação | No Produto | Resultado |
| --- | --- | --- | --- |
| 1 | Scan do Dependency Track para `timespan@2.3.0` | Application 0 | 1 achado ativo criado |
| 2 | Mesmo scan do Dependency Track | Application 1 | 1 achado criado, marcado como duplicata do achado do Application 0 |
| 3 | Generic Findings Import para `timespan@2.3.0` | Application 2 | 1 achado criado, marcado como duplicata do achado do Application 0 (correspondência cross-tool) |
| 4 | Scan do Dependency Track para `timespan@2.3.1` | Application 3 | 1 achado ativo criado — versão diferente, sem correspondência |

Cada achado duplicado mostra seu original na parte inferior da página do achado, na cadeia de duplicatas.

## Cross-Product Visibility

Como a correspondência do Global Component atravessa os limites de Produto, o achado original em uma cadeia de duplicatas pode estar em um Produto ao qual o usuário que visualiza a duplicata não tem permissão de acesso.

Nesse caso, o achado é visível e identificado como duplicata, mas o usuário não conseguirá abri-lo ou navegar até o original. Considere isso antes de habilitar o Global Component em ferramentas cujos achados são sensíveis a controles de acesso em nível de Produto.

## Reverting

Para deixar de usar o Global Component em uma determinada ferramenta, abra suas Deduplication Settings e altere o algoritmo de volta para uma das opções com escopo limitado.

Para o Same Tool Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Para o Cross Tool Deduplication:

- Hash Code
- Disabled

Alterar o algoritmo aciona um recálculo em segundo plano dos hashes de deduplicação para os achados existentes da ferramenta.
