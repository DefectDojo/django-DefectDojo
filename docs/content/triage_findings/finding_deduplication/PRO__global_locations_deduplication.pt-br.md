---
title: Global Locations Deduplication
description: Deduplique achados por localização compartilhada (URL ou dependência)
  em todos os Produtos
weight: 6
audience: pro
---

Global Locations Deduplication é um algoritmo do DefectDojo Pro que identifica achados duplicados em **todos os Produtos** com base puramente em uma **localização compartilhada**: uma URL, ou uma dependência (identificada pela sua Package URL). Dois achados que compartilham uma localização de um tipo selecionado são tratados como duplicatas independentemente de título, severidade, CWE ou IDs de vulnerabilidade — a localização por si só é a identidade.

É a contraparte sensível à localização do [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/), aplicada ao modelo de dados Locations do DefectDojo. Enquanto o Global Component corresponde apenas por nome e versão do componente, o Global Locations corresponde à mesma dependência **pela Package URL completa** *e* por **URLs** compartilhadas — assim, ele consegue deduplicar achados DAST/web entre Produtos, o que o Global Component não faz.

Diferente dos algoritmos com escopo limitado, a correspondência do Global Locations **não tem escopo limitado a um único Produto ou Engajamento**. Um achado importado no Produto B pode ser marcado como duplicata de um achado mais antigo no Produto A, mesmo que os dois Produtos não tenham relação alguma.

## Requirements

O Global Locations é definido sobre o modelo de dados **Locations** do DefectDojo e só é oferecido quando o recurso **Locations** está habilitado. Em instâncias onde o Locations está desativado, a feature flag do Global Locations aparece bloqueada ("Requires Locations to be enabled") e o algoritmo não aparece no Tuner.

## Enabling the Global Locations Algorithm

O Global Locations Deduplication fica atrás de uma feature flag e vem **desativado por padrão**. Depois que o Locations é habilitado, um superusuário pode ativá-lo em **Settings > Feature Flags**, tanto em instâncias Cloud quanto On-Premise. Veja [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Uma vez habilitado o recurso, **Global Locations** passa a estar disponível como opção no menu suspenso **Deduplication Algorithm**, tanto para as configurações de Same Tool Deduplication quanto de Cross Tool Deduplication no Tuner.

## Configuring Global Locations Deduplication

O Global Locations pode ser aplicado ao Same-Tool Deduplication, ao Cross-Tool Deduplication, ou a ambos, e é configurado por ferramenta de segurança em **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** em instâncias que ainda usam o layout de menu anterior; veja [The Settings Menu](/navigation/pro__settings_menu/)).

Ao selecionar **Global Locations**, o seletor de Hash Code Fields fica oculto (não se aplica) e um seletor de **Location Types** aparece em seu lugar.

### Location Types

Escolha quais tipos de localização participam da correspondência:

- **URLs** — dois achados correspondem quando compartilham uma URL (comparada pelos campos de endpoint configurados, `DEDUPE_ALGO_ENDPOINT_FIELDS`).
- **Dependencies** — dois achados correspondem quando referenciam a mesma dependência, pela identidade completa da Package URL.

Pelo menos um tipo deve ser selecionado; ambos vêm selecionados por padrão. Uma ferramenta configurada apenas para **URLs** ignora dependências compartilhadas, e uma ferramenta configurada apenas para **Dependencies** ignora URLs compartilhadas.

### Same-Tool

Use o Same Tool Deduplication com o algoritmo Global Locations quando quiser deduplicar achados de uma única ferramenta em múltiplos Produtos por localização compartilhada.

1. Abra a aba **Same Tool Deduplication**.
2. Selecione a ferramenta no menu suspenso **Security Tool**.
3. Defina o **Deduplication Algorithm** como **Global Locations**.
4. Escolha os **Location Types** para a correspondência.
5. Envie o formulário.

### Cross-Tool

Use o Cross Tool Deduplication com o algoritmo Global Locations quando quiser deduplicar achados que compartilham uma localização entre **diferentes** ferramentas e Produtos.

A correspondência cross-tool lê a seleção de tipo de localização da ferramenta que está importando, portanto configure o Global Locations em **cada** ferramenta que deva participar, com Location Types correspondentes.

1. Abra a aba **Cross Tool Deduplication**.
2. Para cada ferramenta a incluir: selecione-a no menu suspenso **Security Tool**, defina o algoritmo como **Global Locations**, escolha os Location Types e envie.

## How Matching Works

Um novo achado é marcado como duplicata de um achado existente em qualquer lugar da instância quando os dois compartilham **pelo menos uma localização concreta de um tipo selecionado**:

- **Uma URL** cujos campos de endpoint configurados (`DEDUPE_ALGO_ENDPOINT_FIELDS`) correspondem todos, **ou**
- **Uma dependência** com a mesma Package URL (uma correspondência exata de purl, então `pkg:npm/timespan@2.3.0` **não** corresponde a `pkg:npm/timespan@2.3.1`).

A correspondência é **estrita e não vazia**: dois achados que não têm localizações de um tipo selecionado **nunca** são deduplicados (diferente da correspondência de localização com escopo limitado, "ambos vazios" não é uma correspondência). Se a comparação de campos de endpoint estiver desativada (`DEDUPE_ALGO_ENDPOINT_FIELDS = []`), as URLs não conseguem estabelecer correspondência alguma — apenas uma dependência compartilhada pode.

A correspondência Same-Tool permanece dentro de uma única ferramenta (tipo de teste). A correspondência Cross-Tool atravessa ferramentas intencionalmente. A configuração de deduplicação com escopo de Engajamento é ignorada por esse algoritmo; a correspondência é sempre global, e o campo `service` continua particionando a deduplicação, assim como faz para os demais algoritmos globais.

## Example

Suponha que o Global Locations (ambos os tipos de localização) esteja habilitado em uma ferramenta DAST (Same Tool) e, para a linha cross-tool, em uma segunda ferramenta DAST:

| Etapa | Importação | No Produto | Resultado |
| --- | --- | --- | --- |
| 1 | Achado DAST em `https://shared.example.com/login` | Application 0 | 1 achado ativo criado |
| 2 | Mesma URL, vulnerabilidade **diferente** (título + severidade) | Application 1 | 1 achado criado, marcado como duplicata do achado do Application 0 (a localização por si só corresponde) |
| 3 | Segunda ferramenta DAST, mesma URL | Application 2 | 1 achado criado, marcado como duplicata do achado do Application 0 (correspondência cross-tool) |
| 4 | Achado DAST em `https://other.example.com/admin` | Application 3 | 1 achado ativo criado — URL diferente, sem localização compartilhada |
| 5 | Achado sem URL e sem dependência | Application 4 | 1 achado ativo criado — sem localização para compartilhar |

Cada achado duplicado mostra seu original na parte inferior da página do achado, na cadeia de duplicatas.

## Global Component vs. Global Locations

Ambos são algoritmos globais (entre Produtos) que ignoram o escopo de Engajamento e correspondem por uma única identidade, em vez dos campos de hash. Escolha com base no que identifica uma duplicata para sua ferramenta:

| | Global Component | Global Locations |
| --- | --- | --- |
| Corresponde por | Nome **+ versão** do componente | Uma **localização** compartilhada: uma URL e/ou uma dependência |
| Identidade da dependência | Nome e versão | **Package URL** completa (tipo, namespace, nome, versão, qualificadores) |
| Achados de URL / DAST | Não correspondidos | Correspondidos (pelos campos de endpoint configurados) |
| Configurável | Não | Sim — escolha URLs, Dependencies, ou ambos, por ferramenta |
| Modelo de dados | Funciona com ou sem Locations | Requer **Locations** (Pro) |
| Melhor para | Ferramentas SCA em que o nome + versão do pacote é a identidade | Ferramentas web/DAST e SCA sob o modelo Locations, em que a URL ou a dependência exata é a identidade |

Para uma nova instância que usa o modelo de dados Locations, o Global Locations é o sucessor mais preciso do Global Component: ele identifica dependências pela Package URL exata e também deduplica achados baseados em URL. O Global Component continua disponível e inalterado para ferramentas em que o nome + versão do componente é a identidade desejada.

## Cross-Product Visibility

Como a correspondência do Global Locations atravessa os limites de Produto, o achado original em uma cadeia de duplicatas pode estar em um Produto ao qual o usuário que visualiza a duplicata não tem permissão de acesso.

Nesse caso, o achado é visível e identificado como duplicata, mas o usuário não conseguirá abri-lo ou navegar até o original. Considere isso antes de habilitar o Global Locations em ferramentas cujos achados são sensíveis a controles de acesso em nível de Produto.

## Reverting

Para deixar de usar o Global Locations em uma determinada ferramenta, abra suas Deduplication Settings e altere o algoritmo de volta para uma das opções com escopo limitado.

Para o Same Tool Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Para o Cross Tool Deduplication:

- Hash Code
- Disabled

Alterar o algoritmo aciona um recálculo em segundo plano dos hashes de deduplicação para os achados existentes da ferramenta.
