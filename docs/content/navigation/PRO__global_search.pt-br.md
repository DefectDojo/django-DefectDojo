---
title: Busca Global
description: Pesquise em Achados, Ativos e objetos relacionados a partir da barra
  superior do DefectDojo Pro
audience: pro
weight: 3
---

O DefectDojo Pro inclui uma **busca global** que pesquisa em seus Achados e objetos relacionados a partir de uma única caixa na barra superior. Ela é baseada na busca nativa de texto completo (full-text) do Postgres, com correspondência aproximada e tolerante a erros de digitação, para que você encontre um objeto sem precisar lembrar sua grafia exata.

## Executando uma busca

- **Caixa de busca na barra superior** — clique na caixa **Search** na navegação superior e comece a digitar. Enquanto você digita, uma lista suspensa mostra uma prévia dos principais resultados **agrupados por tipo de objeto**, com uma contagem ao lado de cada tipo e um link **See all *N* results** na parte inferior.
- **Página de resultados completa** — pressione **Enter**, ou clique em **See all *N* results**, para abrir a página de resultados completa. Trata-se de uma única tabela, ordenável e filtrável, com todas as correspondências entre todos os tipos de objeto.

Os resultados são sempre **restritos ao que você está autorizado a visualizar** — a busca global nunca exibe objetos aos quais você não teria acesso de outra forma. (Os Modelos de Achado são a única exceção: assim como em outras partes do DefectDojo, eles são visíveis para qualquer usuário autenticado.)

## O que você pode pesquisar

A busca global abrange os seguintes tipos de objeto:

| Tipo de objeto | Observações |
| --- | --- |
| **Achados** | |
| **Ativos** | (Produtos) |
| **Organizações** | (Tipos de Produto) |
| **Engajamentos** | |
| **Testes** | |
| **Endpoints** *ou* **Locations** | O que estiver em uso na sua instância — instâncias com [Locations](/asset_modelling/locations/pro__locations_overview/) habilitado pesquisam Locations; as demais pesquisam Endpoints. |
| **Modelos de Achado** | |
| **Tecnologias** | |
| **IDs de vulnerabilidade** | por exemplo, CVEs |

Para a maioria dos tipos, a busca compara com o **nome/título e a descrição** do objeto. Para Achados, Ativos, Engajamentos e Testes, ela também compara **tags** (por prefixo). Os IDs de vulnerabilidade são comparados pelo próprio valor do ID.

## Sintaxe da consulta

### Texto livre

Digite quaisquer palavras-chave para pesquisar em tudo de uma vez. Os resultados são classificados por relevância, com correspondências em título/nome classificadas acima das correspondências em descrição. A correspondência aproximada (veja abaixo) faz com que termos próximos, mas não exatos, também correspondam.

### Frases entre aspas

Coloque uma frase entre aspas duplas para mantê-la unida — `"space inside"` é tratado como um único termo, em vez de duas palavras-chave.

### Operadores

Prefixe um termo com um operador (`operator:value`) para restringir a busca. Operadores suportados:

| Operador | O que faz |
| --- | --- |
| `finding:` `product:` `engagement:` `test:` `template:` `technology:` | Restringe a busca a um único tipo de objeto e pesquisa o valor nele (por exemplo, `finding:sqli`). |
| `id:` | Busca um Achado pelo seu ID numérico (por exemplo, `id:12345`). |
| `endpoint:` | Encontra Achados cujo host de endpoint/location contém o valor. |
| `vulnerability_id:` | Correspondência exata em um ID de vulnerabilidade. Aceita uma lista separada por vírgulas e pode ser repetido (por exemplo, `vulnerability_id:CVE-2020-1234,CVE-2018-7489`). |
| `tag:` / `tags:` | Corresponde a objetos por tag. `tag:` corresponde a uma única tag por substring; `tags:` corresponde a qualquer tag em uma lista. |
| `test-tag:` `engagement-tag:` `product-tag:` (e seus plurais `-tags`) | Corresponde por uma tag no Teste, Engajamento ou Ativo relacionado, em vez de no próprio objeto. |
| `not-tag:` `not-tags:` (e as variantes de relação `not-…-tag`) | Nega qualquer um dos operadores de tag acima para **excluir** correspondências. |

Você pode combinar operadores com palavras-chave de texto livre na mesma consulta.

### Correspondência aproximada

Para consultas com **três ou mais caracteres**, a busca global também realiza correspondência por trigramas (similaridade de palavras). Isso tolera erros de digitação e encontra termos **dentro** de valores mais longos com pontos ou hífens — por exemplo, `internal` corresponde a `api.internal.example.com`.

## Filtragem e ordenação da página de resultados

Na página de resultados completa, as colunas podem ser filtradas e ordenadas independentemente do texto da consulta — filtre por **tipo de objeto**, **severidade**, **título** ou **contexto**, e ordene por qualquer coluna. Isso é independente da sintaxe `operator:` descrita acima e se aplica à tabela de resultados combinada.

## Limites de resultados

- A página de resultados completa é **paginada** (25 linhas por página, por padrão).
- Cada tipo de objeto contribui com até um **número máximo de correspondências** por busca — **100**, por padrão. Quando existem mais correspondências do que as exibidas, os resultados são sinalizados como truncados; refine sua consulta para ver os resultados mais relevantes.
- A lista suspensa da barra superior mostra uma prévia menor (as principais correspondências por tipo) com as contagens totais, de modo que **See all *N* results** sempre reflete os totais reais.
