---
title: Achados Similares
description: Encontre achados relacionados na página View Finding e vincule-os manualmente
  como duplicatas
audience: pro
weight: 3
---

Embora a [Deduplicação](../about_deduplication) seja executada automaticamente no momento da importação, **Similar Findings** é uma ferramenta manual e interativa na página **View Finding**. Ela exibe outros achados no mesmo Asset que se assemelham ao que você está analisando, e permite vinculá-los manualmente a um cluster de duplicatas.

Use-a quando a deduplicação automática não agrupou achados que você acredita que deveriam estar juntos, ou quando quiser explorar o que mais em um Asset se parece com a vulnerabilidade atual.

## Onde encontrar

Abra qualquer achado e role até o card **Duplicate & Similar Findings**. Ele tem duas abas:

- **Duplicate Findings** – os achados já vinculados a este como duplicatas (o cluster automático).
- **Similar Findings** – outros achados no Asset que correspondem aos valores do achado atual, mas ainda não fazem parte do seu cluster.

Selecione a aba **Similar Findings** para executar a consulta.

![O card Duplicate & Similar Findings na página View Finding](images/pro_similar_findings.png)

## Como os achados são correspondidos

O DefectDojo busca no **mesmo Asset** por achados que se assemelham ao atual, com base em valores como Vulnerability IDs (por exemplo, identificadores CVE), CWE, caminho do arquivo, número da linha e unique ID from tool. O achado atual é sempre excluído de seus próprios resultados, e a correspondência nunca ultrapassa os limites de um Asset.

Isso é diferente do algoritmo de deduplicação automática, que compara `hash_code` (ou Unique ID from tool) para decidir correspondências. O Similar Findings lança deliberadamente uma rede mais ampla para que você possa descobrir achados relacionados que a correspondência estrita por hash deixaria passar.

## Trabalhando com os resultados

A aba Similar Findings é uma tabela de dados completa com os mesmos controles que você usa em outras partes da interface Pro:

- **Keyword Search** e os controles de filtro por coluna (funil) e ordenação permitem restringir a lista.
- O menu suspenso **saved views** (**Default**) e o ícone de salvar permitem armazenar um layout de filtro/coluna para reutilização.
- Os botões de configurações de coluna e de layout controlam quais colunas são exibidas.
- **Export** baixa os resultados atuais, e **Clear Filters** limpa a tabela.

Cada linha mostra o ID do achado correspondente, Severity, Priority, Risk, nome do achado, CWE, pontuações CVSS, Vulnerability IDs, dados de EPSS, inteligência de exploração (Known Exploited / Ransomware), status, Asset, e mais. Clique no nome de um achado para abri-lo.

## Ações

Abra o menu de ações (o botão **⋮** no início de uma linha) para gerenciar o cluster de duplicatas diretamente nesta página:

![O menu de ações de linha do Similar Findings](images/pro_similar_findings_actions.png)

- **Set As Original Finding** – promove um achado a original (raiz do cluster).
- **Mark As Duplicate** – vincula o achado similar ao cluster de duplicatas do achado atual.

Essas ações manipulam os mesmos relacionamentos de duplicata que a deduplicação automática usa, de modo que um achado vinculado aqui se comporta exatamente como uma duplicata detectada automaticamente. Qualquer achado marcado como duplicata passa a aparecer na aba **Duplicate Findings** deste card.

Uma ação pode ficar indisponível quando não for válida, por exemplo quando o achado similar já é o original de um cluster diferente, ou quando vinculá-lo cruzaria um limite de Engagement enquanto a deduplicação em nível de Engagement estiver ativada.

## Ativando e desativando o Similar Findings

O Similar Findings é controlado pela configuração global do sistema **Enable Similar Findings**, que vem ativada por padrão. Como a consulta abrange um Asset inteiro, ela pode ser custosa em Assets grandes; se você notar lentidão nas páginas View Finding, essa configuração pode ser desativada.
