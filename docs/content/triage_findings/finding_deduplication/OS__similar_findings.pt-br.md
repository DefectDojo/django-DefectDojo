---
title: Achados Semelhantes
description: Encontre Achados relacionados na página View Finding e vincule-os manualmente
  como duplicados
audience: opensource
weight: 3
---

Embora a [Deduplicação](../about_deduplication) seja executada automaticamente no momento da importação, **Similar Findings** é uma ferramenta manual e interativa que fica na página **View Finding**. Ela exibe outros Achados no mesmo Asset que se assemelham ao que você está visualizando e permite vinculá-los manualmente a um cluster de duplicados.

Use-a quando a deduplicação automática não agrupar Achados que você acredita que deveriam estar juntos, ou quando quiser explorar o que mais em um Asset se parece com a vulnerabilidade atual.

## Onde encontrar

Abra qualquer Achado para acessar sua página View Finding. Role para baixo até o painel **Similar Findings**. O número no título é a contagem de Achados no Asset que correspondem aos valores do Achado atual.

![O título do painel Similar Findings na página View Finding](images/similar_findings_panel.png)

O painel fica recolhido por padrão. Clique no título do painel (ou no chevron / botão de filtro à direita) para expandi-lo e executar a consulta.

## Como os Achados são correspondidos

Ao abrir o painel, o DefectDojo pré-preenche um filtro com os valores do Achado atual e pesquisa no **mesmo Asset** por outros Achados que correspondam. Os campos usados para iniciar a correspondência são:

- IDs de Vulnerabilidade (por exemplo, identificadores CVE)
- CWE
- Caminho do arquivo
- Número da linha
- Unique ID from tool
- Tipo de Teste
- Asset (e Tipo de Asset)

O Achado atual é sempre excluído de seus próprios resultados. A correspondência é limitada ao Asset, então o Similar Findings nunca ultrapassa os limites de um Asset. Se algum dos Engajamentos tiver a deduplicação em nível de Engajamento ativada, as correspondências que cruzam o limite de um Engajamento não podem ser vinculadas (veja [Actions](#actions) abaixo).

Isso é diferente do algoritmo de deduplicação automática, que compara `hash_code` (ou Unique ID from tool) para decidir as correspondências. O Similar Findings propositalmente lança uma rede mais ampla, para que você possa descobrir Achados relacionados que uma correspondência estrita por hash deixaria passar.

## Refinando a correspondência

Os valores iniciais são apenas um ponto de partida. O painel de filtro no topo da seção permite tornar a correspondência mais rígida ou mais flexível: remova um campo para ampliar os resultados, ou adicione critérios (severidade, status, endpoint, datas, EPSS e mais) para restringi-los.

![O painel de filtro do Similar Findings](images/similar_findings_filters.png)

- **Clear filters** limpa todos os campos para que você possa construir uma consulta do zero.
- **Restart** retorna à correspondência padrão baseada nos valores do Achado atual.

## Lendo os resultados

Cada Achado correspondente é listado em uma tabela. A coluna **Relationship** indica como aquele Achado se relaciona com o que você está visualizando:

- **Original** – o Achado raiz/original do cluster de duplicados do Achado atual
- **Duplicado** – um Achado já marcado como duplicado do atual
- **Semelhante** – uma correspondência que ainda não faz parte do cluster do Achado atual

![A tabela de resultados do Similar Findings](images/similar_findings_list.png)

A tabela também exibe Severidade, Título, Data, Status, Teste, Engajamento, CWE, ID da Vulnerabilidade, pontuação EPSS, Arquivo (com número da linha) e JIRA (quando a integração com o JIRA está habilitada). Todas as colunas são ordenáveis, e os resultados podem ser exportados (Copiar, Excel, CSV, PDF).

## Ações

Se você tiver permissão de edição em um Achado, a coluna **Action** oferece um menu suspenso para gerenciar o cluster de duplicados diretamente nesta página:

![O menu de ações de linha do Similar Findings](images/similar_findings_actions.png)

- **Marcar como duplicado** – vincula o Achado semelhante ao cluster de duplicados do Achado atual.
- **Definir como original** – promove um Achado a original (raiz do cluster).
- **Redefinir status de duplicado do achado** – remove um Achado do seu cluster.

Uma ação pode ficar indisponível (exibida como **None**) quando não é válida, por exemplo quando o Achado semelhante está em um Engajamento diferente e a deduplicação em nível de Engajamento está habilitada, ou quando ele já é o original de um cluster diferente. Essas ações manipulam os mesmos relacionamentos de duplicado usados pela deduplicação automática, então um Achado marcado aqui se comporta exatamente como um duplicado detectado automaticamente.

## Habilitando e desabilitando o Similar Findings

O Similar Findings é controlado por uma configuração global do sistema. Vá para **Configuration > System Settings** e alterne **Enable Similar Findings**. Ele vem habilitado por padrão.

![A configuração de sistema Enable Similar Findings](images/similar_findings_enable_setting.png)

Como a consulta abrange um Asset inteiro, ela pode ser custosa em Assets grandes. Se você notar lentidão nas páginas View Finding, pode desabilitar o recurso aqui, ou limitar o número de resultados retornados com a variável de ambiente `DD_SIMILAR_FINDINGS_MAX_RESULTS` (padrão `25`).
