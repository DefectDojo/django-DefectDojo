---
title: Edição em Massa de Achados
description: Aplique alterações de metadados, tags, notas e revisão a vários Achados
  de uma só vez na interface do DefectDojo Pro
audience: pro
weight: 3
---

Na interface do DefectDojo Pro, os Achados podem ser editados em massa a partir de qualquer Lista de Achados — a página **All Findings**, ou a lista de Achados dentro de um Teste.

## Selecionando Achados para Edição em Massa

Em qualquer tabela de Achados, use as caixas de seleção ao lado dos Achados para selecioná-los. Selecionar um ou mais Achados revela uma **barra de ações em massa** com os seguintes controles:

* **Bulk Edit** — abre um único formulário onde você aplica alterações de metadados, tags, notas e solicitações de revisão a todos os Achados selecionados. Esta é a principal superfície consolidada (detalhada abaixo).
* **Risk Acceptance** — adiciona os Achados selecionados a uma **Aceitação de Risco Completa** nova ou existente.
* **Finding Group** — adiciona os Achados selecionados a um **Grupo de Achados** novo ou existente, ou os remove de seu grupo.
* **Merge** — mescla os Achados selecionados em um único Achado.
* **Delete** — exclui os Achados selecionados (com confirmação).

Um controle fica desabilitado quando a ação não pode ser aplicada à sua seleção atual — veja [Disponibilidade e Achados ignorados](#availability-and-skipped-findings).

## Bulk Edit

O botão **Bulk Edit** abre um único formulário contendo todas as ações em massa em nível de campo. Defina apenas os campos que deseja alterar e deixe os demais inalterados, depois clique em **Update Selected Findings** para aplicar. As ações disponíveis são:

* **Severity** — define a severidade (Critical, High, Medium, Low ou Info).
* **Status** — aplica um entre Active, Verified, False Positive, Out of Scope, Mitigated ou Under Defect Review.
* **Date** — define a data de descoberta.
* **Planned Remediation Date** e **Planned Remediation Version**.
* **Simple Risk Acceptance** — Accept Risk ou Unaccept Risk. Aplicado apenas aos Achados cujo Produto tenha a Aceitação de Risco Simples habilitada; os demais são ignorados.
* **Tags** — adiciona tags aos Achados selecionados, ou usa a alternância **Append / Replace** para sobrescrever todo o conjunto de tags de cada Achado (**Append** adiciona as tags; **Replace** substitui todas as tags existentes).
* **Replace Specific Tag** — troca uma tag nomeada por outra (veja abaixo).
* **Note** — adiciona uma nota, com um tipo de nota opcional, a cada Achado selecionado.
* **Review** — solicita ou limpa a revisão nos Achados selecionados (veja abaixo).
* **Push to Jira** — enfileira os Achados selecionados para envio ao Jira. Exibido apenas quando a integração com o Jira está habilitada.
* **Push to Connector** — envia os Achados selecionados para o seu conector configurado. Exibido apenas quando esse recurso está habilitado.

### Replace Specific Tag

**Replace Specific Tag** realiza uma troca de tag direcionada e não destrutiva. Digite a tag a ser substituída em **Existing Tag to Replace** e a substituta em **New Tag**. Para cada Achado selecionado que de fato tenha a tag antiga, o DefectDojo remove essa tag e adiciona a nova — todas as demais tags são preservadas, e os Achados que não têm a tag antiga permanecem inalterados.

Isso é diferente do campo **Tags** acima: **Tags** *adiciona* tags (Append) ou *sobrescreve todo o conjunto de tags* (Replace), enquanto **Replace Specific Tag** altera apenas a tag nomeada.

### Review

A ação **Review** gerencia a revisão por pares em todos os Achados selecionados:

* **Request Review** — escolha um ou mais **Reviewers** e digite uma **Review Note** (obrigatória). Cada Achado selecionado é definido como *Under Review* (Active, não Verified), os revisores escolhidos são atribuídos, uma nota de solicitação de revisão é adicionada, e os revisores são notificados.
* **Clear Review** — digite uma **Review Note** (obrigatória) para tirar os Achados selecionados do estado *Under Review* e remover seus revisores atribuídos.

Os revisores que você pode escolher são os usuários com acesso de edição aos Achados selecionados.

## Risk Acceptance, Finding Group, Merge e Delete

Os demais botões de ação em massa abrem suas próprias caixas de diálogo:

* **Risk Acceptance** — cria uma nova **Aceitação de Risco Completa** para reger os Achados selecionados, ou os adiciona a uma existente.
* **Finding Group** — cria um novo **Grupo de Achados**, adiciona os Achados a um grupo existente, ou os remove de seu grupo atual. Grupos de Achados só podem ser criados dentro de um único **Teste** — Achados de Testes, Engajamentos ou Produtos diferentes não podem compartilhar um grupo.
* **Merge** — mescla vários Achados selecionados (todos do mesmo Ativo) em um só.
* **Delete** — exclui os Achados selecionados após confirmação em um popup.

## Disponibilidade e Achados Ignorados

Cada ação em massa só fica disponível quando pode ser aplicada a toda a sua seleção:

* **Bulk Edit**, tags e revisão exigem que todos os Achados selecionados sejam editáveis por você.
* **Risk Acceptance** fica indisponível se algum Achado selecionado não for editável, já tiver o risco aceito, ou for um Duplicate.
* A criação de **Finding Group** exige que todos os Achados sejam editáveis, não agrupados, e pertençam ao mesmo Teste.
* **Merge** exige mais de um Achado, todos editáveis e do mesmo Ativo.
* **Delete** exige que todos os Achados selecionados sejam excluíveis por você.

Quando uma ação é executada mas alguns Achados não podem ser atualizados — por exemplo, por não serem editáveis por você, já estarem em revisão, ou pertencerem a um Produto sem a Aceitação de Risco Simples habilitada — o DefectDojo aplica a alteração aos demais e exibe um aviso **"One or More Findings Skipped"** explicando por que cada um foi ignorado.
