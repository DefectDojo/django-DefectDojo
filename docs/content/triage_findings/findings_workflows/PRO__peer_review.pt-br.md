---
title: Revisão por Pares e Reivindicação
description: Solicite uma revisão de pessoas específicas, reivindique uma revisão
  para que outras pessoas saibam que ela está sendo tratada, e controle quem é elegível
  para ser solicitado
audience: pro
weight: 4
---

A revisão por pares permite que você peça para alguém analisar um Achado antes que ele seja encerrado. Na interface do DefectDojo Pro, uma revisão também pode ser **reivindicada (claimed)**, de modo que, quando várias pessoas são elegíveis, todos possam ver quem assumiu a tarefa.

## Solicitando uma revisão

Abra um Achado e escolha **Request Review** no menu do Achado, ou selecione vários Achados em uma lista e use o [editor em massa](../pro__bulk_edit_findings/).

Você pode solicitar uma revisão de usuários e grupos nomeados, ou marcar **Allow Eligible Reviewers** para pedir a todos que sejam elegíveis nesse ativo.

Solicitar uma revisão define o Achado como **Under Review** e notifica os revisores.

## Reivindicando uma revisão

Quando uma revisão foi solicitada a várias pessoas, qualquer uma delas pode assumi-la:

* No Achado, use **Claim Review** no menu do Achado, ou o botão no banner de revisão.
* O Achado então mostra quem detém a revisão: no próprio Achado, como uma coluna **Claimed By** nas listas de Achados, e na fila [My Work](/metrics_reports/dashboards/pro__my_work/) dessa pessoa.

Uma vez que uma revisão é reivindicada:

* Somente a pessoa que a detém, a pessoa que a solicitou, ou um superusuário podem usar **Clear Review**. Outros revisores elegíveis são informados de quem a detém.
* O detentor pode devolvê-la com **Release Review**, que a retorna ao pool sem encerrar a revisão.

Se duas pessoas reivindicarem no mesmo instante, uma tem sucesso e a outra é informada de quem venceu — a revisão só pode ser detida por uma pessoa de cada vez.

As reivindicações se resolvem sozinhas em algumas situações que, de outra forma, você teria que tratar manualmente:

* Limpar a revisão marca a reivindicação como **completed**.
* Remover o detentor da lista de revisores, ou fechar ou reabrir o Achado, **libera** a reivindicação.
* Um job em segundo plano libera reivindicações cujo detentor não seja mais um revisor solicitado.

Completed e released são registrados separadamente, de modo que uma revisão abandonada é distinguível de uma concluída.

A reivindicação é controlada pela [feature flag](/admin/feature_flags/pro__feature_flags/) **Review Claiming**, que vem habilitada por padrão.

## Controlando quem pode ser solicitado para revisar

"Todos os revisores elegíveis" significa todos que possuem a permissão **Review Findings** nesse ativo — não todos que podem editar o Achado.

Isso é importante quando você quer ampla visibilidade, mas um pool pequeno de revisores. Como **Review Findings** é uma permissão separada, você pode:

1. Criar um papel (role) — um "Revisor de Segurança", por exemplo — que conceda **Review Findings**.
2. Concedê-lo ao pequeno grupo de pessoas que de fato devem ser solicitadas.
3. Remover **Review Findings** de seus papéis mais amplos, deixando o acesso a achados dessas pessoas inalterado.

Veja [Papéis Personalizados de RBAC](/admin/user_management/pro__custom_rbac_roles/) para saber como construir um papel.

Na atualização (upgrade), todo papel que já podia editar Achados recebe também **Review Findings**, de modo que "todos os revisores elegíveis" significa exatamente o que significava antes, até que você o altere deliberadamente.

## Atribuindo um Achado a uma pessoa

A revisão pede que alguém *olhe*. A atribuição (assignment) torna alguém *responsável*, e não coloca o Achado em revisão.

**Assignees** fica ao lado de **Owners** no formulário de edição do Achado. Owners é um grupo — a equipe em cuja fila isso pertence — enquanto Assignees são pessoas individuais.

* Atribua a partir do formulário de edição do Achado, ou a vários Achados de uma vez a partir do editor em massa.
* No editor em massa, os responsáveis atribuídos são **adicionados** aos que já estão atribuídos. Marque **Replace existing assignees** para tornar sua seleção a lista completa — o que remove qualquer pessoa não selecionada, incluindo todos, se você não selecionar ninguém.
* As listas de Achados têm uma coluna **Assignees** e um filtro de responsável, e os relatórios podem incluir uma coluna **Assignees**.
* As atribuições de cada pessoa aparecem em sua fila [My Work](/metrics_reports/dashboards/pro__my_work/).

Você só pode atribuir um Achado a alguém que já possa vê-lo. A atribuição não concede acesso.

O [Rules Engine](/automation/rules_engine/) pode definir responsáveis automaticamente: escolha **Set Users** e o campo **assignees**.

A atribuição é controlada pela [feature flag](/admin/feature_flags/pro__feature_flags/) **Work Assignment**.
