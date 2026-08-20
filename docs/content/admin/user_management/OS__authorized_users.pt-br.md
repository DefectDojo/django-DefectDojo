---
title: Permissões do Open Source
description: Como o acesso a Produtos e Tipos de Produto é concedido no DefectDojo
  open source
weight: 1
audience: opensource
---

O DefectDojo open source controla o acesso a Produtos e Tipos de Produto com o modelo de **Usuários Autorizados**. Cada Produto e Tipo de Produto tem um painel de Usuários Autorizados listando as pessoas que podem ver aquele registro e os dados aninhados sob ele.

Se você está usando o DefectDojo Pro, este artigo não se aplica à sua instalação — o Pro usa um sistema baseado em papéis mais completo, abordado em [Permissões no DefectDojo](../about_perms_and_roles/).

## Como o acesso é concedido

Existem duas listas, e um usuário só precisa aparecer em uma delas para obter acesso:

- **A lista de Usuários Autorizados de um Produto** concede acesso a esse Produto específico, além de tudo o que está aninhado sob ele (seus Engajamentos, Testes, Achados e Endpoints).
- **A lista de Usuários Autorizados de um Tipo de Produto** concede acesso ao próprio Tipo de Produto **e se propaga para todos os Produtos sob ele**. Um usuário autorizado em um Tipo de Produto não precisa também ser adicionado a cada Produto filho — ele já está coberto.

Não existem papéis, grupos ou papéis globais. Um usuário está na lista (ou é superusuário/membro da equipe — veja abaixo), ou não consegue ver o Produto.

## Superusuários e membros da equipe ignoram as listas

Usuários marcados como **superusuário** ou **membro da equipe (staff)** no DefectDojo podem ver e atuar em todos os Produtos e Tipos de Produto, independentemente das listas de Usuários Autorizados. As listas existem para conceder acesso a usuários que não são da equipe; elas não restringem membros da equipe ou superusuários.

A primeira conta criada em uma instalação nova do DefectDojo é automaticamente um superusuário.

## Quem pode editar as listas

Somente usuários **superusuário** ou **membro da equipe** veem os controles para adicionar ou remover pessoas de um painel de Usuários Autorizados. Todos os demais que têm acesso a um Produto ou Tipo de Produto veem o painel como uma lista somente leitura — útil para descobrir quem mais está na equipe, mas não para alterar a associação.

## Onde o painel fica

O painel de Usuários Autorizados aparece em duas páginas na interface clássica:

- A **página de detalhes do Produto** tem um painel de Usuários Autorizados para aquele Produto. Ela oferece duas ações para usuários da equipe:
  - **Adicionar um usuário à lista de Usuários Autorizados do Produto**
  - **Remover um usuário da lista de Usuários Autorizados do Produto**
- A **página de detalhes do Tipo de Produto** tem um painel de Usuários Autorizados para aquele Tipo de Produto, com as duas ações correspondentes:
  - **Adicionar um usuário à lista de Usuários Autorizados do Tipo de Produto**
  - **Remover um usuário da lista de Usuários Autorizados do Tipo de Produto**

Quando você remove um usuário da lista de um Tipo de Produto, a propagação também é removida — ele perde o acesso a todos os Produtos filhos, a menos que ainda esteja na lista de um Produto específico, ou seja membro da equipe/superusuário.

## Escolhendo entre acesso por Produto ou por Tipo de Produto

Algumas regras práticas:

- Se uma pessoa deve ver todos os Produtos de uma categoria (por exemplo, todos os Produtos de uma determinada equipe), coloque-a na lista do **Tipo de Produto** e deixe a propagação cuidar do resto.
- Se uma pessoa deve ver apenas um Produto específico, coloque-a na lista daquele **Produto**.
- Se você perceber que está adicionando a mesma pessoa a vários Produtos individuais dentro de um mesmo Tipo de Produto, isso é um sinal de que deveria adicioná-la ao Tipo de Produto em vez disso.

## Vindo de uma versão anterior do DefectDojo

O DefectDojo open source voltou ao modelo de Usuários Autorizados na versão 3.0. Se você está atualizando a partir de uma versão que tinha o sistema de Membros / Grupos / Papéis Globais, seu acesso existente é migrado automaticamente para Usuários Autorizados pela própria atualização — não é necessário nenhum mapeamento manual.

A atualização vem com um comando de gerenciamento somente leitura, `preview_legacy_authorization_migration`, que resume o que uma atualização mudaria em uma cópia do seu banco de dados. O fluxo de trabalho recomendado é instalar a versão 3.0 em um ambiente de staging com um snapshot da produção, executar o comando, revisar o resumo e só então atualizar a produção.

Se você está indo na direção contrária — do open source para o DefectDojo Pro — o Pro vem com um comando `reconcile_authorized_users_to_rbac` que traz o acesso de Usuários Autorizados para o RBAC do Pro. Ele suporta `--dry-run` e é idempotente.

Para mais detalhes sobre os dois caminhos, veja as [notas de atualização da versão 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization).
