---
title: Quadros de permissões de ações
description: Todas as permissões de usuário do DefectDojo Pro em detalhes
weight: 4
audience: pro
aliases:
- /pt-br/en/customize_dojo/user_management/user_permission_chart
---

> **Recurso do DefectDojo Pro.** O sistema de RBAC de Membros / Grupos / Funções Globais descrito nesta página faz parte do DefectDojo Pro. O DefectDojo de código aberto usa o modelo [Usuários Autorizados](../os__authorized_users/) — consulte essa página para o controle de acesso no código aberto, e as [notas de atualização da versão 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) caso você esteja migrando entre edições.

## Quadro de Permissões por Função

Este quadro tem como objetivo listar todas as permissões relacionadas a um Produto ou Tipo de Produto, bem como quais permissões estão disponíveis para cada função.

As cinco funções abaixo são as **funções integradas** do DefectDojo Pro. Elas são predefinições bloqueadas: suas permissões são as mesmas em todas as instâncias e não podem ser alteradas. Se você criou suas próprias funções, este quadro descreve as funções integradas a partir das quais elas foram clonadas, e não as funções personalizadas em si. Para o catálogo completo de permissões que podem ser atribuídas a uma função, consulte [Funções RBAC Personalizadas](../pro__custom_rbac_roles/#choosing-permissions).

| **Seção** | **Permissão** | Reader | Writer | Maintainer | Owner | API Importer |
| --- | --- | --- | --- | --- | --- | --- |
| **Acesso a Produto / Tipo de Produto** | Visualizar o Produto ou Tipo de Produto atribuído ¹ | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Visualizar Produtos, Engajamentos, Testes, Achados e Endpoints aninhados | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Adicionar novos Produtos (dentro do Tipo de Produto atribuído) ² |  |  | ☑️ | ☑️ |  |
|  | Excluir Produtos ou Tipos de Produto atribuídos |  |  |  | ☑️ |  |
| **Associação a Produto / Tipo de Produto** | Adicionar Usuários como Membros (exceto a Função Owner) |  |  | ☑️ | ☑️ |  |
|  | Editar Funções de membros (exceto a Função Owner) |  |  | ☑️ | ☑️ |  |
|  | Editar Funções de membros (incluindo a Função Owner) |  |  |  | ☑️ |  |
|  | Remover a si mesmo da associação a Produto / Tipo de Produto | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Atribuir a Função Owner a outro Usuário |  |  |  | ☑️ |  |
|  | Editar uma Associação a Produto/Tipo de Produto vinculada a um Grupo³ |  |  |  | ☑️ |  |
|  | Excluir uma Associação a Produto/Tipo de Produto vinculada a um Grupo³ |  |  |  |  |  |
| **Engajamentos** (Dentro de um Produto) | Adicionar, Editar Engajamentos |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Visualizar Aceitações de risco ⁴ |  | ☑️ | ☑️ | ☑️ |  |
|  | Adicionar, Editar Aceitações de risco |  | ☑️ | ☑️ | ☑️ |  |
|  | Excluir Engajamentos |  |  | ☑️ | ☑️ |  |
| **Testes** (Dentro de um Produto) | Adicionar Testes |  | ☑️ | ☑️ | ☑️ |  |
|  | Editar Testes |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Excluir Testes |  |  | ☑️ | ☑️ |  |
| **Achados**  (Dentro de um Produto) | Adicionar Achados |  | ☑️ | ☑️ | ☑️ |  |
|  | Editar Achados |  | ☑️ | ☑️ | ☑️ |  |
|  | Importar, Reimportar  Resultados de Scan |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Excluir Achados |  |  | ☑️ | ☑️ |  |
|  | Adicionar, Editar, Excluir  Grupos de Achados |  | ☑️ | ☑️ | ☑️ |  |
| **Outros Dados**  (Dentro de um Produto) | Adicionar, Editar Endpoints |  | ☑️ | ☑️ | ☑️ |  |
|  | Excluir Endpoints |  |  | ☑️ | ☑️ |  |
|  | Editar Benchmarks |  | ☑️ | ☑️ | ☑️ |  |
|  | Excluir Benchmarks |  |  | ☑️ | ☑️ |  |
|  | Visualizar Histórico de Notas | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Adicionar, Editar, Excluir Notas próprias | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Editar Notas de terceiros |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Excluir Notas de terceiros |  |  | ☑️ | ☑️ |  |

1. Um usuário que recebe permissões apenas em nível de Produto não pode visualizar o Tipo de Produto no qual esse Produto está contido.
2. Quando um novo Produto é adicionado sob um Tipo de Produto, todos os Usuários em nível de Tipo de Produto serão adicionados como Membros do novo Produto com sua Função em nível de Tipo de Produto.
3. O usuário que deseja fazer alterações em um Grupo também precisa ter a **Permissão de Configuração** **Editar Grupo**, e uma **Função de Configuração de Grupo** de **Maintainer ou Owner** no Grupo que deseja editar.
4. A visibilidade de Aceitação de risco é controlada por uma permissão mínima distinta da visibilidade de Achados — um Reader no Produto pode visualizar os Achados subjacentes, mas **não pode** visualizar as Aceitações de risco às quais esses Achados pertencem.  Para detalhes sobre permissões de Aceitação de risco, comportamento da data de expiração e fluxos de reinstauração, consulte [Aceitações de risco (Pro)](/triage_findings/findings_workflows/pro__risk_acceptance/#risk-acceptance-permissions-and-visibility).

## Quadro de Permissões de Configuração

Cada Permissão de Configuração se refere a uma função específica do software e tem um conjunto associado de ações que um usuário pode realizar relacionadas a essa função.

A maioria das Permissões de Configuração dá aos usuários acesso a determinadas páginas na interface.

| **Configuration Permission** | **View ☑️** | **Add ☑️** | **Edit ☑️** | **Delete ☑️** |
| --- | --- | --- | --- | --- |
| Gerenciador de Credenciais | Acessar a página **⚙️Configuração \> Gerenciador de Credenciais** | Adicionar novas entradas no Gerenciador de Credenciais | Editar entradas do Gerenciador de Credenciais | Excluir entradas do Gerenciador de Credenciais |
| Ambientes de Desenvolvimento | n/a | Adicionar novos Ambientes de Desenvolvimento à lista 🗓️**Engajamentos \> Ambientes** | Editar Ambientes de Desenvolvimento na lista 🗓️**Engajamentos \> Ambientes** | Excluir Ambientes de Desenvolvimento da lista **🗓️Engajamentos \> Ambientes** |
| Modelos de Achado¹ | Acessar a página **Achados \> Modelos de Achado** | Adicionar um Modelo de Achado | Editar um Modelo de Achado | Excluir um Modelo de Achado |
| Grupos | Acessar a página **👤Usuários \> Grupos** | Adicionar um novo Grupo de Usuários | Somente Superuser | Somente Superuser |
| Instâncias do Jira | Acessar a página **⚙️Configuração \> JIRA page** | Adicionar uma nova Configuração do JIRA | Editar uma Configuração do JIRA existente | Excluir uma Configuração do JIRA |
| Tipos de Idioma |  |  |  |  |
| Banner de Login | n/a | n/a | Editar o banner de login, localizado em **⚙️Configuração \> Banner de Login** | n/a |
| Anúncios | n/a | n/a | Configurar Anúncios, localizados em  **⚙️Configuração \> Anúncios** | n/a |
| Tipos de Nota | Acesso à página ⚙️Configuração \> Tipos de Nota | Adicionar um Tipo de Nota | Editar um Tipo de Nota | Excluir um Tipo de Nota |
| Mecanismos de Priorização | Acessar a página de configuração do Mecanismo de Priorização | Adicionar um novo Mecanismo de Priorização | Editar um Mecanismo de Priorização existente | Excluir um Mecanismo de Priorização |
| Tipos de Produto | n/a | Adicionar um novo Tipo de Produto (em Produtos \> Tipo de Produto) | n/a | n/a |
| Questionários | Acessar a página **Questionários \> Todos os Questionários** | Adicionar um novo Questionário | Editar um Questionário existente | Excluir um Questionário |
| Perguntas | Acessar a página **Questionários \> Perguntas** | Adicionar uma nova Pergunta | Editar uma Pergunta existente | n/a |
| Regulamentações | n/a | Adicionar uma Regulamentação à página **⚙️Configuração \> Regulamentações** | Editar uma Regulamentação existente | Excluir uma Regulamentação |
| Agendamento do Serviço de Agendamento | Acessar a página **Agendamento** | Somente Superuser | Editar um Agendamento existente (alterar gatilho, ativar/desativar) | Excluir um Agendamento |
| Configuração de SLA | Acessar a página **⚙️Configuração \> Configuração de SLA** | Adicionar uma nova Configuração de SLA | Editar uma Configuração de SLA existente | Excluir uma Configuração de SLA |
| Tipos de Teste | n/a | Adicionar um novo Tipo de Teste (em **Engajamentos \> Tipos de Teste**) | Editar um Tipo de Teste existente | n/a |
| Configuração de Ferramenta | Acessar a página **⚙️Configuração \> Configuração de Ferramenta** | Adicionar uma nova Configuração de Ferramenta | Editar uma Configuração de Ferramenta existente | Excluir uma Configuração de Ferramenta |
| Tipos de Ferramenta | Acessar a página **⚙️Configuração \> Tipos de Ferramenta** | Adicionar um novo Tipo de Ferramenta | Editar um Tipo de Ferramenta existente | Excluir um Tipo de Ferramenta |
| Usuários | Acessar a página **👤Usuários \> Usuários** | Adicionar um novo Usuário ao DefectDojo | Editar um Usuário existente | Excluir um Usuário |

1. O acesso à página de Modelos de Achado também requer a Função Global **Writer, Maintainer** ou **Owner** para esse usuário.

## Permissões de Configuração de Grupo

| Configuration Permission | **Reader** | **Maintainer** | **Owner** |
| --- | --- | --- | --- |
| Visualizar Grupo | ☑️ | ☑️ | ☑️ |
| Remover a si mesmo do Grupo | ☑️ | ☑️ | ☑️ |
| Editar a função de um Membro em um Grupo |  | ☑️ | ☑️ |
| Editar ou Excluir uma Associação a Produto ou Tipo de Produto de um Grupo¹ |  | ☑️ | ☑️ |
| Alterar a função de um Membro do Grupo para Owner |  |  | ☑️ |
| Excluir Grupo |  |  | ☑️ |

1. Isso também exige que o Usuário tenha pelo menos a Função Maintainer no Produto ou Tipo de Produto que deseja editar.
