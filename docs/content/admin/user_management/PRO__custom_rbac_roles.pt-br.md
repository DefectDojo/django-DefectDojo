---
title: Funções RBAC Personalizadas
description: Crie suas próprias funções escolhendo permissões individuais, usando
  as cinco funções integradas como pontos de partida clonáveis
weight: 5
audience: pro
---

> **Recurso do DefectDojo Pro.** O sistema de RBAC Members / Groups / Global Roles descrito nesta página faz parte do DefectDojo Pro. O DefectDojo de código aberto usa o modelo [Authorized Users](../os__authorized_users/). Consulte essa página para o controle de acesso no código aberto, e as [notas de atualização da 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) caso você esteja migrando entre edições.

O DefectDojo Pro vem com cinco funções: **Reader**, **Writer**, **Maintainer**, **Owner** e **API Importer**. Se nenhuma delas for adequada, agora você pode criar sua própria função escolhendo exatamente quais permissões ela concede.

Uma função personalizada funciona em qualquer lugar onde uma função integrada funciona: como Função Global, como a função de um Grupo, como a função padrão do grupo, e como função de membro em uma Organização ou Asset individual.

As cinco funções integradas se tornam **predefinições bloqueadas e clonáveis**. Suas permissões não mudam (consulte os [gráficos de permissões de ação](../user_permission_chart/) para saber o que cada uma concede), elas não podem ser editadas nem excluídas, e cloná-las é a forma recomendada de começar uma nova função.

## Antes de começar

O gerenciamento de funções personalizadas vem desativado por padrão. Um **superusuário** o ativa em **Settings > Feature Flags**, habilitando **Custom Roles**. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/) para saber como essa página funciona.

Enquanto o recurso estiver desativado, a página Roles ainda pode ser lida: você pode visualizar as funções integradas e suas permissões, mas não pode criar, editar, clonar ou excluir nada.

Gerenciar funções exige status de **superusuário** ou a Função Global integrada **Owner**. Isso é intencional e não pode ser delegado a uma função personalizada: consulte [O que uma Função Global personalizada desbloqueia](#what-a-custom-global-role-unlocks).

## Abrindo a página Roles

Vá até **👤 Users > Roles** na barra lateral esquerda. O item do menu fica visível para superusuários e para quem possui a Função Global integrada Owner.

![The Roles page listing built-in and custom roles](images/pro_roles_list.png)

A tabela lista todas as funções da sua instância:

| Coluna | O que mostra |
| --- | --- |
| **ID** | O id numérico da função. Útil ao filtrar a tabela de Users ou ao chamar a API. |
| **Name** | O nome da função. |
| **Description** | Sua própria anotação sobre a finalidade da função. Opcional, e vazia a menos que alguém a preencha. As funções integradas vêm sem uma. |
| **Permissions** | Uma contagem de permissões concedidas. Clique para abrir uma visualização somente leitura da grade completa. |
| **Users** | Quantos usuários possuem essa função como sua Função Global. Clique para vê-los na tabela de Users. |
| **Type** | **Built-in** para as cinco predefinições, **Custom** para funções criadas por você. |

Todas as colunas podem ser ordenadas e filtradas, e a busca por palavra-chave corresponde ao nome e à descrição.

## Criando uma função

### Clonar uma função integrada (recomendado)

Clonar parte de um conjunto de permissões já validado, em vez de uma grade vazia, o que torna muito mais difícil esquecer acidentalmente uma permissão de que a função precisa.

1. Encontre a função mais próxima do que você deseja.
2. Abra seu menu **⋮** e escolha **Clone Role**.
3. Uma cópia é criada imediatamente, chamada `<original> (copy)`, com as mesmas permissões e descrição da função de origem.
4. Abra o menu **⋮** da cópia, escolha **Edit Role**, depois renomeie-a e ajuste suas permissões.

Funções integradas podem ser clonadas mesmo não podendo ser editadas. O clone registra de qual função ele se originou.

### Começar do zero

1. Clique em **New Role**.
2. Dê a ela um **Name** (obrigatório) e, opcionalmente, uma **Description**.
3. Escolha suas permissões na grade abaixo (veja a próxima seção).
4. Clique em **Save Role**.

Os nomes das funções devem ser únicos, e a verificação ignora maiúsculas/minúsculas: se `Triage Lead` já existir, `triage lead` será rejeitado.

## Escolhendo permissões

![The permission grid in the role form](images/pro_role_permission_grid.png)

As permissões são agrupadas em três tabelas mais uma lista de verificação.

**Object Permissions** se aplicam às Organizations e Assets aos quais a função é atribuída, e a tudo o que está aninhado sob eles.

| Linha | View | Add | Edit | Delete |
| --- | --- | --- | --- | --- |
| Organization | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset | ☑️ | ☑️ ¹ | ☑️ | ☑️ |
| Engagement | ☑️ | ☑️ | ☑️ | ☑️ |
| Test | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding Group | ☑️ | ☑️ | ☑️ | ☑️ |
| Risk Acceptance | ☑️ | ☑️ | ☑️ | ☑️ |
| Location | ☑️ | ☑️ | ☑️ | ☑️ |
| Component | ☑️ | | | |
| Note | ² | ☑️ | ☑️ | ☑️ |
| Benchmark | ² | | ☑️ | ☑️ |
| Language | ☑️ | ☑️ | ☑️ | ☑️ |
| Technology | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset API Scan Configuration | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset Tracking Files | ☑️ | ☑️ | ☑️ | ☑️ |
| Group | ☑️ | | ☑️ | ☑️ |

1. **Asset > Add** significa criar um novo Asset dentro de uma Organization à qual a função está atribuída.
2. A visualização (View) de Notes e Benchmarks é herdada: uma função que pode ver o Engagement, Test, Finding ou Asset pai pode ver suas Notes e Benchmarks. Essas células mostram um ícone **?** em vez de uma caixa de seleção.

**Group & Member Permissions** controlam quem pode gerenciar a associação. As colunas aqui são View, Manage, Add, Add Owner, Edit e Delete.

| Linha | Ações disponíveis |
| --- | --- |
| Organization Group, Asset Group | View, Add, Add Owner, Edit, Delete |
| Organization Member, Asset Member, Group Member | Manage, Add Owner, Delete |

**Global Feature Permissions** controlam recursos do Pro em toda a instância, e não Organizations ou Assets individuais, portanto **só têm efeito quando a função é mantida como uma Função Global**. Concedê-las em uma função usada apenas como associação de Asset não tem efeito.

| Linha | Ações disponíveis |
| --- | --- |
| Report Template | View, Add, Edit, Delete |
| Generated Report | View, Add, Delete |
| Connector, Sensei, Asset Hierarchy, Version Manager, Tuner, Universal Parser, Rule, Integration | View, Edit |
| Mitigation Policy | Edit |
| Audit Log, Metering | View |

**Additional Permissions** é uma lista de verificação de capacidades que não se encaixam no formato View/Add/Edit/Delete:

* **Configure Asset Notifications**: escolher quais notificações um único Asset envia, e para onde.
* **Import Scan Result**: importar e reimportar resultados de scan, criando e atualizando achados.
* **Share Dashboard Layout**: publicar um layout de painel para outros usuários. Somente Função Global.
* **Share Table Preference**: publicar uma visualização de tabela salva (colunas, filtros, ordem de classificação). Somente Função Global.
* **View Note History**: ver quem alterou uma nota e quando.

### Como ler a grade

![The read-only view of a role's permissions](images/pro_role_permissions_modal.png)

| O que você vê | O que significa |
| --- | --- |
| An empty checkbox | A permissão existe e não está concedida. Clique para concedê-la. |
| A checked checkbox | Concedida. |
| A shaded, empty cell | A permissão não existe para aquela linha e ação. Não é selecionável. |
| A **?** icon | A visualização (View) é herdada de um objeto pai, portanto não há nada para conceder aqui. |
| A green ✔ (read-only view) | Concedida. |
| A red ✘ (read-only view) | Não concedida. |

Em cada linha, a permissão mais à esquerda (**View**, ou **Manage** nas linhas de membro) controla o restante da linha. Você precisa concedê-la antes que as outras células daquela linha fiquem disponíveis, porque uma função não pode, de forma significativa, editar ou excluir o que não pode ver. Desmarcar essa permissão limpa o restante da linha junto com ela.

## Editando, clonando e excluindo

O menu **⋮** de cada linha oferece **Edit Role**, **Clone Role**, **Delete Role** e **Role History**.

Funções integradas só oferecem **Clone Role**. Elas não podem ser editadas nem excluídas, por ninguém, incluindo superusuários. Isso mantém uma base conhecida estável e torna as atualizações previsíveis.

Excluir uma função que ainda está atribuída a alguém falhará. Reatribua ou remova essas atribuições primeiro, depois exclua a função. As atribuições que contam para esse fim são associações de Organization e Asset (tanto de usuário quanto de grupo), Funções Globais, associações de Grupo, e a função de grupo padrão em System Settings.

A API pode fazer essa reatribuição para você em uma única chamada. Consulte [Gerenciando funções pela API](#managing-roles-through-the-api).

## Atribuindo uma função personalizada

Funções personalizadas aparecem em todos os menus suspensos de função, junto com as integradas:

| Onde | Como |
| --- | --- |
| **Global Role em um usuário** | O campo **Global Role** no formulário do usuário. Somente superusuários. Consulte [Definir as permissões de um Usuário](../set_user_permissions/). |
| **Global Role em um grupo** | O campo **Global Role** no formulário do grupo. Consulte [Compartilhar permissões: Grupos de Usuários](../create_user_group/). |
| **Associação de Organization ou Asset** | A caixa de diálogo Permissions na Organization ou Asset, tanto para usuários quanto para grupos. Consulte [Definir permissões no Pro](../pro_permissions_overhaul/). |
| **Função de grupo padrão** | **Default group role** em System Settings, aplicada a usuários recém-criados. Consulte [Gerenciar permissões padrão](../about_perms_and_roles/#manage-default-permissions). |
| **Função dentro de um grupo** | O menu suspenso de função na lista de membros de um grupo. Esse menu suspenso só oferece funções que concedem ao menos uma permissão de Group, portanto uma função sem permissões de Group não aparecerá ali. |

Duas restrições valem a pena conhecer:

* **O nível Owner é reservado.** Uma função personalizada nunca pode ser uma função de nível owner. Somente a Owner integrada é, portanto só ela carrega o poder implícito de gerenciar outros Owners.
* **Conceder a função Owner a outra pessoa ainda exige a permissão Add Owner correspondente**, seja em uma Organization, um Asset ou um Grupo.

## O que uma Função Global personalizada desbloqueia

Partes da interface são controladas por uma Função Global mínima, em vez de por uma permissão individual. Para que funções personalizadas funcionem com esses controles, o DefectDojo classifica uma Função Global personalizada em relação aos níveis integrados: uma função personalizada alcança o nível mais alto cujas permissões ela cobre **completamente**.

* Uma função personalizada que cobre tudo o que Maintainer concede é tratada como Maintainer para esses controles.
* Cubra tudo o que Writer concede, e ela é tratada como Writer. O mesmo vale para Reader.
* Não cubra nenhum deles completamente, e ela não alcança nenhum nível. Suas permissões individuais continuam funcionando exatamente como concedidas; apenas os controles de interface baseados em nível permanecem fechados.
* **Owner nunca pode ser alcançado dessa forma.** O gerenciamento de funções, e tudo o mais controlado pela Função Global Owner, permanece restrito a superusuários e à Owner integrada.

A cobertura precisa ser completa, o que às vezes surpreende as pessoas. Uma função clonada de Maintainer alcança o nível Maintainer. Reconstrua as permissões de Maintainer manualmente, esqueça uma, e a função cai para o nível Writer. Se uma Função Global personalizada estiver sem uma parte da interface que você esperava, compare-a com o nível integrado nos [gráficos de permissões de ação](../user_permission_chart/).

## Histórico de funções

Funções personalizadas mantêm uma trilha de auditoria. Abra **Role History** no menu **⋮** de uma função para ver quais permissões foram concedidas ou revogadas, por quem, e quando, junto com alterações em quem possui a função.

Duas coisas que esse histórico não mostra: alterações no próprio nome e descrição de uma função, e as permissões das funções integradas (essas são pré-carregadas, nunca editadas, e portanto nunca geram histórico).

O histórico de funções é uma leitura, portanto está disponível independentemente de o recurso Custom Roles estar ativado.

## Gerenciando funções pela API

As funções estão disponíveis em `/api/v2/roles/`. As leituras são abertas a qualquer usuário autenticado, pois os clientes precisam da lista de funções para preencher menus suspensos. As gravações exigem status de superusuário ou a Função Global Owner integrada, além do feature flag Custom Roles.

| Operação | Requisição |
| --- | --- |
| Listar funções | `GET /api/v2/roles/` |
| Obter uma função | `GET /api/v2/roles/{id}/` |
| Listar todas as permissões concedíveis | `GET /api/v2/roles/permissions_catalog/` |
| Criar uma função | `POST /api/v2/roles/` com `name`, `description` opcional, e uma lista de `permissions` |
| Substituir as permissões de uma função | `PATCH /api/v2/roles/{id}/` com uma lista de `permissions` |
| Clonar uma função | `POST /api/v2/roles/{id}/clone/` com `name` e `description` opcionais |
| Excluir uma função | `DELETE /api/v2/roles/{id}/` |
| Excluir uma função e mover suas atribuições | `DELETE /api/v2/roles/{id}/?reassign_to={other_role_id}` |
| Ler o histórico de uma função | `GET /api/v2/roles/{id}/history/` |

Observações:

* `permissions` **substitui** a lista de permissões concedidas da função, em vez de adicionar a ela. Envie o conjunto completo que você quer que a função tenha ao final.
* `?reassign_to=` move todas as atribuições da função excluída para a função que você indicar, em uma única transação. Essa é a única forma de reatribuir em massa: a interface não oferece isso.
* Tentar editar ou excluir uma função integrada retorna `403`. Editar um valor de permissão desconhecido, reutilizar um nome de função existente, ou excluir uma função em uso sem `reassign_to` retorna `400` com uma explicação.
* `is_owner` não pode ser definido pela API. Enviá-lo é aceito e ignorado.

## Coisas a saber

* **Múltiplas funções no mesmo objeto concedem a união de suas permissões.** Se um usuário possui uma função diretamente em um Asset e herda outra por meio de um grupo, ele obtém tudo o que qualquer uma das funções conceder. As funções só adicionam permissões, nunca as removem.
* **Alterações de permissão são aplicadas no próximo carregamento de página**, não instantaneamente na visualização atual. Jobs em segundo plano podem levar até 30 segundos, e dados de permissão em cache até 5 minutos, para refletir uma edição.
* **Os menus suspensos de função listam até 250 funções.** Além disso, algumas funções não aparecerão nos menus suspensos, embora continuem funcionando.
* **Maintainer e Owner podem adicionar Organizations, mas a grade não mostra isso.** Para essas duas funções, essa concessão é armazenada como uma concessão de escopo global, e a grade só lê concessões de escopo de objeto, portanto a célula **Organization > Add** delas aparece como não concedida. Clonar qualquer uma das duas preserva a concessão.
* **A terminologia segue sua instância.** Esta documentação usa Organization e Asset, os rótulos padrão. Se sua instância desativou a renomeação de Organization / Asset, as mesmas linhas mostram Product Type e Product em vez disso.
* **A página Roles é somente leitura para todos os demais.** Um usuário que acessar `/settings/roles` diretamente pode ver as funções e suas permissões, mas não pode alterar nada. Os dados de permissão não são sensíveis, e o servidor aplica o limite real em cada gravação.
