---
title: Permissões no DefectDojo
description: Resumo detalhado de todas as opções de permissão do DefectDojo Pro
weight: 2
audience: pro
aliases:
- /pt-br/en/customize_dojo/user_management/about_perms_and_roles
---

> **Recurso do DefectDojo Pro.** O sistema de RBAC de Membros / Grupos / Papéis Globais descrito nesta página faz parte do DefectDojo Pro. O DefectDojo open-source usa o modelo de [Usuários Autorizados](../os__authorized_users/) — consulte essa página para o controle de acesso do open-source, e as [notas de atualização da 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) se você estiver migrando entre edições.

Se você tem uma equipe de usuários trabalhando no DefectDojo, é importante configurar adequadamente o Controle de Acesso Baseado em Papéis (RBAC) para que os usuários só possam acessar dados específicos. Dados de segurança são altamente sensíveis, e as opções de controle de acesso do DefectDojo permitem que você seja específico sobre o acesso de cada membro da equipe às informações.

Este artigo é uma visão geral de como as permissões funcionam no DefectDojo.  Se você preferir ver um detalhamento de **cada ação** que pode ser controlada pelas Permissões, consulte nosso artigo **[Tabela de Permissões](../user_permission_chart/)**.

## Tipos de Permissões

O DefectDojo gerencia quatro tipos diferentes de permissões:

* Os usuários podem ser designados como **Membros** de **Produtos ou Tipos de Produto**. Uma Associação a Produto vem com um **Papel** que permite aos seus usuários visualizar e interagir com Tipos de Dados (Tipos de Produto, Produtos, Engajamentos, Testes e Achados) no DefectDojo. Os usuários podem ter múltiplas associações a Produtos ou Tipos de Produto, com diferentes níveis de acesso.
​
* Os usuários também podem ter **Permissões de Configuração** atribuídas, que permitem acessar páginas de configuração no DefectDojo. As Permissões de Configuração não estão relacionadas a Produtos ou Tipos de Produto, e não estão associadas a Papéis.
​
* Os usuários podem receber **Papéis Globais**, que dão a eles um nível padronizado de acesso a todos os Produtos e Tipos de Produto.
​
* Os usuários podem ser configurados como **Superusuários**: papéis de nível administrativo que dão a eles controle e acesso a todos os dados e configurações do DefectDojo.

Cada um desses tipos de Permissão também pode ser atribuído a um **Grupo** de **Usuários**. Se você tiver um grande número de usuários no DefectDojo, como uma equipe de testes dedicada a um Produto específico, os Grupos permitem configurar e manter as permissões rapidamente.

## Associação a Produto/Tipo de Produto e Papéis

Quando os usuários são designados como membros de um Produto ou Tipo de Produto, eles também recebem um papel que controla como interagem com os dados de Achados associados.

### Resumo dos Papéis

O DefectDojo Pro vem com cinco **papéis integrados**: Reader, Writer, Maintainer, Owner e API Importer. Qualquer um deles pode ser atribuído globalmente ou dentro de um Produto / Tipo de Produto.

Os papéis integrados são predefinições fixas. Eles não podem ser editados ou excluídos, e suas permissões são as mesmas em todas as instâncias do DefectDojo Pro. Se nenhum deles se encaixar na forma como sua equipe trabalha, você pode criar um papel que se encaixe, escolhendo permissões individuais ou clonando um papel integrado e ajustando-o. Veja [Papéis RBAC Personalizados](../pro__custom_rbac_roles/).

"Dados subjacentes" refere-se a todos os Produtos, Engajamentos, Testes, Achados ou Endpoints aninhados sob um Produto, ou Tipo de Produto.

* **Usuários Reader** podem visualizar os dados subjacentes de qualquer Produto ou Tipo de Produto ao qual estejam atribuídos, e adicionar comentários. Eles não podem editar, adicionar ou modificar de outra forma nenhum dado subjacente, mas podem exportar Relatórios e adicionar Notas aos dados.
​
* **Usuários Writer** têm todas as habilidades de Reader, além da capacidade de Adicionar ou Editar Engajamentos, Testes e Achados. Eles não podem adicionar novos Produtos, e não podem Excluir nenhum dado subjacente.
​
* **Usuários Maintainer** têm todas as habilidades de Writer, além da capacidade de editar Produtos ou Tipos de Produto. Eles podem adicionar novos Membros com Papéis ao Produto ou Tipo de Produto, e também podem Excluir Engajamentos, Testes e Achados.
​
* **Usuários Owner** têm o maior nível de controle sobre um Produto ou Tipo de Produto. Eles podem designar outros Owners, e também podem Excluir os Produtos ou Tipos de Produto aos quais estão atribuídos.
​
* **Usuários API Importer** têm habilidades limitadas. Este Papel permite acesso limitado à API sem expor a maioria dos endpoints da API, sendo útil para automação ou para usuários que devem ser 'externos' ao DefectDojo. Eles podem visualizar dados subjacentes, Adicionar / Editar Engajamentos, e Importar Dados de Varredura.

Para informações detalhadas sobre os Papéis integrados, consulte nossa **[Tabela de Permissões por Papel](../user_permission_chart/)**. Para a lista completa de permissões que um papel pode receber, e como criar o seu próprio, veja **[Papéis RBAC Personalizados](../pro__custom_rbac_roles/)**.

### Papéis Globais

Usuários com **Papéis Globais** podem visualizar e interagir com qualquer Tipo de Dados (Tipos de Produto, Produtos, Engajamentos, Testes e Achados) no DefectDojo, dependendo do Papel atribuído a eles.

### Associações de Grupo

Grupos de Usuários podem ser adicionados como Membros de um Produto ou Tipo de Produto. Os usuários que fazem parte do Grupo herdarão acesso a todos os Produtos ou Tipos de Produto associados, e herdarão o Papel atribuído ao Grupo.

#### Usuários com múltiplos papéis

* Se um Usuário é designado como membro de um Produto, ele não recebe automaticamente as permissões associadas do Tipo de Produto.

* Se um Usuário acabar com mais de um papel no mesmo Produto ou Tipo de Produto (por exemplo, um atribuído diretamente e outro herdado de um Grupo), ele recebe as permissões **combinadas** de todos os papéis que possui ali.

* O Papel de Produto de um Usuário sempre substitui seu Papel de Tipo de Produto 'padrão'.
​
* O Papel de Produto / Tipo de Produto de um Usuário sempre substitui seu Papel Global dentro do Produto ou Tipo de Produto subjacente. Por exemplo, se um Usuário tem um Papel de Tipo de Produto de Reader, mas também está atribuído como Owner em um Produto aninhado sob esse Tipo de Produto, ele terá permissões adicionais de Owner somente para esse Produto.
​
* Os Papéis não podem retirar permissões, eles só podem adicionar novas. Por exemplo, se um Usuário tem um Papel de Tipo de Produto ou Papel Global de Owner, atribuir a ele um papel de Reader em um Produto específico não removerá suas permissões de Owner nesse Produto.
​
* O status de Superusuário sempre substitui quaisquer Papéis atribuídos.

## Superusuários

Os Superusuários (Admins) não têm limitações no sistema. Eles podem alterar todas as configurações, gerenciar usuários e têm acesso de leitura/gravação a todos os dados. Eles também podem alterar as regras de acesso para todos os usuários do DefectDojo. Os Superusuários também recebem notificações de todos os problemas e alertas do sistema.

Por padrão, a primeira conta criada em uma nova instância do DefectDojo terá permissões de Superusuário. Esse usuário poderá editar as permissões de todos os usuários do DefectDojo criados posteriormente. Somente um Superusuário existente pode adicionar outro superusuário, ou adicionar um Papel Global a um usuário.


## Permissões de Configuração

As Permissões de Configuração, embora semelhantes, não estão relacionadas a Produtos ou Papéis. Elas devem ser atribuídas separadamente dos Papéis. **Usuários comuns não têm nenhuma Permissão de Configuração por padrão, e a atribuição dessas permissões de configuração deve ser feita com cuidado.**

Os usuários podem ter Permissões de Configuração atribuídas de diferentes formas:

1. Os usuários podem receber Permissões de Configuração diretamente. Permissões específicas podem ser configuradas diretamente na página de um Usuário.

2. Grupos de Usuários podem receber Permissões de Configuração. Assim como com os Papéis, Permissões de Configuração específicas podem ser adicionadas aos Grupos, o que dará a todos os membros do Grupo essas permissões.

Os Superusuários têm todas as Permissões de Configuração, portanto não têm uma seção de Permissões de Configuração em sua página de Usuário.

### Permissões de Configuração de Grupo

Se os usuários fazem parte de um Grupo, eles também têm Permissões de Configuração de Grupo, que controlam seu nível de acesso à configuração de um Grupo. As Permissões de Grupo não correspondem à associação do Grupo a Produtos ou Tipos de Produto.

Se os usuários criarem um novo Grupo, receberão o papel de Owner do novo Grupo por padrão.

Para mais informações sobre Permissões de Configuração, consulte nossa **[Tabela de Permissões de Configuração](../user_permission_chart/#configuration-permission-chart)**.

## Gerenciar permissões padrão

Quando um usuário totalmente novo é criado no DefectDojo — seja manualmente, via SAML / SSO, ou via qualquer provedor de social-auth — ele **não tem nenhuma permissão por padrão**. Ele verá zero Tipos de Produto, zero Produtos e zero Engajamentos no primeiro login. Ele não pode visualizar ou interagir com nenhum dado até que um Superusuário conceda acesso (diretamente, via um Papel Global, via uma associação a Produto / Tipo de Produto, ou adicionando-o a um Grupo).

Se você quiser que todo usuário recém-provisionado receba automaticamente um nível básico de acesso — por exemplo, "todo novo usuário SSO deve ser Reader em um determinado grupo" — você pode configurar um **Grupo padrão** na página de Configurações do Sistema.

1. Abra **⚙️ Configuration → System Settings** (somente Superusuário).
2. Defina **Default group** como o [Grupo de Usuários](../create_user_group/) ao qual os usuários recém-criados devem ser adicionados.
3. Defina **Default group role** como o papel que eles devem ter nesse grupo (por exemplo, **Reader**).
4. Opcionalmente, defina **Default group email pattern** como uma expressão regular (por exemplo, `.*@yourcompany\.com$`) para que o grupo padrão seja aplicado apenas a usuários cujo e-mail corresponda.
5. Salve.

Tanto **Default group** quanto **Default group role** devem ser definidos — se algum estiver vazio, o grupo padrão não é aplicado.

Essa configuração se aplica a todos os fluxos de criação de usuário: criação manual, SAML, OAuth e outros provedores de social-auth. Ela não é aplicada retroativamente — os usuários existentes manterão suas associações de grupo atuais mesmo que você altere essa configuração posteriormente.

Para orientações específicas sobre SSO, consulte [Configuração SAML](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users) ou a seção do seu provedor em [Configuração de SSO](../configure_sso/).
