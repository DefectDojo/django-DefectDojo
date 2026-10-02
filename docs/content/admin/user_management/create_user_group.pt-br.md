---
title: 'Compartilhar permissões: Grupos de Usuários'
description: Compartilhe e mantenha permissões para vários usuários no DefectDojo
  Pro
weight: 3
audience: pro
aliases:
- /pt-br/en/customize_dojo/user_management/create_user_group
---

> **Recurso do DefectDojo Pro.** Os Grupos de Usuários e o sistema de RBAC subjacente são parte do DefectDojo Pro. O DefectDojo open-source usa o modelo de [Usuários Autorizados](../os__authorized_users/) — consulte essa página para o controle de acesso do open-source, e as [notas de atualização da 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) se você estiver migrando entre edições.

Se você tem um número significativo de usuários no DefectDojo, pode ser interessante criar um ou mais **Grupos**, para definir as mesmas regras de Controle de Acesso Baseado em Papéis (RBAC) para vários usuários simultaneamente. Somente Superusuários podem criar Grupos de Usuários.

Os Grupos podem funcionar de várias formas:

* Definir um, ou vários Papéis diferentes em nível de Produto ou Tipo de Produto para todos os Membros do Grupo, permitindo controle específico sobre quais Produtos ou Tipos de Produto podem ser acessados e editados pelo Grupo.
* Definir um Papel Global para todos os Membros do Grupo, dando a eles visibilidade e acesso a todos os Produtos ou Tipos de Produto.
* Definir Permissões de Configuração para um Grupo, permitindo que alterem funcionalidades específicas do DefectDojo.

Para mais informações sobre Papéis, consulte nosso artigo **Introdução aos Papéis**.

## A página Todos os Grupos

Na barra lateral, navegue até 👤**Usuários \> Grupos** para ver uma lista de todos os grupos de usuários ativos e inativos.

![image](images/Create_a_User_Group_for_shared_permissions.png)
A partir daqui, você pode criar, excluir ou visualizar suas páginas de Grupo individuais.

Para usuários do <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, a página Todos os Grupos da interface Pro tem algumas opções adicionais.
* Você pode filtrar essa tabela por Nome do Grupo, Descrição, Endereço de E-mail, Papel Global, além do número total de Usuários, Tipos de Produto e Produtos associados ao Grupo.
* Você também pode ajustar as Permissões de um Grupo ou outras configurações clicando no botão "⋮" ao lado do Grupo que deseja editar.

![image](images/all_groups_pro.png)

## Visualizando um Grupo

Visualizar um grupo exibe todas as informações do Grupo, como ID, nome, descrição, papel global etc. Os Membros do Grupo, Tipos de Produto e Produtos associados ao grupo também são exibidos. Além disso, as permissões de configuração vinculadas a um Grupo podem ser atualizadas diretamente na página "View Group".

Para usuários do <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, a Visualização de Grupo da interface Pro permite atribuir ajustes de Permissão de Configuração de uma forma um pouco diferente.

![image](images/group_view_pro_ui.png)

* Todas as permissões de configuração são exibidas em um menu suspenso agrupado em subcategorias. Se a seleção de permissões de configuração for diferente do valor atual, um botão "Update Configuration Permissions" é exibido.

![image](images/groups_pro_configuration_permissions.png)

* Depois que algumas permissões adicionais forem selecionadas, o usuário será solicitado a confirmar que deseja atualizar as permissões do grupo selecionado antes que a atualização seja feita.

## Criar / Editar um Grupo de Usuários

1. Navegue até a página 👤**Usuários \> Grupos** na barra lateral. Você verá uma lista de todos os Grupos de Usuários existentes, incluindo Nome, Descrição, Número de Usuários, Papel Global (se aplicável) e E-mail.
​
![image](images/Create_a_User_Group_for_shared_permissions_2.png)

2. Clique no **botão 🛠️** ao lado do título Todos os Grupos, e selecione **\+ Novo Grupo.**
​
![image](images/Create_a_User_Group_for_shared_permissions_3.png)


3. Isso o levará a uma página onde você pode criar um novo Grupo. Defina o Nome deste Grupo, e adicione uma Descrição, se desejar.

Você também pode selecionar um Papel Global que deseja aplicar a este Grupo, se desejar. Adicionar um Papel Global ao Grupo dará a todos os Membros do Grupo acesso a todos os dados do DefectDojo, junto com um nível limitado de acesso de edição, dependendo do Papel Global escolhido. Consulte nosso artigo **Introdução aos Papéis** para mais informações.

A conta que cria um Grupo inicialmente terá o Papel de Owner do Grupo por padrão.

### Definir um endereço de e-mail para receber relatórios

O Resumo Semanal (Weekly Digest) é um relatório sobre todos os Produtos / Tipos de Produto atribuídos ao Grupo. Para que um Resumo Semanal seja enviado, insira o endereço de e-mail de destino que deseja usar no formulário Criar / Editar Grupo.  Os membros do Grupo continuarão recebendo notificações normalmente.

### Visualizando uma página de Grupo

Depois de criar um Grupo, você pode acessá-lo selecionando-o no menu listado em **Usuários \> Grupos.**

A página do Grupo pode ser personalizada com uma **Descrição**.Ela apresenta uma lista de todos os **Membros do Grupo,** bem como os **Produtos, Tipos de Produto**, atribuídos, e o **Papel** associado a cada um deles**.**

Você também pode ver as **Permissões de Configuração** do Grupo listadas aqui.

## Gerenciar os Usuários de um Grupo

A Associação ao Grupo é gerenciada a partir da página individual do Grupo, que você pode selecionar na lista da página **Usuários \> Grupos**. Clique no Nome do Grupo destacado para acessar a página do Grupo que deseja editar.

Para visualizar ou editar a Associação de um Grupo, um Usuário deve ter as permissões de Configuração apropriadas habilitadas, além de ser Membro do Grupo (ou ter status de Superusuário).

### **Adicionar um Usuário a um Grupo**

Os Grupos de Usuários podem ter quantos Usuários você desejar. Todos os Usuários em um Grupo receberão o Papel associado em cada Produto ou Tipo de Produto listado, mas os Usuários também podem ter Papéis Individuais que substituem o papel do Grupo.

1. Na página do Grupo, selecione **\+ Add Users** no botão **☰** na borda do título **Members**.
​
![image](images/Create_a_User_Group_for_shared_permissions_4.png)

2. Isso o levará à tela **Add Some Group Members**. Abra o menu suspenso de Usuários e marque cada usuário que deseja adicionar ao Grupo.
​
![image](images/Create_a_User_Group_for_shared_permissions_5.png)

3. Selecione o Papel de Grupo que deseja atribuir a esses Usuários. Isso determina a capacidade deles de configurar o Grupo.

Observe que adicionar um membro a um Grupo não dará a ele, por padrão, acesso à sua própria página de Grupo. Essa é uma Permissão de Configuração separada que deve ser habilitada primeiro.

### **Editar ou Excluir um Membro de um Grupo de Usuários**

1. Na página do Grupo, selecione o ⋮ ao lado do Nome do Usuário que deseja Editar ou Excluir do Grupo.

**📝 Edit** o levará à tela de Edição de Membro, onde você pode alterar o Papel desse usuário (de Reader, Maintainer ou Owner para outra opção).

**🗑️ Delete** remove completamente a Associação de um Usuário. Isso não removerá nenhuma contribuição ou alteração que o Usuário tenha feito no Produto ou Tipo de Produto.

![image](images/Create_a_User_Group_for_shared_permissions_6.png)

## Gerenciar as Permissões de um Grupo

As Permissões de Grupo são gerenciadas a partir da página individual do Grupo, que você pode selecionar na lista da página **Usuários \> Grupos**. Clique no Nome do Grupo destacado para acessar a página do Grupo que deseja editar.

Observe que somente Superusuários podem editar as permissões de um Grupo (Produto / Tipo de Produto, ou Configuração).
​
### **Adicionar Papéis de Produto ou Papéis de Tipo de Produto para um Grupo**

Você pode registrar quantos Papéis de Produto ou Papéis de Tipo de Produto desejar em cada Grupo.

1. Na página do Grupo, selecione **\+ Add Product Types**, ou \+ **Add Product** no título correspondente (Grupos de Tipo de Produto ou Grupos de Produto).
​
![image](images/Create_a_User_Group_for_shared_permissions_7.png)

2. Isso o levará a uma página **Register New Products / Product Types**, onde você pode selecionar um Produto ou Tipo de Produto para adicionar no menu suspenso.

![image](images/Create_a_User_Group_for_shared_permissions_8.png)

3. Selecione o Papel que deseja que todos os membros do Grupo tenham em relação a esse Produto ou Tipo de Produto específico.

Os Grupos não podem ser atribuídos a Produtos ou Tipos de Produto sem um Papel. Se você não tiver certeza de qual Papel deseja que um Grupo tenha, Reader é uma boa opção 'padrão'. Isso manterá o estado do seu Produto seguro até que você tome sua decisão final sobre o Papel do Grupo.

### **Atribuir Permissões de Configuração a um Grupo**

Se você quiser que os Membros do seu Grupo acessem funções de Configuração e controlem certos aspectos do DefectDojo, você pode atribuir essas responsabilidades a partir da página do Grupo.

Atribua os papéis de Visualizar, Adicionar, Editar ou Excluir no menu no canto inferior direito. Marcar uma Permissão de Configuração dará imediatamente ao Grupo acesso a essa função específica.

![image](images/Create_a_User_Group_for_shared_permissions_9.png)
