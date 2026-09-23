---
title: Definir as permissões de um Usuário
description: Como conceder Funções e Permissões a um usuário, além do status de superuser
weight: 2
audience: pro
aliases:
- /pt-br/en/customize_dojo/user_management/set_user_permissions
---

> **Recurso do DefectDojo Pro.** O sistema de RBAC de Membros / Grupos / Funções Globais descrito nesta página faz parte do DefectDojo Pro. O DefectDojo de código aberto usa o modelo [Usuários Autorizados](../os__authorized_users/) — consulte essa página para o controle de acesso no código aberto, e as [notas de atualização da versão 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) caso você esteja migrando entre edições.

## Introdução aos Tipos de Permissão

Usuários individuais podem receber quatro tipos diferentes de permissão:

* Os usuários podem ser atribuídos como **Membros de Produtos ou Tipos de Produto**. Isso permite que eles visualizem e interajam com Tipos de Dados (Tipos de Produto, Produtos, Engajamentos, Testes e Achados) no DefectDojo, de acordo com o papel atribuído a eles no Produto específico. Os usuários podem ter várias associações de Produto ou Tipo de Produto, com diferentes níveis de acesso.
​
* Os usuários também podem ter **Permissões de Configuração** atribuídas, que permitem acessar páginas de configuração no DefectDojo. As Permissões de Configuração não estão relacionadas a Produtos ou Tipos de Produto.
​
* Os usuários podem receber **Funções Globais**, que concedem um nível padronizado de acesso a todos os Produtos e Tipos de Produto.
​
* Os usuários podem ser configurados como **Superusers**: papéis em nível de administrador que concedem controle e acesso a todos os dados e configurações do DefectDojo.

Você também pode criar Grupos caso deseje atribuir Associação de Produto, Permissões de Configuração ou Funções Globais a um grupo de usuários ao mesmo tempo. Se você tiver um grande número de usuários no DefectDojo, como uma equipe de testes dedicada a um Produto específico, os Grupos podem ser um recurso mais útil.

## Superusers \& Funções Globais

Parte da configuração do seu Controle de Acesso Baseado em Função (RBAC) pode exigir que você crie Superusers adicionais, ou usuários com Funções Globais.

* Os Superusers (Admins) não têm limitações no sistema. Eles podem alterar todas as configurações, gerenciar usuários e têm acesso de leitura/gravação a todos os dados. Também podem alterar as regras de acesso de todos os usuários no DefectDojo. Os Superusers também recebem notificações de todos os problemas e alertas do sistema.
* Os usuários com Funções Globais podem visualizar e interagir com qualquer Tipo de Dado (Tipos de Produto, Produtos, Engajamentos, Testes e Achados) no DefectDojo, de acordo com a Função atribuída a eles. Para mais informações sobre cada Função e os privilégios associados, consulte nosso artigo Introdução às Funções.
* Os usuários também podem ter Permissões de Configuração específicas atribuídas, permitindo o acesso a determinadas páginas de configuração do DefectDojo. Por padrão, os usuários não têm nenhuma Permissão de Configuração.

Por padrão, a primeira conta criada em uma nova instância do DefectDojo terá permissões de Superuser. Esse usuário poderá editar as permissões de todos os usuários do DefectDojo criados posteriormente. Somente um Superuser existente pode adicionar outro superuser, ou atribuir uma Função Global a um usuário.

### Adicionar status de Superuser ou Função Global a um usuário existente

1. Navegue até a página 👤 Usuários \> Usuários na barra lateral. Você verá uma lista de todas as contas registradas no DefectDojo, junto com o status Ativo de cada conta, as Funções Globais e outros dados relevantes do Usuário.
​
![image](images/Set_a_User's_Permissions.png)
​
2. Clique no nome da conta à qual deseja conceder privilégios de Superuser. Isso o levará à Página do Usuário.
​
3. Na seção Informações Padrão da Página do Usuário, abra o menu ☰ e selecione Editar.
​
![image](images/Set_a_User's_Permissions_2.png)

4. Na página Editar Usuário:
​
Para o Status de Superuser, marque a caixa ☑️ Status de Superuser, localizada nas Informações Padrão do usuário.
​
Para atribuir uma Função Global, selecione uma no menu suspenso Função Global, na parte inferior da página.
​
![image](images/Set_a_User's_Permissions_3.png)
​
5. Clique em Enviar para aceitar essas alterações.

## Associação de Produto \& Tipo de Produto

Por padrão, qualquer nova conta criada no DefectDojo não terá permissão para visualizar nenhum dado em nível de Produto. Será necessário atribuir a ela associação a cada Produto que deve visualizar e com o qual deve interagir.

* A associação de Produto \& Tipo de Produto só pode ser configurada por **Superusers, Maintainers ou Owners**.
* **Maintainers \& Owners** só podem configurar associação em Produtos / Tipos de Produto aos quais já estão atribuídos.
* **Global Maintainers \& Owners** podem configurar associação em qualquer Produto ou Tipo de Produto, assim como os **Superusers**.

Os usuários podem ter dois tipos de associação simultaneamente no nível de **Produto**:

* A Função conferida pela sua associação subjacente de Tipo de Produto, se aplicável
* Sua Função específica de Produto, se existir.

Se um usuário já foi adicionado como membro de Tipo de Produto e não precisa de um nível adicional de permissões em um Produto específico, não há necessidade de adicioná-lo como Membro do Produto.

### Adicionando um novo Membro

1. Navegue até o Produto ou Tipo de Produto ao qual deseja atribuir um usuário. Você pode selecionar o Produto na lista em **Produtos \> Todos os Produtos**.

![image](images/Set_a_User's_Permissions_4.png)

2. Localize o cabeçalho **Membros**, clique no menu **☰** e selecione **\+ Adicionar Usuários**.
3. Isso o levará a uma página onde você pode **Registrar novos Membros**. Selecione um Usuário no menu suspenso Usuários.
4. Selecione a Função que deseja que esse Usuário tenha nesse Produto ou Tipo de Produto: **API Importer, Reader, Writer, Maintainer** ou **Owner.**
​
![image](images/Set_a_User's_Permissions_5.png)

Os usuários não podem ser atribuídos como Membros de um Produto ou Tipo de Produto sem também ter uma Função. Se você não tiver certeza de qual Função deseja atribuir a um novo usuário, **Reader** é uma boa opção "padrão". Isso manterá o estado do seu Produto seguro até que você tome sua decisão final sobre a Função dele.

### Editar ou Excluir um Membro

Os Membros podem ter sua Função alterada dentro de um Produto ou Tipo de Produto.

Na página do **Produto** ou **Tipo de Produto**, navegue até o cabeçalho **Membros** e clique no botão **⋮** ao lado do Usuário que deseja Editar ou Excluir.

![image](images/Set_a_User's_Permissions_6.png)

📝 **Editar** o levará à tela **Editar Membro**, onde você pode alterar a **Função** desse usuário (de **API Importer, Reader, Writer, Maintainer** ou **Owner** para uma opção diferente).

🗑️ **Excluir** remove completamente a Associação de um Usuário. Isso não removerá quaisquer contribuições ou alterações que o Usuário tenha feito no Produto ou Tipo de Produto.

* Se você não conseguir Editar ou Excluir a Associação de um usuário (o **⋮** não está visível), é porque essa Associação foi conferida em nível de **Tipo de Produto**.
* Um usuário pode ter dois níveis de associação dentro de um Produto \- um atribuído no nível de **Tipo de Produto** e outro no nível de **Produto**.

#### Adicionar uma Função de Produto adicional a um usuário com uma Função de Tipo de Produto relacionada

Se um Usuário tiver uma Função em nível de Tipo de Produto, ele também receberá Associação com essa Função em todos os Produtos subjacentes dentro da categoria. No entanto, se você quiser que esse Usuário tenha uma Função especial em um Produto específico dentro desse Tipo de Produto, você pode atribuir a ele uma Função adicional em nível de Produto.

1. Na página do Produto, navegue até o cabeçalho **Membros**, clique no menu **☰** e selecione **\+ Adicionar Usuários** (como se estivesse adicionando um novo Usuário ao Produto).
2. Selecione o nome do Usuário no menu suspenso e selecione a Função de Produto que deseja atribuir a esse Usuário.

Uma Função de Produto substitui a Função padrão de Tipo de Produto ou a Função Global de um usuário. Por exemplo, se um Usuário tiver uma Função de Tipo de Produto **Reader**, mas também estiver atribuído como **Owner** em um Produto vinculado a esse Tipo de Produto, ele terá permissões adicionais de **Owner** somente para esse Produto.

No entanto, isso não funciona ao contrário. Se um Usuário tiver uma Função de Tipo de Produto ou Função Global **Owner**, atribuir a ele uma função **Reader** em um Produto específico não removerá suas permissões de **Owner**. **As Funções não podem remover permissões concedidas a um Usuário por outras Funções, elas só podem adicionar permissões extras.**

## Permissões de Configuração

Muitas caixas de diálogo de configuração e endpoints de API podem ser habilitados para usuários ou grupos de usuários, independentemente do status de superuser deles. Essas Permissões de Configuração permitem que usuários comuns acessem e contribuam para partes do DefectDojo fora de sua atribuição padrão de Produto ou Função de Produto.

As Permissões de Configuração não estão relacionadas a um Produto ou Tipo de Produto específico \- os usuários podem ter Permissões de Configuração atribuídas sem a necessidade de outros status ou de Associação a Produto / Tipo de Produto.
​
### Lista de Permissões de Configuração

* **Gerenciador de Credenciais:** Acesso à página ⚙️Configuração \> Gerenciador de Credenciais
* **Ambientes de Desenvolvimento:** Gerenciar a lista Engajamentos \> Ambientes
* **Modelos de Achado:** Acesso à página Achados \> Modelos de Achado
* **Grupos**: Acessar a página 👤Usuários \> Grupos
* **Instâncias do Jira:** Acessar a página ⚙️Configuração \> JIRA
* **Tipos de Idioma**: Acessar o endpoint de API [Tipos de Idioma](/automation/api/languages/)
* **Banner de Login**: Editar a página ⚙️Configuração \> Banner de Login
* **Anúncios**: Acessar ⚙️Configuração \> Anúncios
* **Tipos de Nota:** Acesso à página ⚙️Configuração \> Tipos de Nota
* **Tipos de Produto:** n/a
* **Questionários**: Acesso à página Questionários \> Todos os Questionários
* **Perguntas**: Acesso à página Questionários \> Perguntas
* **Regulamentações**: Acesso à página ⚙️Configuração \> Regulamentações
* **Configuração de SLA:** Acesso à página ⚙️Configuração \> Configuração de SLA
* **Tipos de Teste:** Adicionar ou editar um Tipo de Teste (em Engajamentos \> Tipos de Teste)
* **Configuração de Ferramenta:** Acesso à página **⚙️Configuração \> Tipos de Ferramenta**
* **Tipos de Ferramenta:** Acesso à página ⚙️Configuração \> Tipos de Ferramenta
* **Usuários:** Acesso à página 👤Usuários \> Usuários

### Adicionar Permissões de Configuração a um Usuário

**Somente Superusers podem adicionar Permissões de Configuração a um Usuário**.

1. Navegue até a página 👤 Usuários \> Usuários na barra lateral. Você verá uma lista de todas as contas registradas no DefectDojo, junto com o status Ativo de cada conta, as Funções Globais e outros dados relevantes do Usuário.
​
![image](images/Set_a_User's_Permissions_7.png)

2. Clique no nome da conta que deseja editar.
​
3. Navegue até a Lista de Permissões de Configuração. Ela está localizada no lado direito da Página do Usuário.
​
4. Selecione as Permissões de Configuração de Usuário que deseja adicionar.
​
Para uma descrição detalhada das Permissões de Configuração de Usuário, consulte nosso [Quadro de Permissões](../user_permission_chart/).
