---
title: Definir Permissões no Pro
description: Reformulação, recurso do Pro
weight: 3
audience: pro
aliases:
- /pt-br/en/customize_dojo/user_management/pro_permissions_overhaul
---

## Introdução aos Tipos de Permissão

Usuários individuais têm quatro tipos diferentes de permissão que podem ser atribuídos a eles:

* Os usuários podem ser designados como **Membros de Produtos ou Tipos de Produto**. Isso permite que eles visualizem e interajam com Tipos de Dados (Tipos de Produto, Produtos, Engajamentos, Testes e Achados) no DefectDojo, dependendo do papel atribuído a eles no Produto específico. Os usuários podem ter múltiplas associações a Produtos ou Tipos de Produto, com diferentes níveis de acesso.
​
* Os usuários também podem ter **Permissões de Configuração** atribuídas, que permitem acessar páginas de configuração no DefectDojo. As Permissões de Configuração não estão relacionadas a Produtos ou Tipos de Produto.
​
* Os usuários podem receber **Papéis Globais**, que dão a eles um nível padronizado de acesso a todos os Produtos e Tipos de Produto.
​
* Os usuários podem ser configurados como **Superusuários**: papéis de nível administrativo que dão a eles controle e acesso a todos os dados e configurações do DefectDojo.

Você também pode criar Grupos se quiser atribuir Associação a Produto, Permissões de Configuração ou Papéis Globais a um grupo de usuários ao mesmo tempo. Se você tiver um grande número de usuários no DefectDojo, como uma equipe de testes dedicada a um Produto específico, os Grupos podem ser um recurso mais útil.

## Superusuários e Papéis Globais

Parte da sua configuração de Controle de Acesso Baseado em Papéis (RBAC) pode exigir a criação de Superusuários adicionais, ou de usuários com Papéis Globais.

* Os Superusuários (Admins) não têm limitações no sistema. Eles podem alterar todas as configurações, gerenciar usuários e têm acesso de leitura/gravação a todos os dados. Eles também podem alterar as regras de acesso para todos os usuários do DefectDojo. Os Superusuários também recebem notificações de todos os problemas e alertas do sistema.
* Usuários com Papéis Globais podem visualizar e interagir com qualquer Tipo de Dados (Tipos de Produto, Produtos, Engajamentos, Testes e Achados) no DefectDojo, dependendo do Papel atribuído a eles. Para mais informações sobre cada Papel e os privilégios associados, consulte nosso artigo Introdução aos Papéis.
* Os usuários também podem ter Permissões de Configuração específicas atribuídas, permitindo que acessem determinadas páginas de configuração do DefectDojo. Por padrão, os usuários não têm nenhuma Permissão de Configuração.

Por padrão, a primeira conta criada em uma nova instância do DefectDojo terá permissões de Superusuário. Esse usuário poderá editar as permissões de todos os usuários do DefectDojo criados posteriormente. Somente um Superusuário existente pode adicionar outro superusuário, ou adicionar um Papel Global a um usuário.

As permissões no <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> foram simplificadas, para facilitar a atribuição de acesso a objetos.  Esse recurso pode ser acessado através da [interface Pro](/get_started/about/ui_pro_vs_os/).

### Abrindo a janela de Permissões

![image](images/pro_permissions.png)

Ao visualizar um Tipo de Produto ou Produto, você pode abrir a janela de Permissões para definir permissões rapidamente.  Esse menu pode ser encontrado em uma Tabela clicando nos pontos horizontais **"⋮"**.  Se estiver em uma página individual de **Produto** ou **Tipo de Produto**, esse menu pode ser encontrado sob a engrenagem azul '⚙️'.

## Definindo Permissões através da janela de permissões

![image](images/pro_permissions_2.png)

1. Na parte superior dessa janela, você pode optar por gerenciar permissões para um usuário individual ou para um [grupo de usuários](../create_user_group).
2. Aqui, você pode selecionar um usuário ou grupo para adicionar ao Produto, e selecionar o [Papel](../about_perms_and_roles) que deseja que esse usuário tenha.
3. Na tabela inferior, você pode ver uma lista de todos os usuários ou grupos que têm acesso a esse objeto.  Você também pode atribuir rapidamente um novo papel a um desses usuários ou grupos a partir do menu suspenso.

## Definindo Permissões de Configuração através da visualização do Usuário

As permissões de configuração de um usuário agora podem ser definidas de uma forma mais amigável. Na Visualização de Usuários, todas as permissões de configuração são exibidas em um menu suspenso, agrupadas por tipo de permissão. Se a seleção de permissões de configuração for diferente do valor atual, um botão "Update Configuration Permissions" é exibido. Ao clicar nele, o usuário será solicitado a confirmar que deseja atualizar as permissões do grupo selecionado antes que a atualização seja feita.

![image](images/pro_user_view.png)
