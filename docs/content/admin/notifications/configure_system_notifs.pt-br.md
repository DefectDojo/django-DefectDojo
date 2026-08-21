---
title: Definir Notificações do Sistema
description: Como configurar notificações Pessoais e do Sistema
aliases:
- /pt-br/en/customize_dojo/notifications/configure_system_notifs
---

O DefectDojo possui dois tipos diferentes de notificação: **Pessoal** (enviada a uma única conta) e **do Sistema** (enviada a todos os usuários).

Tanto as Notificações Pessoais de uma conta quanto as Notificações do Sistema globais podem ser configuradas na mesma página: **⚙️Configuração \> Notifications** na barra lateral.

![image](images/Configure_System_&_Personal_Notifications.png)

## Configurar notificações do Sistema (Interface Clássica)

**Você precisará de acesso de Superuser para alterar as notificações do Sistema.**

1. Comece pela página de Notificações (⚙️ **Configuração \> Notifications** na barra lateral).
2. No menu suspenso Escopo, você pode selecionar qual conjunto de notificações deseja editar.
3. Selecione Notificações do Sistema.
4. Marque o método de entrega de notificação que deseja usar para cada tipo de notificação. Você pode selecionar mais de um.

![image](images/Configure_System_&_Personal_Notifications_2.png)

Para definir os destinos das notificações de e-mail do sistema (Email, Slack ou MS Teams), consulte nosso [Guia](../email_slack_teams).

## Notificações de Modelo

Os Superusers também têm acesso a um formulário de "Modelo".  O Formulário de Modelo permite definir as Notificações Pessoais padrão que ficam ativadas para qualquer novo usuário.

## Para Onde as Notificações do Sistema São Enviadas

As notificações do sistema serão enviadas para:
- o único endereço de e-mail especificado em System Settings (se ativado)
- quaisquer usuários do DefectDojo com contas e permissões de RBAC apropriadas
- a conta do Slack ou Teams em nível de Sistema.

Assim como qualquer notificação no DefectDojo, as Notificações do Sistema só serão enviadas a usuários que tenham acesso aos dados relevantes.  Portanto, mesmo que as Notificações de Produto sejam configuradas em nível de Sistema, os usuários só receberão notificações dos Produtos aos quais têm acesso para visualizar.

Essa restrição não se aplica a Notificações do Sistema enviadas para um canal específico de E-mail ou Slack.

Consulte nosso guia sobre [Controle de Acesso Baseado em Função](../../user_management/about_perms_and_roles/) para mais informações sobre RBAC e a definição de permissões.

No entanto, as contas conectadas de E-mail, Slack e Teams do Sistema não podem aplicar RBAC, pois não estão associadas a um usuário específico do DefectDojo.  **Todas as notificações selecionadas em nível de sistema serão enviadas para esses destinos, portanto você deve garantir que esses canais só possam ser acessados por pessoas específicas da sua organização.**
