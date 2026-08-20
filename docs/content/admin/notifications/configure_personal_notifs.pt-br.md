---
title: Definir Notificações Pessoais
description: Configure notificações para uma conta pessoal
aliases:
- /pt-br/en/customize_dojo/notifications/configure_personal_notifs
---

## Configurar Notificações Pessoais

As Notificações Pessoais são enviadas além das Notificações do Sistema e se aplicam a qualquer Produto, Tipo de Produto ou outro tipo de dado ao qual você tenha acesso. As preferências de Notificação Pessoal se aplicam apenas a um único usuário e só podem ser definidas na conta que está configurando-as.

![image](images/Configure_System_&_Personal_Notifications.png)

As notificações do sistema são definidas por um Superuser do DefectDojo e não podem ser desativadas por um usuário individual.

1. Comece pela página de Notificações (⚙️**Configuração \> Notifications** na barra lateral).
2. No menu suspenso **Escopo**, você pode selecionar qual conjunto de notificações deseja editar.
3. Selecione Notificações Pessoais.
4. Marque o método de notificação que deseja usar para cada tipo de notificação. Você pode selecionar mais de um.

As Notificações Pessoais não podem ser enviadas pelo Microsoft Teams, já que o Teams só permite publicar notificações Globais em um único canal.

### Receber Notificações Pessoais para um Produto específico

Além das notificações pessoais padrão, os Usuários do DefectDojo também podem receber notificações sobre atividades em um Produto específico. Isso é útil quando há determinados Produtos que um usuário precisa monitorar mais de perto.

![image](images/Configure_System_&_Personal_Notifications_3.png)

Essa configuração pode ser alterada na seção **Notifications** da página do **Produto**: por exemplo, `your-instance.defectdojo.com/product/{id}`.

A partir daí, você pode definir se deseja receber notificações de **🔔 Alert**, **Mail** ou **Slack** para ações realizadas nesse Produto específico. Essas notificações se aplicam além de quaisquer notificações do sistema que você já esteja recebendo.

O Microsoft Teams não pode enviar notificações pessoais de nenhum tipo, portanto as notificações do Teams não podem ser escolhidas nesse menu.

As notificações pessoais por e-mail sempre serão enviadas ao e-mail associado ao seu login do DefectDojo. Para configurar uma conta pessoal do Slack e receber notificações, consulte nosso [Guia](../email_slack_teams/#send-personal-notifications-to-slack).
