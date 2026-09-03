---
title: Configurar notificações por e-mail, Slack ou Teams
description: Configure o Microsoft Teams para receber notificações
aliases:
- /pt-br/en/customize_dojo/notifications/email_slack_teams
---

**Você precisará de acesso de Superusuário para usar a página de Configurações do Sistema, que é necessária para concluir este processo.**

As notificações podem ser enviadas para o Slack ou o Teams quando determinados eventos são disparados no DefectDojo.

## Configuração das notificações do Slack

O DefectDojo pode publicar notificações no Slack de duas formas diferentes:

* Notificações de todo o sistema, que serão enviadas para um único canal do Slack
* Notificações pessoais, que serão enviadas apenas para usuários específicos.

Veja um exemplo de uma notificação do Slack enviada pelo DefectDojo:
​
![image](images/Configure_a_Slack_Integration.png)

O DefectDojo não possui um aplicativo dedicado do Slack, mas é possível criar um facilmente para o seu workspace seguindo este guia. Um aplicativo do Slack é necessário para que tanto as notificações de sistema quanto as pessoais sejam enviadas corretamente.

### Criar um aplicativo do Slack

Para configurar uma conexão do Slack com o DefectDojo, você precisará criar um aplicativo Slack personalizado.

1. Comece esse processo pela página de Apps do Slack: <https://api.slack.com/apps>.
2. Clique em "**Create New App**".
3. Selecione "**From App Manifest**".
4. Selecione seu workspace do Slack no menu.
5. Insira seu App Manifest - você pode copiar e colar este arquivo JSON, que inclui todas as configurações de permissão necessárias para que a integração com o Slack funcione.
​
```
{  
   "_metadata": {  
     "major_version": 1,  
     "minor_version": 1  
   },  
   "display_information": {  
     "name": "DefectDojo",  
     "description": "Notifications from DefectDojo. See https://docs.defectdojo.com/en/notifications/configure-a-slack-integration/ for configuration steps.",  
     "background_color": "#0000AA"  
   },  
   "features": {  
       "bot_user": {  
           "display_name": "DefectDojo Notifications"  
       }  
   },  
   "oauth_config": {  
     "scopes": {  
       "bot": [  
         "chat:write",  
         "chat:write.customize",  
         "chat:write.public",  
         "incoming-webhook",  
         "users:read",  
         "users:read.email"  
       ]  
     },  
     "redirect_urls": [  
       "https://slack.com/oauth/v2/authorize"  
     ]  
   }  
 }
```

Revise o resumo do aplicativo (App Summary) e clique em Create App quando terminar. Conclua a instalação clicando no botão **Install To Workplace**.

### Configurar sua integração do Slack no DefectDojo

Agora você precisará configurar a integração do Slack no DefectDojo para concluir a integração.

**Você precisará de acesso de Superusuário para acessar a página de Configurações do Sistema do DefectDojo.**

1. Navegue até a página App Information do seu aplicativo Slack, em <https://api.slack.com/apps>. Este será o aplicativo criado na primeira seção - **Criar um aplicativo do Slack**.
​
2. Localize seu OAuth Access Token. Ele pode ser encontrado na barra lateral do Slack - **Features / OAuth & Permissions**. Copie o **Bot User OAuth Token.
​**

![image](images/Configure_a_Slack_Integration_2.png)

3. Abra o DefectDojo em uma nova aba e navegue até **Configuration > System Settings** na barra lateral. (Na interface Pro, este formulário está localizado em **Enterprise Settings > System Settings**.)
4. Marque a caixa **Enable Slack notifications**.
5. Cole o **Bot User OAuth Token** obtido no Passo 1 no campo **Slack token**.
6. O campo **Slack Channel** deve corresponder ao canal do seu workspace onde você deseja que as notificações sejam publicadas por um bot do DefectDojo.
7. Se quiser alterar o nome do bot do DefectDojo, você pode inserir um nome personalizado aqui. Caso contrário, será usado **DefectDojo Notifications**, conforme definido no App Manifest do Slack.

Ao concluir esse processo, o DefectDojo poderá enviar notificações de todo o sistema para esse canal. Selecione as notificações que deseja enviar na [página de Notificações do Sistema]().

![image](images/Configure_a_Slack_Integration_3.png)

#### Observações sobre notificações de todo o sistema no Slack:

O Slack não pode aplicar regras de RBAC ao canal do Slack que você está criando, portanto as notificações serão compartilhadas para todo o sistema DefectDojo. Não há como filtrar as notificações de todo o sistema no Slack por Tipo de Produto, Produto ou Engajamento.

Se você deseja aplicar filtragem baseada em RBAC às suas mensagens do Slack, habilitar notificações pessoais do Slack é uma opção melhor.

### Enviar notificações pessoais para o Slack

Se sua equipe tiver uma integração do Slack habilitada (pelo processo acima), usuários individuais também podem configurar notificações para serem enviadas diretamente ao seu canal pessoal do Slackbot.

1. Comece navegando até sua página de Perfil pessoal no DefectDojo. Encontre-a clicando no ícone 👤 no canto superior direito. Selecione seu nome de usuário do DefectDojo na lista. (👤 **paul** em nosso exemplo)
​
![image](images/Configure_a_Slack_Integration_4.png)

2. Defina seu **Slack Email Address** no menu. Esse campo está aninhado em **Additional Contact Information** no DefectDojo.

Agora você pode [definir notificações específicas](../about_notifications/) para serem enviadas ao seu canal pessoal do Slackbot. Outros usuários do seu canal do Slack não receberão essas mensagens.

## Configuração das notificações do Microsoft Teams

O Microsoft Teams pode receber notificações em um canal específico. Para isso, você precisará **configurar um webhook de entrada** no canal onde deseja receber as mensagens.

Observe que os antigos [webhooks do Office Connector](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet) serão descontinuados pela Microsoft; use um novo webhook baseado em Power Automate Workflow, conforme documentado abaixo.

1. Conclua o processo descrito na **[documentação do Microsoft Teams](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)** para criar um novo Incoming Webhook. Mantenha seu link exclusivo logic.azure.com à mão, pois você vai precisar dele nas próximas etapas. Você pode criar o webhook para um canal ou para um chat específico.
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. No DefectDojo, navegue até **Configuration > System Settings** na barra lateral. (Na interface Pro, este formulário está localizado em **Enterprise Settings > System Settings**.)
3. Marque a caixa **Enable Microsoft Teams notifications**. Isso abrirá uma seção oculta do formulário, chamada "**Msteams url**".
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. Cole a URL logic.azure.com (criada no Passo 1) na caixa **Msteams url**. Seu aplicativo do Teams passará a escutar as notificações recebidas do DefectDojo e a publicá-las no canal selecionado.

### Observações sobre a integração com o Teams

* O Slack não pode aplicar regras de RBAC ao canal do Teams que você está criando, portanto as notificações serão compartilhadas para todo o sistema DefectDojo. Não há como filtrar as notificações de todo o sistema no Teams por Tipo de Produto, Produto ou Engajamento.
* O DefectDojo não pode enviar notificações pessoais a usuários no Microsoft Teams.

## Configuração das notificações por e-mail de todo o sistema

As notificações do DefectDojo também podem ser enviadas para um endereço de e-mail específico.

1. Na página de Configurações do Sistema (**Configuration > System Settings** na interface Clássica, ou **Enterprise Settings > System Settings** na interface Pro), navegue até Enable Mail (email) Notifications.

2. Marque a caixa **Enable mail notifications** e, em seguida, insira o endereço de e-mail para o qual deseja que essas notificações sejam enviadas (mail notifications to).

![image](images/notifs_email.png)

Observe que o DefectDojo não pode aplicar filtragem de RBAC a esses e-mails - eles serão enviados para toda a atividade no DefectDojo.  Se preferir enviar um conjunto mais personalizado de notificações por e-mail, é melhor configurar [Notificações Pessoais](../configure_personal_notifs) com um usuário ou conta de serviço vinculada ao endereço apropriado.
