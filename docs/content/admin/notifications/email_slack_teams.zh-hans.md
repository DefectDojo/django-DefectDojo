---
title: 设置电子邮件、Slack 或 Teams 通知
description: 设置 Microsoft Teams 以接收通知
aliases:
- /zh-hans/en/customize_dojo/notifications/email_slack_teams
---

**您需要拥有超级用户权限才能访问系统设置页面,完成此过程需要该权限。**

当 DefectDojo 中触发某些事件时,通知可以推送到 Slack 或 Teams。

## Slack 通知设置

DefectDojo 可以通过两种不同的方式发布 Slack 通知:

* 系统级通知,将发送到单个 Slack 频道
* 个人通知,仅发送给特定用户。

以下是从 DefectDojo 发送的 Slack 通知示例:
​
![image](images/Configure_a_Slack_Integration.png)

DefectDojo 没有专用的 Slack 应用程序,但您可以按照本指南轻松为您的工作区创建一个。无论是系统通知还是个人通知,都需要一个 Slack 应用程序才能正确发送。

### 创建 Slack 应用程序

要设置 DefectDojo 与 Slack 的连接,您需要创建一个自定义 Slack 应用程序。

1. 从 Slack 应用程序页面开始此过程: <https://api.slack.com/apps>。
2. 点击“**Create New App**”。
3. 选择“**From App Manifest**”。
4. 从菜单中选择您的 Slack 工作区。
5. 输入您的 App Manifest——您可以复制并粘贴此 JSON 文件,其中包含允许 Slack 集成运行所需的所有权限设置。
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

查看 App Summary,完成后点击 Create App。点击 **Install To Workplace** 按钮完成安装。

### 在 DefectDojo 中配置您的 Slack 集成

现在,您需要在 DefectDojo 上配置 Slack 集成以完成整合。

**您需要拥有超级用户权限才能访问 DefectDojo 的系统设置页面。**

1. 从 <https://api.slack.com/apps> 导航到您的 Slack 应用程序的 App Information 页面。这是您在第一部分“**创建 Slack 应用程序**”中创建的应用程序。
​
2. 找到您的 OAuth Access Token。可以在 Slack 侧边栏的 **Features / OAuth & Permissions** 中找到。复制 **Bot User OAuth Token。
​**

![image](images/Configure_a_Slack_Integration_2.png)

3. 在新标签页中打开 DefectDojo,并从侧边栏导航到 **Configuration > System Settings**。(在 Pro UI 中,此表单位于 **Enterprise Settings > System Settings** 下。)
4. 勾选 **Enable Slack notifications** 复选框。
5. 将步骤 1 中的 **Bot User OAuth Token** 粘贴到 **Slack token** 字段中。
6. **Slack Channel** 字段应对应您希望 DefectDojo 机器人在您的工作区中发布通知的频道。
7. 如果您想更改 DefectDojo 机器人的名称,可以在此处输入自定义名称。如果不更改,将使用 Slack App Manifest 中确定的 **DefectDojo Notifications**。

完成此过程后,DefectDojo 便可以向该频道发送系统级通知。请从 [System Notifications page]() 中选择您想要发送的通知。

![image](images/Configure_a_Slack_Integration_3.png)

#### 关于 Slack 系统级通知的说明:

Slack 无法对您创建的 Slack 频道应用任何 RBAC 规则,因此该频道将共享整个 DefectDojo 系统的通知。DefectDojo 没有提供按产品类型、产品或测试活动筛选系统级 Slack 通知的方法。

如果您想对 Slack 消息应用基于 RBAC 的筛选,启用 Slack 个人通知是更好的选择。

### 向 Slack 发送个人通知

如果您的团队已启用 Slack 集成(通过上述过程),各个用户还可以配置通知,使其直接发送到您的个人 Slackbot 频道。

1. 首先导航到您在 DefectDojo 上的个人 Profile 页面。点击右上角的 👤 **图标** 即可找到该页面。从列表中选择您的 DefectDojo 用户名。(在我们的示例中为 👤 **paul**)
​
![image](images/Configure_a_Slack_Integration_4.png)

2. 在菜单中设置您的 **Slack Email Address**。此字段嵌套在 DefectDojo 的 **Additional Contact Information** 下。

现在您可以[设置特定通知](../about_notifications/)发送到您的个人 Slackbot 频道。您 Slack 频道中的其他用户不会收到这些消息。

## Microsoft Teams 通知设置

Microsoft Teams 可以在特定频道中接收通知。为此,您需要在希望接收消息的频道上**设置传入 Webhook**。

请注意,旧版 [Office Connector webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet) 即将被 Microsoft 淘汰,请按照下文说明使用基于 Power Automate Workflow 的新版 Webhook。

1. 按照 **[Microsoft Teams Documentation](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)** 中列出的流程创建一个新的 Incoming Webhook。请妥善保管您独有的 logic.azure.com 链接,后续步骤中会用到。您可以为某个频道或特定聊天创建 Webhook。
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. 在 DefectDojo 中,从侧边栏导航到 **Configuration > System Settings**。(在 Pro UI 中,此表单位于 **Enterprise Settings > System Settings** 下。)
3. 勾选 **Enable Microsoft Teams notifications** 复选框。这将展开表单中一个隐藏的部分,标记为“**Msteams url**”。
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. 将(在步骤 1 中创建的)logic.azure.com URL 粘贴到 **Msteams url** 框中。您的 Teams 应用程序现在将侦听来自 DefectDojo 的传入通知,并将其发布到您选择的频道。

### 关于 Teams 集成的说明

* Slack 无法对您创建的 Teams 频道应用任何 RBAC 规则,因此该频道将共享整个 DefectDojo 系统的通知。DefectDojo 没有提供按产品类型、产品或测试活动筛选系统级 Teams 通知的方法。
* DefectDojo 无法向 Microsoft Teams 上的用户发送个人通知。

## 系统级电子邮件通知设置

DefectDojo 的通知也可以发送到特定的电子邮件地址。

1. 从系统设置页面(在 Classic UI 中为 **Configuration > System Settings**,在 Pro UI 中为 **Enterprise Settings > System Settings**)导航到 Enable Mail (email) Notifications。

2. 勾选 **Enable mail notifications** 复选框,然后输入您希望接收这些通知的电子邮件地址(mail notifications to)。

![image](images/notifs_email.png)

请注意,DefectDojo 无法对这些电子邮件应用 RBAC 筛选——它们将针对 DefectDojo 中的所有活动发送。如果您希望发送更加定制化的电子邮件通知,最好使用与相应地址关联的用户或服务账户设置[个人通知](../configure_personal_notifs)。
