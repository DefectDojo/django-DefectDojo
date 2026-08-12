---
title: メール、Slack、Teams通知の設定
description: Microsoft Teamsで通知を受信するための設定
aliases:
- /ja/en/customize_dojo/notifications/email_slack_teams
---

**このプロセスを完了するには、システム設定ページを使用するためのスーパーユーザー権限が必要です。**

DefectDojoで特定のイベントがトリガーされると、SlackまたはTeamsに通知をプッシュできます。

## Slack通知の設定

DefectDojoは、2つの異なる方法でSlack通知を投稿できます。

* システム全体の通知：単一のSlackチャンネルに送信されます
* 個人通知：特定のユーザーにのみ送信されます

DefectDojoから送信されたSlack通知の例を以下に示します。
​
![image](images/Configure_a_Slack_Integration.png)

DefectDojoには専用のSlackアプリはありませんが、このガイドに従うことでワークスペース用に簡単に作成できます。システム通知と個人通知の両方を正しく送信するには、Slackアプリが必要です。

### Slackアプリケーションを作成する

DefectDojoとのSlack連携を設定するには、カスタムSlackアプリを作成する必要があります。

1. Slack Appsページからこのプロセスを開始します: <https://api.slack.com/apps>。
2. 「**Create New App**」をクリックします。
3. 「**From App Manifest**」を選択します。
4. メニューからSlackワークスペースを選択します。
5. App Manifestを入力します。Slack連携の実行に必要なすべての権限設定を含む、このJSONファイルをコピー&ペーストできます。
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

App Summaryを確認し、完了したらCreate Appをクリックします。**Install To Workplace**ボタンをクリックしてインストールを完了します。

### DefectDojoでSlack連携を設定する

連携を完了するには、DefectDojo側でSlack連携を設定する必要があります。

**DefectDojoのシステム設定ページにアクセスするには、スーパーユーザー権限が必要です。**

1. <https://api.slack.com/apps> から、SlackアプリのApp Informationページに移動します。これは最初のセクション「**Slackアプリケーションを作成する**」で作成したアプリです。
​
2. OAuthアクセストークンを見つけます。これはSlackのサイドバーの「**Features / OAuth & Permissions**」にあります。**Bot User OAuth Token**をコピーします。
​

![image](images/Configure_a_Slack_Integration_2.png)

3. 新しいタブでDefectDojoを開き、サイドバーから**Configuration > System Settings**に移動します。（Pro UIでは、このフォームは**Enterprise Settings > System Settings**にあります。）
4. **Enable Slack notifications**チェックボックスをオンにします。
5. 手順1の**Bot User OAuth Token**を**Slack token**フィールドに貼り付けます。
6. **Slack Channel**フィールドには、DefectDojoボットに通知を投稿させたいワークスペース内のチャンネルを指定します。
7. DefectDojoボットの名前を変更したい場合は、ここにカスタム名を入力できます。指定しない場合は、Slack App Manifestで定義された**DefectDojo Notifications**が使用されます。

このプロセスが完了すると、DefectDojoはこのチャンネルにシステム全体の通知を送信できるようになります。送信したい通知は[System Notificationsページ]()から選択してください。

![image](images/Configure_a_Slack_Integration_3.png)

#### Slackにおけるシステム全体通知に関する注意事項:

Slackは、作成したSlackチャンネルにRBACルールを適用できないため、DefectDojoシステム全体の通知が共有されることになります。DefectDojoには、システム全体のSlack通知を製品タイプ、製品、またはエンゲージメントでフィルタリングする方法はありません。

SlackメッセージにRBACベースのフィルタリングを適用したい場合は、Slackの個人通知を有効にする方が適しています。

### Slackへの個人通知の送信

チームで（上記のプロセスにより）Slack連携が有効になっている場合、各ユーザーは自分専用のSlackbotチャンネルに直接通知を送るよう設定することもできます。

1. まず、DefectDojoの個人用Profileページに移動します。右上隅の👤**アイコン**をクリックして見つけます。リストからご自身のDefectDojoユーザー名を選択します。（この例では👤**paul**）
​
![image](images/Configure_a_Slack_Integration_4.png)

2. メニューで**Slack Email Address**を設定します。このフィールドは、DefectDojoの**Additional Contact Information**の下に配置されています。

これで、自分専用のSlackbotチャンネルに送信する[特定の通知を設定](../about_notifications/)できるようになります。同じSlackチャンネルの他のユーザーには、これらのメッセージは届きません。

## Microsoft Teams通知の設定

Microsoft Teamsは、特定のチャンネルで通知を受信できます。これを行うには、メッセージを受信したいチャンネルで**受信Webhookを設定**する必要があります。

旧来の[Office Connector webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet)はMicrosoftによって廃止される予定であるため、以下で説明する新しいPower Automate Workflowベースのwebhookを使用してください。

1. 新しいIncoming Webhookを作成するために、**[Microsoft Teams Documentation](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)**に記載されている手順を完了します。後の手順で必要になるため、固有のlogic.azure.comリンクを手元に控えておいてください。webhookはチャンネル単位でも特定のチャット単位でも作成できます。
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. DefectDojoで、サイドバーから**Configuration > System Settings**に移動します。（Pro UIでは、このフォームは**Enterprise Settings > System Settings**にあります。）
3. **Enable Microsoft Teams notifications**チェックボックスをオンにします。これにより、フォームの隠れたセクション「**Msteams url**」が表示されます。
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. 手順1で作成したlogic.azure.com URLを**Msteams url**ボックスに貼り付けます。これで、TeamsアプリはDefectDojoからの受信通知をリッスンし、選択したチャンネルに投稿するようになります。

### Teams連携に関する注意事項

* Slackは、作成したTeamsチャンネルにRBACルールを適用できないため、DefectDojoシステム全体の通知が共有されることになります。DefectDojoには、システム全体のTeams通知を製品タイプ、製品、またはエンゲージメントでフィルタリングする方法はありません。
* DefectDojoは、Microsoft Teams上のユーザーに個人通知を送信することはできません。

## システム全体のメール通知の設定

DefectDojoからの通知は、特定のメールアドレスに送信することもできます。

1. System Settingsページ（Classic UIでは**Configuration > System Settings**、Pro UIでは**Enterprise Settings > System Settings**）から、Enable Mail (email) Notificationsに移動します。

2. **Enable mail notifications**チェックボックスをオンにし、これらの通知を送信したいメールアドレス（mail notifications to）を入力します。

![image](images/notifs_email.png)

DefectDojoはこれらのメールにRBACフィルタリングを適用できない点に注意してください。DefectDojo内のすべてのアクティビティについて送信されます。よりカスタマイズされたメール通知のセットを送信したい場合は、適切なアドレスに紐づいたユーザーまたはサービスアカウントで[個人通知](../configure_personal_notifs)を設定する方が良いでしょう。
