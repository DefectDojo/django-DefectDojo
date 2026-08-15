---
title: 個人通知を設定する
description: 個人アカウントの通知を設定する
aliases:
- /ja/en/customize_dojo/notifications/configure_personal_notifs
---

## 個人通知を設定する

個人通知はシステム全体通知に加えて送信され、アクセス権を持つすべての製品、製品タイプ、その他のデータタイプに適用されます。個人通知の設定は単一のユーザーにのみ適用され、設定を行っているアカウント自身でのみ設定できます。

![image](images/Configure_System_&_Personal_Notifications.png)

システム通知はDefectDojoのスーパーユーザーによって設定され、個々のユーザーがオプトアウトすることはできません。

1. Notifications ページから開始します(サイドバーの ⚙️**Configuration \> Notifications**)。
2. **Scope** ドロップダウンメニューから、編集したい通知のセットを選択できます。
3. Personal Notifications を選択します。
4. 各種類の通知に使用したい通知方法にチェックを入れます。複数選択できます。

個人通知はMicrosoft Teams経由では送信できません。Teamsは単一チャンネルへのグローバル通知の投稿のみを許可しているためです。

### 特定の製品について個人通知を受け取る

標準の個人通知に加えて、DefectDojoのユーザーは特定の製品でのアクティビティについても通知を受け取ることができます。これは、ユーザーがより注意深く監視する必要がある特定の製品がある場合に役立ちます。

![image](images/Configure_System_&_Personal_Notifications_3.png)

この設定は、**Product** ページ内の **Notifications** セクションから変更できます。例: `your-instance.defectdojo.com/product/{id}`。

ここから、この特定の製品で行われたアクションについて **🔔 Alert**、**Mail**、または **Slack** の通知を受け取るかどうかを設定できます。これらの通知は、すでに受信しているシステム全体通知に加えて適用されます。

Microsoft Teamsはいかなる種類の個人通知も送信できないため、このメニューからTeams通知を選択することはできません。

個人メール通知は、常にDefectDojoログインに関連付けられたメールアドレスに送信されます。通知を受け取るための個人Slackアカウントの設定方法については、[ガイド](../email_slack_teams/#send-personal-notifications-to-slack) を参照してください。
