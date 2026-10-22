---
title: システム全体通知を設定する
description: 個人通知とシステム通知の設定方法
aliases:
- /ja/en/customize_dojo/notifications/configure_system_notifs
---

DefectDojoには2種類の通知があります: **Personal**(単一のアカウントに送信される)と **System**(すべてのユーザーに送信される)です。

アカウントの個人通知とグローバルなシステム通知の両方は、同じページ(サイドバーの **⚙️Configuration \> Notifications**)から設定できます。

![image](images/Configure_System_&_Personal_Notifications.png)

## システム通知を設定する(Classic UI)

**システム全体通知を変更するには、スーパーユーザーアクセスが必要です。**

1. Notifications ページから開始します(サイドバーの ⚙️ **Configuration \> Notifications**)。
2. Scope ドロップダウンメニューから、編集したい通知のセットを選択できます。
3. System Notifications を選択します。
4. 各種類の通知に使用したい通知の配信方法にチェックを入れます。複数選択できます。

![image](images/Configure_System_&_Personal_Notifications_2.png)

システム全体のメール通知(Email、Slack、MS Teams)の送信先を設定するには、[ガイド](../email_slack_teams) を参照してください。

## テンプレート通知

スーパーユーザーは「Template」フォームにもアクセスできます。このTemplateフォームでは、新規ユーザーに対してデフォルトで有効になる個人通知を設定できます。

## システム通知の送信先

システム通知は以下に送信されます:
- System Settings で指定された単一のメールアドレス(有効な場合)
- 適切なRBAC権限を持つアカウントを持つすべてのDefectDojoユーザー
- システム全体のSlackまたはTeamsアカウント。

DefectDojoの他の通知と同様に、システム通知は関連するデータへのアクセス権を持つユーザーにのみ送信されます。そのため、製品通知がシステム全体で設定されている場合でも、ユーザーは自分が閲覧権限を持つ製品についての通知のみを受け取ります。

この制限は、特定のメールアドレスやSlackチャンネルに送信されるシステム通知には適用されません。

RBACおよび権限設定の詳細については、[ロールベースアクセス制御](../../user_management/about_perms_and_roles/) のガイドを参照してください。

ただし、接続されているシステムのメール、Slack、Teamsのアカウントは特定のDefectDojoユーザーに関連付けられていないため、RBACを適用できません。**選択されたすべてのシステム全体通知はこれらの送信先に送信されるため、これらのチャンネルには組織内の特定の人物のみがアクセスできるようにしてください。**
