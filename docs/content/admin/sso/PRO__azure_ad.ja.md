---
title: Azure Active Directory
description: DefectDojo ProでAzure AD SSOとグループマッピングを設定する
weight: 5
audience: pro
---

DefectDojo ProはAzure Active Directory(Azure AD)によるログインをサポートしており、ユーザーグループの自動同期も含まれます。オープンソース版のDefectDojoにはSSOは含まれていません。オープンソース版のアクセス制御については[Authorized Users](/admin/user_management/os__authorized_users/)を参照してください。

## Prerequisites

DefectDojoを設定する前に、Azureポータルで以下の手順を完了してください。

1. Azure Active Directoryで[新しいアプリを登録](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)します。

2. 登録したアプリから以下の値を控えます。
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - **Certificates & Secrets**で新しい**Client Secret**を作成し、その値を控えます
   - **Application ID URI**

3. **Authentication > Redirect URIs**で、**Web**タイプのURIを追加します。
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Configuration

DefectDojoで**Enterprise Settings > OAuth Settings**に移動し、**Azure AD**を選択してフォームに入力します。

- **Azure AD OAuth Key** — **Application (client) ID**を入力します
- **Azure AD OAuth Secret** — **Client Secret**を入力します
- **Azure AD Resource** — デフォルトは`https://graph.microsoft.com/`です。これはDefectDojoが[Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri)から追加情報(グループ名など)を読み取るために使用するURIです。グループ名が別のAPIリソースに保存されている場合のみ変更してください。
- **Azure AD Tenant ID** — **Directory (tenant) ID**を入力します
- **Azure AD Groups Filter** — 必要に応じて正規表現を入力し、インポートするユーザーグループを制限します(下記の[Group Mapping](#group-mapping)を参照)

**Enable Azure AD OAuth**をチェックしてフォームを送信します。ログインページに**Login With Azure AD**ボタンが表示されます。

## Group Mapping

グループマッピングを使うと、DefectDojoはAzure ADから[User Group](../../user_management/create_user_group/)のメンバーシップをインポートできます。DefectDojoのユーザーグループは、[RBAC](../../user_management/set_user_permissions/)を通じて製品と製品タイプへのアクセスを管理します。

**Enable Azure AD OAuth Grouping**をチェックするとこの機能が有効になります。ログイン時、DefectDojoはユーザーのAzure ADグループを既存のDefectDojoグループと照合します。DefectDojoに見つからないグループは自動的に作成されます。

一部のグループのみをインポートするには、**Azure AD Groups Filter**フィールドに正規表現を入力します。例:
- `^team-.*` — `team-`で始まるすべてのグループに一致
- `teamA|teamB|groupC` — 特定の名前のグループに一致

### Configuring Azure AD to send groups

Azure ADトークンには、グループIDを含めるよう設定する必要があります。これがないと、トークンにグループ情報が含まれません。

設定手順:
1. Azure ADのトークン設定で[Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims)を追加します。どのグループタイプを選ぶべきか分からない場合は**All Groups**を選択してください。
2. **Emit groups as role claims**は有効に**しないで**ください。
3. アプリケーションのAPI権限に`GroupMember.Read.All`または`Group.Read.All`を追加します。付与される権限が少ない`GroupMember.Read.All`が推奨されます。

### Group Cleaning

**Enable Azure AD OAuth Group Cleaning**が有効な場合、Azure AD同期によって作成されたDefectDojoグループは、メンバーがいなくなると自動的に削除されます。Azure ADでユーザーがグループから削除されると、DefectDojo上の対応するグループからも削除されます。
