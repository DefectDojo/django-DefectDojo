---
title: Google Auth
description: DefectDojo ProでGoogle OAuthを設定する
weight: 11
audience: pro
---

DefectDojo ProはGoogleアカウントによるログインをサポートしています。新規ユーザーは、初回ログイン時にまだ存在しない場合は自動的に作成されます。既存のDefectDojoユーザーは、Googleメールアドレスの`@`より前の部分(ユーザー名)によってGoogleアカウントと照合されます。オープンソース版のDefectDojoにはSSOは含まれていません。オープンソース版のアクセス制御については[Authorized Users](/admin/user_management/os__authorized_users/)を参照してください。

## Prerequisites

DefectDojoを設定する前に、Google Cloud Consoleで以下の手順を完了してください。

1. [Google Developers Console](https://console.developers.google.com)にサインインします。

2. **Credentials > Create Credentials > OAuth Client ID**に移動します。

   ![image](images/google_1.png)

3. **Web Application**を選択し、分かりやすい名前(例: `DefectDojo`)を付けます。

4. **Authorized Redirect URIs**に以下を追加します。
   `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/`

5. **Client ID**と**Client Secret Key**を控えます。

## Configuration

DefectDojoで**Enterprise Settings > OAuth Settings**に移動し、**Google**を選択してフォームに入力します。

- **Google OAuth Key** — **Client ID**を入力します
- **Google OAuth Secret** — **Client Secret Key**を入力します
- **Whitelisted Domains** — 組織のドメイン(例: `yourcompany.com`)を入力すると、そのドメインを持つすべてのユーザーがログインできるようになります
- **Whitelisted E-mail Addresses** — あるいは、許可する特定のメールアドレス(例: `user1@yourcompany.com, user2@yourcompany.com`)を入力します

ホワイトリストのドメインまたはメールアドレスを少なくとも1つ設定する必要があります。設定しないと、Google経由でログインできるユーザーがいなくなります。

**Enable Google OAuth**をチェックしてフォームを送信します。ログインページに**Login With Google**ボタンが表示されます。
