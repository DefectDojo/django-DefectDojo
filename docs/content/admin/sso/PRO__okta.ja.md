---
title: Okta
description: DefectDojo Pro で Okta SSO を設定する
weight: 15
audience: pro
---

DefectDojo Pro は Okta 経由のログインをサポートしています。オープンソース版の DefectDojo には SSO は含まれていません。オープンソース版のアクセス制御については [Authorized Users](/admin/user_management/os__authorized_users/) を参照してください。

## Prerequisites

DefectDojo を設定する前に、Okta 側で以下の手順を完了してください。

1. [Okta](https://www.okta.com/developer/signup/) にサインインするか、アカウントを作成します。

2. **Applications** に移動し、**Add Application** をクリックします。

   ![image](images/okta_1.png)

3. **Web Applications** を選択します。

   ![image](images/okta_2.png)

4. **Login Redirect URLs** に DefectDojo のコールバック URL を追加します。また、**Implicit** のチェックボックスをオンにします。

   ![image](images/okta_3.png)

5. **Done** をクリックします。

6. **Dashboard** で **Org-URL** を確認します。

   ![image](images/okta_4.png)

7. 新しく作成されたアプリケーションを開き、**Client ID** と **Client Secret** を確認します。

   ![image](images/okta_5.png)

## Configuration

DefectDojo で **Enterprise Settings > OAuth Settings** に移動し、**Okta** を選択して、フォームに入力します。

- **Okta OAuth Key** — **Client ID** を入力します
- **Okta OAuth Secret** — **Client Secret** を入力します
- **Okta Tenant ID** — `https://your-org-url/oauth2` の形式で Org-URL を入力します

**Enable Okta OAuth** をチェックしてフォームを送信します。ログインページに **Login With Okta** ボタンが表示されます。
