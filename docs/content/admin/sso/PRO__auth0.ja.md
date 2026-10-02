---
title: Auth0
description: DefectDojo ProでAuth0 SSOを設定する
weight: 3
audience: pro
---

DefectDojo ProはAuth0によるログインをサポートしています。オープンソース版のDefectDojoにはSSOは含まれていません。オープンソース版のアクセス制御については[Authorized Users](/admin/user_management/os__authorized_users/)を参照してください。

## Prerequisites

DefectDojoを設定する前に、Auth0ダッシュボードで以下の手順を完了してください。

1. Create a new application: **Applications > Create Application > Single Page Web Application**.

2. Configure the application:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. 以下の値を控えておきます。DefectDojo側で必要になります。
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configuration

DefectDojoで**Enterprise Settings > OAuth Settings**に移動し、**Auth0**を選択してフォームに入力します。

- **Auth0 OAuth Key** — **Client ID**を入力します
- **Auth0 OAuth Secret** — **Client Secret**を入力します
- **Auth0 Domain** — **Domain**を入力します

**Enable Auth0 OAuth**をチェックすると、DefectDojoのログインページに**Login With Auth0**ボタンが追加されます。
