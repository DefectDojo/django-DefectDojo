---
title: KeyCloak
description: DefectDojo ProでKeyCloak SSOを設定する
weight: 13
audience: pro
---

DefectDojo ProはKeyCloakによるログインをサポートしています。オープンソース版のDefectDojoにはSSOは含まれていません。オープンソース版のアクセス制御については[Authorized Users](/admin/user_management/os__authorized_users/)を参照してください。

このガイドは、KeyCloak Realmがすでに設定済みであることを前提としています。未設定の場合は[KeyCloak documentation](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html)を参照してください。

## Prerequisites

DefectDojoを設定する前に、KeyCloak Realmで以下の手順を完了してください。

1. タイプ`openid-connect`で新しいクライアントを追加します。クライアントIDを控えます。

2. クライアント設定で以下を行います。
   - **Access Type**を`confidential`に設定します
   - **Valid Redirect URIs**にDefectDojoのURL(例: `https://yourorganization.cloud.defectdojo.com`または`https://your-dojo-host/*`)を追加します
   - **Web Origins**に同じURL(または`+`)を追加します
   - **Fine Grained OpenID Connect Configuration**で以下を設定します。
     - **User Info Signed Response Algorithm**を`RS256`に設定
     - **Request Object Signature Algorithm**を`RS256`に設定
   - 設定を保存します。

3. **Scope**で**Full Scope Allowed**を`off`に設定します。

4. **Mappers**でカスタムマッパーを追加します。
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** クライアントIDを選択
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. **Credentials**で**Secret**をコピーします。

6. **Realm Settings > Keys**で**Public Key**(署名鍵)をコピーします。

7. **Realm Settings > General > Endpoints**でOpenIDエンドポイント設定を開き、**Authorization**エンドポイントと**Token**エンドポイントのURLをコピーします。

## Configuration

DefectDojoで**Enterprise Settings > OAuth Settings**に移動し、**KeyCloak**を選択してフォームに入力します。

- **KeyCloak OAuth Key** — クライアント名(手順1)を入力します
- **KeyCloak OAuth Secret** — クライアントクレデンシャルのシークレット(手順5)を入力します
- **KeyCloak Public Key** — Realm設定のPublic Key(手順6)を入力します
- **KeyCloak Resource** — Authorization EndpointのURL(手順7)を入力します
- **KeyCloak Group Limiter** — Token EndpointのURL(手順7)を入力します
- **KeyCloak OAuth Login Button Text** — DefectDojoのログインボタンに表示するテキストを選びます

**Enable KeyCloak OAuth**をチェックしてフォームを送信します。ログインページに、設定したテキストのログインボタンが表示されます。
