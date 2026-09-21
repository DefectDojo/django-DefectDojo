---
title: "ServiceDesk Plus"
description: "DefectDojo で ServiceDesk Plus のダウンストリームコネクタをセットアップする方法"
weight: 119
audience: pro
---
ManageEngine ServiceDesk Plus 連携を使用すると、DefectDojo の検出事項および検出事項グループを ServiceDesk Plus のリクエストとしてプッシュし、任意の support Group に割り当てることができます。**クラウド版**(ServiceDesk Plus OnDemand)と **オンプレミス版** の両方が同じ連携でサポートされており、どちらのモードが使われるかは指定した認証情報によって決まります。

### インスタンスのセットアップ

- **Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceDesk Plus の URL を設定します。クラウド版の場合は `https://sdpondemand.manageengine.com`(またはお使いのリージョンに対応する URL)、オンプレミスインストールの場合はサーバーのアドレスを設定します。

続いて、以下の 2 種類の認証情報セットのうち **いずれか一方** を指定します。

#### オンプレミス: Technician Key

- **Technician Key** には、サーバーの **Admin > General Settings > API** で技術者(Technician)向けに生成した API キーを設定します。Zoho OAuth の各フィールドは空欄のままにしてください。

#### クラウド: Zoho OAuth

クラウド版は Zoho Accounts OAuth を通じて認証します。

1. [Zoho API Console](https://api-console.zoho.com/) を開き、**Self Client** を作成します。
2. **Client ID** と **Client Secret** を控えておきます。
3. Self Client の「Generate Code」タブで、スコープ `SDPOnDemand.requests.ALL` を入力し、有効期間を選択してコードを生成します。
4. コードをリフレッシュトークンと交換します。

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. インスタンスのフォームに **Client ID**、**Client Secret**、および取得した **Refresh Token** を入力します。アカウントが米国データセンター以外でホストされている場合は、**Token URL** をお使いのリージョンの Zoho Accounts エンドポイント(例: `https://accounts.zoho.eu/oauth/v2/token`)に設定してください。

### 課題管理マッピング

- **Group Name** には、リクエストの割り当て先となる ServiceDesk Plus の support group の名前を、**Admin > Users > Support Groups** に表示されるとおりに設定します。

### 深刻度マッピングの詳細

これは、アカウントの優先度名を使用して、ServiceDesk Plus のリクエストの **Priority** フィールドに名前でマッピングされます。

- **深刻度フィールド名**: `Priority`
- **情報マッピング**: `Low`
- **低マッピング**: `Normal`
- **中マッピング**: `Medium`
- **高マッピング**: `High`
- **重大マッピング**: `High`

### ステータスマッピングの詳細

これは、リクエストの **Status** フィールドに名前でマッピングされます。デフォルトでは組み込みのステータスを使用します。

- **ステータスフィールド名**: `Status`
- **アクティブマッピング**: `Open`
- **クローズマッピング**: `Closed`
- **誤検知マッピング**: `Closed`
- **リスク受容済みマッピング**: `On Hold`

ServiceDesk Plus 固有の動作として、いくつか注意すべき点があります。

- 更新はリクエストの内容全体を同期します。多くのトラッカーとは異なり、ServiceDesk Plus では作成後に件名と説明を編集できます。
- 検出事項が削除されると、リクエストは削除されるのではなくクローズされます。既に Closed または Resolved になっているリクエストはそのままにされます。
- アカウント側でクローズ時にフィールド(たとえば resolution)を必須にしている場合、DefectDojo からプッシュされたクローズがそのルールによって拒否されることがあり、その場合は Integration errors テーブルに表示されます。
