---
title: "ServiceNow"
description: "DefectDojo で ServiceNow のダウンストリームコネクタをセットアップする方法"
weight: 120
audience: pro
---
ServiceNow 連携を使用すると、DefectDojo の検出事項を ServiceNow のインシデントとしてプッシュできます。

### インスタンスのセットアップ

DefectDojo は OAuth 2.0 経由で ServiceNow に認証します。OAuth 認証情報の作成方法は ServiceNow のリリースによって異なります。新しいリリース(Zurich 以降)ではクライアントクレデンシャルグラントを使用し、それより前のリリースではリフレッシュトークンを使用します。

#### ServiceNow Zurich 以降(クライアントクレデンシャル)

最近の ServiceNow リリースでは、従来の「外部クライアント用の OAuth API エンドポイントの作成」オプションは非推奨となり、代わりに **新しいインバウンド統合エクスペリエンス(New Inbound Integration Experience)** が採用されています。これはサービスアカウントに紐づいた OAuth **クライアントクレデンシャル** グラントを発行します。

1. 左側のナビゲーションバーで「Application Registry」を検索して選択します。
2. **New** をクリックし、**New Inbound Integration Experience** を選択します。
3. **New Integration → OAuth - Client credentials grant** を選択します。
4. **OAuth Application User** に、インシデントを作成するサービスアカウントを設定します。このアカウントのロールによって、DefectDojo が書き込める内容が決まります。
5. 登録を保存します。ServiceNow が **Client ID** と **Client Secret** を自動生成します(登録作成時にはこれらのフィールドを空欄のままにしてください)。

その後、DefectDojo 側で以下を設定します。

- **Instance Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceNow サーバーの URL を設定します。例: `https://your-organization.service-now.com/`。
- **Client ID** には、OAuth 登録で取得した Client ID を設定します。
- **Client Secret** には、OAuth 登録で取得した Client Secret を設定します。

Refresh Token、Username、Password の各フィールドは空欄のままにしてください。DefectDojo は同期のたびに新しいクライアントクレデンシャルトークンをリクエストします。

#### それ以前の ServiceNow リリース(リフレッシュトークン)

従来の登録方式がまだ利用できるリリースでは、ServiceNow にインシデントをプッシュする User または Service アカウントに紐づいたリフレッシュトークンを取得します。

1. 左側のナビゲーションバーで「Application Registry」を検索して選択します。
2. 「New」をクリックします。
3. 「Create an OAuth API endpoint for external clients」を選択します。
4. 必須フィールドを入力します。
    * Name: アプリケーションの分かりやすい名前を入力します(例: Vulnerability Integration Client)。
    * (任意)トークンの有効期間を調整します。
    * Access Token Lifespan: デフォルトは 1800 秒(30 分)です。
    * Refresh Token Lifespan: デフォルトは 8640000 秒(約 100 日)です。
5. 「Submit」をクリックしてアプリケーションレコードを作成します。
6. 送信後、リストからアプリケーションを選択し、**Client ID と Client Secret** フィールドを控えておきます。

次に、この登録を使用してリフレッシュトークンを取得する必要がありますが、これは ServiceNow API 経由でのみ取得できます。ターミナルウィンドウを開き、以下を貼り付けてください(`{{}}` で囲まれた変数は実際のユーザー情報に置き換えます)。

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

ServiceNow の認証情報が正しく、ServiceNow への管理者レベルのアクセスが許可されている場合、RefreshToken を含むレスポンスが返されます。DefectDojo との連携を完了するには、そのトークンが必要です。

- **Instance Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceNow サーバーの URL を設定します。例: `https://your-organization.service-now.com/`。
- **Refresh Token** には、取得したリフレッシュトークンを入力します。
- **Client ID** には、OAuth App Registration で設定した Client ID を設定します。
- **Client Secret** には、OAuth App Registration で設定した Client Secret を設定します。

### 深刻度マッピングの詳細

これは ServiceNow の Impact フィールドにマッピングされます。
- **情報マッピング**: `1`
- **低マッピング**: `1`
- **中マッピング**: `2`
- **高マッピング**: `3`
- **重大マッピング**: `3`

### ステータスマッピングの詳細

- **ステータスフィールド名**: `State`
- **アクティブマッピング**: `New`
- **クローズマッピング**: `Closed`
- **誤検知マッピング**: `Resolved`
- **リスク受容済みマッピング**: `Resolved`

各マッピングには、標準のステートラベル(`New`、`In Progress`、`On Hold`、`Resolved`、`Closed`、`Cancelled`)または数値のステート値を指定できます。インシデントのステートがカスタマイズされているインスタンス、または `incident` 以外のテーブルを対象とする場合は、インスタンスの選択リストにある数値の **ステート値** を使用してください。標準セット外の数値は、設定したとおりにそのまま ServiceNow へ送信されます。組み込みの Resolution コードのデフォルトは、標準の resolved/closed ステートにのみ付随するため、カスタムのステート値を使用する場合は、下記のクローズおよび解決フィールドのマッピングと組み合わせてください。

### クローズおよび解決フィールド

一部の ServiceNow インスタンスでは、インシデントが resolved または closed ステートに移行する際に、**Resolution code**(`close_code`)などのフィールドを必須とする Data Policy が適用されています。これらのフィールドを指定せずに DefectDojo がインシデントをクローズしようとすると、ServiceNow は HTTP 403 の *「Data Policy Exception」* で書き込みを拒否し、その理由は連携のエラー表示に記録されます。

**Custom Field Mappings** を使用して、必須フィールドをステート変更に紐づけ、**Apply On** にそれらを適用すべき区分を設定します。

- **Transition to Closed** — 検出事項が緩和済み/クローズになったときに送信されます。
- **Transition to False Positive** — 検出事項が誤検知としてマークされたときに送信されます。
- **Transition to Risk Accepted** — 検出事項がリスク受容されたときに送信されます。

たとえば、必須の Resolution code を満たすには次のようにします。

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

注記:

- Field Name は ServiceNow のカラム名です — `close_code`、`close_notes`、またはカスタムの `u_...` フィールドなど。
- Transition マッピングは、レコードのステートが実際に変化したときに発火します。たとえば、最初にプッシュされた時点で既にクローズしている検出事項、レコードをクローズまたは再オープンする更新、チケットリンクが削除されたときの強制クローズなどです。変化のないレコードの通常の更新では再送信されないため、`work_notes` などのジャーナルフィールドには遷移ごとに 1 件のエントリが記録されます。
- `assignment_group` や `assigned_to` などの参照フィールドには、表示名ではなく **sys_id** を指定する必要があります。
- JSON として解釈できる値は、型付きで送信されます: `true`、`42`、`[...]`、`{...}` — および、フィールドをクリアする `null`。このようなテキストをリテラルの文字列として送信するには、二重引用符で囲みます(例: `"null"`)。
- `short_description`、`description`、`state`、`impact`、`urgency`、`priority` は説明テンプレートおよび深刻度/ステータスのマッピングによって管理されるため、カスタムフィールドマッピングでは設定できません。
- `incident` 以外のテーブルでも、標準のインシデントセットに一致するステート値(`1`、`2`、`3`、`6`、`7`、`8`)は、`6`/`7`/`8` での自動 Resolution コードのデフォルトを含め、引き続きインシデントの意味で解釈されます。カスタムテーブルではその範囲外のステート値を使用するか、上記のようにクローズフィールドを明示的に指定することを推奨します。
