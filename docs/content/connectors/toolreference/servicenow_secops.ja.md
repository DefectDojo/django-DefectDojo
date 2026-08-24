---
title: "ServiceNow SecOps"
description: "DefectDojo で ServiceNow SecOps のダウンストリームコネクタをセットアップする方法"
weight: 122
audience: pro
---
ServiceNow SecOps 連携(**ServiceNow SecOps / Vulnerability Response** とも呼ばれます)は、DefectDojo の検出事項および検出事項グループを ServiceNow のセキュリティテーブル — **Security Incident**(`sn_si_incident`)または **Vulnerable Item**(`sn_vul_vulnerable_item`)— にプッシュし、検出事項の変化(作成、更新、解決/クローズ)に応じて同期を維持します。これは上記の ServiceNow 課題管理連携に対応するセキュリティ運用版であり、Security Incident Response(SIR)または Vulnerability Response(VR)アプリケーションを利用している場合は ServiceNow SecOps を使用してください。

### インスタンスのセットアップ

- **Instance Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceNow サーバーの URL を設定します。例: `https://your-organization.service-now.com/`。

ServiceNow SecOps は 3 種類の認証方式をサポートしています。**いずれか 1 つ** を指定してください。

- **OAuth 2.0** — **Client ID**、**Client Secret**、**Refresh Token** を入力します。取得方法は上記の[ServiceNow](/connectors/toolreference/servicenow/)セクションで説明した手順とまったく同じです(Application Registry で OAuth API エンドポイントを作成し、`/oauth_token.do` で認証情報をリフレッシュトークンと交換します)。あるいは、リフレッシュトークンの代わりに OAuth のパスワードグラントを使用する場合は、**Client ID** と **Client Secret** に加えて **Username** と **Password** を指定します。
- **API Key** — **API Key** を入力します。これは `x-sn-apikey` ヘッダーとして送信されます。このキーは、インスタンス側で Inbound Authentication Profile と REST API Access Policy が紐づけられるまでは、何も認証しません。
- **HTTP Basic** — サービスアカウントの **Username** と **Password** を入力します。

サービスアカウント(または OAuth クライアント)には、対象テーブルへの書き込みアクセス権が必要です。

### 課題管理マッピング

- **Target Table** は、レコードの書き込み先となる ServiceNow テーブルを選択します: **Security Incident**(`sn_si_incident`、デフォルト)または **Vulnerable Item**(`sn_vul_vulnerable_item`)。

### 深刻度マッピングの詳細

Security Incident の場合、これは **Impact** フィールドにマッピングされます。ServiceNow はインシデントの Priority を Impact と Urgency から導出するため、自分で Urgency をマッピングしない限り、Urgency はマッピングされた Impact と同じ値になります。Vulnerable Item の場合は、インスタンスで使用しているリスクフィールドに深刻度をマッピングしてください。以下のデフォルト値は、標準の SIR Impact スケール(`1` 高、`2` 中、`3` 低)に対応しており、編集可能です。

- **深刻度フィールド名**: `impact`
- **情報マッピング**: `3`
- **低マッピング**: `3`
- **中マッピング**: `2`
- **高マッピング**: `1`
- **重大マッピング**: `1`

### ステータスマッピングの詳細

これはレコードの **State** フィールドにマッピングされます。ステート値は数値コードであり、Security Incident テーブルと Vulnerable Item テーブルで異なり、インスタンスごとにカスタマイズできるため、自分の設定と照らし合わせて確認してください。以下のデフォルト値は、標準の SIR ステートコード(`16` Analysis、`3` Closed)を使用しています。

- **ステータスフィールド名**: `state`
- **アクティブマッピング**: `16`
- **クローズマッピング**: `3`
- **誤検知マッピング**: `3`
- **リスク受容済みマッピング**: `3`

レコードがクローズされると、DefectDojo は ServiceNow の **Close Code** と **Close Notes** も設定します(クローズした検出事項には `Resolved`、対応するステートには `False positive` および `Risk accepted`)。

### ServiceNow SecOps 固有の動作

- **重複排除** — 各レコードには、検出事項または検出事項グループの DefectDojo 識別子が `correlation_id` にタグ付けされます。レコードを作成する前に、DefectDojo は `correlation_id` で既存のレコードを検索します。一致するものが見つかった場合は、重複作成せずにそれを採用して更新するため、再同期はべき等です。
- **更新内容** は、顧客に見える Comments ではなく、レコードの **Work notes** ジャーナル(内部用)に投稿されます。
- **削除時の解決(Resolve on delete)** — DefectDojo で検出事項を削除すると、ServiceNow のレコードは削除されるのではなく、解決/クローズされます(State + Close Code)。レコードが物理削除されることはありません。
- **参照フィールド** — 任意項目の `cmdb_ci`、`assignment_group`、`assigned_to` の値は表示名として指定できます。DefectDojo はそれぞれを `sys_id` に解決します。解決できない名前は、プッシュを失敗させることなく、警告とともに除外されます。
