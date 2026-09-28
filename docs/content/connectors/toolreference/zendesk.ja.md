---
title: "Zendesk"
description: "DefectDojo で Zendesk のダウンストリームコネクタをセットアップする方法"
weight: 144
audience: pro
---
Zendesk 連携を使用すると、DefectDojo の検出事項および検出事項グループを Zendesk のチケットとしてプッシュし、任意の Zendesk Group に割り当てることができます。

### インスタンスのセットアップ

- **Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、Zendesk アカウントの URL を設定します。例: `https://your-subdomain.zendesk.com`。
- **Email** には、API トークンの持ち主である Zendesk エージェントのメールアドレスを設定します。
- **API Token** には、Zendesk の API トークンを設定します。管理者は Zendesk Admin Center の **Apps and integrations > APIs > Zendesk API** でトークンを作成できます(トークンアクセスを有効化しておく必要があります)。

### 課題管理マッピング

- **Group ID** には、チケットの割り当て先となる Zendesk Group の数値 ID を設定します。Admin Center の **People > Team > Groups** で確認するか、グループを表示しているときの URL から確認できます。

### 深刻度マッピングの詳細

これは Zendesk チケットの **Priority** フィールドにマッピングされます。このフィールドには `low`、`normal`、`high`、`urgent` を指定できます。

- **深刻度フィールド名**: `Priority`
- **情報マッピング**: `low`
- **低マッピング**: `low`
- **中マッピング**: `normal`
- **高マッピング**: `high`
- **重大マッピング**: `urgent`

### ステータスマッピングの詳細

Zendesk チケットは、`new`、`open`、`pending`、`hold`、`solved`、`closed` のステータスをサポートしています。`hold` を使用するには、事前にアカウントで有効化しておく必要がある点に注意してください。

- **ステータスフィールド名**: `Status`
- **アクティブマッピング**: `new`
- **クローズマッピング**: `solved`
- **誤検知マッピング**: `solved`
- **リスク受容済みマッピング**: `pending`

Zendesk 固有の動作として、いくつか注意すべき点があります。

- Zendesk ではチケットの説明が最初のコメントとして扱われ、作成後は編集できません。そのため、更新された検出事項をプッシュすると、チケットの件名・優先度・ステータスは同期されますが、説明の変更は同期されません。
- 検出事項が削除されると、チケットは削除されるのではなく `solved` にマークされます。Zendesk は solved になったチケットを一定期間後に自動的にクローズします。
- `closed` は最終ステータスです。クローズされたチケットはまったく更新できず、チケットがクローズ済みの検出事項をプッシュするとエラーが報告されます。
