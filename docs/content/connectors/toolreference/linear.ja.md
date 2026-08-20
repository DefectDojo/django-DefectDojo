---
title: "Linear"
description: "DefectDojo で Linear のダウンストリームコネクタをセットアップする方法"
weight: 87
audience: pro
---
Linear 統合を使うと、DefectDojo の Finding を[Linear](https://linear.app/)の Issue としてプッシュできます。Issue は Linear ワークスペース内の Team に作成されます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、`https://api.linear.app/graphql` を設定します。
- **API Key** は、Linear のパーソナル API キーを設定します。キーは Linear の Settings、Security & access、[API](https://linear.app/settings/account/security)から生成できます。このキーは Linear の GraphQL API に `Authorization` ヘッダーで送信されます。

### Issue Tracker Mapping

- **Team (Group) ID** は、Issue の作成先となる Linear Team の ID を設定します。以下のように Linear の GraphQL API を呼び出すことで、Team とその ID の一覧を取得できます。

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Severity Mapping Details

Linear の Issue には深刻度フィールドではなく、数値の **priority** があります。DefectDojo の各深刻度は、`1` が Urgent、`4` が Low となる Linear の優先度にマッピングされます。

- **Severity Field Name**: `Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

### Status Mapping Details

各ステータス値には、Linear Team 内の Workflow State の ID を設定する必要があります。Workflow State の ID はワークスペースごとに異なるため、デフォルト値はありません。以下のように Linear の GraphQL API を呼び出すことで、Workflow State とその ID の一覧を取得できます。

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping** は、開始済みまたは未開始の状態の ID です。例: `Todo` や `In Progress`
- **Closed Mapping** は、完了状態の ID です。例: `Done`。DefectDojo で Finding が削除されると、対応する Issue はこの状態に移動します。
