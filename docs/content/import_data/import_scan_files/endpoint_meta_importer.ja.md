---
title: エンドポイントメタインポーター
description: CSV を使用してタグとカスタムフィールドをエンドポイントに一括適用します
weight: 4
audience: opensource
---

**エンドポイントメタインポーター**を使用すると、CSV ファイルを使って大量のエンドポイントに一度にタグやカスタムフィールドを適用できます。これは、フィルタリング、ソート、レポート作成のために柔軟なメタデータをエンドポイントに必要とする、負荷の高いインフラストラクチャスキャンを実行している組織に特に役立ちます。

## CSV 形式

CSV ファイルには `hostname` 列(必須)に加えて、適用したいタグやカスタムフィールドを表す任意の数の追加列が必要です。追加された各列名がタグ/フィールドのキーとなり、その行の値がタグ/フィールドの値になります。

**例:**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

これにより、以下のメタデータが適用されます。

| Endpoint | Tags / Custom Fields |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## 要件

- `hostname` 列は**必須**です。この列は、ホストが一致する既存のエンドポイントを検索したり、一致するものがない場合に新しいエンドポイントを作成したりするために使用されます。
- それ以外のすべての列名は、タグ/カスタムフィールドのキーとして扱われます。
- 値は `key:value` 形式で保存されます。

## エンドポイントメタインポーターの使用

エンドポイントメタインポーターは、製品を表示しているときの **Endpoints** タブから利用できます。そこに CSV ファイルをアップロードすることで、エンドポイントにメタデータを一括適用できます。
