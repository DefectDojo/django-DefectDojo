---
title: "Shortcut"
description: "DefectDojo で Shortcut のダウンストリームコネクタをセットアップする方法"
weight: 124
audience: pro
---
Shortcut 連携を使用すると、DefectDojo の検出事項を [Shortcut](https://www.shortcut.com/) の Story としてプッシュできます。Story は Story タイプ Bug で作成され、Shortcut ワークスペース内の Team に割り当てられます。

### インスタンスのセットアップ

- **Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には `https://api.app.shortcut.com` を設定します。
- **API Token** には、Shortcut の API トークンを設定します。トークンは Shortcut の Settings > Your Account > [API Tokens](https://app.shortcut.com/settings/account/api-tokens) で生成できます。

### 課題管理マッピング

- **Team (Group) ID** には、Story の作成先となる Shortcut Team の UUID を設定します。この UUID は、Shortcut で Team ページを開いて URL から識別子をコピーするか、Shortcut API を呼び出すことで確認できます。

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### 深刻度マッピングの詳細

各深刻度の値は、ラベルとして Story に適用されます。ラベルが Shortcut にまだ存在しない場合は自動的に作成されるため、以下のデフォルト値をそのまま使用することも、任意のラベル名に置き換えることもできます。検出事項の深刻度が変更されると、古い深刻度ラベルが Story から削除され、新しいラベルが追加されます。

- **深刻度フィールド名**: `Label`
- **情報マッピング**: `sev-info`
- **低マッピング**: `sev-low`
- **中マッピング**: `sev-medium`
- **高マッピング**: `sev-high`
- **重大マッピング**: `sev-critical`

### ステータスマッピングの詳細

各ステータスの値には、Shortcut ワークスペース内の Workflow State の数値 ID を設定する必要があります。Workflow State ID はワークスペースごとに固有であるため、デフォルト値はありません。Workflow State とその ID の一覧は、Shortcut API を呼び出すことで取得できます。

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **ステータスフィールド名**: `Workflow State ID`
- **アクティブマッピング**: 未着手の作業を表すステート(たとえば Backlog や To Do のステート)の ID。
- **クローズマッピング**: Done タイプのステートの ID。DefectDojo で検出事項が削除されると、その Story はこのステートに移動します。
- **誤検知マッピング**: 誤検知の検出事項に使用するステートの ID。
- **リスク受容済みマッピング**: リスク受容済みの検出事項に使用するステートの ID。
