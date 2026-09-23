---
title: "Opsgenie"
description: "DefectDojo で Opsgenie のダウンストリームコネクタをセットアップする方法"
weight: 99
audience: pro
---
Opsgenie 統合を使うと、DefectDojo の Finding および Finding Group を Opsgenie のアラートとしてプッシュでき、必要に応じて Opsgenie の Team をレスポンダーとして割り当てることもできます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、`https://api.opsgenie.com` を設定します。Opsgenie アカウントが EU サービスリージョンでホストされている場合は、代わりに `https://api.eu.opsgenie.com` を使用してください。アラートが Jira Service Management Operations 上にある場合（Atlassian は Opsgenie を JSM に統合しつつあります）は、`https://api.atlassian.com/jsm/ops/integration` を使用してください。
- **API Key** は、Opsgenie の **API integration** キーを設定します。アカウント管理者は、Opsgenie の Web アプリの **Settings > Integrations** から、タイプ **API** の統合を追加し、*Create and Update Access*（DefectDojo が接続を検証できるように *Read Access* も）を付与することで作成できます。これはパーソナル API キーではなく統合キーである点に注意してください。DefectDojo は `GenieKey` 認証方式を使用しており、これに対応しているのは統合キーのみです。

### Issue Tracker Mapping

- **Team Name**（オプション）は、作成されたアラートにレスポンダーとして追加したい Opsgenie Team の名前です。空欄のままにもできます。API integration キーが特定のチームにスコープされている場合、アラートは自動的にそのチームにルーティングされ、そうでない場合はアカウント自身のルーティングルールがレスポンダーを決定します。

### Severity Mapping Details

深刻度は、Opsgenie の固定スケールである `P1`（critical）から `P5`（informational）までを使う、アラートの **Priority** フィールドにマッピングされます。

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P5`
- **Low Mapping**: `P4`
- **Medium Mapping**: `P3`
- **High Mapping**: `P2`
- **Critical Mapping**: `P1`

深刻度が認識されない値にマッピングされている場合、priority は省略され、Opsgenie 側のデフォルト値（`P3`）が適用されます。

### Status Mapping Details

Opsgenie のアラートは `open` または `closed` であり、open のアラートはさらに `acknowledged` にもなり得ます。

- **Status Field Name**: `Status`
- **Active Mapping**: `open`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `acknowledged`

なお、Opsgenie では `closed` は最終ステータスであり、クローズされたアラートは再オープンできず、そのエイリアスも解放されます。他の一部のツールとは異なり、Opsgenie は作成後もコンテンツの編集を許可しているため、更新された Finding をプッシュすると、ステータスとあわせてメッセージ、説明、priority も同期されます。

DefectDojo は、Finding または Finding Group から導出した安定したキーを各アラートの **alias** として設定し、Opsgenie はこの alias によって open 状態のアラートを重複排除します。そのため、同じ Finding を再度プッシュすると、新しいアラートを作成するのではなく、既存の open なアラートが更新されます。
