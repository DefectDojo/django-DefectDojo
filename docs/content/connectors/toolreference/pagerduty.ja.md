---
title: "PagerDuty"
description: "DefectDojo で PagerDuty のダウンストリームコネクタをセットアップする方法"
weight: 102
audience: pro
---
PagerDuty 統合を使うと、DefectDojo の Finding および Finding Group を、選択した PagerDuty の Service 上で開かれる PagerDuty のインシデントとしてプッシュできます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、`https://api.pagerduty.com` を設定します。PagerDuty アカウントが EU サービスリージョンでホストされている場合は、代わりに `https://api.eu.pagerduty.com` を使用してください。
- **API Token** は、PagerDuty の REST API キーを設定します。アカウント管理者は、PagerDuty の Web アプリの **Integrations > API Access Keys > Create New API Key** から作成できます。「Read-only」はチェックしないでください。DefectDojo はインシデントの作成・更新を行う必要があります。
- **From Email** は、PagerDuty アカウント上の有効なユーザーのメールアドレスを設定します。PagerDuty はインシデントの作成・更新時にこのアドレスを必要とし、インシデントのリクエスターとして表示されます。

### Issue Tracker Mapping

- **Service ID** は、インシデントを開く PagerDuty の Service の ID を設定します。PagerDuty で該当の Service を表示中の URL の末尾から取得できます。例: `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`

### Severity Mapping Details

デフォルトでは、`high` または `low` のみを受け付ける PagerDuty のインシデント **Urgency** フィールドにマッピングされます。

- **Severity Field Name**: `Urgency`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `low`
- **High Mapping**: `high`
- **Critical Mapping**: `high`

代わりに、PagerDuty アカウントで[Priorities](https://support.pagerduty.com/main/docs/incident-priority)が有効になっている場合は、深刻度を Priority 名にマッピングすることもできます。その場合は **Severity Field Name** を `Priority` に設定し、マッピング値としてアカウントの Priority 名（例えば `P1` から `P5` まで）を使用します。Priority にマッピングする場合、インシデントの Urgency は Service 自体の urgency ルールに委ねられます。

### Status Mapping Details

PagerDuty のインシデントには、`triggered`、`acknowledged`、`resolved` という3つのステータスがあります。

- **Status Field Name**: `Status`
- **Active Mapping**: `triggered`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `resolved`
- **Risk Accepted Mapping**: `acknowledged`

なお、`resolved` は PagerDuty における最終ステータスであり、resolved のインシデントは再オープンできません。また、PagerDuty はインシデントの作成後にタイトルや説明を編集することを許可していないため、更新された Finding をプッシュすると、ステータス、urgency、priority は同期されますが、コンテンツの変更は同期されません。
