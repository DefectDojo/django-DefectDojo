---
title: "Qualys"
description: "DefectDojo で Qualys の Upstream Connector をセットアップする方法"
weight: 109
audience: pro
---
Qualysコネクタは、Qualys Cloud Platformから**VMDRホストの脆弱性検出結果**をインポートします。これは、それぞれQualysのKnowledgeBase (QID) メタデータと結合されています。DefectDojoは、お使いのサブスクリプション内の各Qualys**ホスト**についてRecordを作成します。

#### 前提条件

**VMDR APIアクセス**を持つQualysユーザーアカウントと、サブスクリプションの**APIサーバー(プラットフォーム)URL**が必要です — これはサブスクリプションごとに異なります。Qualys UIの **Help > About** の下、またはQualysの[Platform Identification](https://www.qualys.com/platform-identification/)ページで確認できます(例: US Platform 1の場合は `https://qualysapi.qualys.com`、US Platform 2の場合は `https://qualysapi.qg2.apps.qualys.com`)。

#### Connector Mappings

1. **Location** フィールドにQualysのAPIサーバーURLを入力します(例: `https://qualysapi.qualys.com`)。
2. **Username** フィールドにQualys APIのユーザー名を入力します。
3. **Secret** フィールドにQualys APIのパスワードを入力します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各Qualysホストが1件のRecordになります。Qualysが**Fixed**とマークした検出結果は除外されるため、再インポートによって修復済みの検出事項がクローズされます。
