---
title: "runZero"
description: "DefectDojo で runZero の Upstream Connector をセットアップする方法"
weight: 115
audience: pro
---
runZeroコネクタはrunZero Export APIを使用して、組織全体のアセットインベントリをDefectDojoに同期します。これは主に**アセット**コネクタです: DefectDojoはすべてのアセットを検出してそれぞれについてRecordを作成し、runZeroの**サイト**ごとにProduct Typeにグループ化します。オプションで、runZeroの脆弱性を検出事項としてインポートすることもできます。

#### 前提条件

runZero(Account → API)から組織の**Export Token**が必要で、これは `XT` というプレフィックスが付きます。このトークンは組織スコープ(組織がトークン内にエンコードされています)、読み取り専用であり、Bearerトークンとして送信されます — ログに記録されることはありません。コミュニティ/スタータープランも利用できます。

#### Connector Mappings

1. **Location** フィールドにrunZeroコンソールのURLを入力します。例: `https://console.runzero.com`。URLはHTTPSである必要があります。
2. **Secret** フィールドにExport Tokenを入力します。
3. 必要に応じて **Import Vulnerabilities** を `true` に設定すると、runZeroの脆弱性も検出事項としてインポートされます。空欄のままにすると、アセットのみが同期されます。
4. 必要に応じて **Minimum Severity** を設定し、インポートする脆弱性の検出事項を絞り込みます(脆弱性がインポートされる場合にのみ適用されます)。

DefectDojoは各runZero**アセット**をRecord (VEP) にマッピングします: 表示名はアセットの名前またはアドレスから取得され、そのサイト、種別、OS、アドレス、タグが属性として付与されます。アセットの**サイト**がそのProduct Typeになります。アセットは、DefectDojoが差分を調整する(追加/削除する)完全なエクスポートによって同期されます。**Import Vulnerabilities** が有効な場合、各runZeroの脆弱性はそのアセット上の検出事項になります — 深刻度、CVSSスコア、CVE、影響を受けるサービス(`protocol://address:port`)のエンドポイント、および修復方法がマッピングされます。

詳細については、[runZero APIドキュメント](https://help.runzero.com/)を参照してください。
