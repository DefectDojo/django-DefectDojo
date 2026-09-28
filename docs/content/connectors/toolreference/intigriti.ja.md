---
title: "Intigriti"
description: "DefectDojo で Intigriti の Upstream Connector をセットアップする方法"
weight: 78
audience: pro
---
Intigritiコネクタは、Intigritiの外部company APIを使用して、バグバウンティ/ペンテストの**submissions**をDefectDojoに取り込みます。companyアカウント全体を同期します。DefectDojoはトークンがアクセスできるすべてのプログラムを検出してそれぞれにRecordを作成し、そのプログラムのsubmissionを検出事項としてインポートします。

#### Prerequisites

Intigritiの**company APIトークン**が必要です。Intigriti companyポータルの**Company Settings > API**(`company_external_api`スコープ)で、プログラムとsubmissionへの読み取りアクセス権を持つアクセストークンを生成します。DefectDojo専用のトークンを使用することをお勧めします。トークンはBearerトークンとして送信され、ログには記録されません。

#### Connector Mappings

1. **Location**フィールドにIntigritiの外部company APIベースURLを入力します: `https://api.intigriti.com/external/company`。URLはHTTPSである必要があります。
2. **Secret**フィールドにcompany APIトークンを入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

DefectDojoは各Intigritiの**program**をRecordに、各**submission**をsubmissionコードをキーとして検出事項にマッピングします。検出事項の深刻度はIntigritiの評価に従います(Exceptional/Critical→重大、続いてHigh/Medium/Low、それ以外はInformational)。submissionのライフサイクル状態は検出事項のステータスにマッピングされます — open/triageのsubmissionはアクティブ、acceptedのsubmissionは検証済み、closedのsubmissionはそのクローズ理由に応じて緩和済み、重複、対象外、誤検知、またはリスク受容済みになります。検出事項の説明には、レポートの脆弱性タイプ、影響を受けるアセット、証拠となるPoC(proof of concept)、および研究者の回答が記載されます。

詳細については、[Intigriti APIドキュメント](https://kb.intigriti.com/en/articles/6117846-intigriti-api)を参照してください。
