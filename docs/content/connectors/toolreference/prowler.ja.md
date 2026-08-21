---
title: "Prowler"
description: "DefectDojo で Prowler の Upstream Connector をセットアップする方法"
weight: 108
audience: pro
---
Prowlerコネクタは**Prowler App** REST APIを使用して、セルフホスト型のProwler Appインスタンスからクラウドセキュリティポスチャ (CSPM) の検出事項をインポートします。DefectDojoは各Prowler**プロバイダ**(クラウドアカウント)をRecordとして検出し、そのプロバイダの最新の完了済みスキャンの**FAIL**検出事項をインポートします。

#### 前提条件

実行中のセルフホスト型**Prowler App**インスタンスと、ユーザーのメールアドレス+パスワード(JWT認証用)またはProwler Appの**APIキー**のいずれかが必要です。検出事項は、Prowler Appでクラウドアカウント(AWS、GCP、Azure、Kubernetesなど)を接続してスキャンを実行して初めて表示されます。

#### Connector Mappings

1. **Location** フィールドにProwler AppのURLを入力します(例: `https://prowler.your-company.com`)。
2. JWT認証の場合は、Prowler Appユーザーの **Email** と **Password** を入力します。あるいは、それらを空欄のままにして、Prowler Appの **API Key** を入力します。両方が指定された場合は、メール/パスワード(JWT)が使用されます。
3. 必要に応じて **Minimum Severity** を設定し、インポートする検出事項を絞り込みます。選択した深刻度未満の検出事項はインポートされません。

DefectDojoは各ProwlerプロバイダについてRecordを作成し、その最新の完了済みスキャンのFAIL検出事項をインポートします。その際、Prowlerの深刻度をDefectDojoの深刻度にマッピングし、影響を受けるクラウドリソース(ARN/リソースID)をコンポーネントとして、チェックの修復方法とリスクを検出事項に反映します。ミュートされた検出事項はスキップされます。クラウドアカウント、リージョン、サービスはタグとして付与されます。

詳細については、**[Prowler App APIドキュメント](https://api.prowler.com/api/v1/docs)**を参照してください。
