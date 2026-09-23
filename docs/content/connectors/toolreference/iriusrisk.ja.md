---
title: "IriusRisk"
description: "DefectDojo で IriusRisk の Upstream Connector をセットアップする方法"
weight: 80
audience: pro
---
IriusRiskコネクタは、APIトークンを使用して、お使いのIriusRiskインスタンスから脅威モデリングデータを取り込みます。

#### Prerequisites

IriusRiskアカウントのAPIトークンが必要です。自動化された操作を手動のチーム操作と明確に区別できるよう、DefectDojo専用のサービスアカウントを作成することをお勧めします。

IriusRiskでAPIトークンを生成するには:

1. IriusRiskインスタンスにログインします。
2. 右上のメニューから**User Profile**に移動します。
3. **API Token**を選択し、新しいトークンを生成します。

詳細については、[IriusRisk APIドキュメント](https://support.iriusrisk.com/hc/en-us/categories/360001148511)を参照してください。

#### Connector Mappings

1. **Location URL**フィールドにIriusRiskインスタンスのURLを入力します。クラウドホスト型インスタンスの場合、通常は`https://{your-subdomain}.iriusrisk.com`です。オンプレミス環境の場合は、インスタンスのベースURLを使用してください。
2. **Secret**フィールドに**API Token**を入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。選択した深刻度を下回る検出事項はインポートされません。
