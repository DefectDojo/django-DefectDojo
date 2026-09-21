---
title: "Endor Labs"
description: "DefectDojo で Endor Labs の Upstream Connector をセットアップする方法"
weight: 54
audience: pro
---
Endor Labsコネクタは、Endor Labs REST APIを使用してEndor Labsの**ネームスペース**全体を同期します。DefectDojoは、Endorの各**プロジェクト**をレコードとして検出し、そのプロジェクトの検出事項をインポートします。その際、Endorの**到達可能性（reachability）**判定も引き継がれるため、実際に到達可能なコードに影響する脆弱性を優先的に対応できます。

#### Prerequisites

Endor Labsの**APIキー**（キー識別子とそのsecretの組み合わせ）と、同期したい**ネームスペース**が必要です。キーはEndor Labsプラットフォームの**Settings > Access > API Keys**で作成します。このキーには、対象ネームスペース内のプロジェクトと検出事項への読み取りアクセス権が必要です。

コネクタは、APIキーとsecretを短命のベアラートークンと交換することで認証を行います。secretはこの交換にのみ使用され、平文で保存されることはありません。

#### Connector Mappings

1. **Location**フィールドに`https://api.endorlabs.com`を入力します。テナントが別のリージョンでホストされている場合は、そのリージョンのAPIベースURLを使用してください。
2. 同期したいEndor Labsの**Namespace**を入力します（例: `your-org`や`your-org.team`）。
3. **API Key**識別子を入力します。
4. キーに対応する**API Secret**を入力します。
5. 必要に応じて、設定したネームスペースの子ネームスペースからも検出事項をインポートするために、**Traverse Child Namespaces**を`true`に設定します。
6. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。選択した深刻度未満の検出事項はインポートされません。

DefectDojoは、ネームスペース内のEndor Labsプロジェクトごとにレコードを作成し、その検出事項をインポートします。その際、Endorの深刻度レベルはDefectDojoの深刻度にマッピングされ、各脆弱性のCVE/GHSA識別子とCVSSスコア、およびEndorの到達可能性タグも引き継がれます。到達可能性の判定（例: *Reachable — vulnerable function is called*や*Unreachable*）は、検出事項のImpactおよびタグとして表示されます。

詳細については、**[Endor Labs REST APIのドキュメント](https://docs.endorlabs.com/rest-api/)**を参照してください。
