---
title: "Deepfence ThreatMapper"
description: "DefectDojo で Deepfence ThreatMapper の Upstream Connector をセットアップする方法"
weight: 46
audience: pro
---
Deepfence ThreatMapperコネクタは、[ThreatMapper](https://github.com/deepfence/ThreatMapper)の管理コンソールREST APIを使用して**脆弱性スキャン**の結果をインポートします。DefectDojoは、ThreatMapperがスキャンしたすべてのノード（コンテナイメージ、ホスト、またはコンテナ）を検出し、それぞれについてレコードを作成したうえで、そのノードの直近に完了したスキャンを検出事項としてインポートします。

#### Prerequisites

ThreatMapperの**APIトークン**が必要です。これはコンソールの**Settings → User Management**（ユーザーのAPIキー）にあります。コネクタは同期のたびにこのトークンを短命のアクセストークンと交換します。APIトークン自体がログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドにThreatMapperコンソールのURLを入力します（例: `https://threatmapper.example.com`）。
2. **Secret**フィールドにThreatMapperのAPIトークンを入力します。
3. コンソールが自己署名証明書を使用している場合は、**Skip TLS Verification**を`true`に設定します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、スキャン済みの各**ノード**をレコードにマッピングし、直近に完了した脆弱性スキャンに含まれる各**CVE**を検出事項にマッピングします。深刻度はThreatMapper自体の評価に基づき、影響を受けるパッケージ、CVSSスコア、修正バージョン（緩和策として）、参照リンク、詳細情報のブロックが引き継がれます。検出事項は動的検出事項として記録され、ノード・CVE・パッケージ・パッケージパスの組み合わせで重複排除されます。

詳細については、[ThreatMapperのドキュメント](https://community.deepfence.io/threatmapper/docs/v2.5/)を参照してください。
