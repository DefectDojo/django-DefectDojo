---
title: "NeuVector"
description: "DefectDojo で NeuVector の Upstream Connector をセットアップする方法"
weight: 93
audience: pro
---
NeuVectorコネクタは、[NeuVector](https://github.com/neuvector/neuvector) コントローラのREST APIを使用して、コンテナ**イメージの脆弱性スキャン**をインポートします。DefectDojoは、NeuVectorがスキャンしたすべてのイメージを検出し、それぞれについてRecordを作成した上で、そのイメージのスキャンレポートを検出事項としてインポートします。

#### 前提条件

スキャン結果の読み取り権限を持つコントローラアカウントの、NeuVectorの**ユーザー名とパスワード**が必要です。コネクタはこれらの認証情報でログインしてセッショントークンを取得します。パスワードとトークンはログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドに、REST APIポートを含むNeuVectorコントローラのURLを入力します — 例: `https://neuvector.example.com:10443`。
2. コントローラの **Username** と **Password** を入力します。
3. コントローラが自己署名証明書を使用している場合は、**Skip TLS Verification** を `true` に設定します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは、スキャン済みの各**イメージ**をRecordにマッピングし、そのスキャンレポート内の各**CVE**を検出事項にマッピングします。深刻度はNeuVector自身の評価に基づき、影響を受けるパッケージとバージョン、CVSSv3スコアとベクター、修正バージョン(緩和策として)、参照リンクが引き継がれます。検出事項は、イメージ、CVE、パッケージ、バージョン、深刻度で重複排除されます。

詳細については、[NeuVector APIドキュメント](https://open-docs.neuvector.com/automation/automation)を参照してください。
