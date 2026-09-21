---
title: "Docker Scout"
description: "DefectDojo で Docker Scout の Upstream Connector をセットアップする方法"
weight: 50
audience: pro
---
Docker Scoutコネクタは、Docker Scoutのmetrics exporter APIを使用して、組織のイメージの脆弱性状況を報告します。DefectDojoは、Docker Scoutの各stream（実行環境）を検出し、それぞれについて脆弱性とポリシー準拠状況のサマリーをインポートします。

#### Prerequisites

**Docker Scoutに登録済み**のDocker組織の**owner**が作成した、Dockerのpersonal access tokenが必要です。metrics exporterは組織レベルの機能であるため、個人アカウントや、Docker Scoutに登録されていない組織では、データが返されません。

トークンは、Dockerアカウント設定の**Personal access tokens**から作成します。また、Dockerの**organization namespace**も必要になるため控えておいてください。

#### Connector Mappings

1. **Location**フィールドに`https://api.scout.docker.com`を入力します。
2. **Secret**フィールドにDockerのpersonal access tokenを入力します。
3. Dockerの**Organization**namespaceを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。選択した深刻度未満の検出事項はインポートされません。

DefectDojoは、Docker Scoutのstreamごとに個別のレコードを作成し、そのstream内でDocker Scoutが集計した脆弱性について深刻度ごとに1件の検出事項をインポートするほか、Docker Scoutのポリシーに違反する各イメージについても検出事項をインポートします。Docker ScoutのmetricsAPIは個別のCVEではなく集計件数を報告するため、これらの検出事項はstreamの状況をまとめたものになります。イメージ単位・CVE単位の詳細については、Docker Scout上でそのstreamを開いて確認してください。

詳細については、[Docker Scoutのドキュメント](https://docs.docker.com/scout/)を参照してください。
