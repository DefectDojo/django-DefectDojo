---
title: "Nuclei (ProjectDiscovery Cloud)"
description: "DefectDojo で Nuclei (ProjectDiscovery Cloud) の Upstream Connector をセットアップする方法"
weight: 97
audience: pro
---
NucleiコネクタはProjectDiscovery Cloud Platform (PDCP) REST APIを使用して、お使いのPDCPアカウントから [nuclei](https://github.com/projectdiscovery/nuclei) のスキャン結果を取得します。DefectDojoはアカウント内のすべてのスキャンを検出し、**スキャン**ごとに個別のRecordを作成します。

#### 前提条件

ProjectDiscovery Cloudの**APIキー**が必要です。自動化された処理と手動のチーム操作を明確に区別するため、DefectDojo専用のサービスアカウントを作成することをお勧めします。ProjectDiscovery Cloud UI([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io))の **Settings > API Key** からキーを生成します。結果は、ホスト型スキャンから、または `-dashboard` を付けて実行したnuclei CLIからPDCPに届きます。

#### Connector Mappings

1. **Location** フィールドにPDCPのAPIベースURLを入力します: `https://api.projectdiscovery.io`。
2. **Secret** フィールドに**APIキー**を入力します。
3. 必要に応じて、**Team ID** を入力してチームワークスペースに同期範囲を絞り込みます(**Settings > Team** の下にあります)。空欄のままにすると、DefectDojoは個人用ワークスペースを同期します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは、各PDCPの**スキャン**を個別のRecordとしてマッピングし、情報レベルを含むすべての深刻度にわたって、そのスキャンの検出事項をインポートします。
