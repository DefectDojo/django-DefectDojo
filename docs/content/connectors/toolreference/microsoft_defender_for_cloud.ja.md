---
title: "Microsoft Defender for Cloud"
description: "DefectDojo で Microsoft Defender for Cloud の Upstream Connector をセットアップする方法"
weight: 90
audience: pro
---
Microsoft Defender for Cloudコネクタは、Defender for Cloudを通じて表示される **Microsoft Defender Vulnerability Management (MDVM)** の脆弱性検出事項をインポートします。これには**サーバー**の検出事項(Azure VMのオペレーティングシステムおよびインストール済みソフトウェアのCVE)と**コンテナレジストリ**の検出事項(コンテナイメージのCVE)の両方が含まれ、深刻度、CVSSスコア、影響を受けるパッケージまたはイメージ、修復方法を含みます。DefectDojoは、サービスプリンシパルが読み取り可能なAzureの**サブスクリプション**を検出し、有効化されたサブスクリプションごとにRecordを作成します。

**ご注意ください:** このConnectorは、Defender for Endpoint APIからデバイスの検出事項をインポートする**Microsoft Defender**コネクタとは別のものです。Defender for Cloudは異なるAPIサーフェス(Azure Resource Manager / Resource Graph)と権限モデル(Azure RBAC)を持つAzure製品です。検出事項がどちらにあるかに応じて実行してください — 両方の製品を使用している場合は両方実行しても構いません。

#### 前提条件

**Microsoft Defender for Cloudが有効化された**1つ以上のAzureサブスクリプションが必要で、スキャン対象のリソースに応じて関連するDefenderプランを有効にしておく必要があります(**Microsoft Defender for Cloud > Environment settings** の下で、サブスクリプションを選択します):

* **Defender for Servers (Plan 2)** — Azure VMのオペレーティングシステムおよびソフトウェアのCVE検出事項(エージェントレス脆弱性スキャン)。
* **Defender for Containers** — コンテナレジストリのイメージCVE検出事項。

SQLの脆弱性評価および設定/ポスチャの検出事項は意図的に**インポートされません** — このコネクタはCVEの脆弱性のみをインポートします。

このコネクタは、クライアントクレデンシャルフローを使用してMicrosoft Entra IDの**アプリ登録**として認証を行います。

1. [Azureポータル](https://portal.azure.com)で **App registrations > New registration** を開きます。名前を付け(例: `defectdojo-connector`)、デフォルトのまま **Register** を選択します。
2. アプリの **Overview** ページで、**Application (client) ID** と **Directory (tenant) ID** を控えます。
3. **Certificates & secrets > New client secret** を開き、有効期限を設定し、シークレットの **Value** をただちにコピーします(一度しか表示されません)。シークレットが期限切れになるとConnectorは動作しなくなるため、期限日を控えておいてください。
4. インポートしたい各サブスクリプションに対してアプリに読み取りアクセス権を付与します: **Subscriptions** を開き、サブスクリプションを選択し、**Access control (IAM) > Add > Add role assignment** を選びます。**Security Reader** ロール(または **Reader**)を選択し、**Members** タブで作成したアプリに割り当てます — ピッカーはクライアントIDと一致しないため、アプリの**名前**または**オブジェクトID**で検索してください。すべてのサブスクリプションについて繰り返します。

デバイスベースのMicrosoft Defenderコネクタとは異なり、API permissionやadmin consentは不要です。Defender for Cloudへのアクセスは、上記のAzure RBACロール割り当てのみによって管理されます。

#### Connector Mappings

1. **Location** フィールドに `https://management.azure.com` を入力します。(政府専用クラウドなど特殊な環境では、対応するARMエンドポイントを使用してください。例: `https://management.usgovcloudapi.net`。)
2. **Tenant ID** フィールドに **Directory (tenant) ID** を入力します。
3. **Client ID** フィールドに **Application (client) ID** を入力します。
4. **Client Secret** フィールドにクライアントシークレットの値を入力します。
5. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

有効化された各Azureサブスクリプションが1件のRecordになります。検出事項はAzure Resource Graphを通じて読み取られるため、Defender for Cloudがリソースをスキャンし終えるとすぐに反映されますが、スキャン自体はMicrosoftのスケジュールで実行されます — コンテナレジストリのイメージは通常プッシュから1時間以内にスキャンされますが、VMの最初のエージェントレス脆弱性スキャンには数時間かかることがあります。新しく有効化されたサブスクリプションでは、リソースがスキャンされるまでSyncで検出事項が0件になるのが正常です。
