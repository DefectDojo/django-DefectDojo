---
title: "Microsoft Defender"
description: "DefectDojo で Microsoft Defender の Upstream Connector をセットアップする方法"
weight: 89
audience: pro
---
Microsoft Defenderコネクタは、**Microsoft Defender Vulnerability Management (MDVM)** からデバイスの脆弱性検出事項をインポートします。これはデバイス／ソフトウェアバージョン／CVEの組み合わせごとに1件の検出事項であり、深刻度、CVSSスコア、悪用可能性のレベル、推奨されるセキュリティ更新プログラムを含みます。DefectDojoはお使いのDefenderの**デバイスグループ**を検出し、それぞれについてRecordを作成します。どのデバイスグループにも割り当てられていないデバイスは、合成的な**Unassigned**グループの下にまとめられます。

**ご注意ください:** このConnectorは、手動でエクスポートしたDefenderファイルをインポートするファイルベースの**「MSDefender Parser」**スキャンタイプとは別のものです。重複した検出事項を避けるため、製品ごとにいずれか一方のインポート経路を選択してください。

#### 前提条件

お使いのMicrosoftテナントには、Defenderの脆弱性エクスポートAPIを含むアクティブなライセンスが必要です: **Defender for Endpoint Plan 2**、**Microsoft Defender Vulnerability Management Standalone**、またはMDVMアドオン付きのMDE P1/P2のいずれかです。（MDVMの*アドオン*SKU単体では不十分で、その下にDefender for Endpoint Plan 2が必要です。）

このコネクタは、クライアントクレデンシャルフローを使用してMicrosoft Entra IDの**アプリ登録**として認証を行います。作成手順は次のとおりです。

1. [Azureポータル](https://portal.azure.com)で **App registrations > New registration** を開きます。名前を付け（例: `defectdojo-connector`）、デフォルトのまま **Register** を選択します。
2. アプリの **Overview** ページで、**Application (client) ID** と **Directory (tenant) ID** を控えます。
3. **API permissions > Add a permission > APIs my organization uses** を開き、**WindowsDefenderATP** を検索します。表示されない場合は、テナントのDefenderバックエンドがまだプロビジョニングされていません。ライセンスがアクティブであることを確認し、一度 [security.microsoft.com](https://security.microsoft.com) を開いてから、数分後に再試行してください。
4. **Application permissions** を選択し（*Delegated*ではありません — Delegated permissionsはコネクタのサービストークンには決して現れません）、**Vulnerability** を展開して **Vulnerability.Read.All** にチェックを入れ、**Add permissions** を選択します。
5. **Grant admin consent** を選択して確認します。Statusカラムに緑色のチェックが表示される必要があります。このステップを行わないと、すべてのAPI呼び出しが403エラーを返します。
6. **Certificates & secrets > New client secret** を開き、有効期限を設定し、シークレットの **Value** をただちにコピーします(一度しか表示されません)。シークレットが期限切れになるとConnectorは動作しなくなるため、期限日を控えておいてください。

#### Connector Mappings

1. **Location** フィールドに `https://api.security.microsoft.com` を入力します。
2. **Tenant ID** フィールドに **Directory (tenant) ID** を入力します。
3. **Client ID** フィールドに **Application (client) ID** を入力します。
4. **Client Secret** フィールドにクライアントシークレットの値を入力します。
5. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各Defenderデバイスグループが1件のRecordになります。Microsoftは、コネクタが読み取る脆弱性スナップショットをおよそ6時間ごとに再生成し、新しくオンボーディングされたデバイスが最初の脆弱性データを生成するまでに最大で約24時間かかることがあります — 新規テナントでは、デバイスがオンボーディングされ評価が完了するまで、Syncで検出事項が0件になるのが正常です。ライセンスの有効化自体もAPIに反映されるまで約20分以上かかることがあり、この間に発生する「No active license found」というエラーは自然に解消されます。
