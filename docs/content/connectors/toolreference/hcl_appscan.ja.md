---
title: "HCL AppScan"
description: "DefectDojo で HCL AppScan の Upstream Connector をセットアップする方法"
weight: 73
audience: pro
---
HCL AppScanコネクタは、AppScan v4 REST APIを使用して、**AppScan on Cloud(ASoC)**またはセルフホスト型の**AppScan 360°**(両者はAPIを共有しています)からissueをインポートします。アカウント全体を同期します。DefectDojoはすべてのアプリケーションを検出してそれぞれにRecordを作成し、そのアプリケーションのissue(DAST、SAST、IAST)を検出事項としてインポートします。

#### Prerequisites

AppScanの**APIキー**が必要です — これはAppScanアカウント設定(API Key)で生成されるKey IDとKey Secretです。コネクタは実行ごとにこれらを短命のセッショントークンと交換します。Key ID、Key Secret、トークンはログに記録されません。

#### Connector Mappings

1. **Location**フィールドにAppScanコンソールのURLを入力します。ASoCの場合は`https://cloud.appscan.com`(EUリージョンの場合は`https://eu.cloud.appscan.com`)、セルフホスト型のAppScan 360°の場合はインスタンスのホストを使用します。
2. AppScan on Cloudの場合は**Provider**を`ASOC`に、セルフホスト型のAppScan 360°の場合は`A360`に設定します。
3. **API Key ID**と**API Key Secret**を入力します。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

DefectDojoは各AppScanの**application**をRecord(VEP)にマッピングし、各**issue**を検出事項にマッピングします。タイトルはissueの種類にドメイン/エンティティ/cause-id/URL/パスを付加したものになります。深刻度はInformational→情報にマッピングされます(Low/Medium/High/Criticalはそのまま渡されます)。CWE、ラベル付きの説明、修復方法とアドバイザリ、およびhost/portエンドポイントが引き継がれます。静的解析によるissueは静的検出事項として、動的/インタラクティブなissueは動的検出事項として記録され、openなissueはアクティブ、fixed/passedのissueは緩和済みになります。

詳細については、[AppScan REST APIドキュメント](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html)を参照してください。
