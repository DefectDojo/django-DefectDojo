---
title: "ServiceNow CMDB"
description: "DefectDojo で ServiceNow CMDB の Upstream Connector をセットアップする方法"
weight: 121
audience: pro
---
ServiceNow CMDBコネクタは**アセットコネクタ**です: 検出事項をインポートする代わりに、お使いのServiceNow構成管理データベースからConfiguration Item (CI) を読み取り、各CIについてDefectDojoアセットを作成し、CIクラスごとにOrganizationにグループ化します。検出事項はインポートされません。

#### 前提条件

ServiceNowインスタンスと、ServiceNow Table API経由でCMDBテーブルを読み取れるアカウントが必要です。DefectDojo専用の読み取り専用サービスアカウントの利用をお勧めします。このアカウントには、インポートしたい `cmdb_ci` テーブルへの読み取りアクセス権が必要です。

#### Connector Mappings

1. **Location** フィールドにServiceNowインスタンスのURLを入力します: `https://{your-instance}.service-now.com`。
2. インスタンスの認証情報(ServiceNowのユーザー名とパスワード)を保持するServiceNowの**Tool Configuration**を選択または作成します。

各Configuration ItemがCIの名前を冠したRecordになり、その**CIクラス**(例: application、server、business serviceなど)でグループ化されます。DiscoveryとSyncはCIリストの差分を調整します: 新しいCIは `NEW` のRecordとして表示され、CMDBから削除されたCIは、チームがトリアージできるように次回のSyncで `MISSING` としてフラグが立てられます。DefectDojoが製品を黙って削除することはありません。
