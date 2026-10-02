---
title: "Coverity"
description: "DefectDojo で Coverity の Upstream Connector をセットアップする方法"
weight: 40
audience: pro
---
Coverityコネクタは、**Coverity Connect**サーバーから検出事項をインポートします。DefectDojoは、Coverityの**プロジェクト**ごとにレコードを作成します。

#### Connector Mappings

1. **Location**フィールドにCoverity ConnectサーバーのURLを入力します。
2. **Username**フィールドにCoverity Connectの**username**を入力します。
3. **Secret**フィールドにユーザーのパスワードまたは認証キーを入力します。
4. 必要に応じて、コネクタが読み取る保存済みissueビューを選択するために**View Name**を設定します。空欄のままにすると、デフォルトの**Outstanding Issues**が使用されます。
5. 必要に応じて、デフォルトのSecurityおよびQuality（`RESOURCE_LEAK`）のissueフィルタより広くインポートするために、**Import All Issue Kinds**を`true`に設定します。
