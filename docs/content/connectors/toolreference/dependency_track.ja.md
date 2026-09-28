---
title: "Dependency-Track"
description: "DefectDojo で Dependency-Track の Upstream Connector をセットアップする方法"
weight: 48
audience: pro
---
このコネクタは、REST API経由でオンプレミスのDependency-Trackインスタンスからデータを取得します。

​**Connector Mappings**

1. **Location**フィールドにローカルのDependency-TrackサーバーのURLを入力します。
2. **Secret**フィールドに有効なAPIキーを入力します。

Dependency-TrackのAPIキーを生成するには:

1. **Access Management**: Dependency-Trackインターフェースで、Administration > Access Management > Teams に移動します。
2. **Teams Setup**: 新しいチームを作成することも、既存のチームを選択することもできます。チームを使うことで、グループメンバーシップに基づいてAPIアクセスを管理できます。
3. **Generate API Key**: 選択したチームの詳細ページで「API Keys」セクションを見つけます。+ボタンをクリックして新しいAPIキーを生成します。
4. **Assign Permissions**: チームページの「Permissions」セクションで+ボタンをクリックし、権限セレクターを開きます。プロジェクトポートフォリオと脆弱性の詳細へのAPIアクセスを有効にするため、**VIEW_PORTFOLIO**と**VIEW_VULNERABILITY**の権限を選択します。
5. 「**Select**」をクリックして、これらの権限を確認し保存します。

詳細については、**[Dependency-Track Documentation](https://docs.dependencytrack.org/integrations/rest-api/)**を参照してください。
