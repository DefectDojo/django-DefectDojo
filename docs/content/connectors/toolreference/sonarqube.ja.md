---
title: "SonarQube"
description: "DefectDojo で SonarQube の Upstream Connector をセットアップする方法"
weight: 127
audience: pro
---
SonarQubeコネクタは、SonarCloudアカウントまたはローカルのSonarQubeインスタンスのいずれからでもデータを取得できます。

**SonarCloudユーザーの場合:**

1. Locationフィールドに https://sonarcloud.io/ を入力します。
2. Secretフィールドに有効な**APIキー**を入力します。

**SonarQube(オンプレミス)ユーザーの場合:**

1. Locationフィールドにお使いのSonarQubeインスタンスのベースURLを入力します: 例 `https://my.sonarqube.com/`
2. Secretフィールドに有効な**APIキー**を入力します。これは**[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [APIトークンタイプ](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)である必要があります。

このトークンには、Sonar内のProjects、Vulnerabilities、Hotspotsへのアクセス権が必要です。

APIトークンは、SonarQubeアプリの **My Account -> Security -> Generate Token** から確認・生成できます。詳細については、[SonarQubeドキュメントを参照してください](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)。
