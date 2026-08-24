---
title: "Contrast"
description: "DefectDojo で Contrast の Upstream Connector をセットアップする方法"
weight: 39
audience: pro
---
Contrastコネクタは、Contrast Assess REST APIを使用してアプリケーションの脆弱性をインポートします。DefectDojoはContrast組織内のアプリケーションを検出し、それぞれについてレコードを作成します。

#### Prerequisites

Contrastから4つの値が必要です。自動化された操作をチームの手動操作と区別しやすくするため、専用のサービスアカウントを作成することをお勧めします。Contrast UIの**User Settings > Profile > Your Keys**で以下を確認できます。

* 組織の**API Key**。
* 個人の**Service Key**。
* 認証情報の所有者である**username**（アカウントのログイン用メールアドレス）。
* インポート元の組織のUUIDである**Organization ID**（**Organization Settings**にも表示されます）。

#### Connector Mappings

1. **Location**フィールドに、Contrastへのアクセスに使用するベースURLを入力します。ホスト版の場合、通常は`https://app.contrastsecurity.com`です（またはリージョンごと・自己ホスト型のTeam ServerのURL）。
2. **Username**フィールドにアカウントのログイン用メールアドレスを入力します。
3. **API Key**フィールドに組織の**API Key**を入力します。
4. **Service Key**フィールドに個人の**Service Key**を入力します。
5. **Organization ID**フィールドに**Organization ID**（UUID）を入力します。
6. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

各Contrastアプリケーションはレコードになり、その脆弱性は検出事項としてインポートされます。
