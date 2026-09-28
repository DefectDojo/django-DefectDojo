---
title: "Mend"
description: "DefectDojo で Mend の Upstream Connector をセットアップする方法"
weight: 88
audience: pro
---
Mendコネクタ(旧**WhiteSource**)は、Mend APIを使用して、Mend組織からセキュリティ検出事項をインポートします。DefectDojoは各Mend**project**にRecordを作成します。

#### Prerequisites

Mendの**User Key**(個人アクセストークン)を持つMend(サービス)ユーザーと、Mendの**Organization UUID**が必要です。自動化された操作を手動のチーム操作と区別しやすくするため、専用のサービスアカウントの使用をお勧めします。Organization UUIDは、Mendアプリの**Administration > Organization UUID**にあります。

#### Connector Mappings

1. **Location**フィールドにMendのAPI URLを入力します。このURLは**リージョン固有**です — Mend組織がホストされているリージョンのAPIベースURLを使用してください。
2. **Email**フィールドにMendユーザーのログインメールアドレスを入力します。
3. **Organization UUID**フィールドにMendの**Organization UUID**を入力します。
4. **User Key**フィールドにMendの**User Key**を入力します。
5. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。
