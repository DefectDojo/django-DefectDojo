---
title: "GitLab"
description: "GitLab の Upstream / ダウンストリームコネクタのセットアップ"
weight: 65
audience: pro
---
## アップストリームコネクタ

GitLabコネクタは**アセットコネクタ**です。トークンがアクセスできるすべてのproject（リポジトリ）を列挙し、それぞれについてDefectDojoのアセットを作成します。作成されたアセットは、GitLabのnamespace（グループまたはユーザー）ごとにOrganizationsにグループ化されます。検出事項はインポートされません。

#### Prerequisites

**read_api**スコープを持つPersonal Access Tokenが必要です。専用のサービスアカウントからトークンを作成することをお勧めします。コネクタは、そのアカウントがメンバーになっているprojectを一覧表示します。

#### Connector Mappings

1. **Location**フィールドにGitLabのURLを入力します: `https://gitlab.com`、または自己ホスト型インスタンスのベースURL。
2. **Secret**フィールドにPersonal Access Tokenを入力します。

各projectはそのproject名にちなんだレコードとなり、**namespace**ごとにグループ化されます。GitLab上で削除待ち状態のproject（ユーザーによって削除されたが、GitLabのバックグラウンドジョブによってまだ完全に削除されていないもの）は自動的に除外されます。そのため、projectを削除すると、名前が変更された幽霊のようなアセットが残るのではなく、次回の同期時に対応するレコードが`MISSING`としてフラグ付けされます。

## ダウンストリームコネクタ

GitLab 統合を使うと、[GitLab Project](https://docs.gitlab.com/ee/user/project/)に Issue を追加できます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、GitLab サーバーへのリンクを設定します。例: `https://gitlab.com/`
- **Token** は、GitLab のパーソナルアクセストークンを設定します。トークンには API スコープが必要です。詳細は[GitLab のパーソナルアクセストークン作成ガイド](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token)を参照してください。

### Issue Tracker Mapping

- **Project Name**: Issue を送信したい GitLab のプロジェクト名です。

### Severity Mapping Details

これは GitLab の Priority フィールドにマッピングされます。
- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `2`
- **Medium Mapping**: `3`
- **High Mapping**: `4`
- **Critical Mapping**: `5`

### Status Mapping Details

GitLab には、デフォルトで「opened」と「closed」というステータスがあります。誤検知やリスク受容済みのステータスを追跡したい場合は、追加のステータスラベルを設定できます。詳細は[GitLab のドキュメント](https://docs.gitlab.com/user/work_items/status/)を参照してください。

- **Status Field Name**: `Status`
- **Active Mapping**: `opened`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `closed`
