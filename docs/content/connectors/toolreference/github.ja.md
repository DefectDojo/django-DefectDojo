---
title: "GitHub"
description: "GitHub の Upstream / ダウンストリームコネクタのセットアップ"
weight: 63
audience: pro
---
## アップストリームコネクタ

GitHubコネクタは**アセットコネクタ**です。トークンがアクセスできるリポジトリを列挙し、それぞれについてDefectDojoのアセットを作成します。作成されたアセットは、GitHubのowner（組織またはユーザー）ごとにOrganizationsにグループ化されます。検出事項はインポートされません。

**Please note:** このコネクタがインポートするのはリポジトリの**インベントリ**のみです。GitHubのセキュリティアラート（code scanning、Dependabot、secret scanning）を検出事項としてインポートするには、以下の別途用意された**GitHub Advanced Security**コネクタを使用してください。この2つは互いに独立しており、併用することもできます。

#### Prerequisites

コネクタはGitHubの**個人アクセストークン**で認証を行い、リポジトリの**メタデータ**（名前、説明、URL、owner）のみを読み取ります。コードやissue、セキュリティアラートにはアクセスしません。トークンのアカウントが所有・コラボレーション・組織メンバーとして参加しているすべてのリポジトリがインポートされるため、ミラーしたいリポジトリをそのアカウントが参照できることを確認してください。専用のサービスアカウントを使用することをお勧めします。

トークンに必要なのは、リポジトリメタデータへの読み取り専用アクセスのみです。

- *fine-grained*トークンの場合、インポート対象のリポジトリ（または組織全体）に対して**Repository permissions → Metadata: Read-only**の権限が必要です。
- *classic*トークンの場合、プライベートリポジトリを含めるには**`repo`**スコープが必要です（パブリックリポジトリのみでよい場合は**`public_repo`**を使用してください）。加えて、組織所有のリポジトリを解決するために**`read:org`**も必要です。

サポートされるのはGitHub.com（GitHub Enterprise Cloudを含む）のみです。GitHub Enterprise **Server**は現時点でこのコネクタではサポートされていません。

#### Connector Mappings

1. **Location**フィールドに`https://api.github.com`を入力します。
2. **Secret**フィールドに個人アクセストークンを入力します。

組織やリポジトリのリストを入力する必要はありません。DefectDojoは、トークンが参照できるすべてのリポジトリをインポートします。各リポジトリはそのリポジトリ名にちなんだレコードとなり、GitHubの**owner**（組織またはユーザー）ごとにグループ化されます。リポジトリが後で削除されたり、トークンがそのアクセス権を失ったりした場合、対応するレコードは削除されるのではなく、次回の同期時に`MISSING`としてフラグが付けられます。DefectDojoが製品を黙って削除することはありません。

## ダウンストリームコネクタ

GitHub 統合を使うと、[GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects)に Issue を追加でき、これにより関連付けられた Repo にも Issue が作成されます。これらの Repo/Project は、GitHub Organization または個人の GitHub アカウントのいずれにも関連付けることができます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、Issue を作成したい場所に応じて、GitHub のユーザーまたは Organization の URL を設定します。例: `https://github.com/{your-organization}`
- **Token** は、GitHub のパーソナルアクセストークンを設定します。

GitHub のパーソナルアクセストークンは https://github.com/settings/tokens で作成できます。トークンには Repo と Project のスコープが必要です。

### Issue Tracker Mapping

- **Issue Tracker Mapping Label** は、Issue を作成したい Project または Repo を識別できるように設定します。
- **Project Number** は、Issue を送信したい GitHub Project の ID を設定します。この値は、Project を表示中の URL から取得できます。例: `https://github.com/orgs/{your-org}/projects/{project number}`
- **Repository Name** は、Issue をプッシュしたい、Organization（またはユーザー）に紐づくリポジトリの名前を設定します。


### Severity Mapping Details

**この統合を設定するには、Project 側で Issue の優先度を表すカスタムフィールドを作成しておく必要があります。作成していない場合、深刻度が正しくマッピングされず、Issue が GitHub にプッシュされません。**

以下のガイドに従って[カスタムフィールド](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority)を作成してください。
各深刻度には、対応する単一選択のオプションを用意する必要があります。例えば、DefectDojo は初期状態で Priority の値として P0、P1、P2、P3、P4 を提案しており、それぞれを Priority カスタムフィールドに追加する必要があります。

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P0`
- **Low Mapping**: `P1`
- **Medium Mapping**: `P2`
- **High Mapping**: `P3`
- **Critical Mapping**: `P4`

### Status Mapping Details

デフォルトでは、新規作成した GitHub Project には Issue のステータスとして「In Progress」と「Done」が用意されています。誤検知やリスク受容済みのステータスを追跡したい場合は、Project に追加のステータスを設定することもできます。その方法の一つが、Project Board に新しいステータス列を追加する方法です。

- **Status Field Name**: `Status`
- **Active Mapping**: `In Progress`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`
