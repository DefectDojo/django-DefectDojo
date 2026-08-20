---
title: "Bitbucket"
description: "Bitbucket の Upstream / ダウンストリームコネクタのセットアップ"
weight: 25
audience: pro
---
## アップストリームコネクタ

Bitbucket コネクタは**Asset Connector**です。指定した Bitbucket Cloud ワークスペース内のリポジトリを列挙し、リポジトリごとに DefectDojo のアセットを作成し、Bitbucket のプロジェクト単位で組織にグループ化します。検出事項はインポートされません。

#### Prerequisites

Bitbucket Cloud では**スコープ付き**の Atlassian API トークンが必要です。従来の(スコープなしの)Atlassian API トークンは、Bitbucket 側で「API Token provided has no Bitbucket scopes」エラーとして拒否されます。

1. [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) にアクセスし、**Create API token with scopes** を選択します。
2. **Bitbucket** アプリを選択し、読み取りスコープ `read:account:bitbucket`、`read:workspace:bitbucket`、`read:repository:bitbucket`、`read:project:bitbucket` を付与します。

対応しているのは Bitbucket Cloud(bitbucket.org)のみです。Bitbucket Server は 2024 年にサポートが終了しており、Bitbucket Data Center にも対応していません。

#### Connector Mappings

1. **Location** フィールドに `https://bitbucket.org` を入力します。
2. **Email** フィールドにトークンが紐づく Atlassian アカウントの email を入力します。
3. **Secret** フィールドにスコープ付き API トークンを入力します。
4. **Workspace Slugs** フィールドに、1 つ以上のワークスペース slug をカンマ区切りで入力します。このフィールドは必須です。Bitbucket のスコープ付き API トークンはワークスペースを自動的に一覧取得できないため、読み取り対象のワークスペースを DefectDojo に明示的に伝える必要があります。

各リポジトリは、そのリポジトリ名を冠したレコードとなり、Bitbucket の**プロジェクト**単位でグループ化されます。

## ダウンストリームコネクタ

Bitbucket 統合を使うと、Bitbucket Cloud リポジトリの[Issue トラッカー](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/)に Issue をプッシュできます。

Bitbucket では Issue トラッカーはオプション機能であり、DefectDojo が Issue を作成できるようにするには、事前にリポジトリ側で有効にしておく必要があります。有効にするには、Bitbucket でリポジトリを開き、**Repository settings** を選択したうえで、**Features** の下で Issue トラッカーを有効にします。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、`https://bitbucket.org` を設定します。
- **Email** は、API トークンの発行元となる Atlassian アカウントのメールアドレスを設定します。
- **API Token** は、スコープ付きの Atlassian API トークンを設定します。

Bitbucket のアプリパスワードは Atlassian によって非推奨とされており、この統合では使用できません。API トークンを作成する手順は以下のとおりです。

1. [Atlassian アカウント設定](https://id.atlassian.com/manage-profile/security/api-tokens)を開き、**Security** を選択したうえで、**Create and manage API tokens** を選択します。
2. **Create API token with scopes** を選択し、トークンに名前を付けて有効期限を設定します。
3. アプリとして **Bitbucket** を選択します。
4. リポジトリの読み取り権限、および Issue の読み取り・書き込み権限をトークンに付与します。

### Issue Tracker Mapping

- **Workspace** は、リポジトリを含むワークスペースのスラッグを設定します。bitbucket.org の URL に表示される値です。
- **Repository Slug** は、Issue を作成したいリポジトリのスラッグを設定します。

### Severity Mapping Details

これは Bitbucket の Issue の Priority フィールドにマッピングされます。フォームの各項目にはデフォルト値が設定されており、各値は Bitbucket の優先度である `trivial`、`minor`、`major`、`critical`、`blocker` のいずれかである必要があります。

- **Severity Field Name**: `priority`
- **Info Mapping**: `trivial`
- **Low Mapping**: `minor`
- **Medium Mapping**: `major`
- **High Mapping**: `critical`
- **Critical Mapping**: `blocker`

### Status Mapping Details

これは Bitbucket の Issue の State フィールドにマッピングされます。各値は Bitbucket の Issue ステータスである `new`、`open`、`resolved`、`on hold`、`invalid`、`duplicate`、`wontfix`、`closed` のいずれかである必要があります。

- **Status Field Name**: `state`
- **Active Mapping**: `new`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `invalid`
- **Risk Accepted Mapping**: `wontfix`
