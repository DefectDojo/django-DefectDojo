---
title: ダウンストリームコネクタ ツールリファレンス
description: ダウンストリームコネクタの詳細なセットアップガイド
weight: 1
audience: pro
aliases:
- /ja/en/share_your_findings/integrations_toolreference
- /ja/issue_tracking/pro_integration/integrations_toolreference/
---

DefectDojo のダウンストリームコネクタをサードパーティの Issue トラッカーと連携させるための、具体的な設定手順を以下に示します。

## Azure DevOps Boards

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、Azure の URL を設定します。例: `https://dev.azure.com/{your organization}`
- **Token** は、Azure のパーソナルアクセストークンを設定します。

Azure DevOps での認証には、作業対象の Azure プロジェクトの「Work Items」に対して「Read, Write and Manage」権限を持つ[パーソナルアクセストークン](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)が必要です。

### Issue Tracker Mapping

これらの項目は、DefectDojo が Finding または Finding Group の属性を Azure DevOps の該当プロジェクトにどのようにマッピングするかを指定します。

#### Issue Tracker Mapping Details

`Project ID` フィールドには、Azure における対象プロジェクトの名前または ID を指定します。

#### Severity Mapping Details

フォームの各項目にはデフォルト値が設定されており、内容は以下のとおりです。

- **Severity Field Name**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

#### Status Mapping Details

フォームの各項目にはデフォルト値が設定されており、内容は以下のとおりです。

- **Status Field Name**: `/fields/System.State`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

## Bitbucket

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

## GitHub

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

## GitLab

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

## Jira

Jira 統合は、DefectDojo の Finding および Finding Group を Jira プロジェクトに Issue としてプッシュし、各 Issue のステータスを Finding と同期し続け、その Finding を作成された Issue にリンクします。Jira **Cloud** と **Data Center / Server** の両方に対応しています。Jira Service Management には対応していません。

### Choosing an authentication method

まず **Jira Deployment** を設定し、続いて **Authentication Method** を選択します。

**Jira Cloud**
- **API Token（メールアドレス + トークン）** — Atlassian アカウントのメールアドレスと[API トークン](https://id.atlassian.com/manage-profile/security/api-tokens)を使った HTTP Basic 認証です。呼び出しはサイト URL に対して直接行われます。
- **OAuth 2.0（推奨）** — ブラウザでの同意操作を一度行うだけで、以降 DefectDojo がトークンの取得と更新を代行します。
- **Service Account Token** — Atlassian の[サービスアカウント](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/)向けに発行された、スコープ付きの API トークンです。

**Jira Data Center / Server**
- **Personal Access Token（推奨）**
- **Username + Password**

> **Cloud 認証が Jira に到達する仕組み:** OAuth 2.0 と Service Account はいずれも、Atlassian のゲートウェイ — `https://api.atlassian.com/ex/jira/{cloudId}` — に対して Bearer トークンで認証します。これは、あなたの `https://your-site.atlassian.net` というサイト URL とは*別のホスト*です。DefectDojo は API 呼び出しには常にこのゲートウェイを使用しますが、Finding に表示するチケットリンクは常に**サイト URL**から生成するため、ユーザーがクリックするリンクは通常どおりブラウザで開ける `.../browse/{ISSUE-KEY}` 形式のリンクになります。（API Token と Data Center の認証はサイト URL を直接呼び出すため、このような分岐はありません。）

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、Jira の**サイト URL**を設定します。例: `https://your-organization.atlassian.net`。この値はブラウザで開けるチケットリンクに使用され、API Token 認証と Data Center 認証では API のベース URL としても使用されます。
- 残りの項目は、上で選択した認証方法（メールアドレス + API トークン、OAuth クライアント資格情報、サービスアカウントトークン、PAT、またはユーザー名 + パスワード）によって異なります。

### OAuth 2.0 setup (Cloud)

[Atlassian developer console](https://developer.atlassian.com/console/myapps/)で専用のアプリを作成し、DefectDojo から接続します。

1. **Create → OAuth 2.0 integration** を選択します。*OAuth 2.0 integration* である必要があります。Connect アプリや Forge アプリでは 3LO 認可コードグラントを使用できません（使用しようとすると `grant_type is not enabled for client` というエラーになります）。
2. **Access type** の入力を求められたら **Resource-level** を選択します。これにより、トークンのスコープはユーザーが認可した単一の Jira サイトに限定されます。これは、1つの DefectDojo 接続が対象とする範囲とちょうど一致します。（**Account-level** を選択すると、その Atlassian アカウントに属するすべてのサイトへのアクセスが許可されてしまい、必要以上に広い範囲になります。）
3. **Permissions** の下で **Jira platform REST API** を追加し、以下に挙げるスコープを付与します。なお `offline_access` はこの画面には表示されません。これは DefectDojo が認可 URL 内でリクエストする標準の OAuth スコープであり、この画面で追加するものではありません。
4. **Authorization** の下で、**OAuth 2.0 (3LO)** の横にある **Configure** をクリックし、**Callback URL** を `https://<your-defectdojo-host>/integrators/jira/oauth/callback` に設定します。この値は DefectDojo のサイト URL と完全に一致している必要があります。これを有効にすることで、認可コードグラントとリフレッシュトークンが使用できるようになります。これを省略すると、`grant_type is not enabled` や `Client is not allowed to use offline_access` といったエラーが発生します。
5. **Client ID** と **Client Secret** をコピーして DefectDojo のフォームに入力し、**Submit** をクリックして接続を保存します。
6. **Connect with Jira** をクリックし、同意画面で承認します。Atlassian は DefectDojo にリダイレクトし、DefectDojo がトークンを保存して `cloudId` を自動的に解決します。成功すると「Connected」という表示が現れます。

> コールバックのホストは、あなたの DefectDojo の `SITE_URL` です。Atlassian はブラウザをそこにリダイレクトできる必要があり、その値は DefectDojo が送信する値と完全に一致していなければなりません。そのため、社内ネットワークからしか到達できない値ではなく、ユーザーが実際に DefectDojo にアクセスする際に使う正しいホスト名を使用してください。

#### Minimum OAuth scopes

DefectDojo はデフォルトで以下の4つのクラシックスコープをリクエストします。これらは同時に**必要最小限**のスコープでもあり、それぞれが特定の動作を支えています。

| Scope | Required for |
|-------|--------------|
| `read:jira-work` | プロジェクト、Issue、利用可能な遷移の読み取り（接続の検証やステータス同期に使用）。 |
| `write:jira-work` | Issue の作成・編集、およびステータス遷移の実行。 |
| `read:jira-user` | 接続時の本人確認 — DefectDojo はアクセス権の検証時に `/myself` を呼び出します。 |
| `offline_access` | **リフレッシュトークン**の発行。これがないと、接続後およそ1時間でアクセストークンが失効し、DefectDojo がそれを更新できなくなるため、接続が機能しなくなります。 |

Atlassian はグラニュラースコープよりもクラシックスコープの使用を推奨しており、上記の4つでアプリの権限範囲を最小限に保ちつつ、この統合が行うすべての処理をカバーできます。

##### Granular scope alternative

組織の方針でクラシックスコープではなく**グラニュラー**スコープが必要な場合、最小限必要となる同等のスコープセットは以下のとおりです。

| Granular scope | Required for |
|----------------|--------------|
| `read:user:jira` | `/myself` による本人確認。 |
| `read:project:jira` | 対象プロジェクトが存在することの検証。 |
| `read:issue:jira` | 同期時に Issue の現在のステータスを読み取る。 |
| `write:issue:jira` | Issue の作成・編集、**およびステータス遷移の実行** — 遷移専用の書き込みスコープは存在せず、遷移も Issue に対する書き込みの一種として扱われます。 |
| `read:issue.transition:jira` | Issue で利用可能な遷移の一覧を取得する。 |
| `offline_access` | リフレッシュトークン（クラシックスコープと同様）。 |

サイトのフィールド設定によっては、フィールドを展開するために付随する読み取りスコープが追加で必要になる場合があります。最も多いのは `read:status:jira` と `read:field:jira`（作成時にはさらに `read:issue-meta:jira`）です。プッシュが `403`「scope does not match」エラーで失敗した場合は、エラーメッセージに示されている正確なスコープを追加してください。このような付随スコープの広がりこそが、クラシックスコープが推奨される理由です。

**Service Account Token** 方式の場合は、トークンに `read:jira-work` と `write:jira-work`（および `read:jira-user`）を付与してください。あるいは、`offline_access` を除いた上記のグラニュラー相当のスコープでも構いません。サービスアカウントトークンは長期間有効で DefectDojo によって更新されることがないため、`offline_access` は適用されません。

### Issue Tracker Mapping

- **Project Key**: Issue を作成する Jira プロジェクトのキーです。例: `SEC`
- **Issue Type**: 作成する Issue の種類です。例: `Bug` や `Task`。デフォルトは `Bug` です。

### Severity Mapping Details

デフォルト値は Jira のデフォルトの優先度スキームに一致しています。プロジェクトの優先度名に合わせて編集してください。

- **Severity Field Name**: `priority`
- **Info Mapping**: `Lowest`
- **Low Mapping**: `Low`
- **Medium Mapping**: `Medium`
- **High Mapping**: `High`
- **Critical Mapping**: `Highest`

### Status Mapping Details

ステータスはプロジェクトのワークフローごとに異なるため、これらのデフォルト値は**あなたの**ワークフローのステータス名に合わせて編集することを前提としています。

- **Status Field Name**: `status`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

### Custom Fields (optional)

マッピングの **Custom Fields** ステップで、追加の Jira フィールド — 例えばクローズ時に必須となる `resolution` や `labels` など — をマッピングできます。カスタムフィールドのマッピングはそれぞれ4つの要素で構成されます。

- **Source** — 値の取得元です。プッシュされる **Finding**、**Test**、**Engagement**、**Asset** のいずれかの属性、または **Static value** です。
- **Value** — オブジェクトを Source に選んだ場合、読み取る具体的な属性を、そのオブジェクトが持つフィールドの一覧（例えば *Severity*、*CVE*、*Mitigation* のような分かりやすいラベル付き）から選択します。Source が **Static value** の場合は、リテラル値を直接入力するフリーテキストのボックスになります。
- **Vendor Field** — 書き込み先となる Jira のフィールドです。DefectDojo は Jira のフィールドカタログを読み取れるため、これは各フィールドを**表示名**で一覧表示し、内部 ID に自動的に解決してくれる検索可能なピッカーになっています。そのため、*DD Close Justification* を選択するだけで、DefectDojo は内部的に `customfield_10255` を保存します。このピッカーは接続情報から値を取得するため、接続を保存して検証済みになった後に使用できます。
- **Application point** — フィールドを送信する*タイミング*です。**ticket creation**（チケット作成時）、**every update**（更新のたびに）、または特定のステータス **transition**（Active / Closed / False Positive / Risk Accepted）の一部として送信するかを選べます。遷移スコープのフィールドは、その遷移の編集内容の一部として送信されます。これは、Jira が遷移画面でのみ受け付ける値 — 多くの場合、Issue を解決する際にワークフローが要求する `resolution` — を渡すための方法です。

### Ticket Templates (optional)

デフォルトでは、Jira の Issue は DefectDojo 組み込みのタイトルと本文を使用します。これをカスタマイズするには、マッピングの **Ticket Template** ステップで**チケットテンプレート**を割り当てます。テンプレートは、**Finding** のサマリーと説明、および **Finding Group** のサマリーと説明という、それぞれ独立して省略可能な4つの要素を定義します。空欄のままにした要素は組み込みのデフォルトにフォールバックするため、タイトルだけ、本文だけ、あるいは4つすべてを上書きすることができます。保存する前に、テンプレートエディタの **Test render** を使ってサンプルデータに対するレンダリング結果をプレビューし、未知のプレースホルダーやフィールドの文字数制限を超える値といったミスを事前に発見できます。テンプレートが後で削除された場合、それを使用していたマッピングは自動的に組み込みのデフォルトに戻ります。

### How it works

- **Create / Update / Delete:** 作成時には新しい Issue がプッシュされ、そのリンクが Finding に記録されます。更新時には既存の Issue が編集されます。Finding を削除すると、対応する Issue は強制的にクローズされます（Jira 側で何かが削除されるわけではありません）。プッシュは手動（「Push to Integrator」）でも、Issue Tracker Assignment の設定に従って自動でも行えます。
- **Status reconciliation:** 作成後（および更新のたび）、DefectDojo は Issue の現在のステータスを読み取り、マッピング先のステータスと異なる場合は、そこに到達できる単一のワークフロー遷移を探して適用します。該当する遷移が存在しない場合、マッピングはサイレントに失敗するのではなくエラーを記録します。遷移スコープのカスタムフィールドがあれば、その遷移と一緒に送信されます。
- **Ticket link:** Finding に表示されるリンクは `https://your-site.atlassian.net/browse/{ISSUE-KEY}` の形式で、常にあなたの公開サイト URL であり、内部ゲートウェイではありません。
- **Token lifecycle (OAuth):** DefectDojo がフロー全体を管理します。認可コードの交換を行い、アクセストークンとリフレッシュトークンを保存し、プッシュの前に必要に応じてトークンを更新し、更新のたびに新しいリフレッシュトークンを保存します（Atlassian は更新のたびにリフレッシュトークンをローテーションします）。
- **Credential storage:** 接続に関するすべての認証情報（パスワード、トークン、クライアントシークレット、OAuth トークン）は保存時に暗号化され、API を通じて返却されることはありません。接続を編集する際、保存済みのシークレットには「leave blank to keep」（空欄のままにすると現在の値を維持）というプレースホルダーが表示されます。

## Linear

Linear 統合を使うと、DefectDojo の Finding を[Linear](https://linear.app/)の Issue としてプッシュできます。Issue は Linear ワークスペース内の Team に作成されます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、`https://api.linear.app/graphql` を設定します。
- **API Key** は、Linear のパーソナル API キーを設定します。キーは Linear の Settings、Security & access、[API](https://linear.app/settings/account/security)から生成できます。このキーは Linear の GraphQL API に `Authorization` ヘッダーで送信されます。

### Issue Tracker Mapping

- **Team (Group) ID** は、Issue の作成先となる Linear Team の ID を設定します。以下のように Linear の GraphQL API を呼び出すことで、Team とその ID の一覧を取得できます。

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Severity Mapping Details

Linear の Issue には深刻度フィールドではなく、数値の **priority** があります。DefectDojo の各深刻度は、`1` が Urgent、`4` が Low となる Linear の優先度にマッピングされます。

- **Severity Field Name**: `Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

### Status Mapping Details

各ステータス値には、Linear Team 内の Workflow State の ID を設定する必要があります。Workflow State の ID はワークスペースごとに異なるため、デフォルト値はありません。以下のように Linear の GraphQL API を呼び出すことで、Workflow State とその ID の一覧を取得できます。

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping** は、開始済みまたは未開始の状態の ID です。例: `Todo` や `In Progress`
- **Closed Mapping** は、完了状態の ID です。例: `Done`。DefectDojo で Finding が削除されると、対応する Issue はこの状態に移動します。

## Opsgenie

Opsgenie 統合を使うと、DefectDojo の Finding および Finding Group を Opsgenie のアラートとしてプッシュでき、必要に応じて Opsgenie の Team をレスポンダーとして割り当てることもできます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、`https://api.opsgenie.com` を設定します。Opsgenie アカウントが EU サービスリージョンでホストされている場合は、代わりに `https://api.eu.opsgenie.com` を使用してください。アラートが Jira Service Management Operations 上にある場合（Atlassian は Opsgenie を JSM に統合しつつあります）は、`https://api.atlassian.com/jsm/ops/integration` を使用してください。
- **API Key** は、Opsgenie の **API integration** キーを設定します。アカウント管理者は、Opsgenie の Web アプリの **Settings > Integrations** から、タイプ **API** の統合を追加し、*Create and Update Access*（DefectDojo が接続を検証できるように *Read Access* も）を付与することで作成できます。これはパーソナル API キーではなく統合キーである点に注意してください。DefectDojo は `GenieKey` 認証方式を使用しており、これに対応しているのは統合キーのみです。

### Issue Tracker Mapping

- **Team Name**（オプション）は、作成されたアラートにレスポンダーとして追加したい Opsgenie Team の名前です。空欄のままにもできます。API integration キーが特定のチームにスコープされている場合、アラートは自動的にそのチームにルーティングされ、そうでない場合はアカウント自身のルーティングルールがレスポンダーを決定します。

### Severity Mapping Details

深刻度は、Opsgenie の固定スケールである `P1`（critical）から `P5`（informational）までを使う、アラートの **Priority** フィールドにマッピングされます。

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P5`
- **Low Mapping**: `P4`
- **Medium Mapping**: `P3`
- **High Mapping**: `P2`
- **Critical Mapping**: `P1`

深刻度が認識されない値にマッピングされている場合、priority は省略され、Opsgenie 側のデフォルト値（`P3`）が適用されます。

### Status Mapping Details

Opsgenie のアラートは `open` または `closed` であり、open のアラートはさらに `acknowledged` にもなり得ます。

- **Status Field Name**: `Status`
- **Active Mapping**: `open`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `acknowledged`

なお、Opsgenie では `closed` は最終ステータスであり、クローズされたアラートは再オープンできず、そのエイリアスも解放されます。他の一部のツールとは異なり、Opsgenie は作成後もコンテンツの編集を許可しているため、更新された Finding をプッシュすると、ステータスとあわせてメッセージ、説明、priority も同期されます。

DefectDojo は、Finding または Finding Group から導出した安定したキーを各アラートの **alias** として設定し、Opsgenie はこの alias によって open 状態のアラートを重複排除します。そのため、同じ Finding を再度プッシュすると、新しいアラートを作成するのではなく、既存の open なアラートが更新されます。

## PagerDuty

PagerDuty 統合を使うと、DefectDojo の Finding および Finding Group を、選択した PagerDuty の Service 上で開かれる PagerDuty のインシデントとしてプッシュできます。

### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、`https://api.pagerduty.com` を設定します。PagerDuty アカウントが EU サービスリージョンでホストされている場合は、代わりに `https://api.eu.pagerduty.com` を使用してください。
- **API Token** は、PagerDuty の REST API キーを設定します。アカウント管理者は、PagerDuty の Web アプリの **Integrations > API Access Keys > Create New API Key** から作成できます。「Read-only」はチェックしないでください。DefectDojo はインシデントの作成・更新を行う必要があります。
- **From Email** は、PagerDuty アカウント上の有効なユーザーのメールアドレスを設定します。PagerDuty はインシデントの作成・更新時にこのアドレスを必要とし、インシデントのリクエスターとして表示されます。

### Issue Tracker Mapping

- **Service ID** は、インシデントを開く PagerDuty の Service の ID を設定します。PagerDuty で該当の Service を表示中の URL の末尾から取得できます。例: `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`

### Severity Mapping Details

デフォルトでは、`high` または `low` のみを受け付ける PagerDuty のインシデント **Urgency** フィールドにマッピングされます。

- **Severity Field Name**: `Urgency`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `low`
- **High Mapping**: `high`
- **Critical Mapping**: `high`

代わりに、PagerDuty アカウントで[Priorities](https://support.pagerduty.com/main/docs/incident-priority)が有効になっている場合は、深刻度を Priority 名にマッピングすることもできます。その場合は **Severity Field Name** を `Priority` に設定し、マッピング値としてアカウントの Priority 名（例えば `P1` から `P5` まで）を使用します。Priority にマッピングする場合、インシデントの Urgency は Service 自体の urgency ルールに委ねられます。

### Status Mapping Details

PagerDuty のインシデントには、`triggered`、`acknowledged`、`resolved` という3つのステータスがあります。

- **Status Field Name**: `Status`
- **Active Mapping**: `triggered`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `resolved`
- **Risk Accepted Mapping**: `acknowledged`

なお、`resolved` は PagerDuty における最終ステータスであり、resolved のインシデントは再オープンできません。また、PagerDuty はインシデントの作成後にタイトルや説明を編集することを許可していないため、更新された Finding をプッシュすると、ステータス、urgency、priority は同期されますが、コンテンツの変更は同期されません。

## ServiceNow

ServiceNow 連携を使用すると、DefectDojo の検出事項を ServiceNow のインシデントとしてプッシュできます。

### インスタンスのセットアップ

DefectDojo は OAuth 2.0 経由で ServiceNow に認証します。OAuth 認証情報の作成方法は ServiceNow のリリースによって異なります。新しいリリース(Zurich 以降)ではクライアントクレデンシャルグラントを使用し、それより前のリリースではリフレッシュトークンを使用します。

#### ServiceNow Zurich 以降(クライアントクレデンシャル)

最近の ServiceNow リリースでは、従来の「外部クライアント用の OAuth API エンドポイントの作成」オプションは非推奨となり、代わりに **新しいインバウンド統合エクスペリエンス(New Inbound Integration Experience)** が採用されています。これはサービスアカウントに紐づいた OAuth **クライアントクレデンシャル** グラントを発行します。

1. 左側のナビゲーションバーで「Application Registry」を検索して選択します。
2. **New** をクリックし、**New Inbound Integration Experience** を選択します。
3. **New Integration → OAuth - Client credentials grant** を選択します。
4. **OAuth Application User** に、インシデントを作成するサービスアカウントを設定します。このアカウントのロールによって、DefectDojo が書き込める内容が決まります。
5. 登録を保存します。ServiceNow が **Client ID** と **Client Secret** を自動生成します(登録作成時にはこれらのフィールドを空欄のままにしてください)。

その後、DefectDojo 側で以下を設定します。

- **Instance Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceNow サーバーの URL を設定します。例: `https://your-organization.service-now.com/`。
- **Client ID** には、OAuth 登録で取得した Client ID を設定します。
- **Client Secret** には、OAuth 登録で取得した Client Secret を設定します。

Refresh Token、Username、Password の各フィールドは空欄のままにしてください。DefectDojo は同期のたびに新しいクライアントクレデンシャルトークンをリクエストします。

#### それ以前の ServiceNow リリース(リフレッシュトークン)

従来の登録方式がまだ利用できるリリースでは、ServiceNow にインシデントをプッシュする User または Service アカウントに紐づいたリフレッシュトークンを取得します。

1. 左側のナビゲーションバーで「Application Registry」を検索して選択します。
2. 「New」をクリックします。
3. 「Create an OAuth API endpoint for external clients」を選択します。
4. 必須フィールドを入力します。
    * Name: アプリケーションの分かりやすい名前を入力します(例: Vulnerability Integration Client)。
    * (任意)トークンの有効期間を調整します。
    * Access Token Lifespan: デフォルトは 1800 秒(30 分)です。
    * Refresh Token Lifespan: デフォルトは 8640000 秒(約 100 日)です。
5. 「Submit」をクリックしてアプリケーションレコードを作成します。
6. 送信後、リストからアプリケーションを選択し、**Client ID と Client Secret** フィールドを控えておきます。

次に、この登録を使用してリフレッシュトークンを取得する必要がありますが、これは ServiceNow API 経由でのみ取得できます。ターミナルウィンドウを開き、以下を貼り付けてください(`{{}}` で囲まれた変数は実際のユーザー情報に置き換えます)。

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

ServiceNow の認証情報が正しく、ServiceNow への管理者レベルのアクセスが許可されている場合、RefreshToken を含むレスポンスが返されます。DefectDojo との連携を完了するには、そのトークンが必要です。

- **Instance Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceNow サーバーの URL を設定します。例: `https://your-organization.service-now.com/`。
- **Refresh Token** には、取得したリフレッシュトークンを入力します。
- **Client ID** には、OAuth App Registration で設定した Client ID を設定します。
- **Client Secret** には、OAuth App Registration で設定した Client Secret を設定します。

### 深刻度マッピングの詳細

これは ServiceNow の Impact フィールドにマッピングされます。
- **情報マッピング**: `1`
- **低マッピング**: `1`
- **中マッピング**: `2`
- **高マッピング**: `3`
- **重大マッピング**: `3`

### ステータスマッピングの詳細

- **ステータスフィールド名**: `State`
- **アクティブマッピング**: `New`
- **クローズマッピング**: `Closed`
- **誤検知マッピング**: `Resolved`
- **リスク受容済みマッピング**: `Resolved`

各マッピングには、標準のステートラベル(`New`、`In Progress`、`On Hold`、`Resolved`、`Closed`、`Cancelled`)または数値のステート値を指定できます。インシデントのステートがカスタマイズされているインスタンス、または `incident` 以外のテーブルを対象とする場合は、インスタンスの選択リストにある数値の **ステート値** を使用してください。標準セット外の数値は、設定したとおりにそのまま ServiceNow へ送信されます。組み込みの Resolution コードのデフォルトは、標準の resolved/closed ステートにのみ付随するため、カスタムのステート値を使用する場合は、下記のクローズおよび解決フィールドのマッピングと組み合わせてください。

### クローズおよび解決フィールド

一部の ServiceNow インスタンスでは、インシデントが resolved または closed ステートに移行する際に、**Resolution code**(`close_code`)などのフィールドを必須とする Data Policy が適用されています。これらのフィールドを指定せずに DefectDojo がインシデントをクローズしようとすると、ServiceNow は HTTP 403 の *「Data Policy Exception」* で書き込みを拒否し、その理由は連携のエラー表示に記録されます。

**Custom Field Mappings** を使用して、必須フィールドをステート変更に紐づけ、**Apply On** にそれらを適用すべき区分を設定します。

- **Transition to Closed** — 検出事項が緩和済み/クローズになったときに送信されます。
- **Transition to False Positive** — 検出事項が誤検知としてマークされたときに送信されます。
- **Transition to Risk Accepted** — 検出事項がリスク受容されたときに送信されます。

たとえば、必須の Resolution code を満たすには次のようにします。

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

注記:

- Field Name は ServiceNow のカラム名です — `close_code`、`close_notes`、またはカスタムの `u_...` フィールドなど。
- Transition マッピングは、レコードのステートが実際に変化したときに発火します。たとえば、最初にプッシュされた時点で既にクローズしている検出事項、レコードをクローズまたは再オープンする更新、チケットリンクが削除されたときの強制クローズなどです。変化のないレコードの通常の更新では再送信されないため、`work_notes` などのジャーナルフィールドには遷移ごとに 1 件のエントリが記録されます。
- `assignment_group` や `assigned_to` などの参照フィールドには、表示名ではなく **sys_id** を指定する必要があります。
- JSON として解釈できる値は、型付きで送信されます: `true`、`42`、`[...]`、`{...}` — および、フィールドをクリアする `null`。このようなテキストをリテラルの文字列として送信するには、二重引用符で囲みます(例: `"null"`)。
- `short_description`、`description`、`state`、`impact`、`urgency`、`priority` は説明テンプレートおよび深刻度/ステータスのマッピングによって管理されるため、カスタムフィールドマッピングでは設定できません。
- `incident` 以外のテーブルでも、標準のインシデントセットに一致するステート値(`1`、`2`、`3`、`6`、`7`、`8`)は、`6`/`7`/`8` での自動 Resolution コードのデフォルトを含め、引き続きインシデントの意味で解釈されます。カスタムテーブルではその範囲外のステート値を使用するか、上記のようにクローズフィールドを明示的に指定することを推奨します。

## ServiceNow SecOps

ServiceNow SecOps 連携(**ServiceNow SecOps / Vulnerability Response** とも呼ばれます)は、DefectDojo の検出事項および検出事項グループを ServiceNow のセキュリティテーブル — **Security Incident**(`sn_si_incident`)または **Vulnerable Item**(`sn_vul_vulnerable_item`)— にプッシュし、検出事項の変化(作成、更新、解決/クローズ)に応じて同期を維持します。これは上記の ServiceNow 課題管理連携に対応するセキュリティ運用版であり、Security Incident Response(SIR)または Vulnerability Response(VR)アプリケーションを利用している場合は ServiceNow SecOps を使用してください。

### インスタンスのセットアップ

- **Instance Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceNow サーバーの URL を設定します。例: `https://your-organization.service-now.com/`。

ServiceNow SecOps は 3 種類の認証方式をサポートしています。**いずれか 1 つ** を指定してください。

- **OAuth 2.0** — **Client ID**、**Client Secret**、**Refresh Token** を入力します。取得方法は上記の[ServiceNow](#servicenow)セクションで説明した手順とまったく同じです(Application Registry で OAuth API エンドポイントを作成し、`/oauth_token.do` で認証情報をリフレッシュトークンと交換します)。あるいは、リフレッシュトークンの代わりに OAuth のパスワードグラントを使用する場合は、**Client ID** と **Client Secret** に加えて **Username** と **Password** を指定します。
- **API Key** — **API Key** を入力します。これは `x-sn-apikey` ヘッダーとして送信されます。このキーは、インスタンス側で Inbound Authentication Profile と REST API Access Policy が紐づけられるまでは、何も認証しません。
- **HTTP Basic** — サービスアカウントの **Username** と **Password** を入力します。

サービスアカウント(または OAuth クライアント)には、対象テーブルへの書き込みアクセス権が必要です。

### 課題管理マッピング

- **Target Table** は、レコードの書き込み先となる ServiceNow テーブルを選択します: **Security Incident**(`sn_si_incident`、デフォルト)または **Vulnerable Item**(`sn_vul_vulnerable_item`)。

### 深刻度マッピングの詳細

Security Incident の場合、これは **Impact** フィールドにマッピングされます。ServiceNow はインシデントの Priority を Impact と Urgency から導出するため、自分で Urgency をマッピングしない限り、Urgency はマッピングされた Impact と同じ値になります。Vulnerable Item の場合は、インスタンスで使用しているリスクフィールドに深刻度をマッピングしてください。以下のデフォルト値は、標準の SIR Impact スケール(`1` 高、`2` 中、`3` 低)に対応しており、編集可能です。

- **深刻度フィールド名**: `impact`
- **情報マッピング**: `3`
- **低マッピング**: `3`
- **中マッピング**: `2`
- **高マッピング**: `1`
- **重大マッピング**: `1`

### ステータスマッピングの詳細

これはレコードの **State** フィールドにマッピングされます。ステート値は数値コードであり、Security Incident テーブルと Vulnerable Item テーブルで異なり、インスタンスごとにカスタマイズできるため、自分の設定と照らし合わせて確認してください。以下のデフォルト値は、標準の SIR ステートコード(`16` Analysis、`3` Closed)を使用しています。

- **ステータスフィールド名**: `state`
- **アクティブマッピング**: `16`
- **クローズマッピング**: `3`
- **誤検知マッピング**: `3`
- **リスク受容済みマッピング**: `3`

レコードがクローズされると、DefectDojo は ServiceNow の **Close Code** と **Close Notes** も設定します(クローズした検出事項には `Resolved`、対応するステートには `False positive` および `Risk accepted`)。

### ServiceNow SecOps 固有の動作

- **重複排除** — 各レコードには、検出事項または検出事項グループの DefectDojo 識別子が `correlation_id` にタグ付けされます。レコードを作成する前に、DefectDojo は `correlation_id` で既存のレコードを検索します。一致するものが見つかった場合は、重複作成せずにそれを採用して更新するため、再同期はべき等です。
- **更新内容** は、顧客に見える Comments ではなく、レコードの **Work notes** ジャーナル(内部用)に投稿されます。
- **削除時の解決(Resolve on delete)** — DefectDojo で検出事項を削除すると、ServiceNow のレコードは削除されるのではなく、解決/クローズされます(State + Close Code)。レコードが物理削除されることはありません。
- **参照フィールド** — 任意項目の `cmdb_ci`、`assignment_group`、`assigned_to` の値は表示名として指定できます。DefectDojo はそれぞれを `sys_id` に解決します。解決できない名前は、プッシュを失敗させることなく、警告とともに除外されます。

## Shortcut

Shortcut 連携を使用すると、DefectDojo の検出事項を [Shortcut](https://www.shortcut.com/) の Story としてプッシュできます。Story は Story タイプ Bug で作成され、Shortcut ワークスペース内の Team に割り当てられます。

### インスタンスのセットアップ

- **Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には `https://api.app.shortcut.com` を設定します。
- **API Token** には、Shortcut の API トークンを設定します。トークンは Shortcut の Settings > Your Account > [API Tokens](https://app.shortcut.com/settings/account/api-tokens) で生成できます。

### 課題管理マッピング

- **Team (Group) ID** には、Story の作成先となる Shortcut Team の UUID を設定します。この UUID は、Shortcut で Team ページを開いて URL から識別子をコピーするか、Shortcut API を呼び出すことで確認できます。

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### 深刻度マッピングの詳細

各深刻度の値は、ラベルとして Story に適用されます。ラベルが Shortcut にまだ存在しない場合は自動的に作成されるため、以下のデフォルト値をそのまま使用することも、任意のラベル名に置き換えることもできます。検出事項の深刻度が変更されると、古い深刻度ラベルが Story から削除され、新しいラベルが追加されます。

- **深刻度フィールド名**: `Label`
- **情報マッピング**: `sev-info`
- **低マッピング**: `sev-low`
- **中マッピング**: `sev-medium`
- **高マッピング**: `sev-high`
- **重大マッピング**: `sev-critical`

### ステータスマッピングの詳細

各ステータスの値には、Shortcut ワークスペース内の Workflow State の数値 ID を設定する必要があります。Workflow State ID はワークスペースごとに固有であるため、デフォルト値はありません。Workflow State とその ID の一覧は、Shortcut API を呼び出すことで取得できます。

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **ステータスフィールド名**: `Workflow State ID`
- **アクティブマッピング**: 未着手の作業を表すステート(たとえば Backlog や To Do のステート)の ID。
- **クローズマッピング**: Done タイプのステートの ID。DefectDojo で検出事項が削除されると、その Story はこのステートに移動します。
- **誤検知マッピング**: 誤検知の検出事項に使用するステートの ID。
- **リスク受容済みマッピング**: リスク受容済みの検出事項に使用するステートの ID。

## Freshservice

Freshservice 連携を使用すると、DefectDojo の検出事項および検出事項グループを Freshservice のチケットとしてプッシュし、任意の agent Group に割り当てることができます。

### インスタンスのセットアップ

- **Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、Freshservice の URL を設定します: `https://yourcompany.freshservice.com`。
- **API Key** には、Freshservice の API キーを設定します。プロフィール画像(右上)をクリックして **Profile settings** を開き、キャプチャを完了すると、**Delegate Approvals** セクションの下、右側にキーが表示されます。キーが表示されない場合は、アカウントレベルで API アクセスが無効になっている可能性があるため、管理者に先に有効化してもらう必要があります。
- **Requester Email** には、チケットの依頼元となるメールアドレスを設定します。Freshservice はすべてのチケットに依頼者を必須としているため、DefectDojo はこのアドレスを依頼者としてチケットを作成します。

### 課題管理マッピング

- **Group ID** には、チケットの割り当て先となる Freshservice の agent group の数値 ID を設定します。**Admin > Agent Groups** でグループを表示しているときの URL から確認できます。
- **Workspace ID**(任意)は、複数ワークスペースのアカウントで、チケットを特定のワークスペースに振り分けます。プライマリワークスペースを使用する場合は空欄のままにします。

### 深刻度マッピングの詳細

これは Freshservice チケットの **Priority** フィールドにマッピングされます。このフィールドは数値コード(`1` Low、`2` Medium、`3` High、`4` Urgent)を使用しますが、優先度名で指定することもできます。

- **深刻度フィールド名**: `Priority`
- **情報マッピング**: `1`
- **低マッピング**: `1`
- **中マッピング**: `2`
- **高マッピング**: `3`
- **重大マッピング**: `4`

### ステータスマッピングの詳細

これはチケットの **Status** フィールドにマッピングされます。このフィールドは数値コード(`2` Open、`3` Pending、`4` Resolved、`5` Closed)を使用しますが、ステータス名で指定することもできます。

- **ステータスフィールド名**: `Status`
- **アクティブマッピング**: `2`
- **クローズマッピング**: `5`
- **誤検知マッピング**: `5`
- **リスク受容済みマッピング**: `3`

Freshservice 固有の動作として、いくつか注意すべき点があります。

- 更新はチケットの内容全体を同期します。Freshservice では、作成後に件名と説明を編集できます。
- 検出事項が削除されると、チケットは削除されるのではなくクローズされます。既に Resolved または Closed になっているチケットはそのままにされます。クローズ時には解決メモが自動的に添付されるため、これを必須とするアカウント(よくあるビジネスルール)でもクローズが受け付けられます。
- 一部のアカウントでは、チケットの優先度を Impact/Urgency マトリクスやビジネスルールから算出し、作成時に送信された優先度を無視します。DefectDojo はこれを検知し、後続の更新でマッピングされた優先度を再適用するため、マッピングは引き続き反映されます。

## ServiceDesk Plus

ManageEngine ServiceDesk Plus 連携を使用すると、DefectDojo の検出事項および検出事項グループを ServiceDesk Plus のリクエストとしてプッシュし、任意の support Group に割り当てることができます。**クラウド版**(ServiceDesk Plus OnDemand)と **オンプレミス版** の両方が同じ連携でサポートされており、どちらのモードが使われるかは指定した認証情報によって決まります。

### インスタンスのセットアップ

- **Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、ServiceDesk Plus の URL を設定します。クラウド版の場合は `https://sdpondemand.manageengine.com`(またはお使いのリージョンに対応する URL)、オンプレミスインストールの場合はサーバーのアドレスを設定します。

続いて、以下の 2 種類の認証情報セットのうち **いずれか一方** を指定します。

#### オンプレミス: Technician Key

- **Technician Key** には、サーバーの **Admin > General Settings > API** で技術者(Technician)向けに生成した API キーを設定します。Zoho OAuth の各フィールドは空欄のままにしてください。

#### クラウド: Zoho OAuth

クラウド版は Zoho Accounts OAuth を通じて認証します。

1. [Zoho API Console](https://api-console.zoho.com/) を開き、**Self Client** を作成します。
2. **Client ID** と **Client Secret** を控えておきます。
3. Self Client の「Generate Code」タブで、スコープ `SDPOnDemand.requests.ALL` を入力し、有効期間を選択してコードを生成します。
4. コードをリフレッシュトークンと交換します。

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. インスタンスのフォームに **Client ID**、**Client Secret**、および取得した **Refresh Token** を入力します。アカウントが米国データセンター以外でホストされている場合は、**Token URL** をお使いのリージョンの Zoho Accounts エンドポイント(例: `https://accounts.zoho.eu/oauth/v2/token`)に設定してください。

### 課題管理マッピング

- **Group Name** には、リクエストの割り当て先となる ServiceDesk Plus の support group の名前を、**Admin > Users > Support Groups** に表示されるとおりに設定します。

### 深刻度マッピングの詳細

これは、アカウントの優先度名を使用して、ServiceDesk Plus のリクエストの **Priority** フィールドに名前でマッピングされます。

- **深刻度フィールド名**: `Priority`
- **情報マッピング**: `Low`
- **低マッピング**: `Normal`
- **中マッピング**: `Medium`
- **高マッピング**: `High`
- **重大マッピング**: `High`

### ステータスマッピングの詳細

これは、リクエストの **Status** フィールドに名前でマッピングされます。デフォルトでは組み込みのステータスを使用します。

- **ステータスフィールド名**: `Status`
- **アクティブマッピング**: `Open`
- **クローズマッピング**: `Closed`
- **誤検知マッピング**: `Closed`
- **リスク受容済みマッピング**: `On Hold`

ServiceDesk Plus 固有の動作として、いくつか注意すべき点があります。

- 更新はリクエストの内容全体を同期します。多くのトラッカーとは異なり、ServiceDesk Plus では作成後に件名と説明を編集できます。
- 検出事項が削除されると、リクエストは削除されるのではなくクローズされます。既に Closed または Resolved になっているリクエストはそのままにされます。
- アカウント側でクローズ時にフィールド(たとえば resolution)を必須にしている場合、DefectDojo からプッシュされたクローズがそのルールによって拒否されることがあり、その場合は Integration errors テーブルに表示されます。

## Zendesk

Zendesk 連携を使用すると、DefectDojo の検出事項および検出事項グループを Zendesk のチケットとしてプッシュし、任意の Zendesk Group に割り当てることができます。

### インスタンスのセットアップ

- **Label** には、この連携を識別するために使用したいラベルを設定します。
- **Location** には、Zendesk アカウントの URL を設定します。例: `https://your-subdomain.zendesk.com`。
- **Email** には、API トークンの持ち主である Zendesk エージェントのメールアドレスを設定します。
- **API Token** には、Zendesk の API トークンを設定します。管理者は Zendesk Admin Center の **Apps and integrations > APIs > Zendesk API** でトークンを作成できます(トークンアクセスを有効化しておく必要があります)。

### 課題管理マッピング

- **Group ID** には、チケットの割り当て先となる Zendesk Group の数値 ID を設定します。Admin Center の **People > Team > Groups** で確認するか、グループを表示しているときの URL から確認できます。

### 深刻度マッピングの詳細

これは Zendesk チケットの **Priority** フィールドにマッピングされます。このフィールドには `low`、`normal`、`high`、`urgent` を指定できます。

- **深刻度フィールド名**: `Priority`
- **情報マッピング**: `low`
- **低マッピング**: `low`
- **中マッピング**: `normal`
- **高マッピング**: `high`
- **重大マッピング**: `urgent`

### ステータスマッピングの詳細

Zendesk チケットは、`new`、`open`、`pending`、`hold`、`solved`、`closed` のステータスをサポートしています。`hold` を使用するには、事前にアカウントで有効化しておく必要がある点に注意してください。

- **ステータスフィールド名**: `Status`
- **アクティブマッピング**: `new`
- **クローズマッピング**: `solved`
- **誤検知マッピング**: `solved`
- **リスク受容済みマッピング**: `pending`

Zendesk 固有の動作として、いくつか注意すべき点があります。

- Zendesk ではチケットの説明が最初のコメントとして扱われ、作成後は編集できません。そのため、更新された検出事項をプッシュすると、チケットの件名・優先度・ステータスは同期されますが、説明の変更は同期されません。
- 検出事項が削除されると、チケットは削除されるのではなく `solved` にマークされます。Zendesk は solved になったチケットを一定期間後に自動的にクローズします。
- `closed` は最終ステータスです。クローズされたチケットはまったく更新できず、チケットがクローズ済みの検出事項をプッシュするとエラーが報告されます。
