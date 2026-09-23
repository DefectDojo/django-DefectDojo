---
title: "Jira"
description: "DefectDojo で Jira のダウンストリームコネクタをセットアップする方法"
weight: 82
audience: pro
---
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
