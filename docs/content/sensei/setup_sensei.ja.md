---
title: Sensei をセットアップする
description: GitHub、GitLab、Bitbucket、Azure DevOps を接続し、ホスト型スキャン用にリポジトリをオンボードします
draft: false
audience: pro
weight: 2
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Sensei は DefectDojo Pro 限定機能であり、現在 BETA 版です。</span>

Sensei のセットアップは2つの部分から構成されます。**ソースコード管理プロバイダーを接続する**、次に **スキャン対象のリポジトリをオンボードする** という流れです。これを行うには、グローバルの **Maintainer** または **Owner** ロールが必要です。Sensei は以下に対応しています。

- **GitHub**: GitHub App(github.com または **GitHub Enterprise Server**)。
- **GitLab**: アクセストークン(gitlab.com またはセルフマネージド)。
- **Bitbucket**: Cloud または Server/Data Center。OAuth(推奨)、Atlassian API トークン、またはアクセストークンを使用します。
- **Azure DevOps**: 個人用アクセストークン(Personal Access Token)。

オンボーディング、設定、スキャン、修正はすべてのプロバイダーで共通で、異なるのは初回の接続部分のみです。このページでは [GitHub App の接続](#connect-a-github-app)、[GitHub Enterprise Server](#connect-github-enterprise-server)、[GitLab](#connect-gitlab)、[Bitbucket](#connect-bitbucket)、[Azure DevOps](#connect-azure-devops) の接続について説明します。[リポジトリの選択](#select-repositories) 以降の手順はすべてのプロバイダーで共通です。

Sensei ハブの **Add Repositories** が両方の入口になります。クリックすると各接続を名前でリストしたメニューが開き、いずれかを選んでそこからリポジトリを選択するか、**Connect a new source** を選んでまだ接続していないプロバイダーをセットアップできます。何も接続されていない場合は、直接接続フローに進みます。

![リポジトリの追加メニュー](images/add_repositories_menu.png)

## Connections

**接続 (connection)** とは、設定済みのソースコード管理アイデンティティを1つ表します。GitHub App の登録、GitLab トークン、Bitbucket ワークスペース、または Azure DevOps 組織のいずれかです。リポジトリは接続からオンボードし、その管理や切断も **Connections** ページ(Sensei ハブの **Connections** ボタン)から行います。

![Sensei の接続](images/connections.png)

この表には、各接続のラベル、アイデンティティ、オンボード済みリポジトリ数、作成日、プロバイダーが一覧表示されます。行アクション(各行の左側にあるメニュー)を使うと、そのプロバイダー上で接続を管理したり、その接続からリポジトリを追加したり、編集用に開いたり(**Update credentials**、GitHub の場合は **Manage App & installations**)、接続を切断したりできます。

![接続の行アクション](images/connection_row_menu.png) **Add a connection** で既存の接続の詳細が表示されることはありません。すでにある接続に関するすべての情報は、その行からアクセスできる専用の画面にあります。

### Several organizations per provider

1つのインスタンスには、**プロバイダーごとに必要な数の接続**を、組織・グループ・ワークスペースごとに1つずつ保持できます。

- **GitHub:** 各組織またはユーザーアカウントに App をインストールします(**Install on another account**)。1つの App 登録ですべてをカバーできます。github.com とは別に GitHub Enterprise Server ホストなど登録を分けたい場合は **Register another GitHub App** を使用します。App 自体の状態(インストール、権限の承認、**Install on another account**、**Disconnect this App**)は、その行の **Manage App & installations** から開くその接続専用の画面にあります。登録が複数ある場合は、そこにあるピッカーで切り替えられます。
- **GitLab:** グループトークンまたはプロジェクトトークンごとに1つの接続を作成します。同じホスト上に複数持つこと(`gitlab.com` とセルフマネージドの両方など)も可能です。
- **Bitbucket:** ワークスペースごとに1つの接続。
- **Azure DevOps:** PAT は組織スコープであるため、組織ごとに1つの接続。

Connections ページで **Connect** を実行するたびに接続が**追加**されるため、2つ目のグループやワークスペースを接続しても最初の接続が置き換わることはありません。表の中で区別できるよう、それぞれに **Connection Label** を付けてください。各リポジトリはオンボードに使用した接続を記録しており、そのスキャン・プルリクエスト・修正はその接続の認証情報を使用します。同じプロバイダーに複数の接続が存在する場合、オンボーディング時にどれを使うか自動で選ばれるのではなく選択を求められます。

トークン、PAT、またはアプリパスワードをローテーションするには、その接続の行にある **Update credentials** を使用します。開く画面は単一の接続に関するものであり、タイトルは **Edit connection: \<label\>** となり、保存するとその接続が更新されます(新しい接続が追加されるわけではありません)。**Connect** から到達した場合は、タイトルは **Add a connection** になります。(GitHub App の認証情報は GitHub 側で管理されます。)

プロバイダーの **webhook URL はすべての接続で共有**され、各接続はそれぞれ自分のシークレットを検証するため、グループ・ワークスペース・組織ごとに異なる URL を用意する必要はありません。

> **⚠️ 切断は破壊的操作です:** 接続を切断すると、その接続自体**と、それを通じてオンボードされたすべてのリポジトリ**が削除されます。この操作は元に戻せません。

## Choose a source-control provider

Sensei ハブで **Add Repositories → Connect a new source**(または Connections ページの **Connect**)を選択して **Add a connection** を開き、ソースコード管理プロバイダー(**GitHub**(GitHub Enterprise Server を含む)、**GitLab**、**Bitbucket**、**Azure DevOps**)を選びます。各プロバイダーの接続手順は以下のとおりです。

![ソースコード管理プロバイダーを選択した状態の Add a connection 画面](images/setup_providers.png)

## Connect a GitHub App

Sensei はすべて GitHub App 経由で動作します。組織またはアカウントにインストールすると、DefectDojo は短命なトークンを使用して PR のオープン、スキャン、修正の適用を行います。貼り付けるものもローテーションするものもありません。

Sensei ハブで **Add Repositories → Connect a new source**(または Connections ページの **Connect**)を選択して **Add a connection** を開きます。

### Step 1: Create the App

スキャン対象のリポジトリを所有する **organization** を入力します(個人アカウントに App を作成する場合は空欄のままにします)。その後 **Create GitHub App** をクリックします。GitHub がアプリ名、URL、権限を事前入力するので、内容を確認して承認してください。

![GitHub App の作成](images/setup_create_app.png)

GitHub の確認ページが開きます。**Create GitHub App for `<org>`** をクリックすると、そのアプリがその組織の配下に登録されます。

![GitHub 上でアプリ作成を確認する](images/github_create_app.png)

> **🔑 Tip:** スキャン予定のリポジトリを所有しているのと同じ組織で App を作成してください。App のオーナーは作成時に設定されます。

### Step 2: Install the App

DefectDojo に戻ると、アプリは *configured*(設定済み)と表示されます。**Install on GitHub** をクリックして組織にインストールします。

![App のインストールと管理を行う、その接続専用の画面](images/setup_install_app.png)

GitHub 上で、インストール先(自分の組織)を確認し、**All repositories** か **Only select repositories** かを選択して、要求される権限を確認します。Sensei がスキャンと修正 PR のオープンを行うには、actions・issues・metadata への読み取りアクセス、および checks・code・pull requests・secrets・workflows への読み書きアクセスが必要です。**Install** をクリックします。

![組織に App をインストールする](images/github_install_app.png)

## Connect GitLab

Sensei は **GitLab** にも対応しており、**gitlab.com** と **セルフマネージド** インスタンスの両方で使用できます。GitHub App の代わりに、GitLab は **プロジェクトまたはグループのアクセストークン** と webhook を使って接続します。Sensei はそのトークンを使ってスキャン、マージリクエストのオープン、修正の適用を行います。

Sensei ハブで **Add Repositories → Connect a new source**(または Connections ページの **Connect**)を選択して **Add a connection** を開き、ソースコード管理プロバイダーとして **GitLab** を選択します。

### Step 1: Create an access token

GitLab で、スキャンしたいプロジェクト(またはグループ)を開き、**Settings → Access tokens → Add new token** に進みます。

- **Role:** 修正用ブランチのプッシュとマージリクエストのオープンには **Developer** で十分です。プロジェクトのプッシュルールで必要な場合は **Maintainer** を選択してください。
- **Scopes:** **`api`** と **`write_repository`**。

トークンを作成し、生成された `glpat-…` の値をコピーします(GitLab はこの値を一度しか表示しません)。

> **🔑 Tip:** **グループ** アクセストークンはそのグループ内のあらゆるプロジェクトをオンボードできます。**プロジェクト** アクセストークンは単一のプロジェクトに限定されます。

### Step 2: Connect

**GitLab** を選択した状態の **Add a connection** に戻り、以下を入力します。

- **GitLab Base URL:** `https://gitlab.com`、またはセルフマネージドインスタンスの URL(例: `https://gitlab.example.com`)。
- **Access Token:** ステップ1で取得した `glpat-…` トークン。
- **Webhook Secret:** 空欄のままにすると自動生成されます(推奨)。このシークレットは次のステップで webhook に追加します。

**Add GitLab connection** をクリックします。DefectDojo はトークンを検証して暗号化して保存し、その後プロジェクトの一覧表示、マージリクエストのオープン、スキャンの実行ができるようになります。

### Step 3: Add the webhook

DefectDojo が push、マージリクエスト、コメントの各イベントを受け取れるように、オンボード予定の GitLab プロジェクト**それぞれ**に webhook を追加します(**Settings → Webhooks → Add new webhook**)。

- **URL:** 接続画面に表示される webhook URL(`https://<your-defectdojo-host>/sensei/gitlab/webhooks`)。
- **Secret token:** ステップ2の webhook シークレット。
- **Trigger events:** **Push events**、**Merge request events**、**Comments** を有効にします。

SSL 検証は有効なままにして **Add webhook** をクリックし、**Test → Push events** を使って DefectDojo が **HTTP 200** で応答することを確認します。

接続後、**Choose Projects** をクリックして [リポジトリの選択](#select-repositories) に進みます。オンボーディング、設定、スキャンは GitHub と同じように動作します。

> **GitLab での対応表現:** このガイドで *pull request* と表記している箇所は、GitLab では **merge request** に相当します。プルリクエストの **status check** は、GitLab ではマージリクエストのヘッドコミットに対する **commit status** として投稿されます。

## Connect GitHub Enterprise Server

Sensei は github.com と同じ GitHub App モデルを使用して **GitHub Enterprise Server (GHES)** に対応しています。異なるのはホストのみです。App マニフェストによる自動作成フローは github.com 限定であるため、GHES では **App を手動で作成**し、その認証情報とホストを DefectDojo に入力する必要があります。

### Step 1: Create the App on your GHES host

GitHub Enterprise Server インスタンスで **Settings → Developer settings → GitHub Apps → New GitHub App** に進み、Sensei が github.com 上で使用するのと同じ権限(actions・issues・metadata への読み取り、checks・code・pull requests・secrets・workflows への読み書き)を持つ App を作成します。webhook の送信先は `https://<your-defectdojo-host>/sensei/webhooks` に設定します。**private key** を生成してダウンロードし、**App ID** を控えておきます(OAuth の **Client ID/Secret** を設定した場合はそれも控えます)。

### Step 2: Connect manually

**GitHub** を選択した接続画面で **Set up manually instead** をクリックし、以下を入力します。

- ステップ1の **App ID** と **Private Key (PEM)**(設定した場合は Client ID/Secret と Webhook Secret も)。
- **GitHub Enterprise host:** インスタンスのホスト。例: `https://github.example.com`。DefectDojo はこれから API(`/api/v3`)と web のオリジンを導出します。github.com の場合は空欄にします。

**Save App credentials** をクリックします。DefectDojo はエンタープライズホストに対して認証情報を検証したうえで、App をインストールし、[リポジトリの選択](#select-repositories) に進みます。

> **🔑 Tip:** ホストは DefectDojo から到達可能である必要があります(また webhook のために DefectDojo も GHES から到達可能である必要があります)。ネットワーク内で相互に到達できる限り、内部限定のホストでも問題ありません。

## Connect Bitbucket

Sensei は **Bitbucket Cloud**(`bitbucket.org`)と **Bitbucket Server / Data Center**(セルフホスト)に対応しています。非推奨でない3つの認証方式が用意されており、**OAuth が推奨**です。

Sensei ハブで **Add Repositories → Connect a new source**(または Connections ページの **Connect**)を選択し、**Bitbucket** と **deployment**(Cloud または Server/Data Center)、**authentication** の種類を選択します。

### Step 1: Create the credential

**OAuth(推奨):** Bitbucket で **Workspace settings → OAuth consumers → Add consumer** を開きます。

- **Callback URL:** 接続画面に表示されるもの(`https://<your-defectdojo-host>/sensei/bitbucket/oauth/callback`)。
- **Permissions:** **Account: Read**、**Repositories: Read + Write**、**Pull requests: Read + Write**(API 経由で webhook を管理する場合は **Webhooks: Read + Write** も追加)。

保存したら、consumer の **Key**(Client ID)と **Secret** をコピーします。

**API token**: `id.atlassian.com`(Account settings → Security → API tokens)で Atlassian の **API token** を作成します。使用する際は **Atlassian アカウントのメールアドレス** と組み合わせます。

**Access token**: Bitbucket でリポジトリまたはワークスペースの **Access Token** を作成し、bearer 認証情報として使用します。

### Step 2: Connect

**Bitbucket** を選択した接続画面に戻ります。

- **OAuth:** **Client ID** と **Client Secret** を貼り付け、**Connect with Bitbucket** をクリックします。同意画面を承認すると、DefectDojo が取得したトークンを暗号化して保存し、自動的に更新します。
- **API token / Access token:** **Workspace**(Cloud)、**email**(API トークン認証のみ)、**token** を入力します。Server/Data Center の場合はホストの **Base URL** を入力します。

DefectDojo は認証情報を検証したうえで、リポジトリの一覧表示、プルリクエストのオープン、スキャンの実行ができるようになります。

### Step 3: Add the webhook

各 Bitbucket リポジトリ**それぞれ**に webhook を追加します(**Repository settings → Webhooks → Add webhook**)。

- **URL:** 接続画面に表示される webhook URL(`https://<your-defectdojo-host>/sensei/bitbucket/webhooks`)。
- **Secret:** ページに表示される webhook シークレット(HMAC-SHA256 の `X-Hub-Signature` 検証に使用)。
- **Triggers:** **Repository push**、**Pull request**(created、updated、merged、declined)、**Pull request comment created**(`/fix` コメント用)。

接続後、**Choose Repositories** をクリックして [リポジトリの選択](#select-repositories) に進みます。

> **Bitbucket 固有の仕様:** リポジトリは `workspace/repo`(Cloud)または `PROJECTKEY/repo`(Server)の形式で指定します。プルリクエストの **status check** は、ヘッドコミットに対する Bitbucket の **build status** として投稿されます。OAuth はユーザーコンテキストで動作し(ワークスペース/ユーザー名に関する癖がなく)自動的に更新されるため推奨方式です。app password は非推奨であり、サポートされていません。

## Connect Azure DevOps

Sensei は **Personal Access Token (PAT)** を使用して **Azure DevOps Repos** に対応しています。リポジトリは **organization → project → repository** という階層構造で管理されます。

Sensei ハブで **Add Repositories → Connect a new source**(または Connections ページの **Connect**)を選択し、**Azure DevOps** を選択します。

### Step 1: Create a PAT

Azure DevOps で **User settings → Personal access tokens → New Token** を開きます。

- **Organization:** スキャン対象のリポジトリを持つ組織。
- **Scopes:** **Code (Read, Write, & Manage)**。クローン、修正用ブランチのプッシュ、プルリクエストのオープンをカバーします。

トークンを作成してコピーします(Azure DevOps はこの値を一度しか表示しません)。

### Step 2: Connect

**Azure DevOps** を選択した接続画面に戻り、以下を入力します。

- **Base URL:** `https://dev.azure.com`、または Azure DevOps **Server** のコレクション URL。
- **Organization:** 組織名。
- **Personal Access Token:** ステップ1のトークン。

**Connect** をクリックします。DefectDojo は `…/_apis/projects` に対して PAT を検証し、暗号化して保存したうえで、リポジトリの一覧表示、プルリクエストのオープン、スキャンの実行ができるようになります。

### Step 3: Add the service hook

Azure DevOps は **Service Hooks** の認証に HTTP Basic を使用し、**イベント種別ごとに1つのサブスクリプション**を使う仕組みです。**Project settings → Service hooks → Create subscription → Web Hooks** で、**Code pushed**、**Pull request created**、**Pull request updated**、**Pull request merged** それぞれについてサブスクリプションを作成し、すべてに以下を設定します。

- **URL:** 接続画面に表示される webhook URL(`https://<your-defectdojo-host>/sensei/azure/webhooks`)。
- **Basic authentication username / password:** ページに表示される値。

接続後、**Choose Repositories** をクリックして [リポジトリの選択](#select-repositories) に進みます。

> **Azure DevOps 固有の仕様:** リポジトリは `project/repo` の形式で指定します(組織は接続側に保存されます)。プルリクエストの **status check** は、ヘッドコミットに対する Git の **commit status** として投稿されます。

## Select repositories

App のインストール後、DefectDojo はアクセス可能なリポジトリを表示します。一覧に表示されるのは Sensei が **プッシュ権限** を持つリポジトリのみです。修正はブランチをプッシュしてプルリクエストをオープンすることで行われるため、プッシュ権限のないリポジトリは表示されません。プルリクエストは各リポジトリの **デフォルトブランチ** に対してオープンされます。

![オンボードするリポジトリを選択する](images/setup_repo_picker.png)

**Add** を使って1つ以上のリポジトリを選択し、**Configure N repo(s)** をクリックします。すでにオンボード済みのリポジトリには **Configured** のマークが付き、二重に追加することはできません。

### A repository isn't listed

ピッカーには、その接続に許可されたリポジトリのみが表示されます。Sensei にアクセス権を与えていないリポジトリは表示されません。接続が単一のリポジトリのみを対象としていて、それがすでにオンボード済みの場合、追加できるものが何もないように見えます。接続が参照できる範囲を広げてから、このステップに戻ってください。

- **GitHub:** **Manage repository access for \<account\>** を使ってその installation の GitHub 上のページを開くと、installation にリポジトリを追加できます。2つ目の組織やユーザーアカウントに App をインストールするには **Install on another account** を使用します。
- **GitLab、Bitbucket、Azure DevOps:** 一覧の範囲は接続した認証情報によって決まります。トークン、app password、または PAT にそのプロジェクトへのアクセス権を付与するか(GitLab の **group** トークンはそのグループ内のすべてのプロジェクトをカバーします)、別のグループ・ワークスペース・組織用に2つ目の接続を追加してください。

## Configure a repository

**Configure Repository** フォームで、Sensei がそのリポジトリをどのようにスキャンし、レポートするかを制御します。

![リポジトリを設定する](images/repo_config.png)

- **Scanning Mode (DefectDojo-hosted):** スキャンは DefectDojo 上で実行されます。リポジトリには何も追加されません。オンデマンドで、または GitHub App 経由で自動的にスキャンをトリガーできます。
- **PR Reporting:** Sensei がプルリクエストに投稿する内容を選択します。
  - プルリクエストに status check を投稿する。
  - 新規の検出事項が追加された場合にチェックを失敗させる。
  - 各コミットに結果サマリーのコメントを投稿する。
  - 最初の PR でベースブランチのベースラインを自動作成する。
- **Automated Fixes:** *Stage matching findings for one-click auto-fix after each scan* を有効にすると、Sensei が各スキャン後に該当する候補を自動的にステージングします(詳細は後述)。

### Automated fix criteria

自動修正を有効にすると、条件を満たす検出事項は各スキャン後に Sensei ページ上で **候補(candidates)** としてステージングされます。自動修正を有効にしない限り、承認するまで何も実行されません(LLM のコストも発生しません)。

![自動修正の条件と詳細オプション](images/repo_config_advanced.png)

- **Severity threshold:** この深刻度以上の検出事項が対象になります(リスクのみで判定したい場合は *Any* を選択します)。
- **Risk threshold:** このリスクレベル以上の検出事項も対象になります(深刻度と OR 条件で組み合わされます)。
- **Open fix PRs against branch:** 自動修正プルリクエストの対象となるブランチ。個別に承認する際は修正ごとに上書きできます。
- **Exclude findings tagged:** 指定したタグ(例: `no-fix`)が付いた検出事項をスキップします。
- **Automatically remediate candidates:** 有効にすると、バックグラウンドチェック(約5分ごと)が承認を待たずにこのリポジトリのステージング済み候補に対して修正プルリクエストをオープンします(修正クォータに達するまで)。無効のままにすると、各候補を自分でレビューして承認することになります。

**Advanced options** では、リポジトリを既存の製品/アセットにリンクするか新規作成するか、organization の設定、そしてレポートやマージゲートの対象から除外する最小深刻度を設定できます。

## Onboard

**Onboard for hosted scanning** をクリックします。リポジトリは Sensei ハブにステータス **Active** で表示され、スキャン可能な状態になります。続けて [Sensei で検出事項を修正する](/sensei/fixing_findings/) に進んでください。
