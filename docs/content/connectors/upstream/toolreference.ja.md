---
title: Upstream Connectors ツールリファレンス
description: 対応している Connector ツールの一覧と、DefectDojo でのセットアップ方法
aliases:
- /ja/import_data/pro/connectors/connectors_tool_reference/
- /ja/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Upstream Connectors は DefectDojo Pro 限定の機能です。</span>

対応ツール向けに Connector をセットアップする際は、そのツールの API に関する特定の情報を DefectDojo に提供する必要があります。基本的には、以下が必要です。

* **Location** \- 通常、ネットワーク内のツールの URL を指すフィールド
* **Secret** \- 通常は API キー

ツールによっては、**Location** と **Secret** 以外にも追加の API 関連フィールドが必要になる場合があります。また、DefectDojo からの Connector 接続を受け入れるために、ツール側での設定変更が必要になることもあります。

![image](images/connectors_tool_reference.png)

ツールごとに API の設定は異なるため、このガイドでは DefectDojo が接続できるように各ツールの API をセットアップする方法を説明します。

可能な限り、Connector 専用に利用する新しい「DefectDojo Bot」アカウントをセキュリティツール内に作成することをお勧めします。これにより、チームが手動で行った操作と Connector による自動操作を区別しやすくなります。

# **Asset Connectors**

ほとんどの Connector はセキュリティツールから**検出事項**をインポートします。**Asset Connectors** はこれとは異なる動作をします。検出事項ではなく**アセットインベントリ**をインポートします。Asset Connector は外部プラットフォームに存在するアセット(例えば GitLab グループ内のリポジトリ)を列挙し、DefectDojo 内に対応する**製品**(アセット)と**製品タイプ**(組織)を自動的に作成・維持します。Asset Connector によって検出事項がインポートされることはありません。

* **Discover** と **Sync** はどちらもアセット一覧を突き合わせます。新しいアセットは `NEW` レコードとして表示され、(自動マッピングが有効な場合は自動的に)マッピングされると、DefectDojo はそのツールから導出された製品タイプ(例えば GitLab の namespace や Azure DevOps のプロジェクト)の下に製品を作成し、グループ化します。
* アセットが後で上流側で削除された場合(例えばリポジトリが削除された場合)、次の Sync 時にマッピング済みのレコードが `MISSING` としてフラグされ、チームがトリアージできるようになります。DefectDojo が製品を無言で削除することはありません。

Azure DevOps、Backstage、Bitbucket、GitHub、GitLab、Jira Service Management Assets、ServiceNow CMDB は Asset Connectors です。runZero は主に Asset Connector ですが、脆弱性を検出事項としてインポートするオプションも備えています。以下に挙げるその他すべての Connector は検出事項をインポートします。

# **Supported Connectors**

## **Acunetix 360**

Acunetix 360 コネクタは、Acunetix 360 クラウドプラットフォーム(Invicti プラットフォーム)から**DAST 脆弱性の検出事項**をインポートします。DefectDojo はアカウント内でスキャンされた Web サイトを検出し、**Web サイト**ごとにレコードを作成します。Web サイトの検出事項は、その最新の完了済みスキャンから取得されます。

**ご注意ください:** このコネクタは(`online.acunetix360.com` のクラウド製品である)**Acunetix 360** 用です。異なる API を持つオンプレミス版の Acunetix Standard/Premium スキャナ用ではありません。

#### Prerequisites

Acunetix 360 のアカウントと**API 認証情報**が必要です。Acunetix 360 でアカウントメニュー \> **API Settings** を開き、**API User ID** を確認して **API Token** を生成してください。コネクタはこれらを HTTP Basic 認証情報として使用するため、手動によるチーム操作と自動操作を区別するために専用のサービスアカウントを利用することをお勧めします。

#### Connector Mappings

1. **Location** フィールドに Acunetix 360 の URL を入力します: `https://online.acunetix360.com`。
2. **API User ID** フィールドに API User ID を入力します。
3. **API Token** フィールドに API Token を入力します。
4. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

スキャンされた各 Web サイトが 1 件のレコードになります。検出事項はその Web サイトの最新の完了済みスキャンから取得されます。Acunetix 360 で **Accepted Risk** または **False Positive** としてマークされた脆弱性もインポートされますが、非アクティブ(risk-accepted または false-positive)としてフラグされるため、DefectDojo 側の製品にベンダーによるトリアージ結果が反映されます。

## **Akamai API Security**

Akamai API Security コネクタは API キーを使用して Akamai API からセキュリティの検出事項を取得します。DefectDojo は Akamai 環境を検出し、アカウントに設定された**Application** と **Host** ごとに個別のレコードを作成します。

#### Prerequisites

Akamai API へのアクセス権を持つ API キーが必要です。自動操作とチームによる手動操作を明確に区別するため、DefectDojo 専用のサービスアカウントを作成することをお勧めします。

#### Connector Mappings

1. **Location** フィールドに Akamai API のベース URL を入力します。この URL は Akamai インスタンス固有のものです。例:
2. **Secret** フィールドに有効な **API Key** を入力します。

DefectDojo は **Application** と **Host** をそれぞれ別のレコードとしてマッピングします。各 Application はレコード一覧に `{name} (application)` として、各 Host は `{name} (host)` として表示されます。

## **Anchore**

Anchore コネクタはユーザーの API トークンを使用して Anchore Enterprise からデータを取得します。製品は「Applications」に基づいてマッピング・検出されます。Applications は Anchore 内の複数の Image で構成されます。詳細は [Anchore Enterprise Documentation](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) を参照してください。

#### Connector Mappings

1. **Location** フィールドに Anchore の URL を入力します。これは Anchore にアクセスする際の URL です。
2. Secret フィールドに有効な API Key を入力します。これは Burp Service アカウントに紐づく API キーです。

Anchore のトークン作成に関する詳細は、公式の [Anchore documentation](https://docs.anchore.com/current/docs/) を参照してください。

## **AWS Security Hub**

AWS Security Hub コネクタは、Security Hub の API とやり取りするために AWS アクセスキーを使用します。

#### Prerequisites

チームメンバーの AWS アクセスキーを使用するのではなく、DefectDojo 専用に AWS アカウント内で IAM ユーザーを作成し、そのユーザーの権限を Security Hub とのやり取りに必要な範囲に限定することをお勧めします。

AWS の「**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)** ポリシー」は、コネクタに必要なレベルのアクセスを提供します。Connector 用にカスタムポリシーを作成したい場合は、以下の権限を含める必要があります。

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

実際に機能するポリシー定義は、以下のようになります。

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**ご注意ください:** 最良の利用体験を提供するため、今後追加の API アクションが必要になる場合があり、その際はこのポリシーの更新が必要になります。

IAM ユーザーを作成し、適切なポリシー/ロールを使って必要な権限を割り当てたら、アクセスキーを生成し、それを使って Connector を作成します。

#### Connector Mappings

1. **Location** フィールドに、[お使いのリージョンに対応する AWS API エンドポイント](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region)を入力します。例えば `us-east-1` リージョンから結果を取得する場合は、以下を指定します。

`https://securityhub.us-east-1.amazonaws.com`
2. **Access Key** フィールドに有効な **AWS Access Key** を入力します。
3. **Secret Key** フィールドに対応する **Secret Key** を入力します。

DefectDojo は Security Hub の**クロスリージョン集約**機能を使って複数のリージョンから検出事項を取得できます。[クロスリージョン集約](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html)が有効な場合は、「**Aggregation Region**」の API エンドポイントを指定してください。追加でリンクされているリージョンについては、AWS アカウント ID とリージョン名に基づいて DefectDojo 内に ProductRecords が作成されます。

## **Azure DevOps**

Azure DevOps コネクタは**Asset Connector**です。Azure DevOps 組織内のすべてのプロジェクトにある git リポジトリを列挙し、リポジトリごとに DefectDojo のアセットを作成し、Azure DevOps のプロジェクト単位で組織にグループ化します。検出事項はインポートされません。

#### Prerequisites

組織用の Personal Access Token(PAT)が必要です。専用のサービスアカウントからトークンを作成することをお勧めします。必要なのは読み取りスコープのみです。

1. Azure DevOps で **User settings \> Personal access tokens \> New Token** を開きます。
2. **Show all scopes** をクリックし、**Code: Read** と **Project and Team: Read** を選択します。

対応しているのは Azure DevOps Services(dev.azure.com)のみです。オンプレミスの Azure DevOps Server には現時点で対応していません。

#### Connector Mappings

1. **Location** フィールドに組織の URL を入力します: `https://dev.azure.com/{your-organization}`。従来の `https://{your-organization}.visualstudio.com` 形式の URL も受け付けられ、余分なパスセグメント(例えば特定プロジェクトへのリンク)は無視されます。
2. **Secret** フィールドに PAT を入力します。

各リポジトリは、そのリポジトリ名を冠したレコードとなり、Azure DevOps の**プロジェクト**単位でグループ化されます。無効化されたリポジトリはスキップされるため、リポジトリを無効化または削除すると、次の Sync でそのレコードは `MISSING` としてフラグされます。

## **Backstage**

Backstage コネクタは**asset connector**です。検出事項をインポートする代わりに、[Backstage](https://backstage.io) の Software Catalog を DefectDojo に取り込み、製品階層とチームの所有関係をそれと同期させます。サービスインベントリと組織構造を Backstage で管理しており、DefectDojo にはそれを手作業ではなく自動的にミラーしてほしい組織向けに設計されています。

#### What gets mapped

| Backstage | DefectDojo |
|---|---|
| **System** | 製品タイプ(System を持たない Component は、設定可能な「Backstage / Uncategorized」製品タイプの下にグループ化されます) |
| **Component** | 製品 — エンティティの `title`(なければ `name` にフォールバック)から命名され、カタログの description が付与されます |
| **Owning Group**(`ownedBy` リレーション) | 製品に紐づく DefectDojo のグループ(デフォルトのロール: Maintainer、設定変更可能) |
| **Owner email**(グループプロファイルの email、または User オーナーの email) | 同じ email を持つ DefectDojo ユーザーが既に存在する場合、そのユーザーが製品メンバーになります(ユーザーが新規作成されることはありません) |
| `metadata.tags`、`spec.type`、`spec.lifecycle`、namespace、domain | `backstage:` プレフィックス付きの製品タグ |
| `metadata.annotations` | レコードに(上限付きで)保存されます。特定の annotation は **Annotation Mappings** を通じて第一級の属性やタグに昇格できます |

レコードはエンティティのサーバー側で割り当てられた `metadata.uid` をキーとするため、Backstage 上でのリネームは次回の同期でマッピング済みの製品を**その場で**更新します。重複は発生しません。製品名は常にカタログに追従します。このコネクタが管理する製品をリネームするには、Backstage 上で Component をリネームしてください(DefectDojo 側でのリネーム、または手動マッピング時に付けたカスタム名は、他の製品と衝突しない限り、次回の同期でカタログ名に合わせて調整されます)。所有者の変更は、製品のグループ割り当てを移動させます。カタログから消えた(または `backstage.io/orphan` annotation が付いた)Component は **MISSING** としてマークされます。DefectDojo が自ら製品を削除することはありません。Domain と Group の階層(親チーム)はタグ/メタデータとしてのみ記録され、追加の階層レベルを作成することはありません。

#### Prerequisites

このコネクタは、Backstage バックエンドに対して**静的な external access token**で認証します。Backstage アプリの設定でトークンを定義し、(推奨として)catalog プラグインに限定してください。

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

強力なランダムトークンを生成し(例えば `openssl rand -hex 32`)、Backstage デプロイの環境変数に保存してください。詳細は [Backstage service-to-service auth documentation](https://backstage.io/docs/auth/service-to-service-auth) を参照してください。

#### Connector Mappings

1. **Location** フィールドに **Backstage バックエンドのルート URL** を入力します。例: `https://backstage.example.com`(コネクタが `/api/catalog` を自動的に付加します)。これは**バックエンド**の URL である必要があり、フロントエンドの Web UI ではありません。
2. **Secret** フィールドに静的な external access token を入力します。

以下はオプションのフィールドです(デフォルトのままにする場合は空欄にしてください)。

* **Namespaces** — インポート対象のカタログ namespace をカンマ区切りで指定します。空欄の場合はすべての namespace をインポートします。
* **Component Types** — `spec.type` の値をカンマ区切りで指定します(例: `service,website`)。空欄の場合はすべてのタイプをインポートします。
* **Page Size** — カタログクエリのページサイズ(1\-500、デフォルト 250)。
* **TLS Verification** — Backstage が DefectDojo で検証できない証明書(内部 CA)を提供している場合にのみ `false` に設定してください。推奨されません。
* **Uncategorized Product Type** — System を持たない Component に使用される製品タイプ(デフォルト `Backstage / Uncategorized`)。
* **Owner Group Role** — マッピングされた製品に対して所有チームに付与されるロール(デフォルト `Maintainer`)。
* **Annotation Mappings** — annotation キーをレコード属性名にマッピングする JSON オブジェクト、または annotation を製品タグとしてインポートするための `"tag"`。例: `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`。

**Auto\-Map** を有効にすると、1 回の Discover \+ Sync で製品タイプ / 製品 / 所有関係の構造全体が手作業なしで構築されます。Auto-Map を無効にした場合、検出された Component はマッピング判断待ちのレコードとして表示されます。

#### Limitations (v1)

* Backstage の**グループメンバーシップは同期されません**。コネクタは所有チームを DefectDojo のグループとして作成・リンクしますが、そのグループへのユーザーの登録は ID プロバイダや管理者に委ねられます。
* Component のみが製品になります。API、Resource、Domain はアセットとしてインポートされません(Domain はタグとして反映されます)。
* タグと annotation は DefectDojo のフィールド上限に収まるよう正規化・制限されます(過大な値は切り詰められます)。

**逆方向についての補足:** Backstage の内部(エンティティページ上)で DefectDojo の検出事項やグレードを表示することは、DefectDojo REST API を利用する Backstage フロントエンドプラグインとして構築するのが自然な発展形ですが、これはこのコネクタの意図的なスコープ外です。このコネクタはあくまでカタログデータを DefectDojo に取り込むだけです。

## **Black Duck**

Black Duck コネクタは、Black Duck(Synopsys / Black Duck)Hub インスタンスから**ソフトウェア構成分析(SCA)**の検出事項をインポートします。DefectDojo はインスタンス内のすべてのプロジェクトを検出し、**プロジェクト**ごとにレコードを作成します。プロジェクトの検出事項は、選択されたバージョンの脆弱な BOM コンポーネントから取得されます。

#### Prerequisites

インポートしたいプロジェクトを閲覧できるユーザーの Black Duck **API トークン**が必要です。Black Duck でユーザーメニュー \> **My Access Tokens** \> **Create New Token** を開き、(少なくとも)読み取りアクセスを付与して、表示されたトークンをコピーしてください(表示されるのは一度きりです)。コネクタは各同期時にこのトークンを短命なベアラートークンと交換します。コネクタの secret フィールド以外に平文で保存されることはありません。

#### Connector Mappings

1. **Location** フィールドに Black Duck の hub URL を入力します。例: `https://your-company.app.blackduck.com`。
2. **Secret** フィールドに API トークンを入力します。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

各 Black Duck プロジェクトが 1 件のレコードになります。デフォルトでは、コネクタはプロジェクトの**リリース済み**バージョン(存在しない場合は最初のバージョンにフォールバック)をインポートします。そのバージョンの脆弱な BOM コンポーネントごとに、`{vulnerability} in {component}:{version}` というタイトルの検出事項が作成されます。

このコネクタは、ファイルベースの Black Duck パーサーとは別物です。このコネクタの検出事項は専用の **Black Duck - Connectors Import** スキャンタイプを使用します。

## **Bitbucket**

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

## **Bugcrowd**

Bugcrowd コネクタは、Bugcrowd REST API を使用してバグバウンティおよび脆弱性開示プログラムからの提出をインポートします。DefectDojo は API トークンがアクセスできるプログラムを検出し、プログラムごとにレコードを作成して、そのプログラムの提出内容を検出事項としてインポートします。

#### Prerequisites

インポートしたいプログラムへのアクセス権を持つ Bugcrowd の **API トークン**が必要です。自動操作をチームによる手動操作と区別しやすくするため、DefectDojo 専用のサービスアカウントを作成することをお勧めします。トークンは Bugcrowd の **Organization settings \> API credentials** で生成します。提出、プログラム、ターゲットへの読み取りアクセスがあれば十分です。

#### Connector Mappings

1. **Location** フィールドに `https://api.bugcrowd.com` を入力します。
2. **Secret** フィールドに Bugcrowd API トークンを入力します。これは `Authorization: Token` ヘッダーとして送信されます。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

各 Bugcrowd **プログラム**が 1 件のレコードになり、その提出内容は Bugcrowd の深刻度を維持したまま検出事項としてインポートされます。重複した提出は除外されるため、再インポートしても同じ問題に対して重複した検出事項が作成されることはありません。

## **Bright Security**

Bright Security コネクタは [Bright](https://brightsec.com)(旧 NeuraLegion)の API を使用して**DAST の検出事項**をインポートします。DefectDojo はトークンがアクセスできるすべてのスキャンを検出し、完了済みスキャンごとにレコードを作成して、そのスキャンの issue を検出事項としてインポートします。

#### Prerequisites

Bright アプリの **User settings → API keys** で作成した Bright の**API キー**(`Org` または個人キー)が必要です。このキーは `Authorization: Api-Key` ヘッダーで送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドを空欄のままにすると `https://app.brightsec.com` が使用されます。または Bright のホストを明示的に入力してください。
2. **Secret** フィールドに Bright の API キーを入力します。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

DefectDojo は完了済みの各**スキャン**を 1 件のレコードにマッピングし、各**issue**を検出事項にマッピングします。深刻度は Bright 自身の評価(Critical/High/Medium/Low)から取得され、CVSS スコア、CWE、修復情報が引き継がれ、影響を受けるエントリーポイントがエンドポイントとなり、リクエスト/レスポンスの証跡が説明に含まれます。検出事項は動的な検出事項として記録され、Bright の issue id で重複排除されます。

詳細は [Bright API documentation](https://docs.brightsec.com/) を参照してください。

## **BurpSuite**

DefectDojo の Burp コネクタは、データを取得するために Burp の GraphQL API を呼び出します。

#### Prerequisites

このコネクタをセットアップする前に、Burp Service Account の API キーが必要です。Burp のユーザーアカウントにはデフォルトで API キーがないため、この目的のために新しいユーザーを作成する必要がある場合があります。

API キーを持つ Service Account ユーザーのセットアップ方法については、[Burp Documentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) を参照してください。

#### Connector Mappings

1. **Location** フィールドに Burp のルート URL を入力します。これは Burp ツールにアクセスする際の URL です。
2. Secret フィールドに有効な API Key を入力します。これは Burp Service アカウントに紐づく API キーです。

Burp API の詳細については、公式の [Burp documentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) を参照してください。

## **Censys**

Censys コネクタは Censys Platform からホストアセットを読み取り、各ホストの公開サービスを検出事項としてインポートします。スコープ対象のホストを列挙するために Censys Platform のグローバル検索 API を使用します。

#### Prerequisites

API アクセスを備えた Censys **Platform** アカウントが必要です。

* Censys Platform Console の Personal Access Tokens で作成した**Personal Access Token**。
* 同じ設定ページの「Current Organization」に表示される**Organization ID**。search エンドポイントへの API アクセスには組織が必要なため、Starter 以上のティアが必要です。無料ティアのトークンには organization ID がなく、search API を利用できません。

ホストごとの CVE およびリスクデータは Censys Core(エンタープライズ)ティアでのみ利用可能なため、それより下位のティアでは検出事項は脆弱性ではなく公開サービスを表します。

詳細は [Censys Platform API documentation](https://docs.censys.com/reference/get-started) を参照してください。

#### Connector Mappings

1. **Location** フィールドに `https://api.platform.censys.io` を入力します。
2. **API Key** フィールドに Personal Access Token を入力します。
3. **Organization ID** を入力します。
4. インポート対象を自社のアセットに絞り込む**Search Query**を入力します。例: `host.autonomous_system.asn: <your ASN>` や `host.ip: 203.0.113.0/24`。
5. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

DefectDojo はホストごとにレコードを作成し、その公開サービスを検出事項としてインポートします。

## **Checkmarx ONE**

DefectDojo の Checkmarx ONE コネクタは、データを取得するために Checkmarx の API を呼び出します。

#### **Connector Mappings**

1. **Checkmarx Tenant** フィールドに**Tenant Name** を入力します。この名前は Checkmarx ONE のログインページの右上に表示されているはずです。  
" Tenant: \<**your tenant name**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. 有効な API キーを入力します。新しく生成する必要がある場合があります。詳細は [Checkmarx API Documentation](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) を参照してください。
3. **Location** フィールドにテナントの場所を入力します。この URL は次の形式です。  
​`https://<your-region>.ast.checkmarx.net/`。リージョンは、Checkmarx アプリ利用時の Checkmarx URL の先頭に表示されます。**<https://ast.checkmarx.net>** は主要な US サーバーです(リージョンプレフィックスはありません)。

#### **Branch handling**

デフォルトでは、各同期はブランチに関わらず、プロジェクトの**直近の完了済みスキャン 1 件のみ**の検出事項をインポートします。CI で多数のブランチをスキャンしている場合、たまたま最後にスキャンされたブランチがその同期で「勝ち」となります。他のブランチにのみ存在する検出事項はインポートされず、同期のクローズ処理(close-old reconciliation)によって、異なるブランチが交互に最新スキャンになるたびに検出事項が開いたり閉じたりを繰り返すことがあります。

この動作を制御する 2 つのオプションフィールドがあります。

- **Branch**: すべてのプロジェクトを 1 つのブランチ名に固定します。そのブランチのスキャンのみがインポートされます。これはコネクタ全体に対する単一のグローバル値であるため、すべてのプロジェクトが同じ長期運用ブランチ(例えば `main`)を使用しているフリート向けです。
    - **`*` ワイルドカード**に対応しています。`*` を含む Branch 値は、単一のブランチではなく*一致するすべてのブランチ*を対象とします。例えば `release/*` は各リリースブランチをインポートし、`*` はすべてのブランチにマッチします。**Track Scanned Branches** と組み合わせることで、すべてを個別に追跡することなく、一群のブランチを追跡する方法になります。
    - ワイルドカードがスキャンウィンドウ内で**どのブランチにもマッチしない**場合、その同期は「ブランチに検出事項がない」として扱われるのではなく**スキップ**されます。これにより、一時的に何にもマッチしないパターンが、アセット上のすべての検出事項をクローズしてしまうことを防ぎます。
- **Track Scanned Branches**: 有効にすると、各同期はプロジェクトの直近のスキャン履歴の中から完了済みスキャンを持つすべてのブランチを検出し、**各ブランチの最新の完了済みスキャン**をインポートします(ブランチごとに 1 回の再インポート)。各ブランチの検出事項は、マッピングされたアセット上の「\<default engagement\> \- \<branch\>」という名前の独自のエンゲージメントに格納されるため、古い検出事項のクローズ処理はブランチ単位でスコープされます。あるブランチにマージされた修正が、別のブランチの検出事項をクローズすることはありません。プロジェクトの主要ブランチ(Checkmarx が報告するもの)が最初にインポートされるため、他のブランチで同じ検出事項が再発した場合、主要ブランチのオリジナルと重複排除されます。

**Track Scanned Branches** に関する注意点:

- **自分にどのデフォルトが適用されるか確認してください。** ブランチ追跡は**新規インストールではデフォルトで有効**です。この変更より前から存在するインストールは従来の動作を維持するため、誰かがトグルを有効にするまでオフのままです。
- 両方のフィールドが設定されている場合、追跡されるのは固定された **Branch** のみです。その Branch 値がワイルドカードパターンである場合も同様で、その場合はパターンに一致するすべてのブランチが追跡されます。
- スキャンされなくなった(マージまたは削除された)ブランチは更新を受け取らなくなります。そのエンゲージメントは最後に判明している検出事項とともに表示され続けるため、レビューして一括でクローズできます。
- 後でトグルをオフにしても安全です。ブランチごとのエンゲージメントはインポートを受け取らなくなり、次の同期からデフォルトのエンゲージメントが再開されます。
- Connector は同期スケジュールに沿って状態を突き合わせます。ブランチ追跡は各同期をブランチ横断で完結させるものであり、同期と同期の間のデータをリアルタイム化するものではありません。

## **Cloudflare**

Cloudflare コネクタは**Security Center insights** をインポートします。これは、DMARC レコードの欠落、DNSSEC が有効化されていない、証明書の問題など、Cloudflare がアカウントとゾーンについて表示するセキュリティ体制上の問題です。DefectDojo は、未解決の insight を持つゾーン(ドメイン)ごとにレコードを作成し、特定のゾーンに紐づかない insight についてはアカウントレベルのレコードを作成します。

#### Prerequisites

Cloudflare の**API トークン**(従来の Global API Key ではない)が必要です。Cloudflare ダッシュボードの **My Profile > API Tokens > Create Token** で作成してください。最も手軽な方法は**「Read all resources」**テンプレートです。最小権限のトークンにする場合は、**Zone > Zone > Read**(すべてのゾーン)に加えて、Security Center 用のアカウントレベルの読み取りアクセスを付与してください。

#### Connector Mappings

1. **Location** フィールドに `https://api.cloudflare.com/client/v4` を入力します。
2. **Secret** フィールドに API トークンを入力します。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

DefectDojo は、トークンがアクセスできるアカウントとゾーンを自動検出します。アカウント ID は不要です。未解決(アクティブで、却下されていない)の insight のみがインポートされるため、Cloudflare 上で解決または却下した insight は、次の同期で DefectDojo 上でも自動的に緩和済みになります。

## **Cobalt.io**

Cobalt.ioコネクタは、Cobalt.io API（v2）を使用して、Cobalt.io組織からペネトレーションテストの検出事項を取得します。DefectDojoは、APIトークンでアクセスできるすべての組織を検出し、Cobaltがペネトレーションテストを行う単位である**アセット**ごとに個別のレコードを作成します。

#### Prerequisites

Cobalt.ioの**個人用APIトークン**が必要です。自動化された操作とチームによる手動操作を明確に区別できるよう、DefectDojo専用のサービスアカウントを作成することをお勧めします。Cobalt.io UIの**Settings > API Tokens**からトークンを生成してください。組織トークンは自動的に検出されるため、指定する必要はありません。

#### Connector Mappings

1. **Location**フィールドにCobalt.io APIのベースURLを入力します: `https://api.cobalt.io`（またはリージョンごとのホスト、例: `https://api.us.cobalt.io`）。
2. **Secret**フィールドに**個人用APIトークン**を入力します。
3. 必要に応じて、同期を単一の組織に固定するために**Organization Token**を入力します。空欄のままにした場合、DefectDojoは個人用APIトークンがアクセスできるすべての組織を同期します。

DefectDojoは、Cobalt.ioの各**アセット**を個別のレコードとしてマッピングします。マッピングされた各アセットについて検出事項がインポートされ、Cobalt.io側のステータス（例: `valid_fix`、`wont_fix`、`invalid`）によってDefectDojo内の検出事項のステータスが決まります。

## **Contrast**

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

## **Coverity**

Coverityコネクタは、**Coverity Connect**サーバーから検出事項をインポートします。DefectDojoは、Coverityの**プロジェクト**ごとにレコードを作成します。

#### Connector Mappings

1. **Location**フィールドにCoverity ConnectサーバーのURLを入力します。
2. **Username**フィールドにCoverity Connectの**username**を入力します。
3. **Secret**フィールドにユーザーのパスワードまたは認証キーを入力します。
4. 必要に応じて、コネクタが読み取る保存済みissueビューを選択するために**View Name**を設定します。空欄のままにすると、デフォルトの**Outstanding Issues**が使用されます。
5. 必要に応じて、デフォルトのSecurityおよびQuality（`RESOURCE_LEAK`）のissueフィルタより広くインポートするために、**Import All Issue Kinds**を`true`に設定します。

## **CrowdStrike Falcon**

CrowdStrike Falconコネクタは、Falconプラットフォームから**Spotlightの脆弱性**と**EDR検知**を、2つの独立した検出事項タイプ（`CrowdStrike:Spotlight`と`CrowdStrike:Detections`）としてインポートします。DefectDojoは、Falconの**ホスト**ごとにレコードを作成します。

#### Prerequisites

Falconコンソールの**Support > API Clients and Keys**で作成する、Falconの**APIクライアント**（Client IDとsecret）が必要です。インポートしたいデータに応じたスコープを付与してください: **Hosts: Read**（ホスト検出に必須）、**Vulnerabilities (Spotlight): Read**（Spotlightの検出事項用）、**Alerts: Read**（EDR検知用）。この2つの検出事項タイプは独立しており、クライアントに該当スコープがない場合、同期全体が失敗するのではなく、そのタイプの検出事項がスキップされます。そのため、**Alerts: Read**を持たないクライアントでも、Spotlightの脆弱性は問題なくインポートされます。

#### Connector Mappings

1. **Location**フィールドに、コンソールのリージョンに対応するFalconクラウドのAPIベースURLを入力します。例: `https://api.crowdstrike.com`（US-1）、`https://api.us-2.crowdstrike.com`（US-2）、`https://api.eu-1.crowdstrike.com`（EU-1）、`https://api.laggar.gcw.crowdstrike.com`（US-GOV-1）。
2. **Client ID**フィールドにAPIクライアントのClient IDを入力します。
3. **Client Secret**フィールドにAPIクライアントのsecretを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

各Falconホストはレコードとなり、そのホスト名・OS・タイプにちなんで命名されます。Spotlightの脆弱性は**open**および**reopened**のものだけがインポートされるため、再インポートを行うと修復済みの検出事項はクローズされます。

## **Deepfence ThreatMapper**

Deepfence ThreatMapperコネクタは、[ThreatMapper](https://github.com/deepfence/ThreatMapper)の管理コンソールREST APIを使用して**脆弱性スキャン**の結果をインポートします。DefectDojoは、ThreatMapperがスキャンしたすべてのノード（コンテナイメージ、ホスト、またはコンテナ）を検出し、それぞれについてレコードを作成したうえで、そのノードの直近に完了したスキャンを検出事項としてインポートします。

#### Prerequisites

ThreatMapperの**APIトークン**が必要です。これはコンソールの**Settings → User Management**（ユーザーのAPIキー）にあります。コネクタは同期のたびにこのトークンを短命のアクセストークンと交換します。APIトークン自体がログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドにThreatMapperコンソールのURLを入力します（例: `https://threatmapper.example.com`）。
2. **Secret**フィールドにThreatMapperのAPIトークンを入力します。
3. コンソールが自己署名証明書を使用している場合は、**Skip TLS Verification**を`true`に設定します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、スキャン済みの各**ノード**をレコードにマッピングし、直近に完了した脆弱性スキャンに含まれる各**CVE**を検出事項にマッピングします。深刻度はThreatMapper自体の評価に基づき、影響を受けるパッケージ、CVSSスコア、修正バージョン（緩和策として）、参照リンク、詳細情報のブロックが引き継がれます。検出事項は動的検出事項として記録され、ノード・CVE・パッケージ・パッケージパスの組み合わせで重複排除されます。

詳細については、[ThreatMapperのドキュメント](https://community.deepfence.io/threatmapper/docs/v2.5/)を参照してください。

## Dependency-Track

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

## **Docker Scout**

Docker Scoutコネクタは、Docker Scoutのmetrics exporter APIを使用して、組織のイメージの脆弱性状況を報告します。DefectDojoは、Docker Scoutの各stream（実行環境）を検出し、それぞれについて脆弱性とポリシー準拠状況のサマリーをインポートします。

#### Prerequisites

**Docker Scoutに登録済み**のDocker組織の**owner**が作成した、Dockerのpersonal access tokenが必要です。metrics exporterは組織レベルの機能であるため、個人アカウントや、Docker Scoutに登録されていない組織では、データが返されません。

トークンは、Dockerアカウント設定の**Personal access tokens**から作成します。また、Dockerの**organization namespace**も必要になるため控えておいてください。

#### Connector Mappings

1. **Location**フィールドに`https://api.scout.docker.com`を入力します。
2. **Secret**フィールドにDockerのpersonal access tokenを入力します。
3. Dockerの**Organization**namespaceを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。選択した深刻度未満の検出事項はインポートされません。

DefectDojoは、Docker Scoutのstreamごとに個別のレコードを作成し、そのstream内でDocker Scoutが集計した脆弱性について深刻度ごとに1件の検出事項をインポートするほか、Docker Scoutのポリシーに違反する各イメージについても検出事項をインポートします。Docker ScoutのmetricsAPIは個別のCVEではなく集計件数を報告するため、これらの検出事項はstreamの状況をまとめたものになります。イメージ単位・CVE単位の詳細については、Docker Scout上でそのstreamを開いて確認してください。

詳細については、[Docker Scoutのドキュメント](https://docs.docker.com/scout/)を参照してください。

## **Endor Labs**

Endor Labsコネクタは、Endor Labs REST APIを使用してEndor Labsの**ネームスペース**全体を同期します。DefectDojoは、Endorの各**プロジェクト**をレコードとして検出し、そのプロジェクトの検出事項をインポートします。その際、Endorの**到達可能性（reachability）**判定も引き継がれるため、実際に到達可能なコードに影響する脆弱性を優先的に対応できます。

#### Prerequisites

Endor Labsの**APIキー**（キー識別子とそのsecretの組み合わせ）と、同期したい**ネームスペース**が必要です。キーはEndor Labsプラットフォームの**Settings > Access > API Keys**で作成します。このキーには、対象ネームスペース内のプロジェクトと検出事項への読み取りアクセス権が必要です。

コネクタは、APIキーとsecretを短命のベアラートークンと交換することで認証を行います。secretはこの交換にのみ使用され、平文で保存されることはありません。

#### Connector Mappings

1. **Location**フィールドに`https://api.endorlabs.com`を入力します。テナントが別のリージョンでホストされている場合は、そのリージョンのAPIベースURLを使用してください。
2. 同期したいEndor Labsの**Namespace**を入力します（例: `your-org`や`your-org.team`）。
3. **API Key**識別子を入力します。
4. キーに対応する**API Secret**を入力します。
5. 必要に応じて、設定したネームスペースの子ネームスペースからも検出事項をインポートするために、**Traverse Child Namespaces**を`true`に設定します。
6. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。選択した深刻度未満の検出事項はインポートされません。

DefectDojoは、ネームスペース内のEndor Labsプロジェクトごとにレコードを作成し、その検出事項をインポートします。その際、Endorの深刻度レベルはDefectDojoの深刻度にマッピングされ、各脆弱性のCVE/GHSA識別子とCVSSスコア、およびEndorの到達可能性タグも引き継がれます。到達可能性の判定（例: *Reachable — vulnerable function is called*や*Unreachable*）は、検出事項のImpactおよびタグとして表示されます。

詳細については、**[Endor Labs REST APIのドキュメント](https://docs.endorlabs.com/rest-api/)**を参照してください。

## **Edgescan**

Edgescanコネクタは、Edgescan REST APIを使用して、Edgescanアカウント全体のオープンな脆弱性をインポートします。DefectDojoは、すべてのEdgescanの**アセット**を列挙してそれぞれについてレコードを作成し、そのアセットのオープンな脆弱性を検出事項としてインポートします。アセットごとの個別設定はありません。

#### Prerequisites

EdgescanのAPIトークンが必要です。Edgescanアカウントの**Account settings > API tokens**からラベルを入力し、**Create**をクリックして、生成されたトークンをコピーします（トークンは一度しか表示されません）。自動化された操作を区別しやすくするため、コネクタ専用のアカウントを使用することをお勧めします。

#### Connector Mappings

1. **Location**フィールドにEdgescanのURLを入力します。標準的なホスト版プラットフォームの場合は`https://live.edgescan.com`、異なる場合はテナントのホストを入力してください。
2. **Secret**フィールドにEdgescanのAPIトークンを入力します。これは`X-API-TOKEN`ヘッダーとして送信されます。
3. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

各Edgescanアセットはレコードとなり、そのアセット上のオープンな脆弱性はそれぞれ検出事項としてインポートされます。深刻度は、Edgescanの数値スケール（1〜5）からDefectDojoの情報〜重大にマッピングされます。また、Edgescanが提供している場合は、CVE参照、CWE、CVSS v3ベクトルも含まれます。

## **Escape**

Escapeコネクタは、[Escape](https://escape.tech) APIを使用して**APIセキュリティ（DAST）の検出事項**をインポートします。DefectDojoは、トークンがアクセスできるすべての組織と、それぞれの組織内のすべてのアプリケーションを列挙し、スキャンがあるアプリケーションごとにレコードを作成して、そのアプリケーションの最新スキャンのissueを検出事項としてインポートします。アプリケーションごとの個別設定はありません。

#### Prerequisites

Escapeの**APIキー**が必要です。これはEscapeアプリの**Settings → API keys**で作成します。このキーは`Authorization: Key`ヘッダーで送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドを空欄のままにすると`https://public.escape.tech/v2`が使用されます。あるいは、EscapeのAPIホストを明示的に入力することもできます。
2. **Secret**フィールドにEscapeのAPIキーを入力します。
3. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、各**アプリケーション**をレコードにマッピングし、スキャンの各**issue**を検出事項にマッピングします。深刻度はEscapeの評価（重大/高/中/低）に基づき、CWEが引き継がれ、OWASPカテゴリとHTTPメソッドがタグになり、影響を受けるURLがエンドポイントになり、修復ガイダンスも含まれます。検出事項は動的検出事項として記録され、Escapeのissue IDで重複排除されます。

詳細については、[Escape APIのドキュメント](https://docs.escape.tech/)を参照してください。

## **Fairwinds Insights**

Fairwinds Insightsコネクタは、[Fairwinds Insights](https://insights.fairwinds.com) REST APIを使用して、組織全体の**Kubernetesセキュリティの検出事項**をインポートします。DefectDojoは、アクティブな**クラスタ**をすべて列挙してそれぞれについてレコードを作成し、そのクラスタのSecurity **アクションアイテム**（Polaris、Trivy、Kube-bench、OPA、その他のInsightsレポートに由来）を検出事項としてインポートします。クラスタごとの個別設定はありません。

#### Prerequisites

Fairwinds Insightsの**organization**名と**APIトークン**が必要です。トークンはInsightsアプリの**Organization Settings > Tokens**で作成します。`read_only`トークンで十分です。このトークンは組織単位のスコープを持ち、ベアラートークンとして送信されます。ログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドを空欄のままにすると`https://insights.fairwinds.com`が使用されます。あるいは、Insightsのホストを明示的に入力することもできます。
2. Insightsの**Organization**名（ダッシュボードのURLに表示されるスラッグ）を入力します。
3. **Secret**フィールドにInsightsのAPIトークンを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、アクティブな各**クラスタ**をレコードにマッピングし、Securityの各**アクションアイテム**を検出事項にマッピングします。深刻度はFairwindsの数値スコア（DefectDojoの情報〜重大にマッピング）に基づき、そのアイテムを生成したFairwindsのレポート（`polaris`、`trivy`、`kube-bench`など）がツールタグになり、影響を受けるKubernetesリソースとコンテナイメージが含まれ、CVE識別子があれば抽出されます。検出事項は静的検出事項として記録され、Fairwindsのアクションアイテムのidで重複排除されます。

詳細については、[Fairwinds Insights APIのドキュメント](https://insights.docs.fairwinds.com/technical-details/api/)を参照してください。

## **Fortify**

Fortifyコネクタは、Fortify（OpenText/Micro Focus）からSAST/DASTの結果をインポートします。同じプラットフォームを共有する2つのエディション、**SSC**（Software Security Center、自己ホスト型）と**Fortify on Demand（FoD）**（SaaS）の両方に対応しています。アカウント全体を同期し、DefectDojoはすべてのアプリケーション（SSCのproject version / FoDのrelease）を検出してそれぞれについてレコードを作成し、そのアプリケーションのissueを検出事項としてインポートします。

#### Prerequisites

- **SSC**: **FortifyToken**が必要です。これはSSC UIの**Administration → Token Management**で作成します（CIToken/UnifiedLoginToken）。
- **FoD**: **OAuth2 APIキー**が必要です。これは**Settings → API**から取得するClient IDとClient Secretです（`api-tenant`スコープを付与）。

トークンとOAuthのsecretがログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドにFortifyのベースURLを入力します。SSCの場合はサーバーのホスト（コネクタが`/ssc/api/v1`を追加します）、FoDの場合はリージョンに応じたAPIホスト（例: `https://api.ams.fortify.com`）を入力します。
2. **Edition**を`SSC`または`FoD`に設定します。
3. **FoD**の場合は、OAuthの**Client ID**を入力します。SSCの場合は空欄のままにします。
4. **Token / Client Secret**には、SSCのFortifyTokenまたはFoDのOAuthクライアントシークレットを入力します。
5. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、Fortifyの各**アプリケーション**をレコードにマッピングし、各**issue**を検出事項にマッピングします。深刻度はFortify独自の**friority**評価（重大/高/中/低）に基づき、タイトルはissueのカテゴリとファイル・行番号を組み合わせたものになります。また、ファイルパス、行番号、kingdom、analyzer、engine typeが引き継がれます。静的解析エンジン（SCA）のissueは静的検出事項として、WebInspect（DAST）のissueは動的検出事項として記録されます。抑制済み・削除済み・非表示のissueはスキップされ、「Not an Issue」と判定されたissueは誤検知としてマークされ、「Exploitable」/レビュー済みのissueは検証済みとしてマークされます。

詳細については、[Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/)および[Fortify on Demand](https://api.ams.fortify.com/swagger/ui)のAPIドキュメントを参照してください。

## **GitGuardian**

GitGuardianコネクタは、GitGuardian REST APIを使用して**secret incident**（GitGuardianが監視対象のソース全体で検出した、漏えいした認証情報）をインポートします。DefectDojoは、現在オープンなincidentを持つ監視対象ソース（リポジトリまたはperimeter）ごとにレコードを作成し、オープンな各incidentを検出事項としてインポートします。

セキュリティ上の理由から、コネクタがインポートするのはincidentの**メタデータ**（detector、深刻度、validity、status、GitGuardianへのリンク）のみです。漏えいしたsecretの値そのものがDefectDojoによって取得・保存されることはありません。影響を受けた箇所を確認するには、各検出事項に含まれるリンクからGitGuardianを参照してください。

#### Prerequisites

GitGuardianのAPIキーが必要です。自動化された操作を区別しやすくするため、個人アクセストークンではなく**Service Accountトークン**を使用することをお勧めします。GitGuardianダッシュボードの**API**でトークンを作成し、以下の読み取りスコープを付与してください。

* `incidents:read`
* `sources:read`

#### Connector Mappings

1. **Location**フィールドにGitGuardianのAPI URLを入力します。SaaSプラットフォームの場合は`https://api.gitguardian.com`、自己ホスト型インスタンスの場合はそのAPI URLを入力します。
2. **Secret**フィールドにAPIキーを入力します。

インポートされるのは**open**なincident（statusが`TRIGGERED`または`ASSIGNED`のもの）のみです。GitGuardian側でresolveまたはignoreにしたincidentは、次回の同期時にDefectDojo側でも自動的に緩和済みになります。有効性が確認済みのsecret（validityが*valid*）は、検証済みの検出事項としてインポートされます。

## **GitHub**

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

## **GitHub Advanced Security**

GitHub Advanced Securityコネクタは、GitHubから**code scanning**、**Dependabot**、**secret scanning**のアラートを、3つの独立した検出事項タイプ（`GitHub:CodeScanning`、`GitHub:Dependabot`、`GitHub:SecretScanning`）としてインポートします。DefectDojoは、設定した組織内のアーカイブされていないすべてのリポジトリを検出し、それぞれについてレコードを作成します。

#### Prerequisites

インポートしたいリポジトリでは、GitHub Advanced Security機能が有効になっている必要があります。コネクタはGitHubの**個人アクセストークン**で認証を行います。

1. GitHubで**Settings > Developer settings > Personal access tokens**を開き、対象の組織が所有する（またはアクセス権を持つ）トークンを作成します。
2. セキュリティアラートへの読み取りアクセス権を付与します。*fine-grained*トークンの場合、組織のリポジトリに対して**Code scanning alerts**、**Dependabot alerts**、**Secret scanning alerts**への**Read-only**アクセスが必要です。*classic*トークンの場合は**`repo`**と**`security_events`**のスコープが必要です。
3. トークンのownerがインポート対象のリポジトリを参照できることを確認してください。コネクタは、トークンがアクセスできるリポジトリしか参照できません。

#### Connector Mappings

1. **Location**フィールドに`https://api.github.com`を入力します。GitHub Enterprise Serverの場合は`https://<your-host>/api/v3`を使用してください。
2. **Organization**フィールドに組織のログイン名を入力します。
3. **Secret**フィールドに個人アクセストークンを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

アーカイブされていない各リポジトリはレコードとなり、3種類のアラートファミリーそれぞれについてオープンなアラートが照会されます。あるリポジトリで特定のアラートファミリーが有効になっていない場合、それはresolvedとして報告されるのではなくスキップされるため、無効化された機能によって誤ってクローズされることはありません。

## **GitLab**

GitLabコネクタは**アセットコネクタ**です。トークンがアクセスできるすべてのproject（リポジトリ）を列挙し、それぞれについてDefectDojoのアセットを作成します。作成されたアセットは、GitLabのnamespace（グループまたはユーザー）ごとにOrganizationsにグループ化されます。検出事項はインポートされません。

#### Prerequisites

**read_api**スコープを持つPersonal Access Tokenが必要です。専用のサービスアカウントからトークンを作成することをお勧めします。コネクタは、そのアカウントがメンバーになっているprojectを一覧表示します。

#### Connector Mappings

1. **Location**フィールドにGitLabのURLを入力します: `https://gitlab.com`、または自己ホスト型インスタンスのベースURL。
2. **Secret**フィールドにPersonal Access Tokenを入力します。

各projectはそのproject名にちなんだレコードとなり、**namespace**ごとにグループ化されます。GitLab上で削除待ち状態のproject（ユーザーによって削除されたが、GitLabのバックグラウンドジョブによってまだ完全に削除されていないもの）は自動的に除外されます。そのため、projectを削除すると、名前が変更された幽霊のようなアセットが残るのではなく、次回の同期時に対応するレコードが`MISSING`としてフラグ付けされます。

## **Google Cloud Security Command Center**

Google Cloud SCCコネクタは、Security Command Center v2 REST APIを使用して、Google Cloudのorganization、folder、またはprojectからアクティブなセキュリティの検出事項をインポートします。DefectDojoは、オープンな検出事項を持つGoogle Cloudの**project**ごとにレコードを作成します。

#### Prerequisites

組織でSecurity Command Centerが**有効化**されている必要があります（Standardティアは無料です）。次に、検出事項を一覧取得できるサービスアカウントと、そのJSONキーが必要です。

1. Google Cloudでサービスアカウントを作成します。DefectDojo専用のアカウントを作成することをお勧めします。
2. インポートしたいスコープ（organization、folder、またはproject）に対して、**Security Center Findings Viewer**ロール（`roles/securitycenter.findingsViewer`）を付与します。
3. そのサービスアカウントの**JSONキー**を作成してダウンロードします。

#### Connector Mappings

1. 標準以外のエンドポイントを使用しない限り、**Location**フィールドはデフォルトの`https://securitycenter.googleapis.com`のままにします。
2. **Parent Resource**フィールドに、インポート元のスコープを入力します: `organizations/{id}`、`folders/{id}`、または`projects/{id}`。
3. サービスアカウントの**JSONキー**ファイルの内容全体を**Service Account Key**フィールドに貼り付けます。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

インポートされるのは`ACTIVE`かつミュートされていない検出事項のみです。そのため、SCCで非アクティブ化またはミュートした検出事項は、次回の同期時にDefectDojo側でも自動的に緩和済みになります。各検出事項が影響するGCPのprojectが、そのレコードになります。

## **Group-IB ASM**

Group-IB ASM(Attack Surface Management)コネクタは、Group-IB ASM REST APIを使用して、外部の攻撃対象領域の**issue**(検出事項)をDefectDojoに取り込みます。DefectDojoは各Group-IBの**company/tenant**を個別のRecordとして検出し、そのcompanyのissueをスケジュールに基づいて増分的にインポートします。各issueが関連するアセット(ドメイン、IP、またはURL)は、生成された検出事項に**Endpoint**として付加されます。

#### Prerequisites

Group-IB ASMのログイン情報とAPIキーが必要です。自動化された操作を手動のチーム操作と区別できるよう、DefectDojo専用のサービスアカウントを作成することをお勧めします。

APIキーを生成するには:

1. Group-IB Attack Surface Managementを開き、左下の**Help**をクリックして**API**を選択します。
2. (右上、ユーザー名の下にある)**Generate API Key**をクリックします。
3. SSOパスワードを入力して**Next**をクリックし、次に**Copy token**をクリックします。
4. キーをシークレットマネージャーに保管し、定期的なローテーションを計画してください。

#### Connector Mappings

Group-IB ASMはHTTP Basic認証で認証を行います。ユーザー名はASMのログイン情報、パスワードはAPIキーです。**両方の値が必要です** — APIキーだけでは十分ではありません。

1. **Location**フィールドに`https://asm.group-ib.com`を入力します。これはすべてのGroup-IB ASMテナントで共通です。
2. **Username**フィールドにASMのログイン情報(通常はメールアドレス)を入力します。
3. **API Key**(Secret)フィールドにAPIキーを入力します。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。選択した深刻度を下回る検出事項はインポートされません。

DefectDojoは各Group-IBの**company**をcompany IDを識別子として個別のRecordにマッピングします。最初のSyncでは、DefectDojoは最近のissue履歴をバックフィルします。以降のSyncは増分的で、前回のSync以降に変更されたissueのみを(各issueの最新の`lastSeen`タイムスタンプで追跡して)取り込みます。

#### Scoping to a single company (optional)

デフォルトでは、コネクタはお使いのAPI資格情報でアクセス可能なcompanyを(ASMの`clients`エンドポイント経由で)自動的に検出し、company一つにつき一つのRecordを作成します。これが推奨のセットアップであり、追加の設定は不要です。

`clients`エンドポイントがお使いのテナントで利用できない場合(たとえばパートナー/MSPアカウントに制限されている場合など)、コネクタの設定でツール固有フィールド`company_id`にそのcompanyの**company ID**を指定することで、単一のcompanyにスコープを限定できます。`company_id`が設定されている場合、DefectDojoはcompanyを列挙する代わりにそのcompanyを直接使用します。自動検出を使用するには未設定のままにしてください。

詳細については、Group-IB ASM REST APIマニュアル(製品内の**Help → API**から利用可能)を参照してください。

## **HackerOne**

HackerOneコネクタは、HackerOne REST APIを使用して、バグバウンティまたは脆弱性開示プログラムからレポートをインポートします。DefectDojoはトークンがアクセスできる各プログラムのRecordを作成し、そのレポートを検出事項としてインポートします。

#### Prerequisites

このコネクタはHackerOneの**customer** APIを使用しており、**organization APIトークン**が必要です。ユーザー設定の個人トークンはhacker APIに対してのみ有効で、ここでは認証できません。

1. HackerOneで**Organization Settings > API Tokens**に移動します。
2. トークンを作成し、**identifier**と**token**の両方の値を控えておきます。プログラムへの読み取りアクセスがあれば十分です。

#### Connector Mappings

1. **Location**フィールドに`https://api.hackerone.com`を入力します。
2. **API Token Identifier**フィールドにトークンの**identifier**を入力します。
3. **API Token**フィールドにトークンの値を入力します。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

各プログラムがRecordとなり、そのレポートはHackerOneの深刻度評価を維持したまま検出事項としてインポートされます。

## **Harbor**

Harborコネクタは、Harbor v2.0 REST APIを使用して、レジストリ全体のコンテナイメージの脆弱性をインポートします。DefectDojoはすべてのHarbor**project**を列挙し、それぞれにRecordを作成した上で、そのprojectのリポジトリとアーティファクトを走査し、**スキャン済み**の各アーティファクトから脆弱性をインポートします — その際、イメージ(リポジトリ+タグ/ダイジェスト)を検出事項のコンテキストとして保持します。イメージごとの個別設定はありません。

#### Prerequisites

インポート対象のprojectへのpull/読み取りアクセス権を持つHarborアカウント(または**robotアカウント**)が必要です。専用のrobotアカウントの使用をお勧めします。Harborでprojectを開き(システムrobotの場合は**Administration > Robot Accounts**)、リポジトリとアーティファクトに対する**pull**権限を持つrobotを作成し、そのフルネームとシークレットをコピーします。robot名はデフォルトで`robot$`から始まりますが、このプレフィックスはHarborインスタンスごとに設定可能です(`robot_`を使用するものもあります) — Harborに表示されている名前をそのままコピーしてください。通常のユーザー名/パスワードも使用できます。

#### Connector Mappings

1. **Location**フィールドにHarborのURLを入力します — 例: `https://harbor.example.com`。DefectDojoは`/api/v2.0`のAPIパスを自動的に付加します。
2. **Username**フィールドにHarborのユーザー名、またはHarborに表示されているとおりのrobotアカウント名(デフォルトでは`robot$<name>`)を入力します。
3. **Secret**フィールドにパスワードまたはrobotアカウントのシークレットを入力します。これはHTTP Basic認証で送信されます。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

各Harbor projectがRecordとなります。スキャンが完了しているアーティファクトごとに、その脆弱性が検出事項としてインポートされます。影響を受けるパッケージ/バージョン、CVSSに基づく深刻度、CVE、CWE、および修復方法(修正済みバージョン)は、Harborが提供している場合に含まれます。インポートされるのはスキャン済みのアーティファクトのみです — まだスキャンされていないイメージについては、Harbor側でスキャンを実行してください。

## **Have I Been Pwned**

Have I Been Pwned(HIBP)コネクタは、HIBP REST APIを使用して、組織自身のドメイン上のどのアカウントが既知のデータ漏洩に含まれているかを報告します。DefectDojoはHIBPで検証済みの各ドメインを検出し、そのドメインに影響する漏洩ごとに1件の検出事項をインポートします。

#### Prerequisites

ドメイン検索機能付きのHave I Been Pwned APIキーが必要です。これには**Core**サブスクリプション以上のプランが必要です。キーは[Have I Been Pwnedアカウント](https://haveibeenpwned.com/API/Key)から取得できます。

また、漏洩データを利用できるようにするには、HIBPアカウントで**少なくとも1つのドメインを検証**する必要があります。HIBPでは、アカウントの**Domain search**セクションから、DNS TXTレコード、metaタグ、ファイルアップロード、またはメールでドメインを検証できます。ドメインが検証されるまで、コネクタはドメインを検出せず、検出事項もインポートされません。

#### Connector Mappings

1. **Location**フィールドに`https://haveibeenpwned.com`を入力します。
2. **Secret**フィールドにAPIキーを入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。選択した深刻度を下回る検出事項はインポートされません。

DefectDojoは、HIBPで検証済みの各ドメインごとに個別のRecordを作成し、そのドメイン上のアカウントに影響する漏洩ごとに1件の検出事項をインポートします。各検出事項の深刻度は漏洩で公開されたデータの種類を反映し、説明にはあなたのドメイン上で影響を受けたアカウントが記載されるため、チームが対応を取ることができます。

詳細については、[Have I Been Pwned APIドキュメント](https://haveibeenpwned.com/API/v3)を参照してください。

## **HCL AppScan**

HCL AppScanコネクタは、AppScan v4 REST APIを使用して、**AppScan on Cloud(ASoC)**またはセルフホスト型の**AppScan 360°**(両者はAPIを共有しています)からissueをインポートします。アカウント全体を同期します。DefectDojoはすべてのアプリケーションを検出してそれぞれにRecordを作成し、そのアプリケーションのissue(DAST、SAST、IAST)を検出事項としてインポートします。

#### Prerequisites

AppScanの**APIキー**が必要です — これはAppScanアカウント設定(API Key)で生成されるKey IDとKey Secretです。コネクタは実行ごとにこれらを短命のセッショントークンと交換します。Key ID、Key Secret、トークンはログに記録されません。

#### Connector Mappings

1. **Location**フィールドにAppScanコンソールのURLを入力します。ASoCの場合は`https://cloud.appscan.com`(EUリージョンの場合は`https://eu.cloud.appscan.com`)、セルフホスト型のAppScan 360°の場合はインスタンスのホストを使用します。
2. AppScan on Cloudの場合は**Provider**を`ASOC`に、セルフホスト型のAppScan 360°の場合は`A360`に設定します。
3. **API Key ID**と**API Key Secret**を入力します。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

DefectDojoは各AppScanの**application**をRecord(VEP)にマッピングし、各**issue**を検出事項にマッピングします。タイトルはissueの種類にドメイン/エンティティ/cause-id/URL/パスを付加したものになります。深刻度はInformational→情報にマッピングされます(Low/Medium/High/Criticalはそのまま渡されます)。CWE、ラベル付きの説明、修復方法とアドバイザリ、およびhost/portエンドポイントが引き継がれます。静的解析によるissueは静的検出事項として、動的/インタラクティブなissueは動的検出事項として記録され、openなissueはアクティブ、fixed/passedのissueは緩和済みになります。

詳細については、[AppScan REST APIドキュメント](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html)を参照してください。

## **Intigriti**

Intigritiコネクタは、Intigritiの外部company APIを使用して、バグバウンティ/ペンテストの**submissions**をDefectDojoに取り込みます。companyアカウント全体を同期します。DefectDojoはトークンがアクセスできるすべてのプログラムを検出してそれぞれにRecordを作成し、そのプログラムのsubmissionを検出事項としてインポートします。

#### Prerequisites

Intigritiの**company APIトークン**が必要です。Intigriti companyポータルの**Company Settings > API**(`company_external_api`スコープ)で、プログラムとsubmissionへの読み取りアクセス権を持つアクセストークンを生成します。DefectDojo専用のトークンを使用することをお勧めします。トークンはBearerトークンとして送信され、ログには記録されません。

#### Connector Mappings

1. **Location**フィールドにIntigritiの外部company APIベースURLを入力します: `https://api.intigriti.com/external/company`。URLはHTTPSである必要があります。
2. **Secret**フィールドにcompany APIトークンを入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

DefectDojoは各Intigritiの**program**をRecordに、各**submission**をsubmissionコードをキーとして検出事項にマッピングします。検出事項の深刻度はIntigritiの評価に従います(Exceptional/Critical→重大、続いてHigh/Medium/Low、それ以外はInformational)。submissionのライフサイクル状態は検出事項のステータスにマッピングされます — open/triageのsubmissionはアクティブ、acceptedのsubmissionは検証済み、closedのsubmissionはそのクローズ理由に応じて緩和済み、重複、対象外、誤検知、またはリスク受容済みになります。検出事項の説明には、レポートの脆弱性タイプ、影響を受けるアセット、証拠となるPoC(proof of concept)、および研究者の回答が記載されます。

詳細については、[Intigriti APIドキュメント](https://kb.intigriti.com/en/articles/6117846-intigriti-api)を参照してください。

## **Intruder**

Intruderコネクタは、[Intruder REST API](https://developers.intruder.io/)を使用して、アカウント全体のセキュリティ状況をDefectDojoに取り込みます。各Intruderの**target**はRecord(Product)として検出され、target上のissueの各**occurrence**がFindingになります。

#### Connector Mappings

1. **Location**フィールドは`https://api.intruder.io/`(デフォルトのIntruder APIサーバー)のままにしておきます。
2. **Secret**フィールドにIntruderの**APIアクセストークン**を入力します。

Intruderの**My account > API Access Tokens**でアクセストークンを生成します(作成にはアカウントパスワードが必要で、トークンは一度しか表示されません)。詳細は[Intruder APIドキュメント](https://developers.intruder.io/docs/creating-an-access-token)を参照してください。

検出事項はoccurrenceごとに導出されます。深刻度はissueの深刻度から、CVEとCVSSはoccurrenceから、locationはtarget/portから取得され、snooze(一時停止)されたoccurrenceは非アクティブ(誤検知またはリスク受容済み)な検出事項としてインポートされます。

## **IriusRisk**

IriusRiskコネクタは、APIトークンを使用して、お使いのIriusRiskインスタンスから脅威モデリングデータを取り込みます。

#### Prerequisites

IriusRiskアカウントのAPIトークンが必要です。自動化された操作を手動のチーム操作と明確に区別できるよう、DefectDojo専用のサービスアカウントを作成することをお勧めします。

IriusRiskでAPIトークンを生成するには:

1. IriusRiskインスタンスにログインします。
2. 右上のメニューから**User Profile**に移動します。
3. **API Token**を選択し、新しいトークンを生成します。

詳細については、[IriusRisk APIドキュメント](https://support.iriusrisk.com/hc/en-us/categories/360001148511)を参照してください。

#### Connector Mappings

1. **Location URL**フィールドにIriusRiskインスタンスのURLを入力します。クラウドホスト型インスタンスの場合、通常は`https://{your-subdomain}.iriusrisk.com`です。オンプレミス環境の場合は、インスタンスのベースURLを使用してください。
2. **Secret**フィールドに**API Token**を入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。選択した深刻度を下回る検出事項はインポートされません。

## **JFrog Xray**

JFrog Xrayコネクタは、JFrog Xray REST APIを使用して、Artifactoryリポジトリから脆弱性データを取得します。DefectDojoはJFrogインスタンス内のすべてのリポジトリを検出し、Xray経由で脆弱性レポートを生成して、スケジュールに基づいて検出事項をインポートします。

#### Prerequisites

ArtifactoryとXrayの両方のAPIにアクセスできるAPIトークンが必要です。DefectDojo専用のサービスアカウントの作成をお勧めします。このアカウントには以下が必要です。

* Artifactoryリポジトリへの読み取りアクセス
* Xrayの脆弱性レポートを生成・閲覧する権限(Xrayの`Apply on Watches`権限、またはそれに相当するもの)

#### Connector Mappings

1. **Location**フィールドにJFrogインスタンスのベースURLを入力します。これはJFrogインスタンスのルートURLである必要があります。例: `https://your-instance.jfrog.io`。末尾にパスを含めないでください — DefectDojoが適切なAPIパスを自動的に構築します。
2. **Secret**フィールドに有効な**Reference Token**を入力します。トークンはJFrog PlatformのUIの**User Management > Access Tokens**から生成できます。
**Reference Token**を生成し、その値を使用する必要があります。

JFrog Xrayに必要なトークンスコープ:

- **All Services** — DefectDojoはXRayとArtifactoryの両方のサービスへのアクセスが必要なため
- 最低限**Manage Reports + Manage Resources**が必要です。

デフォルトでは、DefectDojoは各Artifactory**リポジトリ**を個別のRecordとしてマッピングします。各Syncでリポジトリごとに完全な脆弱性レポートがXray経由で生成されるため、DefectDojo内の検出事項のステータスは常にリポジトリの現在の状態を反映します。

#### Repository Filter (optional)

デフォルトでは、コネクタはJFrogインスタンス内の**すべて**のリポジトリを検出します。リポジトリ数が非常に多いインスタンス(その多くはセキュリティレビューに関係ない場合もあります)では、コネクタフォームの**Import Filters**の下にある任意項目の**Repository Filter**フィールドで検出範囲を絞り込むことができます。

このフィルタは検出時、つまり**リポジトリごとの処理が行われる前**に適用されます。フィルタ範囲外のリポジトリにはコストがかかりません — そのリポジトリのXrayレポートは生成されず、アーティファクトモードでは第1階層のアーティファクトも列挙されません。これにより、Syncにかかる時間とDefectDojoがJFrogインスタンスにかける負荷の両方を削減する、最も効果的な方法となります — これはSync後半に適用される他のどの設定よりも効果的です。特に大規模なインスタンスでは、**Artifact-Level Records**と併用することが推奨されます。

**構文:** リポジトリキーのカンマ区切りリストです。各項目には`*`ワイルドカードを使用できます。

* `*`を含む項目はパターンとして照合されます — `releases-*`は`releases-`で始まるすべてのリポジトリキーに一致し、`*docker-pr-local*`は`docker-pr-local`を含むすべてのキーに一致します。`*`は`/`を含む任意の文字列に一致します。
* `*`を含まない項目は、リポジトリキーに**完全一致**する必要があります。
* リストの**いずれかの**項目に一致すれば、そのリポジトリは検出されます。カンマの前後の空白は無視されます。

```
releases-*, snapshots
```

上記の例では、`releases-`で始まるすべてのリポジトリキーに加えて、`snapshots`という名前に完全一致する単一のリポジトリを検出します。

補足:

* このフィルタは**許可リスト(allow-list)**です — 一致するとそのリポジトリが選択されます。除外や否定の構文はないため、「Xを除くすべて」を直接表現することはできません。
* 一致は完全一致・ワイルドカードともに**大文字小文字を区別します**。ワイルドカード文字は`*`のみで、`?`や文字範囲はサポートされていません。
* **すべてのリポジトリを検出するには空欄のままにしてください。** 空白またはカンマのみの値は空欄として扱われます。
* 何にも一致しないフィルタは単に何も検出しません — エラーにはなりません。Syncで予期せずリポジトリが見つからない場合は、コネクタログの`repository filter scoped discovery`のエントリを確認してください。これは全リポジトリ数のうち何件が一致したかを報告します。
* このフィールドは接続作成後にも変更できます。

**後からフィルタを変更する場合:** 新たに絞り込まれたフィルタによって除外されたリポジトリは検出されなくなり、その既存のRecordはツールがそれ以上報告しなくなったproductに対する通常のライフサイクルに従います — **マッピング済み**のRecordは次のSyncで`MISSING`とフラグが立てられ、未マッピングの`NEW`のRecordは削除されます。すでにDefectDojoにインポートされた検出事項は削除されません。フィルタが管理するのは検出のみです。

#### Artifact-Level Records

**Artifact-Level Records**のトグルをオンにすると、検出範囲がリポジトリの1階層下に変わります。リポジトリルート直下の第1階層の各エントリ(Dockerリポジトリの場合は各イメージ、汎用リポジトリの場合は各トップレベルのファイルまたはフォルダ)が、それぞれ独自のRecordになります。各Syncは引き続きリポジトリごとに1つのXrayレポートを生成しますが、DefectDojoは各脆弱性を影響を受けるアーティファクトに割り当てるため、JFrogインスタンスへの負荷は増加しません。

> **最初のSyncを行う前に、どちらのモードになっているか確認してください。** Artifact-Level Recordsは**新規インストールではデフォルトで有効**です。この機能より前から存在するインストールでは、既存のリポジトリレベルのレイアウトが維持されるため、誰かが有効化するまでトグルはオフのままです。どちらの場合も、トグルはいつでも変更できます。詳細は以下の*既存の接続の切り替え*を参照してください。

Artifact-Level Recordsを有効にすると:

* リポジトリはRecordのままですが、**親アセット**になります。リポジトリ自体は検出事項を持ちませんが、Asset Hierarchy機能が有効な場合、DefectDojoは各アーティファクトアセットをそのリポジトリアセットに`parent`関係で自動的に関連付けます。これにより、アセットを親/子でフィルタリングでき、検出事項は階層をロールアップします。
* 複数のアーティファクトに影響する脆弱性は、影響を受ける各アーティファクトのアセットにインポートされるため、すべてのアセットにそれぞれへ影響する検出事項の完全なセットが表示されます。
* 検出事項は各アーティファクトの**最新ビルド**にスコープされるため、アーティファクトの検出事項は、Xrayがこれまでスキャンしたすべてのビルドの結果を蓄積するのではなく、現在のビルドを表します。
* コネクタが作成した階層関係が、あなたが手動で作成した関係を上書きすることはありません。アセットにすでに割り当てた親がある場合、コネクタはそれに手を加えません。
* トークンにはさらにArtifactory storage APIへの読み取りアクセスが必要です(上記のスコープに含まれています)。

**既存の接続をArtifact-Level Recordsに切り替える:** このトグルはいつでも変更できます。切り替え後の最初のSyncでは、マッピング対象として新しいアーティファクトRecordが表示されます — トグルを切り替える際は、検出事項が途切れなく移行するよう、接続で**Auto Map**を有効にしてください。リポジトリレベルのアセットは検出事項を受け取らなくなり、以前にインポートされた検出事項は次のSyncでクローズされます(同じ検出事項は新しいステータスで新しいアーティファクトアセットの下に再インポートされます)。古いリポジトリレベルの検出事項に付いていたメモと履歴は、リポジトリアセットに残ります。元に戻すとこの逆になります — リポジトリRecordが検出事項を持つ状態に戻り(以前にクローズされた検出事項は再一致して再オープンします)、アーティファクトRecordはMISSINGとしてマークされます。そのアセットと検出事項は保持されますが更新されなくなるため、任意のタイミングでアーカイブできます。

詳細については、[JFrog Xray REST APIドキュメント](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis)を参照してください。

## **Jira Service Management Assets**

JSM Assetsコネクタは**Asset Connector**です。お使いのJira Service Management Assets(旧Insight)ワークスペース内のオブジェクトを列挙し、それぞれのオブジェクトに対してDefectDojoのAssetを作成します。オブジェクトスキーマごとにOrganizationsにグループ化されます。検出事項はインポートされません。

#### Prerequisites

* AssetsはJira Service Managementの**PremiumまたはEnterprise**プランが必要です。FreeまたはStandardプランでは、サイトの他の部分は動作していても、Assets APIは`403 "Access to Assets API was denied"`を返します。
* トークンに紐づくAtlassianアカウントは、そのサイトで**Jira Service Managementの製品アクセス権**(エージェントシート)を持っている必要があります。サイトへのアクセスだけでは不十分です。
* [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)でクラシックなAtlassian APIトークンを作成します。専用のサービスアカウントの使用をお勧めします。

#### Connector Mappings

1. **Location**フィールドにAtlassianサイトのURLを入力します: `https://{your-site}.atlassian.net`。
2. **Email**フィールドに、トークンが属するAtlassianアカウントのメールアドレスを入力します。
3. **Secret**フィールドにAPIトークンを入力します。

各AssetsオブジェクトはオブジェクトのラベルにちなんだRecordとなり、その**object schema**でグループ化されます。

## **Kubescape**

Kubescapeコネクタは、[Kubescapeオペレーター](https://kubescape.io/docs/install-operator/)によって生成されたKubernetesのposture(構成不備)結果を、クラスタのKubernetes APIから直接読み取ります — ARMO SaaSアカウントは不要です。オペレーターのクラスタ内ストレージ集約APIが提供する`WorkloadConfigurationScan`オブジェクト(`spdx.softwarecomposition.kubescape.io/v1beta1`)を読み取ります。posture結果を持つ各Kubernetesの**namespace**はRecord(Product)にマッピングされ、ワークロード上の失敗したcontrolはそれぞれFindingになります。

#### Prerequisites

- 対象クラスタでKubescapeオペレーターがインストールされ、構成スキャンが有効になっている必要があります([クラスタへのインストール](https://kubescape.io/docs/install-operator/)を参照)。`kubectl get workloadconfigurationscans -A`で結果が存在することを確認してください。
- 対象クラスタの`spdx.softwarecomposition.kubescape.io` APIグループ(`workloadconfigurationscans`に対するlist/get)への読み取りアクセスを許可する**kubeconfig**。

#### Connector Mappings

1. **Location**フィールドにクラスタのAPIサーバーURL(またはわかりやすいクラスタ識別子)を入力します。
2. `kubeconfig`フィールドに対象クラスタの**kubeconfig**を貼り付けます。必要に応じて`kube_context`でその中のコンテキストを選択し、`cluster_name`で検出されるProductにラベルを付けられます。
3. posture結果を持つ各namespaceがRecordとして検出されます。DefectDojoのProductにマッピングしたいものを選択してください。

検出事項は失敗したcontrolごとに導出されます。control名とワークロードがFindingを識別し、深刻度はcontrolのスコア係数から取得され、control IDが脆弱性IDになり、各Findingは`https://hub.armosec.io/docs/`のcontrolリファレンスにリンクします。

## **Mend**

Mendコネクタ(旧**WhiteSource**)は、Mend APIを使用して、Mend組織からセキュリティ検出事項をインポートします。DefectDojoは各Mend**project**にRecordを作成します。

#### Prerequisites

Mendの**User Key**(個人アクセストークン)を持つMend(サービス)ユーザーと、Mendの**Organization UUID**が必要です。自動化された操作を手動のチーム操作と区別しやすくするため、専用のサービスアカウントの使用をお勧めします。Organization UUIDは、Mendアプリの**Administration > Organization UUID**にあります。

#### Connector Mappings

1. **Location**フィールドにMendのAPI URLを入力します。このURLは**リージョン固有**です — Mend組織がホストされているリージョンのAPIベースURLを使用してください。
2. **Email**フィールドにMendユーザーのログインメールアドレスを入力します。
3. **Organization UUID**フィールドにMendの**Organization UUID**を入力します。
4. **User Key**フィールドにMendの**User Key**を入力します。
5. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

## **Lacework / FortiCNAPP**

Lacework / FortiCNAPPコネクタは、Lacework v2 APIを使用して、Laceworkアカウント全体の**ホストおよびコンテナの脆弱性**をインポートします。

#### Prerequisites

Laceworkの**APIキー**(APIキーIDとシークレット)が必要です。これはLaceworkコンソールの**Settings → API keys**で作成します。コネクタは同期のたびにこれらを短命のアクセストークンと交換します。キーID、シークレット、トークンはログに記録されません。

#### Connector Mappings

1. **Location**フィールドにLaceworkのアカウントURLを入力します — 例: `https://YOUR-ACCOUNT.lacework.net`(アカウント名のみでも受け付けられます)。
2. **API Key ID**と**API Secret**を入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

DefectDojoはLaceworkの**アカウント**をRecord(アカウント全体のスコープ)にマッピングします。各**container**と**host**の脆弱性はそれぞれ検出事項になります。深刻度はLacework独自の評価から取得され、影響を受けるパッケージとバージョンがcomponentになり、修正バージョンがmitigationになり、影響を受けるイメージ/ホストはタグとして記録されます。コンテナの脆弱性は静的検出事項(イメージスキャン)として、ホストの脆弱性は動的検出事項(実行中ホストのスキャン)として記録されます。

詳細については、[Lacework APIドキュメント](https://docs.lacework.net/api/v2/docs)を参照してください。

## **Microsoft Defender**

Microsoft Defenderコネクタは、**Microsoft Defender Vulnerability Management (MDVM)** からデバイスの脆弱性検出事項をインポートします。これはデバイス／ソフトウェアバージョン／CVEの組み合わせごとに1件の検出事項であり、深刻度、CVSSスコア、悪用可能性のレベル、推奨されるセキュリティ更新プログラムを含みます。DefectDojoはお使いのDefenderの**デバイスグループ**を検出し、それぞれについてRecordを作成します。どのデバイスグループにも割り当てられていないデバイスは、合成的な**Unassigned**グループの下にまとめられます。

**ご注意ください:** このConnectorは、手動でエクスポートしたDefenderファイルをインポートするファイルベースの**「MSDefender Parser」**スキャンタイプとは別のものです。重複した検出事項を避けるため、製品ごとにいずれか一方のインポート経路を選択してください。

#### 前提条件

お使いのMicrosoftテナントには、Defenderの脆弱性エクスポートAPIを含むアクティブなライセンスが必要です: **Defender for Endpoint Plan 2**、**Microsoft Defender Vulnerability Management Standalone**、またはMDVMアドオン付きのMDE P1/P2のいずれかです。（MDVMの*アドオン*SKU単体では不十分で、その下にDefender for Endpoint Plan 2が必要です。）

このコネクタは、クライアントクレデンシャルフローを使用してMicrosoft Entra IDの**アプリ登録**として認証を行います。作成手順は次のとおりです。

1. [Azureポータル](https://portal.azure.com)で **App registrations > New registration** を開きます。名前を付け（例: `defectdojo-connector`）、デフォルトのまま **Register** を選択します。
2. アプリの **Overview** ページで、**Application (client) ID** と **Directory (tenant) ID** を控えます。
3. **API permissions > Add a permission > APIs my organization uses** を開き、**WindowsDefenderATP** を検索します。表示されない場合は、テナントのDefenderバックエンドがまだプロビジョニングされていません。ライセンスがアクティブであることを確認し、一度 [security.microsoft.com](https://security.microsoft.com) を開いてから、数分後に再試行してください。
4. **Application permissions** を選択し（*Delegated*ではありません — Delegated permissionsはコネクタのサービストークンには決して現れません）、**Vulnerability** を展開して **Vulnerability.Read.All** にチェックを入れ、**Add permissions** を選択します。
5. **Grant admin consent** を選択して確認します。Statusカラムに緑色のチェックが表示される必要があります。このステップを行わないと、すべてのAPI呼び出しが403エラーを返します。
6. **Certificates & secrets > New client secret** を開き、有効期限を設定し、シークレットの **Value** をただちにコピーします(一度しか表示されません)。シークレットが期限切れになるとConnectorは動作しなくなるため、期限日を控えておいてください。

#### Connector Mappings

1. **Location** フィールドに `https://api.security.microsoft.com` を入力します。
2. **Tenant ID** フィールドに **Directory (tenant) ID** を入力します。
3. **Client ID** フィールドに **Application (client) ID** を入力します。
4. **Client Secret** フィールドにクライアントシークレットの値を入力します。
5. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各Defenderデバイスグループが1件のRecordになります。Microsoftは、コネクタが読み取る脆弱性スナップショットをおよそ6時間ごとに再生成し、新しくオンボーディングされたデバイスが最初の脆弱性データを生成するまでに最大で約24時間かかることがあります — 新規テナントでは、デバイスがオンボーディングされ評価が完了するまで、Syncで検出事項が0件になるのが正常です。ライセンスの有効化自体もAPIに反映されるまで約20分以上かかることがあり、この間に発生する「No active license found」というエラーは自然に解消されます。

## **Microsoft Defender for Cloud**

Microsoft Defender for Cloudコネクタは、Defender for Cloudを通じて表示される **Microsoft Defender Vulnerability Management (MDVM)** の脆弱性検出事項をインポートします。これには**サーバー**の検出事項(Azure VMのオペレーティングシステムおよびインストール済みソフトウェアのCVE)と**コンテナレジストリ**の検出事項(コンテナイメージのCVE)の両方が含まれ、深刻度、CVSSスコア、影響を受けるパッケージまたはイメージ、修復方法を含みます。DefectDojoは、サービスプリンシパルが読み取り可能なAzureの**サブスクリプション**を検出し、有効化されたサブスクリプションごとにRecordを作成します。

**ご注意ください:** このConnectorは、Defender for Endpoint APIからデバイスの検出事項をインポートする**Microsoft Defender**コネクタとは別のものです。Defender for Cloudは異なるAPIサーフェス(Azure Resource Manager / Resource Graph)と権限モデル(Azure RBAC)を持つAzure製品です。検出事項がどちらにあるかに応じて実行してください — 両方の製品を使用している場合は両方実行しても構いません。

#### 前提条件

**Microsoft Defender for Cloudが有効化された**1つ以上のAzureサブスクリプションが必要で、スキャン対象のリソースに応じて関連するDefenderプランを有効にしておく必要があります(**Microsoft Defender for Cloud > Environment settings** の下で、サブスクリプションを選択します):

* **Defender for Servers (Plan 2)** — Azure VMのオペレーティングシステムおよびソフトウェアのCVE検出事項(エージェントレス脆弱性スキャン)。
* **Defender for Containers** — コンテナレジストリのイメージCVE検出事項。

SQLの脆弱性評価および設定/ポスチャの検出事項は意図的に**インポートされません** — このコネクタはCVEの脆弱性のみをインポートします。

このコネクタは、クライアントクレデンシャルフローを使用してMicrosoft Entra IDの**アプリ登録**として認証を行います。

1. [Azureポータル](https://portal.azure.com)で **App registrations > New registration** を開きます。名前を付け(例: `defectdojo-connector`)、デフォルトのまま **Register** を選択します。
2. アプリの **Overview** ページで、**Application (client) ID** と **Directory (tenant) ID** を控えます。
3. **Certificates & secrets > New client secret** を開き、有効期限を設定し、シークレットの **Value** をただちにコピーします(一度しか表示されません)。シークレットが期限切れになるとConnectorは動作しなくなるため、期限日を控えておいてください。
4. インポートしたい各サブスクリプションに対してアプリに読み取りアクセス権を付与します: **Subscriptions** を開き、サブスクリプションを選択し、**Access control (IAM) > Add > Add role assignment** を選びます。**Security Reader** ロール(または **Reader**)を選択し、**Members** タブで作成したアプリに割り当てます — ピッカーはクライアントIDと一致しないため、アプリの**名前**または**オブジェクトID**で検索してください。すべてのサブスクリプションについて繰り返します。

デバイスベースのMicrosoft Defenderコネクタとは異なり、API permissionやadmin consentは不要です。Defender for Cloudへのアクセスは、上記のAzure RBACロール割り当てのみによって管理されます。

#### Connector Mappings

1. **Location** フィールドに `https://management.azure.com` を入力します。(政府専用クラウドなど特殊な環境では、対応するARMエンドポイントを使用してください。例: `https://management.usgovcloudapi.net`。)
2. **Tenant ID** フィールドに **Directory (tenant) ID** を入力します。
3. **Client ID** フィールドに **Application (client) ID** を入力します。
4. **Client Secret** フィールドにクライアントシークレットの値を入力します。
5. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

有効化された各Azureサブスクリプションが1件のRecordになります。検出事項はAzure Resource Graphを通じて読み取られるため、Defender for Cloudがリソースをスキャンし終えるとすぐに反映されますが、スキャン自体はMicrosoftのスケジュールで実行されます — コンテナレジストリのイメージは通常プッシュから1時間以内にスキャンされますが、VMの最初のエージェントレス脆弱性スキャンには数時間かかることがあります。新しく有効化されたサブスクリプションでは、リソースがスキャンされるまでSyncで検出事項が0件になるのが正常です。

## **MobSF**

MobSFコネクタは、[Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) REST APIを使用して、モバイルアプリケーション(APK/IPA)の静的解析結果をインポートします。DefectDojoは、お使いのMobSFインスタンス上でスキャン済みのすべてのアプリを検出し、それぞれについてRecordを作成した上で、そのアプリの静的解析の検出事項をインポートします。

#### 前提条件

MobSFの**REST APIキー**が必要です。MobSFのホームページの **API** の下にあります(MobSFドキュメントでは `Authorization` 値としても示されています)。このキーはすべてのリクエストで送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドにMobSFのベースURLを入力します(例: `https://mobsf.example.com`)。
2. **Secret** フィールドに、MobSFのREST APIキーを入力します。
3. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは、スキャン済みの各**アプリ**をRecordにマッピングし、MobSFのJSONレポートの複数のセクション — アプリケーションの権限、コード解析、署名証明書、Androidマニフェスト、Android APIの使用状況、バイナリ解析 — から検出事項をインポートします。各検出事項には**CWE 919**(モバイル)のタグが付けられ、深刻度はMobSF自身の評価(high、warning、info、secure/good)に基づきます — *dangerous*な権限はHighとして扱われます。検出事項は静的検出事項として記録され、スキャン、セクション、タイトル、深刻度、ファイルパスで重複排除されます。

詳細については、[MobSF REST APIドキュメント](https://mobsf.github.io/docs/#/rest_api)を参照してください。

## **NeuVector**

NeuVectorコネクタは、[NeuVector](https://github.com/neuvector/neuvector) コントローラのREST APIを使用して、コンテナ**イメージの脆弱性スキャン**をインポートします。DefectDojoは、NeuVectorがスキャンしたすべてのイメージを検出し、それぞれについてRecordを作成した上で、そのイメージのスキャンレポートを検出事項としてインポートします。

#### 前提条件

スキャン結果の読み取り権限を持つコントローラアカウントの、NeuVectorの**ユーザー名とパスワード**が必要です。コネクタはこれらの認証情報でログインしてセッショントークンを取得します。パスワードとトークンはログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドに、REST APIポートを含むNeuVectorコントローラのURLを入力します — 例: `https://neuvector.example.com:10443`。
2. コントローラの **Username** と **Password** を入力します。
3. コントローラが自己署名証明書を使用している場合は、**Skip TLS Verification** を `true` に設定します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは、スキャン済みの各**イメージ**をRecordにマッピングし、そのスキャンレポート内の各**CVE**を検出事項にマッピングします。深刻度はNeuVector自身の評価に基づき、影響を受けるパッケージとバージョン、CVSSv3スコアとベクター、修正バージョン(緩和策として)、参照リンクが引き継がれます。検出事項は、イメージ、CVE、パッケージ、バージョン、深刻度で重複排除されます。

詳細については、[NeuVector APIドキュメント](https://open-docs.neuvector.com/automation/automation)を参照してください。

## **Nuclei (ProjectDiscovery Cloud)**

NucleiコネクタはProjectDiscovery Cloud Platform (PDCP) REST APIを使用して、お使いのPDCPアカウントから [nuclei](https://github.com/projectdiscovery/nuclei) のスキャン結果を取得します。DefectDojoはアカウント内のすべてのスキャンを検出し、**スキャン**ごとに個別のRecordを作成します。

#### 前提条件

ProjectDiscovery Cloudの**APIキー**が必要です。自動化された処理と手動のチーム操作を明確に区別するため、DefectDojo専用のサービスアカウントを作成することをお勧めします。ProjectDiscovery Cloud UI([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io))の **Settings > API Key** からキーを生成します。結果は、ホスト型スキャンから、または `-dashboard` を付けて実行したnuclei CLIからPDCPに届きます。

#### Connector Mappings

1. **Location** フィールドにPDCPのAPIベースURLを入力します: `https://api.projectdiscovery.io`。
2. **Secret** フィールドに**APIキー**を入力します。
3. 必要に応じて、**Team ID** を入力してチームワークスペースに同期範囲を絞り込みます(**Settings > Team** の下にあります)。空欄のままにすると、DefectDojoは個人用ワークスペースを同期します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは、各PDCPの**スキャン**を個別のRecordとしてマッピングし、情報レベルを含むすべての深刻度にわたって、そのスキャンの検出事項をインポートします。

## **OpenVAS / Greenbone**

OpenVAS / Greenboneコネクタは、Greenbone(Greenbone Community EditionまたはGreenbone Enterprise)インスタンスから**ネットワーク脆弱性の検出事項**をインポートします。これは、HTTPではなく**GMP (Greenbone Management Protocol)** — TLSソケット上のXMLプロトコル — を介して `gvmd` と通信し、インスタンス全体を同期します。スキャン**タスク**を列挙してそれぞれについてDefectDojoの製品を作成し、各タスクの最新レポートの結果をインポートします。

#### 前提条件

Greenboneの**GMPユーザー**(ユーザー名とパスワード)と、gvmdのGMP TLSポート(デフォルトは**9390**)へのネットワークアクセスが必要です。Greenbone Community Editionのcomposeスタックは、unixソケット経由でgvmdをフロントに置いているため、ネットワーク経由のコネクタからそこに到達するには、ソケットに到達できる場所でコネクタを実行するか、GMP TLSポートを公開する必要があります(例: `gvmd.sock` へのTLSブリッジとして `socat` を使用)。

#### Connector Mappings

1. **Location** フィールドにgvmdホストを入力します(ホスト名、または `host:port`)。
2. GMPの **Username** と **Password** を入力します。
3. 必要に応じて **GMP Port** を設定します(デフォルトは9390)。
4. gvmdのデフォルトの自己署名証明書に対しては、検証用に **CA Certificate (PEM)** を指定するか、**Skip TLS Verification** を `true` に設定してください。
5. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各Greenboneタスクが1件のRecordになります。検出事項はタスクの最新の完了レポートから取得され、`<result>` ごとに1件です。深刻度は結果の脅威レベルから取得され(Greenboneの `Log`/`Debug` の情報レベルはInfoにマッピングされます)、数値のCVSSスコアが記録されます。CVEの参照は脆弱性IDになり、NVTのsolutionは緩和策になり、各結果のホスト/ポートはエンドポイントになります。

## Probely

このコネクタは、Probely REST APIを使用してデータを取得します。

​**Connector Mappings**

1. **Location** フィールドに適切なAPIサーバーアドレスを入力します。(<https://api.us.probely.com/> または <https://api.eu.probely.com/> のいずれか)
2. **Secret** フィールドに有効なAPIキーを入力します。

APIキーは、ProbelyのUser > API Keysメニューから確認できます。
詳細については[Probelyのドキュメント](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key)を参照してください。

## Prowler

Prowlerコネクタは**Prowler App** REST APIを使用して、セルフホスト型のProwler Appインスタンスからクラウドセキュリティポスチャ (CSPM) の検出事項をインポートします。DefectDojoは各Prowler**プロバイダ**(クラウドアカウント)をRecordとして検出し、そのプロバイダの最新の完了済みスキャンの**FAIL**検出事項をインポートします。

#### 前提条件

実行中のセルフホスト型**Prowler App**インスタンスと、ユーザーのメールアドレス+パスワード(JWT認証用)またはProwler Appの**APIキー**のいずれかが必要です。検出事項は、Prowler Appでクラウドアカウント(AWS、GCP、Azure、Kubernetesなど)を接続してスキャンを実行して初めて表示されます。

#### Connector Mappings

1. **Location** フィールドにProwler AppのURLを入力します(例: `https://prowler.your-company.com`)。
2. JWT認証の場合は、Prowler Appユーザーの **Email** と **Password** を入力します。あるいは、それらを空欄のままにして、Prowler Appの **API Key** を入力します。両方が指定された場合は、メール/パスワード(JWT)が使用されます。
3. 必要に応じて **Minimum Severity** を設定し、インポートする検出事項を絞り込みます。選択した深刻度未満の検出事項はインポートされません。

DefectDojoは各ProwlerプロバイダについてRecordを作成し、その最新の完了済みスキャンのFAIL検出事項をインポートします。その際、Prowlerの深刻度をDefectDojoの深刻度にマッピングし、影響を受けるクラウドリソース(ARN/リソースID)をコンポーネントとして、チェックの修復方法とリスクを検出事項に反映します。ミュートされた検出事項はスキップされます。クラウドアカウント、リージョン、サービスはタグとして付与されます。

詳細については、**[Prowler App APIドキュメント](https://api.prowler.com/api/v1/docs)**を参照してください。

## Qualys

Qualysコネクタは、Qualys Cloud Platformから**VMDRホストの脆弱性検出結果**をインポートします。これは、それぞれQualysのKnowledgeBase (QID) メタデータと結合されています。DefectDojoは、お使いのサブスクリプション内の各Qualys**ホスト**についてRecordを作成します。

#### 前提条件

**VMDR APIアクセス**を持つQualysユーザーアカウントと、サブスクリプションの**APIサーバー(プラットフォーム)URL**が必要です — これはサブスクリプションごとに異なります。Qualys UIの **Help > About** の下、またはQualysの[Platform Identification](https://www.qualys.com/platform-identification/)ページで確認できます(例: US Platform 1の場合は `https://qualysapi.qualys.com`、US Platform 2の場合は `https://qualysapi.qg2.apps.qualys.com`)。

#### Connector Mappings

1. **Location** フィールドにQualysのAPIサーバーURLを入力します(例: `https://qualysapi.qualys.com`)。
2. **Username** フィールドにQualys APIのユーザー名を入力します。
3. **Secret** フィールドにQualys APIのパスワードを入力します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各Qualysホストが1件のRecordになります。Qualysが**Fixed**とマークした検出結果は除外されるため、再インポートによって修復済みの検出事項がクローズされます。

## **Quay**

QuayコネクタはProject Quay REST APIを使用して、コンテナリポジトリを検出し、Quay組み込みの**Clair**スキャナが生成した脆弱性レポートをインポートします。DefectDojoは各Quay**リポジトリ**についてRecordを作成し、Syncのたびにアクティブな各タグのイメージマニフェストのClairセキュリティレポートを読み取ります。

#### 前提条件

Quayインスタンスでセキュリティスキャン(Clair)が有効になっている必要があり、Quayの**OAuth 2アクセストークン**が必要です:

* Quayで、Organizationを作成(または開き)、**Applications** に移動し、OAuthアプリケーションを作成し、少なくとも**Read repositories**スコープで **Generate Token** を実行します。DefectDojo専用のアプリケーションを作成することをお勧めします。
* トークンはすべてのリクエストでBearerトークンとして送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドにQuayのベースURLを入力します。例: `https://quay.io` またはセルフホストの `https://quay.example.com`。URLはHTTPSである必要があり、末尾にAPIパスを含めないでください — DefectDojoがAPIパスを自動的に構築します。
2. **Secret** フィールドにOAuthアクセストークンを入力します。
3. 必要に応じて **Namespace** を設定し、検出範囲を単一のQuay組織またはユーザーに限定します。空欄のままにすると、トークンが読み取れるすべてのリポジトリが検出されます。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは各Quay**リポジトリ**をRecordにマッピングします。各リポジトリについてアクティブなタグを列挙し、それらを一意のイメージマニフェストへと重複排除した上で(複数のタグで共有されるマニフェストは1回だけスキャンされます)、各マニフェストのClairレポートを読み取ります。Clairがまだスキャンを完了していないマニフェスト(例えばマルチアーキテクチャのマニフェストリストや、まだキュー中のイメージ)は、後のSyncまでスキップされます。各Clairの脆弱性は検出事項になります — 影響を受けるパッケージがコンポーネントとなり、修正バージョンが緩和策となり、Clairの**Negligible**/**Unknown**の深刻度は**Informational**として記録されます。

詳細については、[Project Quay APIドキュメント](https://docs.projectquay.io/api_quay.html)および[Clairドキュメント](https://quay.github.io/clair/)を参照してください。

## **Rapid7 InsightAppSec**

Rapid7 InsightAppSecコネクタは、InsightAppSecクラウドプラットフォームから**DAST脆弱性検出事項**をインポートし、アタックモジュールのメタデータ(例: *SQL Injection*)、CVSSスコア、スキャンで収集された証拠を付加します。DefectDojoは各InsightAppSecの**アプリ**についてRecordを作成します。

**ご注意ください:** このConnectorは、以下の**Rapid7 InsightVM**コネクタとは別のものです — InsightAppSecはInsightプラットフォーム上のRapid7のクラウドDAST製品であり、InsightVMの検出事項はお使いのSecurity Consoleから取得されます。

#### 前提条件

InsightAppSecを利用するInsightプラットフォームのアカウントと、プラットフォームの**APIキー**が必要です: [Rapid7 Insightプラットフォーム](https://insight.rapid7.com)で設定(歯車)メニュー > **API Keys** を開き、**User Key**(任意のロール)または**Organization Key**(プラットフォーム管理者)を生成します。表示された時点でキーをコピーしてください — 一度しか表示されません。

また、Insight URLに表示されるプラットフォームの**リージョン**(例: `us`、`us2`、`us3`、`eu`、`ca`、`au`、`ap`)も必要です。

#### Connector Mappings

1. **Location** フィールドにリージョンのAPIエンドポイントを入力します — 例: `https://us.api.insight.rapid7.com`(`us` をお使いのリージョンに置き換えてください)。
2. **API Key** フィールドにInsightプラットフォームのAPIキーを入力します。
3. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各InsightAppSecアプリが1件のRecordになります。**オープン**な脆弱性(UnreviewedまたはVerified)のみがインポートされます — Rapid7がRemediated、False Positive、Ignored、またはDuplicateとマークした検出事項は除外されるため、再インポートによってDefectDojo内でそれらがクローズされます。深刻度は直接マッピングされます(`SAFE` と `INFORMATIONAL` はInfoとしてインポートされます)。

## **Rapid7 InsightVM**

Rapid7 InsightVMコネクタは、お使いのInsightVM**Security Console**(API v3)からアセットの脆弱性検出事項をインポートし、コンソールのグローバル脆弱性カタログで情報を付加します。DefectDojoは各InsightVM**サイト**についてRecordを作成します。

#### 前提条件

DefectDojoからお使いのSecurity Consoleへのネットワークアクセスと、コンソールの**ユーザーアカウント**が必要です — そのログイン情報がHTTP Basic認証に使用されます。コンソールAPIはデフォルトでポート**3780**で提供されます。

#### Connector Mappings

1. **Location** フィールドに、ポートを含むSecurity ConsoleのURLを入力します — 例: `https://console.example.com:3780`。
2. **Username** フィールドにコンソールのユーザー名を入力します。
3. **Secret** フィールドにコンソールのパスワードを入力します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各InsightVMサイトが1件のRecordになります。コネクタはサイトのアセットを走査し、脆弱性のある検出事項をインポートします。

## **runZero**

runZeroコネクタはrunZero Export APIを使用して、組織全体のアセットインベントリをDefectDojoに同期します。これは主に**アセット**コネクタです: DefectDojoはすべてのアセットを検出してそれぞれについてRecordを作成し、runZeroの**サイト**ごとにProduct Typeにグループ化します。オプションで、runZeroの脆弱性を検出事項としてインポートすることもできます。

#### 前提条件

runZero(Account → API)から組織の**Export Token**が必要で、これは `XT` というプレフィックスが付きます。このトークンは組織スコープ(組織がトークン内にエンコードされています)、読み取り専用であり、Bearerトークンとして送信されます — ログに記録されることはありません。コミュニティ/スタータープランも利用できます。

#### Connector Mappings

1. **Location** フィールドにrunZeroコンソールのURLを入力します。例: `https://console.runzero.com`。URLはHTTPSである必要があります。
2. **Secret** フィールドにExport Tokenを入力します。
3. 必要に応じて **Import Vulnerabilities** を `true` に設定すると、runZeroの脆弱性も検出事項としてインポートされます。空欄のままにすると、アセットのみが同期されます。
4. 必要に応じて **Minimum Severity** を設定し、インポートする脆弱性の検出事項を絞り込みます(脆弱性がインポートされる場合にのみ適用されます)。

DefectDojoは各runZero**アセット**をRecord (VEP) にマッピングします: 表示名はアセットの名前またはアドレスから取得され、そのサイト、種別、OS、アドレス、タグが属性として付与されます。アセットの**サイト**がそのProduct Typeになります。アセットは、DefectDojoが差分を調整する(追加/削除する)完全なエクスポートによって同期されます。**Import Vulnerabilities** が有効な場合、各runZeroの脆弱性はそのアセット上の検出事項になります — 深刻度、CVSSスコア、CVE、影響を受けるサービス(`protocol://address:port`)のエンドポイント、および修復方法がマッピングされます。

詳細については、[runZero APIドキュメント](https://help.runzero.com/)を参照してください。

## **Semgrep**

このコネクタは、Semgrep REST APIを使用してデータを取得します。

#### Connector Mappings

**Location** フィールドに `https://semgrep.dev/api/v1/` を入力します。

1. **Secret** フィールドに有効なAPIキーを入力します。これはTokensページで確認できます:
​
左側のナビゲーションバーの「Settings」 \> Tokens \> Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

詳細については[Semgrepのドキュメント](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list)を参照してください。

## **ServiceNow CMDB**

ServiceNow CMDBコネクタは**アセットコネクタ**です: 検出事項をインポートする代わりに、お使いのServiceNow構成管理データベースからConfiguration Item (CI) を読み取り、各CIについてDefectDojoアセットを作成し、CIクラスごとにOrganizationにグループ化します。検出事項はインポートされません。

#### 前提条件

ServiceNowインスタンスと、ServiceNow Table API経由でCMDBテーブルを読み取れるアカウントが必要です。DefectDojo専用の読み取り専用サービスアカウントの利用をお勧めします。このアカウントには、インポートしたい `cmdb_ci` テーブルへの読み取りアクセス権が必要です。

#### Connector Mappings

1. **Location** フィールドにServiceNowインスタンスのURLを入力します: `https://{your-instance}.service-now.com`。
2. インスタンスの認証情報(ServiceNowのユーザー名とパスワード)を保持するServiceNowの**Tool Configuration**を選択または作成します。

各Configuration ItemがCIの名前を冠したRecordになり、その**CIクラス**(例: application、server、business serviceなど)でグループ化されます。DiscoveryとSyncはCIリストの差分を調整します: 新しいCIは `NEW` のRecordとして表示され、CMDBから削除されたCIは、チームがトリアージできるように次回のSyncで `MISSING` としてフラグが立てられます。DefectDojoが製品を黙って削除することはありません。

## **Shodan**

Shodanコネクタは、Shodan REST APIを使用して、インターネットに露出しているホストでShodanが観測した脆弱性 (CVE) をインポートします。お使いの資産に取り込み範囲を限定するShodan検索クエリを指定し、DefectDojoは一致する各ホストについてRecordを作成し、そのCVEを検出事項としてインポートします。

#### 前提条件

Shodanの**Account**ページで確認できるShodan APIキーが必要です。脆弱性データ付きのホスト検索には、Shodanのメンバーシップまたは有料APIプランが必要です — 無料プランでは検索結果をページングできません。

#### Connector Mappings

1. **Location** フィールドに `https://api.shodan.io` を入力します。
2. **API Key** フィールドにShodan APIキーを入力します。
3. **Search Query** フィールドに、お使いの組織の資産に取り込み範囲を限定するShodanクエリを入力します — 例: `hostname:example.com`、`net:203.0.113.0/24`、`org:"Example Inc"`。このクエリに一致するホストのみがインポートされるため、自組織が所有するインフラストラクチャに範囲を限定してください。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

一致する各ホストが1件のRecordになり、そのホストの露出しているサービス上でShodanが検出した各CVEが検出事項としてインポートされます — 深刻度はCVSSスコアから導出され、利用可能な場合はEPSSとCISA KEVのコンテキストが含まれます。検索結果の各ページはShodanのクエリクレジットを1つ消費します。

## SonarQube

SonarQubeコネクタは、SonarCloudアカウントまたはローカルのSonarQubeインスタンスのいずれからでもデータを取得できます。

**SonarCloudユーザーの場合:**

1. Locationフィールドに https://sonarcloud.io/ を入力します。
2. Secretフィールドに有効な**APIキー**を入力します。

**SonarQube(オンプレミス)ユーザーの場合:**

1. Locationフィールドにお使いのSonarQubeインスタンスのベースURLを入力します: 例 `https://my.sonarqube.com/`
2. Secretフィールドに有効な**APIキー**を入力します。これは**[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [APIトークンタイプ](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)である必要があります。

このトークンには、Sonar内のProjects、Vulnerabilities、Hotspotsへのアクセス権が必要です。

APIトークンは、SonarQubeアプリの **My Account -> Security -> Generate Token** から確認・生成できます。詳細については、[SonarQubeドキュメントを参照してください](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)。

## **Snyk**

Snykコネクタは、Snyk REST APIを使用してデータを取得します。

#### Connector Mappings

1. **Location** フィールドに **[https://api.snyk.io/rest](https://api.snyk.io/v1)** または(リージョナルなEUデプロイメントの場合)**[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** を入力します。
2. **Secret** フィールドに有効なAPIキーを入力します。APIトークンは、Snykのユーザーの**[アカウント設定](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)**[ページ](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)にあります。

詳細については[Snyk APIドキュメント](https://docs.snyk.io/snyk-api)を参照してください。

## **Socket**

Socket コネクタは [Socket.dev](https://socket.dev) API を使用して、**ソフトウェアサプライチェーンの検出事項**（依存関係に対する Socket のアラート — マルウェア、タイポスクワッティング、インストールスクリプト、既知の脆弱性、その他 70 以上のカテゴリ）をインポートします。DefectDojo はトークンがアクセスできる組織内のすべてのリポジトリを検出し、それぞれに対して Record を作成した上で、そのリポジトリの最新のフルスキャンからアラートをインポートします。

#### Prerequisites

Socket の **API トークン**（Socket ダッシュボードの **Settings → API Tokens** で作成する組織トークンで、`repo:list` とフルスキャンの読み取りスコープを持つもの）が必要です。トークンはベアラートークンとして送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドを空欄のままにすると `https://api.socket.dev/v0` が使用されます。明示的に入力することもできます。
2. **Secret** フィールドに Socket API トークンを入力します。
3. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

DefectDojo は各**リポジトリ**を Record にマッピングし、その最新のフルスキャンからアラートをインポートします。各アラートは検出事項になります。深刻度は Socket 自身の評価(low、medium、high、critical)に基づき、影響を受けるパッケージはコンポーネントおよび PURL になり、アラートのカテゴリ(サプライチェーンリスク、品質、メンテナンス、脆弱性、ライセンス)はタグとして記録され、アラートの詳細は説明に反映されます。検出事項は静的検出事項として記録され、Socket のアラートキーで重複排除されます。

詳細については、[Socket API ドキュメント](https://docs.socket.dev/reference)を参照してください。

## **Sonatype IQ**

Sonatype IQ コネクタは Sonatype IQ Server(Nexus Lifecycle)の REST API を使用して、オープンソースコンポーネントの脆弱性をインポートします。IQ 組織内のすべてのアプリケーションを列挙し、それぞれについて、設定したライフサイクルステージにおけるそのアプリケーションの最新レポートからコンポーネントの脆弱性をインポートします。DefectDojo は各アプリケーションに対して自動的に Record を作成します — アプリケーションごとの設定は不要です。

#### Prerequisites

インポートしたいアプリケーションに対して **View IQ Elements** 権限を持つ Sonatype IQ ユーザーアカウントが必要です。Sonatype はパスワードではなく、(IQ Server の **My Profile > User Token** で生成する)**ユーザートークン**を使用した認証を推奨しています。トークンの 2 つの部分は、以下の Username フィールドと User Token フィールドにそれぞれ対応します。このコネクタはセルフホスト型の IQ Server と、Sonatype がホストする(SaaS)インスタンスの両方に対応しています。

#### Connector Mappings

1. **Location** フィールドに IQ Server のベース URL を入力します — セルフホスト型サーバーの場合は `https://iq.example.com`、Sonatype がホストするインスタンスの場合は `https://<tenant>.sonatype.app/platform` です。
2. **Username** フィールドに IQ ユーザー(またはユーザートークンのユーザーコード部分)を入力します。
3. **User Token** フィールドに IQ ユーザートークン(またはパスワード)を入力します。
4. 必要に応じて、**Stage** を設定して、アプリケーションごとにどのライフサイクルステージのレポートをインポートするかを選択します(`build`、`stage-release`、`release` など)。空欄のままにすると `build` が使用されます。
5. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

各アプリケーションは Record になり、選択したステージにおけるそのアプリケーションの最新レポート内の各セキュリティ問題が検出事項としてインポートされます。深刻度は問題の数値スコアから導出され、CVE 参照、CWE、CVSS ベクター、影響を受けるコンポーネントのパッケージ URL(PURL)が利用可能な場合は含まれます。
## **Sysdig Secure**

Sysdig Secure コネクタは、Sysdig Secure の脆弱性管理 API から**コンテナ / CNAPP 脆弱性検出事項**をインポートします。設定されたスコープ全体でアカウント全体を同期し、スキャン対象のアセットグループごとに DefectDojo 製品を作成します。

#### Prerequisites

Sysdig Secure の **API トークン**: Sysdig Secure で **Settings > Sysdig Secure API Token** に移動し、トークンをコピーします。また、Sysdig の**リージョン URL**(例: `https://us2.app.sysdig.com`、`https://eu1.app.sysdig.com`、またはオンプレミスホスト)も必要です。

#### Connector Mappings

1. **Location** フィールドに Sysdig のリージョン / ベース URL を入力します。
2. **Secret** フィールドに API トークンを入力します。
3. 必要に応じて **Scopes** を設定します — `runtime`、`registry`、`pipeline` のカンマ区切りリストです(空欄の場合はデプロイ済みワークロードのスコープである `runtime` になります)。
4. 必要に応じて **Runtime Product Grouping** を設定します — ランタイムの結果を製品にどうマッピングするか(`cluster`、`namespace`、`workload`、`image`)を指定します(空欄の場合は `namespace` になります)。レジストリおよびパイプラインの結果は常にイメージリポジトリ単位でグループ化されます。
5. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

各アセットグループは Record になります。各スキャン結果について、コネクタは脆弱性のあるすべてのパッケージを検出事項としてインポートします。**Runtime** の検出事項(デプロイ済みワークロード)は動的検出事項として記録され、Kubernetes のクラスター / 名前空間 / ワークロード / コンテナのコンテキストがタグ付けされます。**registry** および **pipeline** の検出事項は静的なイメージスキャン検出事項として記録されます。Sysdig の `NEGLIGIBLE` 深刻度は Info にマッピングされます。

## Tenable

Tenable コネクタは **Tenable.io** REST API を使用してデータを取得します。 スキャンは Tenable VM の `/scans` エンドポイントから取得されます。

オンプレミス版の Tenable コネクタは現時点では利用できません。

#### **Connector Mappings**

1. Location フィールドに <https://cloud.tenable.com> を入力します。
2. Secret フィールドに有効な **API キー**を入力します。

詳細については、[Tenable の API ドキュメント](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm)を参照してください。

## **Tenable Web App Scanning**

Tenable Web App Scanning コネクタは、Tenable Web App Scanning から**Web アプリケーション(DAST)検出事項**をインポートします。これは Tenable(Vulnerability Management)とは別のコネクタです。両製品は対象とするアセットが異なり、それぞれ独立して設定されるため、どちらか一方、または両方を使用できます。

DefectDojo は**スキャン対象の Web アプリケーション**ごとに Record を作成します。アプリケーションは Web App Scanning のスキャン設定から検出されます。一度も実行されていない設定は、最初のスキャンが完了するまで Record を生成しません。複数の設定が同じアプリケーションをスキャンする場合、それらは 1 つの Record を共有します。

#### Prerequisites

Web App Scanning の権限を持つユーザー用の Tenable **API キー**(アクセスキーとシークレットキー)。Tenable で **My Account > API Keys** に移動して生成し、そのユーザーがインポートしたいスキャンを閲覧できることを確認してください — Vulnerability Management に限定されたキーでは Web App Scanning のデータを読み取れません。

オンプレミス版の Tenable コネクタは現時点では利用できません。

#### Connector Mappings

1. **Location** フィールドに <https://cloud.tenable.com> を入力します。
2. **Access Key** と **Secret Key** を入力します。
3. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

検出事項は、チームが変更した深刻度も含め、Tenable がアカウントに対して報告する深刻度でインポートされます。各検出事項には、影響を受ける URL がエンドポイントとして、検出のきっかけとなったリクエストパラメータとペイロード、および Tenable の証拠と出力が再現手順として含まれ、検出プラグインが提供する場合は CWE、CVE、CVSS、EPSS の値も含まれます。

現在オープンまたは再オープンされている検出事項のみがインポートされます。Tenable が修正済みとマークした検出事項は、次回の同期時に DefectDojo でクローズされます。

## **Veracode**

Veracode コネクタは、Veracode プラットフォームからアプリケーションの検出事項をインポートし、スキャンタイプごとに **SAST**、**DAST**、**SCA**、**Manual** の検出事項タイプに分けます。DefectDojo は Veracode の**アプリケーション**ごとに Record を作成します。

#### Prerequisites

インポートしたいアプリケーションを閲覧できるアカウントに対して、Veracode の **API 認証情報**を生成します: Veracode プラットフォームでアカウントメニューを開き、**API Credentials** から **Generate API Credentials** を選択します([Veracode API 認証情報の管理](https://docs.veracode.com/r/c_api_credentials3)を参照)。**API ID** と **API Secret Key** の両方をコピーしてください — シークレットは一度しか表示されません。

#### Connector Mappings

1. **Location** フィールドに Veracode API のベース URL を入力します: `https://api.veracode.com`(商用リージョン)、`https://api.veracode.eu`(欧州リージョン)、または `https://api.veracode.us`(米国連邦リージョン)です。
2. **API ID** フィールドに API ID を入力します。
3. **Secret** フィールドに API シークレットキーを入力します。
4. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

各 Veracode アプリケーションは Record になります。**open**(未解決)の検出事項のみがインポートされるため、再インポートを行うと、Veracode が解決済みと報告した検出事項はクローズされます。

## **Wazuh**

Wazuh コネクタは、Wazuh Indexer(OpenSearch)を使用して脆弱性の検出事項を取得します。Wazuh 4.8 以降では、検出された CVE は Wazuh サーバー API ではなく Indexer に保存されるため、このコネクタは `wazuh-states-vulnerabilities-*` インデックスから直接それらを読み取ります。

DefectDojo は Wazuh エージェント(エンドポイント)ごとに Record を作成し、そのエージェントで検出された CVE をスケジュールに基づいて検出事項としてインポートします。

#### Prerequisites

以下が必要です。

* ポートを含む Wazuh Indexer のベース URL(Indexer はデフォルトでポート 9200 で待ち受けます)。DefectDojo は Indexer に直接接続するため、このエンドポイントは DefectDojo から到達可能である必要があります。セルフマネージド環境では、これは Wazuh Indexer を実行しているホストです。Wazuh Cloud の場合は、Wazuh Cloud コンソールに表示される Indexer エンドポイントを使用してください。これは Wazuh ダッシュボードの URL とは別のものです。
* `wazuh-states-vulnerabilities-*` インデックスへの読み取りアクセス権を持つ Indexer のユーザーとパスワード。DefectDojo 専用のユーザーを作成することをお勧めします。

脆弱性状態インデックスにデータが投入されるよう、Wazuh で脆弱性検出を有効にしておく必要があります。詳細については、[Wazuh 脆弱性検出ドキュメント](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html)を参照してください。

#### Connector Mappings

1. **Location** フィールドに、スキームとポートを含む Wazuh Indexer のベース URL を入力します。例: `https://your-indexer.example.com:9200`。末尾にパスを含めないでください。DefectDojo が検索パスを自動的に構築します。
2. **Username** フィールドに Indexer のユーザー名を入力します。
3. **Password** フィールドに Indexer のパスワードを入力します。
4. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。選択した深刻度を下回る検出事項はインポートされません。

## Wiz

Wiz コネクタを使用するには、サービスアカウントを作成する必要があります。詳細については [Wiz のドキュメント](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account)を参照してください。ドキュメントにアクセスするには Wiz アカウントが必要です。

サービスアカウントは、以下の要件をすべて満たしている必要があります。いずれかを満たしていないサービスアカウントでも認証自体は成功しますが、何もインポートされません。

* **Type**: Custom Integration(GraphQL API)。
* **API scopes**: 最低限 `read:projects`、`read:issues`、`read:vulnerabilities` が必要です。
* **Project visibility**: サービスアカウントは、インポートしたいすべての Wiz Project(またはすべての Project)に対してスコープが設定されている必要があります。コネクタはまず Wiz Project を検出し、その後各 Project の検出事項を取得します — issue を読み取れても Project の可視性がないアカウントは Project を 1 つも検出できないため、インポートするものがなく、双方からエラーも報告されません。

#### **Connector Mappings**

1. Client ID フィールドに Wiz の Client ID を入力します。
2. Secret フィールドに Wiz の Client Secret を入力します。

## **YesWeHack**

YesWeHack コネクタは、YesWeHack REST API を使用して、バグバウンティおよび脆弱性開示プログラムからレポートをインポートします。DefectDojo は、トークンがアクセスできるプログラムごとに Record を作成し、そのレポートを検出事項としてインポートします。

#### Prerequisites

YesWeHack の **Personal Access Token(PAT)**が必要です。プログラムへの読み取りアクセス権があれば十分です。一部のアカウントではトークン作成時に TOTP/MFA が必要ですが、作成後はトークンの値自体をコネクタが使用します。

1. YesWeHack でアカウント設定を開き、**API / Personal Access Tokens** に移動します。
2. トークンを作成し、その値をコピーします。値は一度しか表示されません。

#### Connector Mappings

1. **Location** フィールドに `https://api.yeswehack.com/` を入力します。
2. **Secret** フィールドに Personal Access Token を入力します。
3. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。選択した深刻度を下回る検出事項はインポートされません。

DefectDojo は、トークンがアクセスできるプログラムごとに個別の Record を作成し、各レポートを検出事項としてインポートします。検出事項の深刻度はレポートの CVSS 評価から取得され(利用できない場合はトリアージの優先度にフォールバックします)、そのステータスはレポートのワークフロー状態を反映します — 例えば、解決済みのレポートは緩和済みとしてインポートされ、無効または対象外とマークされたレポートは非アクティブとしてインポートされます。
