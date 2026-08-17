---
title: DefectDojo Pro インストールガイド
description: Helm チャートを使用して DefectDojo Pro を Kubernetes にインストールする方法。インフラストラクチャ、シークレット、インストール自体について説明します
draft: false
weight: 13
audience: pro
---

<!--
  DefectDojo Pro Helm チャートリポジトリから生成されています。
  ソース: chart バージョン 3.1.304 の docs/INSTALLATION_GUIDE.md。
  このファイルではなく、ソースのガイドを編集してください。ローカルでの変更は
  次回チャートがリリースされた際に上書きされます。
-->
AWS EKS と OpenShift (ROSA) へのデプロイを対象としています。どちらもワークフローは
同じです。インフラストラクチャをセットアップし、シークレットを作成し、チャートを
インストールします。

---

## インストール前チェックリスト

作業を始める前に、以下の情報を収集してください。あらかじめ準備しておくことで、
インストール作業中の遅延を避けられます。

### インフラストラクチャの詳細

| 項目 | 例 | 確認方法 |
|------|---------|-------------------|
| **PostgreSQL ホスト** | `mydb.abc123.us-east-1.rds.amazonaws.com` | AWS RDS コンソールまたは `aws rds describe-db-instances` |
| **PostgreSQL ポート** | `5432` | カスタマイズされていない限り、通常は5432です |
| **PostgreSQL データベース名** | `dojodb` | DBA、または Terraform/CloudFormation の出力 — インストール前に作成しておく必要があります（下記の注記を参照） |
| **オーケストレーターデータベース** | `dojodb-ddorch` | アプリケーションロールに `CREATEDB` を付与するか、`<dbname>-ddorch` を事前に作成してください — [事前確認: オーケストレーター (ddorch) データベース](#pre-flight-orchestrator-ddorch-database) を参照 |
| **PostgreSQL ユーザー名** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **PostgreSQL パスワード** | — | AWS Secrets Manager、Terraform の状態ファイル、または DBA |
| **Redis/ElastiCache エンドポイント** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Redis パスワード** | — | 認証が無効な場合（VPC内のみ）は省略可能です。確認方法: `aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **EFS ファイルシステムID** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **EFS アクセスポイントID**（該当する場合） | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **EFS アクセスポイントのUID/GID** | UID `1001`、GID `1337` | コンテナのセキュリティコンテキストと一致させる必要があります（下記の注記を参照） |
| **ドメイン名（FQDN）** | `dojo.example.com` | DNS管理者に確認してください（下記のプラットフォーム固有の注記を参照） |
| **ACM証明書ARN**（HTTPS利用時のEKS） | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **OpenShift appsドメイン**（ROSAのみ） | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **OpenShift ネームスペースfsGroup**（ROSAのみ） | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'` — 開始値を使用してください |
| **ライセンスファイル** | `onprem-dojopro.lic` | DefectDojo サポートより提供されます |

> **インストール前にデータベースを作成してください。** このチャートは外部の
> PostgreSQL サーバー上にデータベースを作成しません。`helm install` を実行する
> 前に、アプリケーションユーザーが所有する形で、以下の両方をデータベース
> サーバー上に作成してください。
>
> - `dojodb` — メインの DefectDojo データベース
> - `dojodb-ddorch` — オーケストレーター (ddorch) データベース。常にメイン
>   データベース名に `-ddorch` サフィックスを付けた名前になります。あるいは、
>   アプリケーションロールに `CREATEDB` を付与すれば、ddorch が初回起動時に
>   自身でこれを作成します。
>
> すぐに実行できる `CREATE DATABASE` コマンドについては、
> [事前確認: データベース接続の確認](#pre-flight-verify-database-connectivity)
> と [事前確認: オーケストレーター (ddorch) データベース](#pre-flight-orchestrator-ddorch-database)
> を参照してください。

> **EFS アクセスポイントのUID/GID:** EFS ファイルシステムでアクセスポイントを
> 使用している場合、その POSIX ユーザー設定は DefectDojo コンテナのセキュリティ
> コンテキストに合わせて UID `1001`、GID `1337` を使用する**必要があります**。
> 一致していないと、コンテナがメディアのサブディレクトリを作成しようとする
> 初期化時に `Permission denied` エラーが発生します。以下で確認してください。
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **OpenShift/ROSA の FQDN:** ROSA では、Route はホスト名を
> `<release-name>-<namespace>.apps.<cluster-domain>` というパターンで自動生成
> します。例えば、リリース名が `dojopro`、ネームスペースが `dojopro` の場合、
> Route のホスト名は `dojopro-dojopro.apps.abc123.p1.openshiftapps.com` に
> なります。クラスターの apps ドメインは以下で確認できます。
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```
>
> 得られた FQDN を `dojo.fqdn`、`dojo.url`、`dojo.hosts.main` に使用してください。

> **OpenShift/ROSA の fsGroup:** `securityContext.openshift.fsGroup` には、
> ネームスペースの supplemental-groups の開始値が必要です。後で values
> ファイルを編集し直さずに済むよう、今のうちに確認しておきましょう。
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### 生成するシークレット

以下のシークレットは、デプロイのために新規に生成する必要があります。暗号学的に
ランダムな値を作成するには、記載のコマンドを使用してください。

| シークレット | K8s Secret内のキー | 生成方法 |
|--------|-------------------|---------------|
| Django シークレットキー | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| AES-256 暗号化キー | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| クラウドポータルシークレット | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| コネクター共有シークレット | `DD_CONNECTORS_SHARED_SECRET` | `CLOUD_PORTAL_SECRET_KEY` と同じ値を使用 |
| 管理者パスワード | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| メトリクスパスワード | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### 既存インフラストラクチャからのシークレット

これらは既存のインフラストラクチャから取得するものであり、新規に生成しないで
ください。

| シークレット | K8s Secret内のキー | 取得元 |
|--------|-------------------|--------|
| データベースパスワード | `DD_DATABASE_PASSWORD` | PostgreSQLのパスワード |
| データベース接続URL | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Redis パスワード | `redis-password`（別の `dojopro-redis` シークレット内） | Redisのパスワード。認証がない場合は省略可 |
| メールサービスURL | `DD_EMAIL_URL` | テスト用には `consolemail://`、または SMTP の URL |

### オプション（無効にする場合は空欄のまま）

| シークレット | K8s Secret内のキー | 用途 |
|--------|-------------------|---------|
| EPSS バケットキー | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | EPSS スコアのエンリッチメント |

> **ヒント:** `secrets-template.yaml` をコピーして、上記の値を入力してください。
> Kubernetes Secret の作成に関する詳しい手順は
> [シークレットの生成](#generate-secrets) を参照してください。

---

## 前提条件

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

OpenShift/ROSA の場合は、以下も併せてインストールしてください。
```bash
brew install rosa openshift-cli
```

### アウトバウンド接続の要件

制限されたネットワーク環境では、インストール前に以下のアウトバウンド接続を
許可しておく必要があります。ファイアウォールルールの変更には事前の変更申請が
必要な場合があるため、作業を進める前に許可設定が済んでいることを確認してください。

**コンテナレジストリ（必須）**

すべてのクラスターノードは、ポート443で DefectDojo のコンテナレジストリに
到達できる必要があります。

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> エアギャップ環境については、
> [プライベートレジストリ / エアギャップ環境](#private-registry-air-gapped-environments)
> を参照してください。

**データベース（必須）**

クラスターノードから PostgreSQL インスタンスへ、通常はポート5432で接続します。

- 同一 VPC 内の RDS: EKS ノードのセキュリティグループがポート5432でインバウンド
  許可されていることを確認してください
- 別の VPC またはアカウントの RDS: VPC ピアリングまたは Transit Gateway が必要です
- 外部/オンプレミス: VPN または Direct Connect の経路でポート5432を許可する
  必要があります

**EPSS の更新（推奨）**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**KEV フィード（推奨）**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**AWS サービス（EKSのみ、必須）**

EBS CSI ドライバーと ALB Controller は、ポート443で AWS API エンドポイントへの
アクセスが必要です。

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com`（EFSを使用する場合）

### AWS EKS の前提条件

DefectDojo Pro をデプロイする前に、以下のコンポーネントを EKS クラスターに
インストールしておく必要があります。インストールしていない場合、デプロイは
失敗します。

**EBS CSI Driver**（組み込みの PostgreSQL と Redis を使用する minimal プロファイル
の場合にのみ必要です。外部の RDS と ElastiCache を使用する場合は不要です）:

```bash
# Associate IAM OIDC provider
eksctl utils associate-iam-oidc-provider \
  --cluster <your-cluster> --region <region> --approve

# Create IAM role for EBS CSI
eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EBS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-ebs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EBS_CSI_DriverRole \
  --force
```

**EFS CSI Driver**（EFS ストレージを使用する場合に必要です。マルチレプリカの
EKS デプロイでは、これが推奨のストレージバックエンドです）:

```bash
# Create IAM role for EFS CSI
eksctl create iamserviceaccount \
  --name efs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EFS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-efs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EFS_CSI_DriverRole \
  --force
```

**AWS Load Balancer Controller**（ALB ingress を使用する場合に必要です）:

インストール手順は EKS のバージョンによって異なります。
[AWS Load Balancer Controller の公式インストールガイド](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/)
に従ってください。

---

## チャートパッケージの展開

チャートは `.tgz` の Helm パッケージを含む zip として配布されます。作業を
進める前に、両方を展開してください。後で新しいバージョンのチャートを展開した
際にプリセットが気づかないうちに上書きされないよう、バージョン番号を含む
展開先パスを使用してください。

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

展開したチャートディレクトリを指す `CHART` 変数を設定してください。この
ガイドの以降の `helm` コマンドはすべて `$CHART` を使用します。

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **CLI ユーザーが展開を必要とする理由:** プリセットファイル
> (`presets/platforms/*.yaml`、`presets/profiles/*.yaml`) は `.tgz` パッケージ
> 内に同梱されています。`helm install -f` はローカルファイルシステム上の
> ファイルを必要とし、パッケージ化された `.tgz` の中のファイルを読み込む
> ことはできません。プリセットにアクセスするには、チャートを展開する
> 必要があります。
>
> **ArgoCD ユーザーは展開する必要はありません。** ArgoCD はチャートパッケージ
> の内部から直接 `valueFiles` を読み込みます。詳細は
> [ArgoCD でのデプロイ](#deploy-with-argocd) を参照してください。

---

## Values ファイルの準備

顧客向け設定テンプレート（`template.yaml`）とシークレットテンプレート
（`secrets-template.yaml`）は、DefectDojo サポートポータルから、または
support@defectdojo.com から別途入手できます。これらはチャートの `.tgz` には
含まれていません。テンプレートを入手したら、コピーして詳細情報を入力して
ください。

```bash
cp template.yaml my-company.yaml
```

少なくとも、以下を設定してください。

| 設定 | 説明 |
|---------|-------------|
| `dojo.fqdn` | ドメイン名（ROSA: 上記の [FQDNに関する注記](#infrastructure-details) を参照） |
| `dojo.url` | プロトコルを含む完全なURL（例: `https://dojo.example.com`） |
| `dojo.hosts.main` | FQDNと一致させる必要があります |
| `dojo.secureCookies` | **OpenShift/ROSA** では `false` に設定します（下記の警告を参照） |
| `dojo.admin.*` | `user`、`email`、`firstName`、`lastName` — 管理者アカウント |
| `database.host`、`.port`、`.name`、`.user` | PostgreSQL の接続情報（パスワードはシークレットに設定） |
| `celery.broker.host` | Redis/ElastiCache のエンドポイント |
| `redis.enabled` | 外部の Redis を使用する場合は**必ず `false`** にしてください（下記の警告を参照） |
| `storage.type` | ストレージバックエンド — プラットフォーム固有の注記を参照 |
| `certificates.*` | TLS証明書の設定 |
| `django.ingress.*` または `django.route.*` | Ingress（EKS）または Route（OpenShift）— プリセットがデフォルト値を設定します |
| `securityContext.openshift.fsGroup` | **ROSAのみ** — ネームスペースの supplemental-groups 開始値 |

> **警告 — 外部の Redis/ElastiCache を使用する場合、`redis.enabled` を明示的に
> `false` に設定する必要があります。** `standard` および `performance`
> プロファイルのプリセットは、デフォルトで `redis.enabled: true` を設定
> します。values ファイルでこれを上書きしないと、チャートは外部のブローカー
> に**加えて**クラスター内 Redis もデプロイしてしまい、設定が壊れた状態に
> なります。values ファイルに以下を追加してください。
>
> ```yaml
> redis:
>   enabled: false
> ```

> **警告 — OpenShift/ROSA では `dojo.secureCookies` を `false` にする必要が
> あります。** エッジ TLS 終端の OpenShift Route を使用する場合、
> `secureCookies: true`（`template.yaml` のデフォルト）はリダイレクトループ
> やログイン不可を引き起こします。これはオプションではなく、エッジ終端の
> Route では以下が必須です。
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**ストレージに関する注記:**
- **EKS:** EBS ではなく EFS を使用してください。EBS ボリュームはノード間で
  共有できず、`Multi-Attach` エラーの原因になります。詳細は
  [既知の問題](#known-issues-chart-version-2.57.1) を参照してください。
  EFS でアクセスポイントを使用している場合は、`storage.efs.accessPointId`
  も設定してください。詳細は [EFS アクセスポイント](#efs-access-points)
  を参照してください。
- **OpenShift/ROSA:** プラットフォームプリセットのデフォルトは
  `storage.type: "pvc"` と `createNew: true` で、クラスターのデフォルト
  StorageClass を使用します。マルチノードデプロイでは、EFS 経由の NFS
  （`storage.type: "nfs"`）を使用してください。

必要に応じて、ログの詳細度を設定できます。
- `config.logLevel` — Django アプリケーションのログレベル（デフォルト: `"INFO"`）
- `celery.logLevel` — Celery worker/beat のログレベル（デフォルト: `"INFO"`）

トラブルシューティングの際は、いずれかを `"DEBUG"` に設定してください。values
ファイルを編集せずに実行時にこれを切り替える方法については、
[ログの詳細度](#log-verbosity) を参照してください。

このファイルにシークレットやライセンスの内容を含めないでください。それらは
次の2つのセクションで扱います。

オプションの一覧については `template.yaml` を参照してください。

### 事前確認: データベース接続の確認

作業を進める前に、データベースに到達できることを確認してください。これにより、
後々のトラブルシューティングにかかる時間を大幅に削減できます。`psql` を使った
一時的な Pod を起動します。

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

接続に成功すると、以下のような表示になります。

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

`database "dojodb" does not exist` というエラーで失敗する場合、RDS インスタンス
には到達できていますが、データベースがまだ作成されていません。以下で作成
してください。

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

その後、上記の接続確認を再実行して確認してください。

他の理由で失敗する場合は、以下を確認してください。
- **セキュリティグループ / ファイアウォールルール** — クラスターから
  データベースホストへ、ポート5432が開いている必要があります
- **データベースユーザーの権限** — ユーザーは対象のデータベースに対する
  CREATE、ALTER、SELECT 権限に加えて、`CREATEDB` またはオーケストレーター
  データベースの事前作成のいずれかが必要です（次のセクションを参照）

> このチャートには組み込みのチェックも含まれています。データベースへの TCP
> 接続を待機する init コンテナと、デプロイ後に PostgreSQL への完全な接続を
> 検証する `helm test` です。この事前確認のステップにより、シークレットの
> 作成や `helm install` の実行に時間を費やす前に問題を発見できます。

### 事前確認: オーケストレーター (ddorch) データベース

オーケストレーター（`ddorch`、デフォルトで有効）は、メインの DefectDojo
データベースに加えて**2つ目のデータベース**にワークフローの状態を保存します。
起動時に `DD_DATABASE_URL` からデータベース名を取得して `-ddorch` を付加し、
そのデータベースが存在しない場合は作成します。メインデータベースが `dojodb`
であれば、オーケストレーターは `dojodb-ddorch` を使用するということです。

アプリケーションロールにデータベースの作成が許可されていない場合、ddorch の
Pod は起動時に以下のエラーで失敗します。

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

インストールの前に、以下の**いずれか**を満たしてください。

**オプションA — アプリケーションロールに `CREATEDB` を付与する** — ddorch が
初回起動時に自身のデータベースを作成できるようにします。

```sql
ALTER ROLE defectdojo CREATEDB;
```

**オプションB — オーケストレーターデータベースを事前に作成する** — メイン
データベース名に `-ddorch` サフィックスを付けた名前にし、同じアプリケーション
ユーザーが所有するようにします。名前にハイフンが含まれるため、SQL では
ダブルクォートが必要です。

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

上記の接続確認と同じ一時的な Pod の手法を使用します。

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## シークレットの生成

ここでは2つの方法があります。

### オプションA: 外部シークレット（GitOps推奨）

チャートをインストールする前に、必要な12個のキーを含む Kubernetes Secret を
作成してください。DefectDojo サポートが提供する `secrets-template.yaml` を
出発点として使用します（入手方法は
[Values ファイルの準備](#prepare-your-values-file) を参照してください）。

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

ファイルを編集してすべてのプレースホルダーの値を置き換え、適用します。
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

このシークレットは、External Secrets Operator や Sealed Secrets、その他
Kubernetes Secret を作成する任意のツールで管理することもできます。チャート
はシークレットがどのように作成されたかを気にしません。`dojo.existingSecret`
にその名前を設定するだけです。

インストール時には次のようにします。
```bash
--set dojo.existingSecret=dojopro-secrets
```

`dojo.existingSecret` が設定されている場合、チャートは組み込みの Secret の
レンダリングを自動的にスキップします。追加のフラグは不要です。

外部の Redis で認証が必要な場合、`secrets-template.yaml` には別途
`dojopro-redis` Secret も含まれています。チャートは
`redis.auth.existingSecret`（デフォルト: `dojopro-redis`）から Redis の
認証情報を読み取ります。Redis にパスワードがない場合（例: VPC内のみの
ElastiCache）は、これを省略できます。

### オプションB: インラインシークレット（よりシンプルだが GitOps には不向き）

values ファイルにシークレットの値を直接指定します。

```yaml
dojo:
  secretKey: ""                    # openssl rand -hex 25
  credentialAES256Key: ""          # openssl rand -hex 16
  cloudPortalSecretKey: ""         # openssl rand -hex 25
  connectorsSharedSecret: ""       # openssl rand -hex 25 (or reuse cloudPortalSecretKey)
  admin:
    password: ""                   # openssl rand -base64 16
  emailUrl: "consolemail://"
  proEnhancementsEpssBucketKey: "" # leave empty if not using EPSS

database:
  password: ""                     # your PostgreSQL password

redis:
  auth:
    password: ""                   # your Redis password (omit if Redis has no auth)

monitoring:
  password: ""                     # openssl rand -hex 16
```

これを `my-secrets.yaml` として保存し、インストール時に `-f` で指定して
ください。

> シークレットファイルをバージョン管理にコミットしないでください。

---

## 内部TLS証明書の作成

このチャートは、サービス間通信のために内部TLS証明書を必要とします。

インストールの前に、ネームスペース内に2つの Kubernetes TLS シークレットを
作成してください。

1. `dojopro-internal-tls` — サービス間の暗号化（nginx ↔ connectors など）
   のための `tls.crt` と `tls.key` を含む TLS シークレット
2. `dojopro-internal-ca` — connectors が内部TLS証明書を検証するために使用
   する、`ca.crt` キーの下にCA証明書を含むシークレット

自己署名のCAとサーバー証明書は `openssl` で生成することも、組織の内部CAを
使用することもできます。サーバー証明書の CN/SAN は、Helm リリースが使用する
内部 nginx サービス名を**必ず**カバーしている必要があります。デフォルトでは、
これは `<release-name>-nginx` です（例えば、リリース名が `dojopro` の場合は
`dojopro-nginx`）。

自己署名のCAとサーバー証明書を生成する例:
```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# Generate CA
# basicConstraints + keyUsage MUST be set explicitly. Without them the CA may
# be rejected as not a valid CA (e.g. "x509: certificate signed by unknown
# authority" / missing keyUsage) depending on your local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-internal-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# Generate server cert with correct SANs and usage extensions
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes \
  -subj "/CN=${RELEASE_NAME}-nginx" \
  -addext "subjectAltName=DNS:${RELEASE_NAME}-nginx,DNS:${RELEASE_NAME}-nginx.${NAMESPACE}.svc.cluster.local" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -copy_extensions copyall

# Create the Kubernetes secrets
kubectl create secret tls dojopro-internal-tls \
  --cert=server.crt --key=server.key \
  -n $NAMESPACE

kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=ca.crt \
  -n $NAMESPACE
```

> **よくある間違い:** CN/SAN として `<release-name>-nginx` の代わりに
> `nginx-internal` を使用してしまうケースです。connectors の Pod は実際の
> サービス名（`<release-name>-nginx.<namespace>.svc.cluster.local`）に対して
> TLS証明書を検証するため、SAN が一致しないと
> `x509: certificate is valid for ... not ...` エラーで失敗します。

その後、values ファイルに以下を設定します。
```yaml
certificates:
  generation:
    enabled: false
  internal:
    source: "secret"
    secretName: "dojopro-internal-tls"
    caBundle:
      secretName: "dojopro-internal-ca"
      key: "ca.crt"
```

### ddorch mTLS証明書

上記の内部TLSシークレットに加えて、`ddorch` オーケストレーターは、ddorch
サーバーおよびそれと通信するすべてのワーカー（`ddorch-workers`、
`integrators`）が使用する、別個のmTLS証明書一式（3ファイル）を必要とします。
これらはインストール時に `--set-file` を通じてチャートに渡されます（既存の
Kubernetes secret から読み込まれる**わけではありません**）:

- `orch_tls_root.ca` — CA証明書
- `orch_tls.crt` — サーバー証明書
- `orch_tls.key` — サーバーの秘密鍵

これら3つのファイルがないと、`helm install` は `ddorch.tls.rootCa is required`
というエラーで失敗します。

サーバー証明書の SAN には、ワーカーが ddorch に到達するために使用するすべての
ホスト名を**必ず**含める必要があります。

- `ddorch` — クラスター内サービスの短縮名
- `<release-name>-ddorch` — 完全修飾サービス名（例: `dojopro-ddorch`）
- `<release-name>-ddorch.<namespace>.svc.cluster.local` — クラスターのFQDN
- `nginx` — hatchet 方式のワーカーが使用するデフォルトの `SERVER_TLS_SERVER_NAME`
- `localhost`、`127.0.0.1` — hostAlias のループバック経由で ddorch に到達する
  同一Pod内のワーカー用

3ファイル一式を生成する例:

```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# ddorch CA
# As with the internal CA, set basicConstraints + keyUsage explicitly so the
# generated cert is a valid signing CA regardless of local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout orch_ca.key -out orch_ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-ddorch-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# ddorch server cert
openssl req -newkey rsa:2048 -keyout orch_server.key -out orch_server.csr -nodes \
  -subj "/CN=ddorch" \
  -addext "subjectAltName=DNS:ddorch,DNS:${RELEASE_NAME}-ddorch,DNS:${RELEASE_NAME}-ddorch.${NAMESPACE}.svc.cluster.local,DNS:nginx,DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in orch_server.csr -CA orch_ca.crt -CAkey orch_ca.key \
  -CAcreateserial -out orch_server.crt -days 365 -copy_extensions copyall
```

これらを `helm install` / `helm template` に渡します。

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> `scripts/bootstrap-aws-eks.sh` ヘルパースクリプトは、
> `dojopro-orch-certs-configmap` を通じてこれらを自動的に生成・再利用します。
> このスクリプトを使用している場合は、手動で作成する必要はありません。

---

## ライセンス

このチャートには DefectDojo Pro のライセンスが必要です。

### ライセンスの確認

デプロイする前に、ライセンスが有効であり、期限切れでないことを確認してください。

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

これにより、以下を含むライセンスのメタデータが表示されます。
- `not_after` — ライセンスの有効期限
- `license_package` — ご利用のティアを確認できます

> **イメージプルシークレット:** `images.pullSecrets.extractFromLicense: true`
> が設定されている場合（プラットフォームプリセットのデフォルト）、チャートは
> ライセンスファイルに埋め込まれた GCP サービスアカウントを自動的に抽出し、
> コンテナレジストリから DefectDojo イメージを取得するために必要なイメージ
> プルシークレットを作成します。手動での抽出やデコードは不要です。代わりに
> プライベートレジストリを使用する場合は、`extractFromLicense: false` を
> 設定し、独自のプルシークレットを用意してください。詳細は
> [プライベートレジストリ / エアギャップ環境](#private-registry-air-gapped-environments)
> を参照してください。

### オプション1: --set-file（標準的な Helm インストール）

インストール時にライセンスファイルを渡します。
```bash
--set-file license.contents=/path/to/license.lic
```

### オプション2: 既存のシークレット（GitOps / ArgoCD）

ライセンスを含む Kubernetes Secret を作成し、それを使用するようチャートに
指示します。これにより、`--set-file` を使う必要も、ライセンスを git に保存
する必要もなくなります。

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

その後、values ファイルまたは helm のフラグで以下を設定します。
```yaml
license:
  existingSecret: "dojopro-license"
```

このシークレットは、External Secrets Operator、Sealed Secrets、または通常の
kubectl で管理できます。

> **重要:** `license.existingSecret` は、デフォルトの
> `images.pullSecrets.extractFromLicense: true` 設定とは**互換性がありません**。
> チャートは、埋め込まれたコンテナレジストリの認証情報を抽出するために、
> レンダリング時にライセンスの内容を利用できる必要があります。
> `license.existingSecret` を使用する場合は、自動プルシークレット抽出を
> 無効にし、独自のプルシークレットを用意する必要もあります。
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```
>
> チャートにライセンスからプルシークレットを自動抽出させたい場合（デフォルト
> の動作）は、代わりに**オプション1**（`--set-file license.contents=`）を
> 使用してください。


---

## FIPS 140-3 モード（オプション）

FedRAMP **SC-13** などの要件が適用される環境向けに、チャートは `-fips`
イメージバリアントをデプロイできます。この暗号処理は **OpenSSL FIPS
Provider 3.1.2**（NIST CMVP 証明書**#4985**）、Go サービスについては
**Go Cryptographic Module v1.0.0**（CMVP **#5247**）によって行われます。

この強制はコンテナ内部で行われるため、FIPS対応のホストカーネルは不要です。
これにより、ホストOSを自分で管理できないマネージドランタイム上でも実現
可能になっています。

デフォルトでは無効になっており、オフの場合はレンダリング結果に変化はありません。

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

`-fips` タグ付きのイメージがレジストリで利用可能である必要があります。
アクセスについては hello@defectdojo.com までお問い合わせください。

### FIPSバリアントがないコンポーネント

Sensei と**組み込みの** PostgreSQL/Redis には FIPS ビルドがありません。同梱の
valkey イメージは Alpine ベースであり、FIPS 認証済みの OpenSSL を持っていません。
そのため、FIPS インストールでは外部のデータストアを使用し、Sensei を無効の
ままにする必要があります。

```yaml
fips:
  enabled: true
sensei:
  enabled: false
postgresql:
  enabled: false    # point at an external FIPS-compliant database
redis:
  enabled: false    # point at an external FIPS-compliant cache
```

`fips.validate: true`（デフォルト）の場合、これらのいずれかと一緒に FIPS を
有効にすると、チャートは**レンダリングに失敗**し、該当する対象を名指しします。

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

これは意図的な挙動です。ほとんどのサービスが検証済みの暗号を使用している
一方で、1つか2つだけがひっそりとそうなっていないデプロイは、明白な失敗より
も悪質です。一見すると準拠しているように見えて、評価の際に初めて表面化する
からです。`fips.validate: false` は、そのリスクを明示的に許容した場合にのみ
設定してください。

### デプロイ後の確認

すべての Pod は fail-closed 方式の起動時チェックを実行します。認証済みの
プロバイダーが有効でない場合、コンテナはサービスを提供せずに終了します。
このチェックが出力する証跡は、多くの場合、評価者が求めているものです。

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

計画しておくべき挙動の変化（パスワードハッシュ化が PBKDF2 に切り替わる、
ChaCha20 が TLS 暗号スイート一覧から除外される、など）については、製品
ドキュメントの FIPS 140-3 モードのページで説明しています。

---

## Pre-flight: テンプレートの検証

インストールを行う前に、`helm template` を実行してクラスターに触れることなくすべてのマニフェストをレンダリング・検証してください。これにより、`helm install` を実行する前に values のエラー、必須フィールドの欠落、YAML の問題を検出できます。

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  > /dev/null
```

`helm install` に渡す予定のものと同じフラグを使用してください。これがエラーなく終了すれば、values は有効です。失敗した場合、エラーメッセージに欠落または無効なフィールドが示されるので、values ファイルを修正して成功するまで再実行してください。

---

## デプロイ

プラットフォームのオーバーレイ、リソースプロファイル、顧客固有の values、そして上記で選択したシークレットとライセンスの設定を組み合わせます。

### AWS EKS

> **EKS でのブラウザアクセスには HTTPS を強く推奨します。**
> ingress の TLS が有効な場合、チャートは自動的に `SECURE_SSL_REDIRECT` を有効にし、CSRF/セッションクッキーを `Secure` に設定します。そのため、ALB に HTTPS リスナーがないとブラウザからのログインは失敗します。最良の体験のため、デプロイ前に ACM 証明書を設定してください。
>
> HTTPS なしで実行する必要がある場合は、以下の
> [HTTPS なしでのデプロイ(非推奨)](#deploying-without-https-not-recommended)
> を参照してください。

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **ネームスペースの一貫性:** ネームスペースの値は、シークレットの YAML(`metadata.namespace`)、`kubectl create namespace`、`helm install -n` のすべてのリソースで一致している必要があります。`dojopro` の代わりにカスタムのネームスペースを使用する場合は、すべてのコマンドとシークレットマニフェストで一貫して置き換えてください。

**外部シークレット + ライセンスシークレット(GitOps):**

まだ適用していない場合は、シークレットを適用してから([シークレットの生成](#generate-secrets)を参照)、インストールします。

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**インラインシークレット + ライセンスファイル(よりシンプル):**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

#### HTTPS なしでのデプロイ(非推奨)

> **警告:** HTTPS なしで実行すると、セッションクッキーが平文で送信され、セキュアクッキーによる CSRF 保護が無効になります。この構成を本番環境で使用しないでください。

一時的に HTTPS なしでデプロイする必要がある場合(例: ACM 証明書のない初期テストなど)、values ファイルに以下の変更を**すべて**適用してください。

```yaml
dojo:
  url: "http://dojo.example.com"       # must be http://, not https://
  secureCookies: false                  # disable Secure flag on session/CSRF cookies

django:
  ingress:
    tls:
      enabled: false
    annotations:
      # HTTP-only listener — remove the HTTPS listener entirely
      alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}]'
      # Do NOT include the ssl-redirect annotation — it causes a redirect
      # loop when no HTTPS listener exists (see BUG-17 in Known Issues)
      # alb.ingress.kubernetes.io/ssl-redirect: "443"   # REMOVE this line
```

4つの変更すべてが必要です。いずれか一つでも欠けると、リダイレクトループやログインの不具合が発生します。HTTPS を有効にする準備ができたら、これらの変更を元に戻し、ACM 証明書を設定してください。

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **注記:** [インストール前チェックリスト](#infrastructure-details)で、ネームスペースの `fsGroup` の値をすでに取得しているはずです。まだの場合は、今すぐ確認してください。
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**外部シークレット + ライセンスシークレット(GitOps):**

まだ適用していない場合は、シークレットを適用してから([シークレットの生成](#generate-secrets)を参照)、インストールします。

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**インラインシークレット + ライセンスファイル(よりシンプル):**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

---

## ArgoCD でのデプロイ

DefectDojo Pro は ArgoCD と完全に互換性があります。チャートには、ArgoCD が `valueFiles` として直接参照できるプラットフォームおよびプロファイルのプリセットが含まれています。

### 前提条件

ArgoCD の Application を作成する前に、以下の Kubernetes リソースがターゲットのネームスペースに存在している必要があります。

- アプリケーションシークレット([シークレットの生成](#generate-secrets)を参照)
- ライセンスシークレット([ライセンス](#license)を参照)
- 自動生成を使用しない場合の内部 TLS シークレット([内部 TLS 証明書の作成](#create-internal-tls-certificates)を参照)
- ddorch の mTLS 用素材([ddorch mTLS 証明書](#ddorch-mtls-certificates)を参照)。ArgoCD には `--set-file` に相当する機能がないため、3つの PEM の内容は Application のパラメータ(`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`)経由で渡します。鍵を平文でコミットするのではなく、ArgoCD のシークレット管理プラグイン(Sealed Secrets、External Secrets、または ConfigMap プラグイン)を使用してください。

### 仕組み

ArgoCD はプリセットファイルをチャートのルートからの相対パスで参照します。Application の spec には以下の3つが必要です。

1. `valueFiles` としてのプラットフォームおよびプロファイルのプリセット
2. 環境固有の設定(`valueFiles`、インラインの `values`、またはその両方経由)
3. `parameters` としてのシークレットおよびライセンスの参照

```yaml
helm:
  valueFiles:
    - presets/platforms/aws-eks.yaml       # or openshift
    - presets/profiles/standard.yaml       # or minimal, performance
  values: |
    # Your environment-specific configuration goes here.
    # This is applied last and overrides the presets above.
    dojo:
      fqdn: dojo.example.com
      admin:
        user: admin
        email: admin@example.com
    database:
      host: your-db-host.example.com
    # ... see template.yaml for all options
  parameters:
    - name: dojo.existingSecret
      value: dojopro-secrets
    - name: license.existingSecret
      value: dojopro-license
```

### 設定の提供方法

環境固有の values を ArgoCD に提供する方法はいくつかあります。

- Application spec 内のインライン `values` — 最もシンプルな方法で、追加のファイルやリポジトリは不要です。設定がシンプルな場合にうまく機能します。
- 別の git リポジトリにある values ファイル — ArgoCD のマルチソース機能(v2.6以降)を使用し、`$ref` 変数でチャートと一緒に values ファイルを取得します。OCI で公開されたチャートを使用する場合に推奨されます。
- チャートと同じ git リポジトリにある values ファイル — チャートディレクトリからの相対パス(例: `../../overrides/customers/my-company.yaml`)で `valueFiles` から参照します。

これら3つの方法はいずれも同じレイヤー構造に従います。プラットフォームのプリセット → プロファイルのプリセット → お客様の設定、の順です。後から指定した values が先の values を上書きします。

### アップグレード

チャートが OCI レジストリに公開されている場合、アップグレードは Application spec の `targetRevision` を変更するだけで完了します。プラットフォームおよびプロファイルのプリセットはチャートとともにバージョン管理されているため、自動的に更新されます。

ArgoCD の Helm サポートの詳細については、[ArgoCD Helm ドキュメント](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/)を参照してください。

---

## 検証

```bash
# Check the initializer job completed successfully (required for first install)
kubectl get jobs -n $NAMESPACE
# The initializer job must show 1/1 COMPLETIONS. If it shows 0/1, the
# database migrations did not run and the application will not work.
# Check its logs:
#   kubectl logs -n $NAMESPACE -l app.kubernetes.io/component=initializer
# To retry: delete the failed job and run helm upgrade with the same flags:
#   kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
#   helm upgrade dojopro <chart> ... (same flags as install)

# Check all pods are running
kubectl get pods -n $NAMESPACE
# Expected components (chart 2.57+): django, celery-worker, celery-beat,
# connectors, nginx, ddorch, ddorch-workers, integrators, mcp-server, plus
# redis and postgresql if you are using the bundled copies, plus psirt and
# sensei if you enabled them (psirt.enabled, sensei.enabled).
# Note: ddorch-workers replaces the legacy kairos, rulesengine, and
# hatchet-integrators workers.

# Check ingress (EKS) or route (OpenShift)
kubectl get ingress -n $NAMESPACE    # EKS
oc get route -n $NAMESPACE           # OpenShift

# Run built-in helm tests
helm test dojopro -n $NAMESPACE --logs --timeout 5m

# Health check
# EKS (use https:// if TLS is configured, http:// otherwise):
ALB=$(kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}')
curl -sk "https://${ALB}/api/v2/health_check/light/"
# or for HTTP-only deployments:
# curl -s "http://${ALB}/api/v2/health_check/light/"

# OpenShift:
ROUTE=$(oc get route -n $NAMESPACE -o jsonpath='{.items[0].spec.host}')
curl -sk "https://${ROUTE}/api/v2/health_check/light/"
```

### 組み込みの Helm テスト

このチャートには、`helm test` を実行すると Kubernetes Pod として実行される4つのテストが同梱されています。これらは DefectDojo とそのバックエンドサービスとの間の重要な統合ポイントを検証します。

| Test | What it checks |
|------|----------------|
| `test-database` | 設定された認証情報を使用して PostgreSQL に接続し、`SELECT version()` を実行して、データベースがクエリを受け付けていることを確認します。最大60秒までリトライします。 |
| `test-redis-broker` | Redis/Valkey ブローカーに接続し、`PING` を送信した後、set/get/delete のサイクルを実行して読み書きアクセスを検証します。 |
| `test-django-health` | 内部の nginx サービス上の `/api/v2/health_check/light/` エンドポイントにアクセスし、HTTP 2xx/3xx レスポンスを確認します。データベースおよびブローカーのテストの後に実行されます(hook-weight 10)。 |
| `test-storage` | メディアボリュームをマウントし、write/read/delete のサイクルを実行して、ストレージバックエンドにアプリケーションからアクセス可能で書き込み可能であることを確認します。最後に実行されます(hook-weight 15)。 |

テストは hook-weight の順に実行されます。まずインフラストラクチャのテスト(database、broker)が実行され、その後アプリケーションレベルのテスト(health、storage)が実行されます。前のテストが失敗した場合、後続のテストも実行されることはありますが、同様に失敗する可能性が高くなります。

デプロイの失敗や設定変更の後にテストを再実行するには、
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

テスト Pod は実行のたびに自動的にクリーンアップされます(`before-hook-creation` の削除ポリシー)。失敗したテスト Pod のログを手動で確認するには、
```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### 管理者パスワードの取得

初期管理者パスワードはアプリケーションシークレットに保存されています。以下のコマンドで取得します。

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

外部シークレットの代わりにインラインシークレットを使用した場合、パスワードはチャートが管理するシークレットに含まれています。

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

設定した URL に、管理者ユーザー名(デフォルト: `admin`)とこのパスワードでログインします。初回ログイン後にパスワードを変更してください。

---

## 運用

### ログの詳細度

このチャートには2つのログレベル設定があり、いずれもデフォルトは `INFO` です。

| Setting | Controls | Env var |
|---------|----------|---------|
| `config.logLevel` | Django アプリケーションのログ | `DD_LOG_LEVEL` |
| `celery.logLevel` | Celery ワーカーおよび beat のログ | `DD_CELERY_LOG_LEVEL` |

トラブルシューティングのために詳細度を上げるには、values ファイルでどちらか一方または両方を `DEBUG` に設定し、`helm upgrade` を実行します。

```yaml
config:
  logLevel: "DEBUG"
celery:
  logLevel: "DEBUG"
```

```bash
helm upgrade dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set config.logLevel=DEBUG \
  --set celery.logLevel=DEBUG \
  --wait --timeout 15m
```

`--set` フラグは values ファイルの設定を上書きするため、ファイルを編集せずにデバッグログの切り替えができます。問題が解決したら、`--set` フラグなしで再度 `helm upgrade` を実行し、設定済みのデフォルトに戻してください。

Django のデプロイメントは `django.uwsgi.enableDebug: true` もサポートしており、これを設定するとより低レベルなフレームワークのデバッグのために `DD_DEBUG=True` が設定されます。これにより出力が大幅に増えるため、短期間の調査にのみ使用してください。

### スキャンインポートの分離

スキャンのインポート(`/api/v2/import-scan/` および `/api/v2/reimport-scan/`)は同期的にパースされ、ワーカーのメモリを大量に消費する可能性があります。デフォルトでは、このチャートは専用の `django-import` デプロイメント(独自の Service の背後で port 3032 上で動作する uwsgi)を実行し、Django Pod の nginx がインポートのエンドポイントをそこにルーティングします。これにより、大きなインポートがインタラクティブな web ワーカーを枯渇させたり OOM させたりすることがなくなり、インポーターのプール(writer)は web Pod(reader)とは独立してスケールします。

`django.uwsgiImport` 配下のチューニング可能な項目:

```yaml
django:
  uwsgiImport:
    enabled: true          # false routes imports back to the main uwsgi pool
    replicas: 2            # importer pods (ignored when autoscaling is on)
    maxBodySizeMb: null    # client_max_body_size on the import routes; null
                           # derives dojo.scanMaxFileSize + 5 (multipart
                           # overhead), so raising scanMaxFileSize just works.
                           # Set an integer to override.
    performance:
      processes: 2         # concurrent imports per pod = processes x threads
      threads: 4
    resources:
      requests:
        cpu: "100m"
        memory: "512Mi"
      limits:
        memory: "4Gi"
    terminationGracePeriodSeconds: 60   # raise toward 1800 to let in-flight
                                        # imports finish on rollouts/drains
    autoscaling:
      enabled: false       # scale importers on their own CPU signal
    horizontalpodautoscaler:
      minReplicas: 2
      maxReplicas: 5
      averageUtilization: 60
```

運用上の注意点:

- インポーター Pod は共有のメディアボリュームをマウントするため、ノード間で自由にスケジューリングするには ReadWriteMany 対応のストレージが必要です。このチャートのストレージバックエンド(`efs`、`filestore`、`gcsfuse`、`nfs`、およびデフォルトの RWX メディア PVC)はすべて対応していますが、ReadWriteOnce の PVC は対応していません。
- インポーターのオートスケーリングはデフォルトで無効です。これは、スケールダウンが発生すると、`terminationGracePeriodSeconds` が経過した時点で、その Pod が実行中のインポートが強制終了されてしまうためです。有効にする場合は、実行中のインポートが完了できるよう猶予期間を長くしてください。
- PodDisruptionBudget(`podDisruptionBudget.djangoImport`)は、複数のインポーターが稼働している場合に、任意の中断からインポーターのプールを保護します。

`minimal` プロファイルは、フットプリントを小さく保つためにインポーターのデプロイメントを無効化します。この場合、インポートは以前と同様に単一の uwsgi プールを共有します。

### PSIRT アドバイザリエンジン(オプション)

このチャートは、DefectDojo の検出事項からセキュリティアドバイザリを作成・公開するためのサービスである PSIRT アドバイザリエンジンをデプロイできます。デフォルトでは無効です。有効にすると、メインの DefectDojo ホストの `/psirt/` 配下に表示されます。nginx のサイドカーがプロキシするため、追加の ingress や DNS エントリは不要です。

```yaml
psirt:
  enabled: true
  # REQUIRED: full async connection URL. Use a dedicated database (its
  # migrations must not share DefectDojo's database).
  databaseUrl: "postgresql+asyncpg://pae:<password>@<host>:5432/pae"
  # Pre-shared secret for autonomous advisory publishing. The scheduler sends
  # it to DefectDojo as an X-Psirt-Secret header (no minted token, no UI step);
  # the chart injects the SAME value into the DefectDojo pods so they accept it.
  # Optional — omit to disable autonomous publishing (the pod still boots).
  psirtSharedSecret: "<high-entropy secret>"
  # Strongly recommended: pin both secrets. Left empty they are re-generated
  # on every helm upgrade, which logs out active sessions and invalidates
  # stored DefectDojo tokens.
  sessionSecretKey: ""   # any 64-character string
  fernetSaltB64: ""      # python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`psirtSharedSecret` は自分で選ぶ単純な値であり、DefectDojo のユーザーや発行されたトークンは関与しません。高エントロピーな文字列(例: `python -c "import secrets; print(secrets.token_urlsafe(48))"`)を設定してください。このチャートは、この値を psirt エンジンの Secret と DefectDojo の Pod の両方に組み込むため、単一の値を設定するだけで、起動後の追加手順なしに新規インストールでの自動公開が可能になります。ローテーション: 値を変更して `helm upgrade` を実行してください。

データベースのセットアップ: `databaseUrl` は、DefectDojo が使用しているのと同じ PostgreSQL ホスト(または他の到達可能な任意のホスト)を、任意のデータベース名で指定してください。データベースが存在しない場合、Pod は初回起動時にそれを作成しますが、そのためには postgres スーパーユーザーとして一度だけ権限を付与する必要があります。

```sql
ALTER ROLE pae CREATEDB;
```

運用上の注意点:

- `psirt.replicas` は 1 のままにしてください。このサービスは独自の内部ジョブスケジューラーを実行するため、レプリカを2つにすると、スケジュールされたジョブがすべて2回ずつ実行されてしまいます。
- Pod は共有のメディアボリュームをマウントします(アドバイザリの添付ファイルは `<media>/pae/uploads` 配下に保存されます)。そのため、インポーターのプールと同じ ReadWriteMany のストレージに関するガイダンスが適用されます。
- アドバイザリのフィードと NVD の検索には、アウトバウンドの HTTPS が必要です。`networkPolicy.profile=aggressive` の場合、許可された CIDR のリスト(`networkPolicy.externalAPIs.allowedCidrs`)がこれらのエンドポイントをカバーしている必要があります。
- オプションの `psirt.nvdApiKey` を設定すると、NVD のレート制限が 30 秒あたり 5 リクエストから 50 リクエストに引き上げられます。

### Sensei スキャン/修正エンジン(オプション)

このチャートは、サーバーサイドのスキャンおよび自動修復(fix)ジョブを担うサービスである Sensei エンジンをデプロイできます。デフォルトでは無効で、起動に追加の設定は必要ありません。

```yaml
sensei:
  enabled: true
```

このエンジンは長期間有効なシークレットを保持しません。スキャン/修正の認証情報とエンドポイントの URL は、DefectDojo の暗号化されたワーカー設定からディスパッチされる各ジョブに付随します。django と celery はクラスター内でエンジンにアクセスします(`SENSEI_ENGINE_URL` は共有 configmap に自動的に組み込まれます)。そのため、ingress や DNS エントリは不要です。

運用上の注意点:

- デフォルトでは、エンジンは公開サイトの URL(`dojo.url`)を使って DefectDojo をコールバックします。これを上書きするには `sensei.ddCallbackUrl` を設定してください。クラスター内のみの通信にする場合は内部の nginx リスナーを指定できますが、その場合エンジンは DefectDojo の内部 CA を信頼する必要があります。
- fix ジョブ用の LLM 認証情報は、通常アプリ内(AI モデル設定)で設定され、ジョブごとに渡されます。エンジンが自身の環境から鍵を読み取る必要がある場合にのみ `sensei.llm.*` を設定してください。平文の `sensei.llm.apiKey` よりも `sensei.llm.existingSecret` を優先してください。
- プロバイダーの API キーの代わりに Google Vertex AI に対してエンジンを実行するには、`sensei.llm.provider: vertex` と、Vertex をホストする GCP プロジェクトを指す `sensei.llm.vertexProject` を設定します(`sensei.llm.vertexRegion` は通常 `global` です)。Pod は Application Default Credentials で認証するため、`sensei.serviceAccountName` + Workload Identity 経由で GCP サービスアカウントを付与するか、`sensei.extraVolumesRaw` と `sensei.extraVolumeMounts` で鍵ファイルをマウントし、`sensei.extraEnv` 経由で `GOOGLE_APPLICATION_CREDENTIALS` をそこに指定してください。
- `sensei.llm.fallbackChain` には、プライマリのプロバイダーがリトライ可能な失敗を返した際にエンジンがフォールバックする `provider` または `provider:model` のエントリをカンマ区切りで指定します。チェーンの末尾を別のベンダー(例: `vertex-gemini:gemini-2.5-pro`)にしておくと、プライマリプロバイダーの障害中も fix ジョブを継続して実行できます。
- スキャナーのイメージは重量級です。`sensei.maxConcurrentJobs`(デフォルト 3)が Pod あたりの並列ジョブ数を制限しており、デフォルトのリソース(request 1Gi / limit 4Gi)はこの上限に合わせたサイズになっています。両方とも一緒に引き上げてください。
- CPU ベースの HPA(レプリカ数 1〜4)がデフォルトで有効です。台数を `sensei.replicas` に固定したい場合は、`sensei.hpa.maxReplicas` を `sensei.hpa.minReplicas` と同じ値に設定してください。
- リポジトリのクローン、git ホスティングの API、LLM プロバイダーの API にはアウトバウンドの HTTPS が必要です。`networkPolicy.profile=aggressive` の場合、許可された CIDR のリスト(`networkPolicy.externalAPIs.allowedCidrs`)がこれらのエンドポイントをカバーしている必要があります。

### TLS 証明書のローテーション

このチャートでは2種類の TLS 証明書を使用しており、それぞれローテーション手順が異なります。

#### 内部 TLS(サービス間)

これらは、nginx、connectors、その他の内部サービス間の通信に使用される `dojopro-internal-tls` および `dojopro-internal-ca` のシークレットです。

```bash
# Replace the existing secret with new cert/key
kubectl create secret tls dojopro-internal-tls \
  --cert=new-server.crt \
  --key=new-server.key \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Replace the CA bundle
kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=new-ca.crt \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart affected pods to pick up new certs
kubectl rollout restart deployment -n $NAMESPACE
```

#### Ingress TLS(外部/ブラウザ向け)

ローテーションの方法は、TLS をどのように設定したかによって異なります。

- **ACM 管理(EKS):** 更新は自動で行われます。対応は不要です。
- **cert-manager:** `duration` と `renewBefore` の設定(デフォルト: 2160h / 720h)に基づき、更新は自動で行われます。
- **GKE マネージド証明書:** 更新は自動で行われます。対応は不要です。
- **Kubernetes シークレット経由の手動証明書:** 上記で示したものと同じ `kubectl create secret tls ... --dry-run=client` のパターンを使用して、ingress が参照するシークレットを更新します。
- **自動生成された内部証明書:** `certificates.generation.enabled: true` の場合、このチャートは `helm upgrade` でこれらを再生成できます。

> Kubernetes では、Secret オブジェクトが信頼できる情報源(source of truth)です。シークレットを更新し、デプロイメントをローリングすることが、証明書ローテーションの仕組みです。

> TLS シークレットの管理に External Secrets Operator や Sealed Secrets を使用している場合、ローテーションはそのレイヤーで処理され、Kubernetes のシークレットは自動的に更新されます。手動での `kubectl` の操作は不要です。

---

## values ファイルのレイヤー構造

このチャートは values ファイルを重ねて適用します。後から指定したファイルが優先されます。

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

プラットフォームのプリセットとプロファイルのプリセットはチャート内(`dojopro/presets/`)に同梱されています。これらはパッケージ化された `.tgz` に含まれ、チャートとともにバージョン管理されます。お客様がこれらを変更する必要はありません。

展開済みのチャートから `helm install` を使用する場合、[展開](#extract-the-chart-package)時に設定した `$CHART` 変数を使ってこれらを参照します。
```
-f $CHART/presets/platforms/aws-eks.yaml
```

ArgoCD を使用する場合は、チャートのルートからの相対パスで参照します。
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

リソース制限を顧客ファイルに置いたり、プラットフォームの設定をプロファイルファイルに置いたりしないでください。各レイヤーは一つの役割に集中させてください。

> **プリセットのバージョン管理 — ArgoCD と CLI の違い:** ArgoCD はチャートパッケージ内からプリセットを参照するため、`targetRevision` を変更すると自動的に更新されます。CLI を使用する場合は、新しいチャートバージョンにアップグレードする際に、プラットフォームやプロファイルのデフォルトへの変更を反映させるためにプリセットを再展開する必要があります。バージョン管理された展開先パス(例: `dojopro-2.55.4/`)を使用すると、チャートバージョン間の混同を避けられます。詳しくは[チャートパッケージの展開](#extract-the-chart-package)を参照してください。

---

## カスタマイズと拡張性

プラットフォーム/プロファイル/顧客の values ファイルに加えて、このチャートはチャートをフォークすることなく、独自のインフラストラクチャ(サイドカー、init コンテナ、環境変数、ボリューム、サービスアカウント、スケジューリング制約、任意の追加マニフェストなど)を組み込むための第一級の拡張ポイントを提供します。

- **コンポーネント単位のフック** — すべてのワークロード(django、celery worker/beat、connectors、ddorch、ddorch-workers、integrators、mcp-server、psirt)における `extraEnv`、`extraEnvFrom`、`extraVolumesRaw`、`extraVolumeMounts`、`extraInitContainers`、`extraContainers`、`hostAliases`、`priorityClassName`、`topologySpreadConstraints`、`dnsConfig`、`serviceAccountName`。
- **トップレベルの `extraManifests`** — 任意のユーザー提供の YAML(ConfigMap、Secret、NetworkPolicy など)を、チャートのルートコンテキストで Helm の `tpl` を通してチャートと一緒にレンダリングします。
- **アンブレラチャートとしての利用** — `dojopro` は `file://` または OCI の依存関係を通じてサブチャートとして組み込むことができ、チャートの周りに追加のリソースを重ねる顧客バンドルを出荷する際に便利です。
- **スキーマに基づく検証** — `values.schema.json` はすべてのフックをカバーしているため、エディタでの自動補完が可能になり、`helm lint`/`helm install` がオーバーライドを検証します。

パターン、実例、アップグレード時の安定性の保証については、BYO 拡張性ガイド(PDF 版では**付録: Bring Your Own Infrastructure(BYO)**として同梱)を参照してください。

---

## ネットワークポリシー

このチャートはすべてのコンポーネントに対する NetworkPolicy を同梱しており、デフォルトで有効です(`networkPolicy.enabled: true`)。デフォルト拒否のベースラインは、このリリースの Pod(`app.kubernetes.io/name` + `app.kubernetes.io/instance` のラベルによる)にスコープされているため、同じネームスペースを共有する他のワークロードに影響を与えることはありません。

ルールの厳格さは **`networkPolicy.profile`** で制御します。

| Profile | Egress | Pod-to-pod ingress | External ingress |
|---------|--------|--------------------|------------------|
| `standard`(デフォルト) | すべての egress を許可(`0.0.0.0/0`) | このリリース自身の Pod 間のすべてのトラフィックを許可 | ingress controller / ロードバランサーに限定 |
| `aggressive` | コンポーネントごとの詳細な許可リスト(DNS、database/broker、特定のクラスター内サービス、明示的に許可された外部 API のみ) | コンポーネントごとの詳細な許可リスト | ingress controller / ロードバランサーに限定 |

- **`standard`** はほとんどのクラスターで推奨されます。クラスター固有の egress 依存関係(GKE のメタデータサーバー、NodeLocal DNSCache、クラウドストレージ/API のエンドポイント)やアプリ内部のサービス呼び出しによる不具合を回避しつつ、外部からの ingress は引き続き ingress のパスに限定されます。リリースは自身の Pod を信頼しますが、外部からのアクセスは変わらず正面玄関を通ります。
- **`aggressive`** は両方向で厳格な許可リストを強制します。これを使用する場合、クラスターに合わせて `networkPolicy` 配下の例外設定を調整する必要があるかもしれません。
  - `nodeLocalDns` — NodeLocal DNSCache のリゾルバー(デフォルトではリンクローカルの `169.254.20.10`、ポート53)を許可します。NodeLocal DNSCache を実行しているクラスター(例: GKE アドオン)では必須で、設定しないと DNS 解決が失敗します。
  - `dnsSelectors` — カスタム DNS 構成向けに DNS の egress 送信先を上書きします。
  - `allowExternalAPIs` / `externalAPIs` — 外部の HTTPS API への egress と、ブロックする CIDR(クラウドのメタデータなど)を制御します。

任意の values ファイルでプロファイルを設定します。例:

```yaml
networkPolicy:
  profile: aggressive
```

> **GKE のヘルスチェック** はどちらのプロファイルでも処理されます。GKE 上では、GCE ロードバランサーのプローブの IP レンジ(`130.211.0.0/22`、`35.191.0.0/16`)は常に django バックエンドへのアクセスが許可されます。[GCP GKE](#gcp-gke)を参照してください。

### Ingress controller のアクセス(502 Bad Gateway)

GKE / OpenShift 以外のクラスターでは、django の NetworkPolicy は、Kubernetes がすべてのネームスペースに自動的に付与する `kubernetes.io/metadata.name` ラベルでそのネームスペースを選択することにより、ingress controller の通信を許可します。デフォルトでは、controller が **`ingress-nginx`** という名前のネームスペースにあり、controller の Pod が `app.kubernetes.io/name: ingress-nginx`(ingress-nginx チャートのデフォルト)を持っていることを想定しています。

ingress controller が異なる名前のネームスペースにある場合、異なる Pod ラベルを使用している場合、あるいはまったく別の controller(Traefik、ALB など)である場合、このポリシーはそのトラフィックを黙って破棄し、リクエストは **502 Bad Gateway**(controller のログには `connect() failed (110: Operation timed out)`)を返します。`networkPolicy.ingressSource` で、実際の ingress の送信元をポリシーに指定してください。

```yaml
networkPolicy:
  ingressSource:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: <ingress-namespace>
      podSelector:
        matchLabels:
          app.kubernetes.io/name: <controller-label>
```

名前だけが異なる場合は、`networkPolicy.ingressNamespace` / `networkPolicy.ingressControllerLabel` を調整してください。`ingressSource` のその他の例(Traefik、OpenShift router、AWS ALB)については、`values.yaml` 内の `networkPolicy` 配下のコメントを参照してください。

---

## アップグレード

推奨されるアップグレード方法は、zip の展開を必要とせず、DefectDojo の OCI レジストリから直接チャートを取得する方法です。

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

典型的な OCI アップグレードは以下のようになります(元のインストール時と同じ values ファイルと `--set` フラグを使用します)。

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --wait --timeout 15m
```

インストール時に使用したパッケージ化された zip のワークフローも、アップグレードで利用できます。展開済みの `$CHART` パスに対して、`helm install` の代わりに `helm upgrade` を実行してください。

認証、ArgoCD でのアップグレード、検証、ロールバック、トラブルシューティングについては、[アップグレードガイド](/get_started/pro/onprem/upgrading_on_kubernetes/)(PDF 版では**付録: DefectDojo Pro のアップグレード**として同梱)を参照してください。

---

## Uninstalling

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> PVC、外部データベース、外部シークレットは削除されません。
> それらは個別にクリーンアップしてください。

### PersistentVolume のクリーンアップ

`Retain` 回収ポリシーを持つ PersistentVolume は**クラスタスコープ**です。`helm uninstall` やネームスペースの削除では削除されません。DefectDojo を別のネームスペースに再インストールすると、孤立した PV の所有権メタデータが新しいインストールと競合し、`helm install` をブロックします。

アンインストール後、孤立した PV がないか確認してください。

```bash
kubectl get pv | grep dojopro
```

残っている場合は削除してください。

```bash
kubectl delete pv dojopro-media-pv
```

> **注:** PV を削除すると Kubernetes のボリューム参照は削除されますが、基盤となるデータはストレージバックエンド（EFS ファイルシステムなど）上に残ります。再インストールを予定している場合は安全ですが、意図的に行ってください。

---

## 埋め込み PostgreSQL と Redis によるローカルテスト

> **この構成はローカルテストおよび評価のみを目的としています。本番環境では埋め込み PostgreSQL や Redis を使用しないでください。** 本番デプロイでは、信頼性、バックアップ、スケーリングのためにマネージドサービス（RDS、ElastiCache など）を使用してください。DefectDojo サポートは、本番環境における埋め込みデータベースの問題をサポート対象としません。

このチャートは、`minimal` プロファイルを使用することで、迅速なローカルテストのために独自の PostgreSQL と Redis をデプロイできます。これにより、外部データベースおよびブローカーのインフラストラクチャが不要になります。

values ファイルに以下を追加してください。

```yaml
# Enable embedded PostgreSQL (instead of external RDS)
postgresql:
  enabled: true
  database:
    password: "your-password"   # required — must match DD_DATABASE_PASSWORD in your secrets

database:
  external: false

# Enable embedded Redis (instead of external ElastiCache)
redis:
  enabled: true

celery:
  broker:
    external: false
```

> **重要: `postgresql.enabled` が true で `database.existingSecret` が設定されていない場合、`postgresql.database.password` が必須です。** これがないとチャートのレンダリングに失敗します。このパスワードは、アプリケーションシークレット内の `DD_DATABASE_PASSWORD` の値と一致している必要があります。

> **埋め込み PostgreSQL のデフォルト認証情報:** 埋め込み PostgreSQL のチャートデフォルトは、ユーザー名 `dojodbusr`、データベース名 `dojodb`（チャートの `values.yaml` で定義）です。アプリケーションシークレット内の `DD_DATABASE_URL` は、`secrets-template.yaml` にある外部データベース用のプレースホルダーではなく、これらの値を使用する必要があります。例:
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

`minimal` プロファイル（`dojopro/presets/profiles/minimal.yaml`）は、シングルノードのテストクラスタに適した削減済みのリソースリクエストを設定しますが、これらのデータベース/ブローカーのフラグは切り替えません。自分で設定する必要があります。

> **コンテナ権限に関する注記:** 埋め込みの PostgreSQL と Redis のコンテナは root では**実行されません**。PostgreSQL は UID 999、Redis は UID 1001 で実行されます。唯一の例外は PostgreSQL の**init コンテナ**（`init-chmod-data`）で、メインプロセスの開始前にデータボリュームのディレクトリ所有権を設定するため、root（UID 0）で実行されます。これは永続ストレージを使う StatefulSet でよく見られるパターンです。クラスタが root の init コンテナを禁止する `restricted` Pod Security Standard や OpenShift SCC を適用している場合は、`postgresql.initContainer.enabled: false` で無効化してください（[既知の問題](#known-issues-chart-version-2.57.1)を参照）。

EKS 上で埋め込み PostgreSQL を使用する場合は、EBS CSI ドライバーも必要になり（[AWS EKS の前提条件](#aws-eks-prerequisites)を参照）、ストレージのデフォルト設定の調整が必要になる場合もあります（[既知の問題](#known-issues-chart-version-2.57.1)を参照）。

インストール前に values を検証してください。minimal パスはより多くのオーバーライドを必要とし、レンダリングエラーが発生しやすくなります。

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/minimal.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  > /dev/null
```

これがエラーなく終了したら、同じフラグで `helm install` を実行してください。

> **minimal / 新規データベースへのインストールでは `--timeout 30m` を使用してください。** 埋め込み PostgreSQL はリソースが削減されており、initializer は新しいデータベースに対してすべてのデータベースマイグレーションを最初から実行する必要があります。テストではこれに約23分かかり、標準インストール例で使われている `--timeout 15m` を超えます。タイムアウトが発生すると、デプロイがバックグラウンドで正常に完了していても `helm install` は `INSTALLATION FAILED` を報告します。`--timeout 30m` を使用することで、この誤った失敗とそれに伴う `failed` リリースステータスを回避できます。

---

## プライベートレジストリ / エアギャップ環境

クラスタがデフォルトの DefectDojo レジストリからプルできない場合は、イメージを自分のレジストリにミラーリングし、それを使用するようチャートを設定してください。

### オプション1: グローバルレジストリのオーバーライド

`global.imageRegistry` を設定して、すべてのイメージプルをリダイレクトします。チャートは `images.prefix` から元のレジストリを取り除き、あなたのレジストリを先頭に付加します。

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

これはすべてのイメージ（django、nginx、celery、connectors、redis など）に影響します。

### オプション2: イメージごとのオーバーライド

より細かい制御が必要な場合は、`images.registry`（メインアプリのイメージに影響）を設定し、個々のイメージを個別にオーバーライドしてください。

```yaml
images:
  registry: "my-registry.example.com"
  prefix: "defectdojo/"          # path within your registry
  tag: "2.53.0"
  connectors:
    registry: "my-registry.example.com"
    repository: "defectdojo/connectors"
    tag: "2.53.0"
  redis:
    registry: "my-registry.example.com"
    repository: "defectdojo/redis"
    tag: "7.2.4"
```

### プライベートレジストリ用のイメージプルシークレット

レジストリで認証が必要な場合は、プルシークレットを作成して参照してください。

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

または、明示的な認証情報からチャートに作成させることもできます。

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

デフォルトの動作（`extractFromLicense: true`）は、DefectDojo のレジストリからプルするために、ライセンスファイルから GCP サービスアカウントの認証情報を抽出します。独自のレジストリを使用する場合はこれを無効にしてください。

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## プラットフォームアノテーションのオーバーライド

このチャートは、`cloudProvider` に基づいて Ingress と Service にプラットフォーム固有のアノテーションを自動的に注入します（例: EKS 向けの ALB アノテーション、GKE 向けの GCE アノテーション）。アノテーションを完全に制御したい場合、例えば ALB の代わりに EKS 上で nginx ingress コントローラーを使用する場合は、`platformAnnotations.enabled: false` を設定し、独自のアノテーションを指定してください。

```yaml
django:
  ingress:
    platformAnnotations:
      enabled: false
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "500m"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
  service:
    platformAnnotations:
      enabled: false
    annotations: {}
```

`platformAnnotations.enabled` が `true`（デフォルト）の場合、チャートはプラットフォームアノテーションとカスタムアノテーションをマージします。キーが競合した場合はカスタムアノテーションが優先されますが、このトグルを使わずにプラットフォームアノテーションを削除することはできません。

### Ingress のアップロードサイズ制限

デフォルトでは、大きなスキャン結果のアップロードや PDF レポートが `413 Request Entity Too Large` を発生させずに nginx-ingress を通過できるよう、チャートは Ingress に `nginx.ingress.kubernetes.io/proxy-body-size: "2400m"` を設定します。以下でオーバーライドできます。

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

これは、EKS、GKE、AKS 上で動作する nginx-ingress を含め、nginx-ingress がコントローラーである場合には常に適用されます。nginx 以外のコントローラーはこのアノテーションを無視するため、それぞれの仕組み（AWS WAF のボディ検査制限、AppGW の request-body-limit、OpenShift Route HAProxy の `tuningOptions`）を使って調整する必要があります。

---

## プラットフォーム固有の注記

### AWS EKS

- ALB ingress には AWS Load Balancer Controller が必要です
- EFS ストレージを使用する場合は EFS CSI ドライバーが必要です
- TLS は ACM 証明書を介して ALB で終端します
- `certificates.ingress.source: "acm"` を設定し、`acmCertArn` を指定してください
- ALB が HTTPS を処理するため、`dojo.secureCookies: true` は問題なく機能します

#### EFS アクセスポイント

EFS ファイルシステムが**アクセスポイント**で構成されている場合（マウント時の UID/GID 所有権を強制するために推奨されます）、values ファイルで `storage.efs.accessPointId` を設定する**必要があります**。これを設定しないと、PV は EFS のルートを root 所有としてマウントし、DefectDojo のコンテナ（UID 1001 で実行）はメディアのサブディレクトリを作成できず、initializer が `Permission denied` エラーで失敗します。

EFS アクセスポイントを確認してください。

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

アクセスポイントが存在する場合は、values ファイルに追加してください。

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **重要:** PersistentVolume の `volumeHandle` フィールドは、作成後は**変更不可**です。最初にアクセスポイントなしでインストールし、後から追加が必要になった場合は、`helm upgrade` を実行する前に既存の PV と PVC を削除する必要があります。
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> これは安全です。PV を削除しても Kubernetes の参照が削除されるだけで、EFS ファイルシステム上のデータには影響しません。

#### 強化された / GitOps で管理されるクラスタでのストレージクラス

カスタムの StorageClass 命名を使用しているクラスタや、クラスタスコープのリソースがアプリケーションチャートの外部で管理されているクラスタでは、2つのストレージクラスに関する前提がつまずきの原因になります。

**動的にプロビジョニングされる PVC は EKS 上でデフォルトで `gp3` になります。** チャートが動的にプロビジョニングする PVC（埋め込み Redis のボリューム（`redis.enabled: true`）や `storage.type: "pvc"` のメディアボリューム）は、StorageClass をプラットフォームのデフォルトに解決し、それは EKS では `gp3` です。クラスタに `gp3` という名前の StorageClass が存在しない場合（カスタム命名を使う強化クラスタでよくあります）、PVC は `storageclass.storage.k8s.io "gp3" not found` イベントとともに `Pending` のままとなり、Pod は起動しません。

以下の2つのいずれかの方法でオーバーライドできます。

- **グローバルに（推奨）** — チャートがプロビジョニングするすべての PVC に対する単一のレバーです。

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- 異なるクラスが必要な場合は**コンポーネントごと**に設定します。

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  解決順序は次のとおりです: コンポーネントごとの値 → `storage.defaultStorageClass` → プラットフォームのデフォルト（`gp3`）。値を `""` に設定すると、クラスタのデフォルト StorageClass にフォールバックします。これは、StorageClass を使用しないデフォルトの EFS メディアパス（下記参照）には適用**されません**。

**デフォルトの EFS メディアボリュームには StorageClass は不要です。** `storage.type: "efs"` の場合、チャートは EFS ファイルシステムの `volumeHandle` と `claimRef` を使って、メディア PV を静的にバインドします。PV と PVC はどちらも空の `storageClassName` を使用します。メディア PVC がバインドされるために `efs-sc` という StorageClass が存在する必要は**ありません**。

このチャートは、`storageClasses.efs.enabled: true`（デフォルト: `false`）を指定して**動的な** EFS プロビジョニングを明示的に選択した場合にのみ、クラスタスコープの `efs-sc` StorageClass を作成します。クラスタスコープのリソースがアプリケーションチャートの外部（GitOps）で管理されているクラスタでは、デフォルトの `false` のままにしてください。上記の静的な EFS パスは、StorageClass もこのチャートからのクラスタスコープのオブジェクトも必要としません。GitOps 配下で動的な EFS プロビジョニングを行いたい場合は、StorageClass を別途作成し、`storageClasses.efs.enabled: false` のままにしてください。

### GCP GKE

- GCE ingress コントローラー（`className: "gce"`）を使用し、TLS は Google Cloud ロードバランサーで終端します
- `gcp-gke.yaml` プリセットは、`FrontendConfig`（HTTP→HTTPS リダイレクト + SSL ポリシー）と `BackendConfig` を ingress に自動的にアタッチします
- GCE ロードバランサーは、Google の IP 範囲（`130.211.0.0/22`、`35.191.0.0/16`）から直接 django バックエンドのヘルスチェックを行います。チャートの NetworkPolicy は、`networkPolicy.profile` のどちらの値でも GKE 上でこれらを自動的に許可するため、`/nginx_health` プローブは成功し、バックエンドは正常と報告されます。[ネットワークポリシー](#network-policies)を参照してください

#### Google 管理 TLS と BYO TLS の比較

`gcp-gke.yaml` プリセットはデフォルトで**Google 管理の証明書**を使用します。以下の2つのアプローチのいずれかを選択してください。

- **Google 管理（デフォルト）:** GCP が証明書をプロビジョニングし更新します。ドメインを列挙するだけで、Kubernetes の TLS シークレットは不要です。

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **持ち込み（BYO）:** リリースのネームスペースに既存の Kubernetes TLS シークレットを用意し、ingress にそれを指定します。

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  これにより、ingress に `spec.tls[].secretName` がレンダリングされ、`networking.gke.io/managed-certificates` アノテーションは省略されます。

> **ブートストラップスクリプトの対応範囲:** `scripts/bootstrap/bootstrap-gcp-gke.sh` は、GCP ネイティブの証明書フロー（`google-managed` と `pre-shared`）のみをカバーします。BYO の `secret` パスを使う場合は、直接 `helm` でインストールしてください（先に TLS シークレットを作成し、その後 `certificates.ingress.source=secret` と `certificates.ingress.secretName=<your-secret>` を渡します）。

> Google 管理の証明書の更新は自動です。[TLS 証明書のローテーション](#rotating-tls-certificates)を参照してください。

### OpenShift / ROSA

- デフォルトでは Route を使用します（`django.route.enabled: true`）が、Ingress もサポートされています
- 代わりに Ingress を使用するには: `django.ingress.enabled: true` と `django.route.enabled: false` を設定してください
- 一度に有効化できるのはどちらか一方のみです（チャートは相互排他性を検証します）
- エッジ終端の Route（デフォルト）を使用する場合、**`dojo.secureCookies` は `false` である必要があります。** これは任意ではなく必須です。[値ファイルの準備における警告](#prepare-your-values-file)を参照してください。
- `securityContext.openshift.fsGroup` は、ネームスペースの supplemental-groups の範囲と一致している必要があります（確認方法については[インストール前チェックリスト](#infrastructure-details)を参照してください）
- EFS 経由の NFS はうまく機能します。サーバーとして EFS の DNS 名を指定し、`storage.type: "nfs"` を使用してください

#### OpenShift で Route の代わりに Ingress を使用する

OpenShift には、デフォルトで HAProxy ベースの ingress コントローラーが付属しています。（他のクラスタとの一貫性のため、あるいはカスタムの ingress コントローラーを使用するためなど）Route よりも Ingress を使いたい場合は、次のように values を設定してください。

```yaml
django:
  ingress:
    enabled: true
    className: "openshift-default"   # or your custom ingress class
    platformAnnotations:
      enabled: false                 # recommended — provide your own annotations
    pathType: "Prefix"
    path: "/"
    tls:
      enabled: true
    annotations: {}                  # add your ingress controller annotations here
  route:
    enabled: false
  nginx:
    tls:
      enabled: false
      generateCertificate: false
```

どちらの公開方法を選んでも、チャートのプラットフォームヘルパーは OpenShift 向けのセキュリティコンテキスト、DNS リゾルバー、ストレージのデフォルト設定を引き続き正しく処理します。

---

## 既知の問題（チャートバージョン 2.57.1）

これらは現行チャートで確認済みのバグです。修正版がリリースされるまで、回避策をここに記載しています。

### ローカルの PostgreSQL または Redis のみを使う minimal インストール

以下の問題は、チャート内蔵の PostgreSQL または Redis を使用している場合（`postgresql.enabled: true` または `broker.external: false`）にのみ該当します。外部データベースおよびブローカーを使用する本番デプロイには影響しません。

**メディアボリュームに EBS を使用しないでください（BUG-14、BUG-15）**

EBS ボリュームは `ReadWriteOnce` のみをサポートしており、一度に1つのノードにしかアタッチできません。DefectDojo は、異なるノードにスケジューリングされる可能性がある複数の Pod（django、celery-worker、initializer、connectors）間でメディアボリュームを共有する必要があります。これが発生すると、EBS は複数のノードに同時にボリュームをマウントできないため、Pod は `Multi-Attach error` とともに `ContainerCreating` の状態で止まります。これは `helm test` にも影響し、test-storage の Pod がアプリケーションの Pod とは異なるノードにスケジューリングされる場合があります。

**メディアボリュームには、EBS の代わりに EFS（または他の `ReadWriteMany` 対応ストレージバックエンド）を使用してください。** EFS はクラスタ内のすべてのノードからの同時アクセスをサポートしており、EKS デプロイに推奨されるストレージバックエンドです。

シングルノードクラスタでのテストのために EBS を使用する必要がある場合は、デフォルトをオーバーライドしてください。

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

このオーバーライドを行っても、Pod が複数のノードにまたがってスケジューリングされた時点（スケーリング時、ノード交換時、`helm test` 実行時など）で EBS は破綻することに注意してください。EFS ではこの問題は完全に回避されます。

**PostgreSQL の init コンテナが non-root セキュリティコンテキストと競合する（BUG-16）**

`CreateContainerConfigError` が発生した場合は無効化してください。

```yaml
postgresql:
  initContainer:
    enabled: false
```

### すべてのデプロイ

**initializer 実行中に connectors の Pod がクラッシュループする（想定される動作）**

初回インストール中、initializer ジョブがデータベースマイグレーションを実行している間、connectors の Pod は `CrashLoopBackOff` に入ります。これは想定内の動作です。connectors の Pod は Django API（`/api/connectors/v1/config/`）の呼び出しを試みますが、データベーススキーマがまだ完全にマイグレーションされていないため 500 が返されます。initializer ジョブが正常に完了すると（`kubectl get jobs` で `1/1 COMPLETIONS` と表示されます）、connectors の Pod は次の再起動サイクルで回復します。手動での対応は不要です。

**マイグレーション後の initializer のクラッシュにより、回復不能なデータベース状態が残る（BUG-18）**

initializer ジョブが、データベースマイグレーションの実行**後**、初期データの投入**前**にクラッシュした場合（ストレージの権限エラーやリソース制限などが原因）、データベースは部分的に初期化された状態のまま残ります。テーブルは存在しますが、`dojo_system_settings` テーブルは空です。以降の再起動では、initializer は次のエラーで即座に失敗します。

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

これにより、自動回復のないクラッシュループが発生します。**回避策:** データベーススキーマをリセットし、initializer を再実行してください。

```bash
# Drop and recreate the public schema
kubectl run psql-reset --rm -i --tty=false --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d <your-db-name> -U <your-db-user> \
     -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO <your-db-user>;"

# Delete the failed initializer job and trigger a new one
kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
helm upgrade dojopro $CHART ... (same flags as install)
```

> **予防策:** 初回インストールの**前**に、ストレージの権限（特に EFS アクセスポイント。[EFS アクセスポイント](#efs-access-points)を参照）とリソース制限が正しく構成されていることを確認してください。`helm template` を実行して values を検証し、可能であればテスト用 Pod で EFS のマウント権限を確認してください。

**ログ内の Hatchet トークン警告（情報提供のみ）**

`hatchet.enabled: false`（デフォルト）の場合、Pod は起動時に次の警告をログに出力します。

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

これは**想定内であり無害です**。チャート 2.57 以降、バックグラウンドのワークフロー実行は `ddorch` + `ddorch-workers` に統合され、これらが従来の Hatchet ベースのワーカー（`kairos`、`rulesengine`、`hatchet-integrators`）を置き換えました。Hatchet のクライアントコードは起動時に依然として初期化されるため、Hatchet が無効な場合でもこの警告は表示されますが、何もそれに依存していません。この警告は無視して問題ありません。

### HTTPS が構成されていない

**ALB の ssl-redirect アノテーションには HTTPS リスナーが必要（BUG-17）**

EKS プリセットには、ALB 上に HTTPS リスナーが存在することを前提とした `ssl-redirect` アノテーションが含まれています。ACM 証明書と HTTPS リスナーを構成していない場合、このアノテーションはリダイレクトループを引き起こします。HTTPS を構成する（推奨）か、必要な変更の全容については[HTTPS を使わないデプロイ（非推奨）](#deploying-without-https-not-recommended)を参照してください。

---

## トラブルシューティング

### CrashLoopBackOff で止まる Pod

ログを確認してください。
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

通常、原因は次のいずれかです: シークレットの欠落または誤り（12個のキーすべてを確認）、データベースに到達できない（`database.host` とセキュリティグループを確認）、または内部 TLS 証明書の欠落（`dojopro-internal-tls` シークレットが存在するか確認）。

### 外部シークレットとインラインシークレットの混在

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

どちらか一方の方式を選んでください。`dojo.existingSecret` を使用している場合は、values ファイルからすべてのインラインシークレット値（`dojo.secretKey`、`dojo.admin.password`、`monitoring.password` など）を取り除いてください。

### スキーマが admin.password は必須だと表示する

`dojo.existingSecret` を設定してください。外部シークレットが構成されている場合、スキーマはパスワードの必須要件を解除します。

### OpenShift の fsGroup 権限エラー

Pod が NFS ボリュームで権限エラーにより失敗する場合は、`securityContext.openshift.fsGroup` がネームスペースの supplemental-groups の範囲内にあるか確認してください。fsGroup の確認方法については、[デプロイ → OpenShift / ROSA](#openshift-rosa)を参照してください。

### ALB が表示されない（EKS）

AWS Load Balancer Controller が実行中であることを確認してください。
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

ingress のイベントを確認してください。
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## 付録: 顧客向け構成テンプレート

完全なテンプレート（`template.yaml`）は、DefectDojo サポートポータルまたは support@defectdojo.com から入手できます。それをコピーし、`REPLACE_*` のプレースホルダーを置き換え、自分のプラットフォームに該当しないセクションを削除してください。テンプレートには、次の項目についてコメント付きの例が含まれています。

- プラットフォームの識別（`cloudProvider`）
- イメージプルシークレットの構成
- Ingress と Route の構成（EKS/GKE/OpenShift 向けの Ingress、OpenShift 向けの Route）
- EFS と NFS のストレージオプション
- 証明書と TLS の構成
- セキュリティコンテキスト（uwsgi、nginx、OpenShift fsGroup）
- ネットワークポリシー
- ライセンスの配布方法（ファイル、シークレット、インライン）

---

## 改訂履歴

| Date       | Version | Changes                                                              |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | オプションの PSIRT Advisory Engine（`psirt.enabled`）を追加: nginx サイドカー経由で `/psirt/` 配下で提供、`psirt.databaseUrl` による専用データベース、シークレットのピン留めガイダンス、ネットワークポリシールール、BYO フック |
| 2026-04-17 | 2.57.1  | `ddorch` + `ddorch-workers`（kairos/rulesengine/hatchet-integrators を置き換える新しいオーケストレーターペア）を文書化。pre-flight およびデプロイコマンドに `ddorch.tls.rootCa/cert/key` の `--set-file` フラグを追加。SAN 要件を含む新しい ddorch mTLS 証明書セクションを追加。想定される Pod 一覧に mcp-server を追加。ddorch（シングルトン）と ddorch-workers 向けの PDB を追加。ddorch 証明書の配布に関する ArgoCD の前提条件の注記。Hatchet 警告をワーカー統合を反映するよう更新 |
| 2026-03-25 | 2.55.4  | EFS アクセスポイントのドキュメントとテンプレートフィールドを追加。initializer のクラッシュ復旧（BUG-18）を文書化。init 中の connectors のクラッシュループを想定内として文書化。Hatchet トークン警告が無害であることを明確化。既知の問題への古いアンカーを修正。バージョン管理されたチャート展開パス。HTTPS 未構成時のガイダンスを統合。アンインストール時の PV クリーンアップ。ネームスペースの一貫性に関する注記。ArgoCD と CLI のプリセットバージョニングに関する注記 |
| 2026-03-11 | 2.53.0  | helm コマンドのパスを修正。チャートの展開、EKS の前提条件、pre-flight データベースチェック、HTTPS 通知、TLS ローテーション、既知の問題セクションを追加 |
