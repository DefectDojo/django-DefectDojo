---
title: FIPS 140-3 モード
date: 2026-07-27 00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro は、FedRAMP の統制**SC-13**または同様の要件が適用される環境向けに、FIPS 140-3 で検証された暗号技術を用いてデプロイできます。

FIPS モードは、`-fips` というタグサフィックスで識別される**別のコンテナイメージ一式**として提供されます。標準イメージは変更されません。FIPS の有効化は明示的な選択であり、暗黙のデフォルトになることはありません。

FIPS イメージへのアクセスについては、[hello@defectdojo.com](mailto:hello@defectdojo.com) までお問い合わせください。

## FIPS イメージが提供するもの

すべての暗号処理は、FIPS 140-3 のもとで NIST CMVP 証明書**[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)**を保持する**OpenSSL FIPS Provider 3.1.2**によって実行されます。Go 製のサービスは、CMVP 証明書**[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**を持つ**Go Cryptographic Module v1.0.0**を使用します。

強制の適用は**コンテナ内部**で行われるため、FIPS モードはホストが FIPS 対応カーネルで動作していることを必要としません。これにより、ホストのオペレーティングシステムを自分で制御できない**Amazon ECS の Fargate 起動タイプ**のようなマネージドコンテナランタイムでも運用可能になります。

> **FIPS 140-2 ではなく FIPS 140-3。** FIPS 140-3 は 140-2 の後継であり、140-2 を対象に書かれた要件も満たします。すべての FIPS 140-2 証明書は**2026年9月21日**に CMVP のヒストリカルリストへ移行し、それ以降は新規デプロイをサポートしなくなるため、新しいシステムは 140-3 モジュールに対して検証すべきです。

### 対応範囲

| コンポーネント | 対応 | モジュール |
|---|:---:|---|
| Django アプリケーション（`dojo`） | 対応 | OpenSSL FIPS Provider 3.1.2 |
| 非同期インポート（`dojo-import-scan`） | 対応 | OpenSSL FIPS Provider 3.1.2 |
| Celery ワーカーおよび beat | 対応 | OpenSSL FIPS Provider 3.1.2 |
| 初期化処理（`init`） | 対応 | OpenSSL FIPS Provider 3.1.2 |
| オーケストレーションワーカー（`ddorch-workers`） | 対応 | OpenSSL FIPS Provider 3.1.2 |
| nginx | 対応 | OpenSSL FIPS Provider 3.1.2 |
| PSIRT アドバイザリエンジン | 対応 | OpenSSL FIPS Provider 3.1.2 |
| Connectors、Integrators、ddorch、MCP サーバー | 対応 | Go Cryptographic Module v1.0.0 |
| **Sensei** | **一部対応** | サービスバイナリ: Go Cryptographic Module v1.0.0。バンドルされたスキャナツールチェーン: **対象外** |
| **PostgreSQL / Redis（組み込み）** | **非対応** | 外部の FIPS 準拠サービスを使用してください |

**Sensei は理解しておく価値のある一部対応のケースです。** Sensei 自体のバイナリは検証済みの Go モジュールに対してビルドされているため、ジョブ API の TLS とトークンは対応範囲に含まれます。一方でこのイメージには、Node（独自の OpenSSL を同梱）、Rust（rustls）、Python、Ruby、そして私たちがコンパイルしていないサードパーティ製 Go バイナリといった、複数言語にまたがるサードパーティ製スキャナツールチェーンもバンドルされており、その一部は独自の暗号技術を使って TLS 経由でアドバイザリデータベースを取得します。このツールチェーンを単一の検証済みモジュールの傘下に置くことはできないため、対象外であり、審査担当者に対応済みと説明すべきではありません。

組み込みの PostgreSQL/Redis には FIPS バリアントが一切存在しません。Kubernetes では、Sensei や組み込みデータストアと同時に FIPS を有効化すると、チャートはレンダリングを拒否します。そのため、このトレードオフは暗黙の前提ではなく明示的な判断として扱われます（[ガードレール](#guard-rails)を参照）。

## FIPS モードの有効化 — Docker Compose

変更点は2つです。`-fips` イメージを使用することと、`DD_FIPS_MODE` を設定することです。

**1. イメージタグを FIPS バリアントに向けます。** `.env` または compose のオーバーライドファイルで次のように設定します。

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. 共有環境アンカーに `DD_FIPS_MODE` を設定します。** compose ファイルは、関連する各サービスがマージする共有ブロックを定義しているため、サービスごとに1回ずつではなく、3か所の編集で済みます。

```yaml
x-dojo-vars: &dojoenv
  DD_FIPS_MODE: "1"        # dojo, dojo-import-scan, celerybeat, celeryworker, init, ddorch-workers
  # ... existing settings

x-nginx-vars: &nginxenv
  DD_FIPS_MODE: "1"        # nginx
  # ... existing settings

x-psirt-vars: &psirtenv
  DD_FIPS_MODE: "1"        # psirt
  # ... existing settings
```

その後、スタックを再作成します。

```bash
docker compose up -d --force-recreate
```

## FIPS モードの有効化 — Kubernetes（Helm）

値を1つ設定するだけです。チャートが `-fips` イメージバリアントを選択し、すべての Pod に対して `DD_FIPS_MODE` を設定します。

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

組み込みデータストアには FIPS バリアントがなく、Sensei も一部対応にとどまるため、FIPS 環境では外部の PostgreSQL と Redis を使用し、上記の注意点を受け入れない限り Sensei は無効のままにしておくべきです。

```yaml
fips:
  enabled: true
sensei:
  enabled: false          # partial coverage — see the table above
postgresql:
  enabled: false          # use an external FIPS-compliant database
redis:
  enabled: false          # use an external FIPS-compliant cache
```

FIPS 環境で Sensei が必要な場合は、`fips.validate: false` を指定して意図的に有効化し、バンドルされたスキャナツールチェーンが未検証であることをシステムセキュリティ計画書に明記してください。

### ガードレール

`fips.enabled` が true になっている一方で、FIPS バリアントを持たないコンポーネントも有効になっている場合、**チャートはレンダリングを拒否し**、該当するコンポーネントを名指しします。

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

これは意図的な仕様です。ほとんどのサービスが検証済み暗号を使用している一方で、1つか2つのサービスがひそかにそうなっていないというデプロイは、明白な失敗よりも厄介です。一見コンプライアンスに準拠しているように見え、簡単な点検では見過ごされ、審査の段階になって初めて表面化するからです。そのリスクを書面で受け入れているのであれば、`fips.validate: false` で上書きしてください。

## FIPS モードの有効化 — Amazon ECS / Fargate

Fargate は独立したサービスではなく、ECS の起動タイプです。`requiresCompatibilities: ["FARGATE"]` と `networkMode: awsvpc` を指定して ECS タスク定義を登録します。

すでに ECS で DefectDojo Pro を運用している場合、変更点は2つだけです。

**1. イメージタグ**に `-fips` サフィックスが付きます。

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2.** アプリケーションコードを実行するすべてのコンテナ（uwsgi、celery worker、celery beat、initializer、オーケストレーションワーカー、nginx、psirt）の `environment` ブロックに **`DD_FIPS_MODE=1`** を設定します。

このセクションの残りの部分では、ゼロから始める読者のために、FIPS を有効化した ECS デプロイの全体像を説明します。

### 最初に用意すべきもの

| リソース | 備考 |
|---|---|
| サブネット2つを持つ VPC | プライベートサブネットと NAT ゲートウェイの組み合わせ、または `assignPublicIp: ENABLED` を指定したパブリックサブネット |
| RDS for PostgreSQL | FIPS 対応エンドポイントを使用し、継承コンポーネントとして文書化してください |
| ElastiCache for Redis | 論理データベースを2つ使用します。Celery ブローカー用の `/0` とキャッシュ用の `/1` です |
| EFS ファイルシステム | ディレクトリを2つ用意します。1つは `/app/media` 用、もう1つは nginx の TLS 証明書を格納します |
| Secrets Manager のエントリ | データベース URL、`DD_SECRET_KEY`、`DD_CREDENTIAL_AES_256_KEY`、および Pro ライセンス |
| Application Load Balancer | HTTPS リスナーを、ポート**8443**の**HTTPS**ターゲットグループへ転送します |
| ECR リポジトリ | 2つの `-fips` イメージを格納します |
| IAM ロール | ECR からのプル、ログの書き込み、シークレットの読み取りが可能な実行ロールと、タスクロール |
| CloudWatch ロググループ | 各コンテナの `awslogs` 設定から参照されます |

TLS 証明書と鍵は、`dojo.crt` / `dojo.key` および `nginx_int.crt` / `nginx_int.key` として EFS に配置します。両方のペアが存在している必要があります。理由については、下記の[Compose が無償で提供している3つのものを ECS で用意する](#three-things-ecs-needs-that-compose-provides-for-free)を参照してください。

### 1. 初期化タスク（アップグレードごとに1回実行）

マイグレーションを適用し、初回起動時のデータを投入したうえで終了します。これはサービスではなくタスクです。

```json
{
  "family": "defectdojo-pro-init",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "init",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-initializer.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_INITIALIZE", "value": "true" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" },
        { "name": "DD_ADMIN_USER", "value": "admin" },
        { "name": "DD_ADMIN_MAIL", "value": "admin@example.com" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_ADMIN_PASSWORD", "valueFrom": "<SECRET_ARN_ADMIN_PASSWORD>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "init"
        }
      }
    }
  ]
}
```

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-init.json
aws ecs run-task --cluster <CLUSTER> --launch-type FARGATE \
  --task-definition defectdojo-pro-init \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}"
```

サービスを起動する前に、終了コード 0 で `STOPPED` になるのを待ちます。

### 2. Web サービス（nginx + uwsgi）

両方のコンテナは同じタスク内に配置されるため、nginx は `127.0.0.1` で uwsgi にアクセスできます。

```json
{
  "family": "defectdojo-pro-web",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "volumes": [
    {
      "name": "media",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/media"
      }
    },
    {
      "name": "certs",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/nginx-certs"
      }
    }
  ],
  "containerDefinitions": [
    {
      "name": "uwsgi",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_UWSGI_ENDPOINT", "value": "0.0.0.0:3031" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "mountPoints": [{ "sourceVolume": "media", "containerPath": "/app/media" }],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "uwsgi"
        }
      }
    },
    {
      "name": "nginx",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips",
      "essential": true,
      "dependsOn": [{ "containerName": "uwsgi", "condition": "START" }],
      "portMappings": [{ "containerPort": 8443, "protocol": "tcp" }],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "USE_TLS", "value": "false" },
        { "name": "GENERATE_TLS_CERTIFICATE", "value": "false" },
        { "name": "DD_UWSGI_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_PORT", "value": "3031" },
        { "name": "DD_UWSGI_IMPORT_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_IMPORT_PORT", "value": "3031" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
        { "name": "DD_MCP_PORT", "value": "9142" },
        { "name": "PSIRT_ENABLED", "value": "false" },
        { "name": "NGINX_METRICS_ENABLED", "value": "false" }
      ],
      "mountPoints": [
        { "sourceVolume": "certs", "containerPath": "/etc/nginx/certs", "readOnly": true }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "nginx"
        }
      }
    }
  ]
}
```

`USE_TLS=false` はオンプレミス構成を選択し、マウントされた証明書を使ってポート 8443 で TLS を自前で終端します。これを登録し、ロードバランサーに紐づいたサービスを作成します。

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. ワーカーサービス（Celery worker と beat）

イメージとシークレットは uwsgi と同じで、エントリポイントによってプロセスが決まります。beat のレプリカは必ず**1つだけ**実行してください。

```json
{
  "family": "defectdojo-pro-worker",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "celeryworker",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-worker.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celeryworker"
        }
      }
    },
    {
      "name": "celerybeat",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-beat.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celerybeat"
        }
      }
    }
  ]
}
```

### 4. デプロイが検証済み暗号を使用していることを確認する

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

各コンテナは、何らかの処理を提供する前にモジュール情報を報告するはずです。

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

この出力にコンテナが表示されていない場合、そのコンテナは起動していません。チェックはフェイルクローズ（安全側に倒して失敗）するためです。理由はそのコンテナのログストリームを確認してください。

### Compose が無償で提供している3つのものを ECS で用意する

Docker Compose は、バインドマウント元となるホストのファイルシステムと、コンテナ名を解決する DNS を提供してくれます。Fargate はそのどちらも提供しないため、これらのギャップはそれぞれ、静かに機能が劣化するのではなく nginx の起動そのものを妨げます。

**1. nginx の起動前に TLS 証明書が存在している必要があります。** nginx は設定の読み込み時にすべての `ssl_certificate` を検証し、オンプレミス構成には証明書なしで動くパスが存在しません。ポート 8080 は HTTPS への `301` を発行するだけなので、実際に機能するのは 8443 の TLS リスナーです。`dojo.crt` / `dojo.key` と `nginx_int.crt` / `nginx_int.key` を含む **EFS** ボリュームを `/etc/nginx/certs` にマウントしてください。片方のリスナーしか使わない場合でも、両方のペアを用意しておく必要があります。

代わりに `USE_TLS=true` を設定する方法もあります。この場合はアップストリームの `nginx_TLS.conf` が使われ、`GENERATE_TLS_CERTIFICATE=true` によってエントリポイントが自前で証明書を生成します。この構成はすべてのパスを Django にプロキシし、`/ui` から Vue UI を提供しないため、API 専用のデプロイや、ALB の背後に厳密に置く構成に適しています。

**2. `DD_MCP_HOST` は名前解決できる必要があります。** nginx は設定の読み込み時に `proxy_pass` のホスト名を解決します。デフォルトの `mcp-server` は Compose（コンテナ名として）や Helm（Service 名として）では解決できますが、`awsvpc` ではコンテナ自身に DNS 名が割り当てられず、`extraHosts` と `dnsSearchDomains` のどちらも拒否されます。

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

MCP サーバーをデプロイしていない場合にループバックを指定しておけば、Web 層全体の起動を妨げるのではなく、`/mcp` が `502` を返すだけで済みます。

**3. nginx の設定ファイルはイメージに含まれています。** `-fips` の nginx イメージにはオンプレミス構成が焼き込まれているため、マウントは不要です。Compose は独自のバインドマウントを上乗せするので、Compose での動作は変わりません。

### その他の Fargate 固有の注意点

- **永続ストレージは EFS である必要があります。** Fargate は EBS をアタッチできないため、アップロードされたスキャンファイルを保持する場合、media ディレクトリ（`/app/media`）には EFS ボリュームが必要です。
- **特権コンテナやホストネットワーキングは不要です。** イメージは非 root ユーザーとして動作し、`awsvpc` により各タスクに専用のネットワークインターフェースが割り当てられます。
- **nginx → uwsgi。** *同じ*タスク内のコンテナはネットワーク名前空間を共有するため、nginx と uwsgi を同居させれば nginx は `127.0.0.1` でアクセスできます。これが最もシンプルで正しい選択です。別々の ECS サービスに分割する場合は、`DD_UWSGI_HOST` に Cloud Map のサービスディスカバリ名を指定し、uwsgi のポートに対してセキュリティグループを開放してください。
- **uwsgi のエントリポイントを上書きしないでください。** `DD_UWSGI_ENDPOINT=0.0.0.0:3031` を設定し、イメージの ENTRYPOINT はそのままにしておきます。uwsgi は uwsgi プロトコルで話し、これは nginx が期待しているものです。エントリポイントを `uwsgi --http` に置き換えると、FIPS の起動チェックも一緒にスキップされてしまいます。
- **initializer はワンショットタスクであり**、サービスではありません。`aws ecs run-task`（あるいはデプロイ前のステップとして）で実行し、終了するに任せてください。desired count は設定しないでください。
- **`healthCheck.retries` は 10 を超えられません。** それより大きい値はタスク定義の登録時に拒否されます。
- **ロードバランサーは 8443 を対象にしてください**（HTTPS ターゲットグループを使用）。オンプレミス構成の 8080 リスナーは HTTPS へのリダイレクトしか行わないため、8080 を対象にするとループしてしまいます。ターゲット側の証明書は自己署名でも ALB は受け付けます。
- **TLS の終端。** クライアント向けの TLS を ALB が終端している場合は、ロードバランサー自体の FIPS 対応状況を SSP に別途記載してください。
- **シークレット**は `secrets` ブロックを通じて Secrets Manager または SSM Parameter Store に置くべきであり、`environment` に置いてはいけません。これは `DD_LICENSE` にも当てはまります。

### ECS でエビデンスを取得する

起動時のエビデンスブロックは、コンテナの `awslogs` 設定で指定されたロググループに出力されます。

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

実行中のタスク内でオンデマンドに確認することもできます（サービスで `enableExecuteCommand` が必要です）。

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## フェイルクローズな起動

`DD_FIPS_MODE` が設定されている場合、各コンテナは起動時に、検証済みプロバイダーが読み込まれていること、そして未承認のアルゴリズムが実際に拒否されることを確認します。**このチェックに失敗すると、コンテナは起動せずに終了します。**

これはチャートのガードレールと同じ考え方です。未検証の暗号技術へひそかにフォールバックしたコンテナがそのままトラフィックを処理し続ければ、コンプライアンス上の立場が損なわれているにもかかわらず、審査の段階まで気づけないことになります。

## FIPS モードの検証

各コンテナは起動時にエビデンスブロックを出力します。これは通常、審査担当者にとって最も扱いやすい形式です。マネージドランタイムでは、これはログ集約サービスに出力されます。

```
================================================================
[FIPS] DefectDojo Pro FIPS mode verification
Providers:
  fips
    name: OpenSSL FIPS Provider
    version: 3.1.2
    status: active
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
================================================================
```

次のコマンドで取得できます。

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

実行中のコンテナ内でオンデマンドに検証することもできます。

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

Go 製のサービスでは、FIPS モードはコンパイル時に組み込まれ、Go ランタイムによって報告されます。

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## FIPS モードでの動作の違い

一部の未承認アルゴリズムが使用できなくなるため、いくつかの動作が変わります。ここでは、あらかじめ計画しておく価値のあるものを挙げます。

### パスワードハッシュ

FIPS ビルドでは、デフォルトのパスワードハッシャーとして**PBKDF2-SHA256**が使用されます。Argon2、bcrypt、scrypt は FIPS 承認済みの鍵導出関数ではないため無効化されます。

既存のユーザーがロックアウトされることはありません。Django は、ユーザーが次回ログインに成功した際に各パスワードを PBKDF2 へ再ハッシュ化し、移行期間中は PBKDF2-SHA1 のハッシュも引き続き検証可能です。段階的な移行ではなく一斉切り替えを希望する場合は、パスワードのリセットを強制してください。

### TLS 暗号スイート

ChaCha20-Poly1305 は FIPS 承認済みではないため、TLS を終端するすべての nginx 設定から除去され、TLS 1.3 は `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256` に固定されます。TLS 1.2 と TLS 1.3 は、いずれも AES-GCM スイートを使って引き続き利用できます。ChaCha20 のみをサポートするクライアントは接続できなくなります。

検証済みモジュールはいずれにせよ ChaCha20 を拒否します。設定からこれを除去しておくことで、サーバーは完了できないスイートを一切提示しなくなり、デプロイされた構成自体が審査担当者にとって説明不要なものになります。

### メトリクスの Basic 認証

nginx のメトリクス認証を有効にすると、パスワードハッシュには Apache の MD5（`apr1`）形式ではなく SHA-256 crypt が使用されます。検証済みモジュールは MD5 形式を拒否するためです。`.htpasswd` のエントリを自分で生成しない限り、この違いを意識する必要はありません。自分で生成する場合は `openssl passwd -5` を使用してください。

### スキャンパーサー

一部のパーサーは重複排除キーの生成に MD5 を使用しています。これはセキュリティ目的ではない用途として明示的に注釈されているため、これらのパーサーは FIPS 環境下でも通常どおり動作します。パーサーの機能が失われることはありません。

## デプロイに関する注意事項

- **TLS の終端。** DefectDojo の手前にあるロードバランサーで TLS を終端している場合、その機器自身の FIPS 対応状況についてはそのロードバランサー側の責任であり、システムセキュリティ計画書に別途記載する必要があります。`-fips` の nginx イメージは、DefectDojo 自身が終端する TLS をカバーします。
- **データベースとキャッシュ。** PostgreSQL と Redis は別製品です。FIPS 環境では、FIPS エンドポイントを提供するマネージドデータベースなど、FIPS 準拠のインスタンスを使用し、継承コンポーネントとして文書化してください。
- **コンプライアンスの範囲。** DefectDojo 自体は暗号モジュールではなく、独自の証明書も保持していません。これらのイメージが提供しているのは、証明書を保持するモジュールが FIPS 承認モードで実行する検証済みの暗号処理です。審査担当者はモジュール名と証明書番号を求めますが、これらは上記のエビデンス出力に記載されています。
