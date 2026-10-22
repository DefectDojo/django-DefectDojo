---
title: 本番環境での実行
description: 本番環境で使用する場合は、パフォーマンス調整とバックアップを推奨します。
draft: false
weight: 4
audience: opensource
aliases:
- /ja/en/open_source/installation/running-in-production
---

## 本番環境での使用(Docker Composeを使用)

このリポジトリのdocker-compose.ymlファイルは、ローカル環境でDefectDojoを評価するために完全に機能します。

Docker Composeは、コンテナ化されたDefectDojoを本番環境にデプロイするためのサポートされたインストール方法の1つですが、docker-compose.ymlファイルは、お使いの状況に合わせて事前にカスタマイズすることなく本番環境で使用することは想定されていません。

Docker ComposeでDefectDojoを実行する方法の詳細については、[Docker Composeでの実行](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md)を参照してください。

### システム要件

事前設定されたPostgreSQLデータベースではなく、専用のデータベースサーバーを使用することをお勧めします。これにより、DefectDojoのパフォーマンスが大幅に向上します。

#### インスタンスサイズ

データベースを分離した場合、DefectDojoを実行するための最小推奨要件は次のとおりです。

-   2 vCPU
-   8GBのRAM
-   10GBのディスク容量(データベースはここには含まれないため、OS用に用意した容量で足りるはずです)。パフォーマンス向上のため、
    OS用とは別のディスクを割り当てることも
    できます。

### セキュリティ
コンプライアンス要件を満たすために、`nginx`の設定やセキュリティヘッダーなどの実行時の側面を確認してください。
`docker-compose.yml`内のAES256暗号化キー`&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw`を、お使いのインスタンス固有のものに変更してください。
この暗号化キーは、SonarQubeなど外部ツールに接続するためにDefect Dojoに保存されるAPIキーやその他の認証情報を暗号化するために使用されます。キーは、パスワードマネージャーや`openssl`を使用するなど、さまざまな方法で生成できます。

```
     openssl rand -base64 32
```
```
      DD_CREDENTIAL_AES_256_KEY: "${DD_CREDENTIAL_AES_256_KEY:-<PUT THE GENERATED KEY HERE>o}"
```

## ファイルバックアップ

どちらの場合(専用DBまたはコンテナ化)でも、セルフホスティングを行っている場合は、データの定期的なバックアップを実装・作成することをお勧めします。

### メディアファイル

脅威モデルやリスク受容を含む、アップロードされたファイルのメディアファイルはdockerボリュームに保存されます。このボリュームは定期的にバックアップする必要があります。

## パフォーマンス調整

### uWSGI

デフォルトでは(デバッグ用の`ptvsd`モードを除き)、uWSGIは
16の同時接続を処理します。

リソース設定に応じて、以下を調整できます。

-   `DD_UWSGI_NUM_OF_PROCESSES`: 起動するプロセス数。
    (デフォルト4)
-   `DD_UWSGI_NUM_OF_THREADS`: これらの
    プロセス内のスレッド数。(デフォルト4)

たとえば、4つのプロセスにそれぞれ6つのスレッドを設定すると、24の
同時接続が得られます。

### Celery worker

デフォルトでは、単一のモノプロセスのcelery workerが起動します。大量の検出事項を保存したり、大規模なインポートを実行したりする場合は、リソース枯渇を防ぐためにこれらのパラメータを調整すると役立つことがあります。

以下の変数を変更することで、単一のceleryコンテナを維持しながらworkerのパフォーマンスを向上させることができます。

-   `DD_CELERY_WORKER_POOL_TYPE`: `prefork`に切り替えることができます。
    (デフォルト `solo`)

`prefork`を有効にする場合、以下の変数を使用する必要が
あります。ファイル内の参照については
Dockerfile.django-*を参照してください。

-   `DD_CELERY_WORKER_AUTOSCALE_MIN`: デフォルトは2です。
-   `DD_CELERY_WORKER_AUTOSCALE_MAX`: デフォルトは8です。
-   `DD_CELERY_WORKER_CONCURRENCY`: デフォルトは8です。
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER`: デフォルトは128です。

以下のコマンドを実行すると、設定を確認できます。

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
これにより、現在有効な設定を確認できます。

### 非同期インポート: 非推奨
この機能はバージョン2.47.0で削除されました。
