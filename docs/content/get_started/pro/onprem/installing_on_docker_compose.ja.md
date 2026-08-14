---
title: Docker Composeへのインストール
description: dojo-compose-cliを使用して、PostgreSQLを別サーバーに置いた単一ホストにセルフホスト型DefectDojo Proをインストールします
draft: false
weight: 15
audience: pro
---

このページでは、セルフホスト型の二つのモデルのうちよりシンプルな方法であり、すでにKubernetesを運用していない場合に適した選択肢である、Docker ComposeへのDefectDojo Proのインストールについて説明します。

結果として二台のホストが必要になります。一台はDocker Compose上でアプリケーションとその補助サービスを実行し、もう一台はPostgreSQLを実行します。自前で運用する代わりに管理型データベースを指定することもでき、評価用途であればアプリケーションホスト上のコンテナ内でデータベースを実行することもできますが、それは本番データには適していません。

作業のほとんどは、DefectDojoがライセンスとともに提供する`dojo-compose-cli`が行います。その`first-install`コマンドは、デプロイを設定し、イメージをプルし、すべてを起動し、systemdサービスを登録する対話式ウィザードです。

## 開始前に

まずデプロイのサイズを決めてください。このセクションのハードウェアサイジングのガイダンスでは、アプリケーションホストとデータベースの両方について何をプロビジョニングすべきかを説明しています。

このインストールでサポートされているオペレーティングシステムはUbuntu 24.04 LTSです。開始前に完全にアップデートしてください。インストールはrootとしてコマンドを実行するため、両方のホストで`sudo`またはrootシェルが必要です。

サブスクリプションとともに届く、DefectDojoからの二つのファイルが必要です。`dojo-compose-cli`アーカイブと、通常`dojopro.lic`という名前のライセンスファイルです。お持ちでない場合は、アカウント担当者または[support@defectdojo.com](mailto:support@defectdojo.com)までご連絡ください。

## データベースをセットアップする

DefectDojo ProにはPostgreSQL 16以降が必要です。

### 管理型データベースを使用する

管理型のPostgreSQLサービスを使用する場合は、そのプロバイダーのドキュメントに従ってインスタンスを作成し、次に以下を作成してください。

- `dojodb`という名前のデータベース
- `dojodbusr`という名前のデータベースユーザー。`dojodb`に対するすべての権限を持ち、そのオーナーとして設定されているもの

ホスト名、デフォルトの5432以外の場合はポート番号、そして認証情報を控えておいてください。インストール中に必要になります。

### 自前でPostgreSQLを運用する

Ubuntu 24.04では、PostgreSQL 16はデフォルトのリポジトリに含まれています。

```bash
apt update
apt -y install postgresql postgresql-contrib
```

データベースとアプリケーションユーザーを作成します。DefectDojoはオーケストレーションサービス用に二つ目のデータベースを使用するため、両方を作成してください。

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

英数字のパスワードを使用してください。特殊文字は、後でパスワードを接続文字列に組み込む際にURLエンコードする必要があり、そこは間違えやすいポイントです。

次に、アプリケーションホストからの接続をデータベースが待ち受けるようにします。`/etc/postgresql/16/main/postgresql.conf`で、`listen_addresses`をデータベースサーバー自身のアドレスに設定するか、固定したくない場合は`*`に設定してください。

```bash
listen_addresses = '<db-server-address>'
```

そして`/etc/postgresql/16/main/pg_hba.conf`に、アプリケーションホストを許可する3行を追加します。すべてに対して開放するより、アプリケーションホストのアドレスに制限する方が望ましいです。

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

両方の変更を反映させるために再起動します。

```bash
systemctl restart postgresql
```

## アプリケーションホストを準備する

### アウトバウンド接続

制限されたネットワークでは、アプリケーションホストは以下へのアウトバウンドアクセスを必要とします。特に記載がない限り、すべてポート443のHTTPSです。

| Destination | Purpose | Required |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | DefectDojo Proのコンテナレジストリ | 必須 |
| データベースホスト(通常はポート5432) | アプリケーションからデータベースへの接続 | 必須 |
| 使用しているディストリビューションのパッケージリポジトリ | セットアップ時のオペレーティングシステムの依存関係 | 必須 |
| `download.docker.com` | セットアップ時のDocker Engineパッケージ | 必須 |
| `api.first.org` | EPSSの悪用予測スコア | 任意 |
| `www.cisa.gov` | 既知の悪用された脆弱性のKEVカタログ | 任意 |

アドレスではなくホスト名で許可リストに登録してください。レジストリはコンテンツデリバリーネットワークの背後にあるため、そのアドレスは場所によって異なり、時間とともに変化します。

ホストがアウトバウンドプロキシ経由でインターネットに到達する場合は、[フォワードHTTPSプロキシの背後でDefectDojoを実行する](/onprem_deployment/forward_proxy/)を参照してください。インターネットへの経路が全くない場合は、代わりにこのセクションのエアギャップインストール手順に従ってください。

### データベースへの到達性を確認する

先に進む前に、クライアントツールをインストールして接続してください。データベースの問題は、インストールの途中よりも今診断する方がはるかに簡単です。

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### Docker Engineをインストールする

[UbuntuでのDocker Engineインストール手順](https://docs.docker.com/engine/install/ubuntu/)に従ってください。手順は時間とともに変わるため、コピーではなくDocker自身のドキュメントを使用してください。それらの手順にはデフォルトで含まれている`docker-compose-plugin`パッケージも、エンジンと一緒にインストールしてください。

次に、ユーザーを`docker`グループに追加し、新しいメンバーシップを反映させます。

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## DefectDojoをインストールする

CLIアーカイブとライセンスファイルを同じディレクトリに入れてアプリケーションホストにコピーし、CLIを展開します。

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

次に、そのディレクトリからインストーラーを実行します。

```bash
sudo ./dojo-compose-cli first-install
```

ウィザードは以下の項目を尋ねます。

| Prompt | What it is |
| --- | --- |
| `DOJO_CLI_KEY` | CLIがディスクに保存する設定を暗号化するためのキーです。後続のコマンドで必要になるため、今決めて保管しておいてください。 |
| DefectDojo Version | インストールするリリースです。 |
| Deploy Version | 使用するデプロイファイルです。バージョンと同じ値に設定してください。 |
| Deploy Type | データベースが専用ホストにある場合は`separate-db`、PostgreSQLをコンテナで実行する場合は`containerized-db`です。 |
| Database Connection Type | Single Lineを選択し、接続文字列全体を入力してください。 |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`です。`postgresql://`ではなく`postgres://`で始まる必要があります。 |
| `DD_ALLOWED_HOSTS` | アプリケーションが応答するHostヘッダーです。 |
| `DD_SITE_URL` | ユーザーがDefectDojoにアクセスする完全なURLです。例:`https://defectdojo.internal.example.com`。 |

プロンプトについて知っておくべき点が二つあります。値ごとの入力方式では現状ユーザー名を尋ねないため、データベース接続は値ごとではなく1行で入力してください。また、パスワードに`!`、`@`、`#`のような文字が含まれる場合は、接続文字列内でURLエンコードしてください。

その後インストーラーはイメージをプルし、スタックを起動し、systemdサービスを作成し、生成された管理者の認証情報を表示します。**ターミナルを閉じる前に、その認証情報を保存してください。二度と表示されません。**

完了すると、指定したサイトURLでDefectDojoにアクセスできるようになります。

## インストールによって作成されるもの

| Item | Location |
| --- | --- |
| CLIバイナリ | `/usr/bin/dojo-compose-cli` |
| アプリケーションファイル、composeファイル、nginx設定、メディア | `/opt/dojo/` |
| ライセンスファイル | `/etc/defectdojo/dojopro.lic` |
| 暗号化されたCLI設定 | `/etc/defectdojo/compose.config` |
| TLS証明書 | `/opt/dojo/certs/` |
| カスタマイズ | `/opt/dojo/customizations/` |
| systemdサービス | `/etc/systemd/system/defectdojo-compose.service` |

また、アプリケーションのファイルを所有する`dojosrv`ユーザーとグループも作成します。

稼働するスタックは、Djangoアプリケーション、スキャンインポートを処理する別コンテナ、nginx、Celeryワーカーとスケジューラー、キャッシュとキューイング用のValkey、connectorsサービス、そしてMCPサーバーです。`docker ps`で一覧を確認できます。

日常的に必要なコマンドは以下のとおりです。

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

設定を変更した後は`app restart`を使用してください。コンテナが再作成され、新しい値が反映されます。

## TLS証明書を差し替える

インストール直後にサイトが動作するよう、自己署名証明書が同梱されています。ファイル名をそのまま保った状態で二つのファイルを上書きすることで、自前の証明書に差し替えられます。

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

その後、`dojo-compose-cli app restart`で反映させます。

## 管理者パスワードをリセットする

生成されたパスワードを紛失した場合は、アプリケーションホストからリセットしてください。DefectDojoが稼働している必要があります。

```bash
dojo-compose-cli app change-password
```

## アップグレード

まずデータベースをバックアップし、対象バージョンだけでなく、現在のバージョンから対象バージョンまでのすべてのバージョンのリリースノートを読んでください。[アップグレードノート](/releases/os_upgrading/upgrading_guide/)を参照してください。

CLIはバージョンを尋ねながら、アップグレード全体を実行できます。

```bash
dojo-compose-cli app upgrade
```

段階的に行いたい場合は、アプリケーションを停止し、新しいバージョンを設定し、対応するデプロイファイルをダウンロードしてから、再度起動してください。

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

ダウンロードのステップでは、新しく取得する`docker-compose.yml`、nginx設定、`local_settings.py`を既存のものと比較し、差異がある場合は変更を統合できるよう知らせてくれます。`--overwrite`を追加すると、それらのファイルの新しいバージョンを受け入れてローカルの変更を破棄するため、意図を持って使用してください。

自分の設定は`/opt/dojo/customizations/local_settings.py`に保持してください。このファイルはユーザー自身のものであり、アップグレードを経ても残ります。

## コマンドリファレンス

`dojo-compose-cli --help`ですべてが一覧表示され、各サブコマンドも同様に`--help`を受け付けます。最も必要になりそうなコマンドは以下のとおりです。

| Command | What it does |
| --- | --- |
| `first-install` | 対話式の初回インストール |
| `app start`, `app stop`, `app restart` | スタックの制御 |
| `app upgrade` | 新しいバージョンへのアップグレード |
| `app pull-images`, `app purge-images` | 設定されたイメージの取得または削除 |
| `app change-password` | アプリを稼働させたまま管理者パスワードをリセット |
| `config print` | 現在の設定を表示 |
| `config set` | バージョン、デプロイバージョン、デプロイタイプ、エアギャップモードを設定 |
| `config rotate-secret` | 保存された設定を暗号化するキーをローテーション |
| `environment print`, `environment add`, `environment remove` | 環境変数の管理 |
| `deploy download` | 設定されたバージョンのデプロイファイルを取得 |
| `license print`, `license status`, `license update` | ライセンスの確認と更新 |
| `validate db-connection` | データベース接続文字列を確認 |
| `validate deploy-version` | デプロイファイルが設定されたバージョンと一致するか確認 |
| `diagnostics collect` | サポート依頼用の診断バンドルを収集 |
| `register` | コンテナレジストリへの認証 |
| `update-binary` | CLI自体を更新 |

設定は保存時に暗号化されているため、ほとんどのコマンドには`DOJO_CLI_KEY`が必要です。セッション用にエクスポートするか、`sudo -E`で`sudo`に渡してください。

```bash
export DOJO_CLI_KEY="your-key"
```

## ご質問・サポート

インストールが完了しない場合、`dojo-compose-cli diagnostics collect`がレポートバンドルを収集します。これが弊社が最も迅速に支援できる方法です。失敗時に実行していた内容とあわせて、[support@defectdojo.com](mailto:support@defectdojo.com)までお送りください。
