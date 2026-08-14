---
title: オープンソースからセルフホスト型DefectDojo Proへの移行
description: オープンソース版DefectDojoのデータベースとメディアファイルをセルフホスト型DefectDojo Proのデプロイメントに移行する
draft: false
weight: 6
audience: pro
---

このページでは、オープンソース版DefectDojoインスタンスのデータをセルフホスト型DefectDojo Proのデプロイメントに移行する方法について説明します。

以下の例では、Amazon Web Servicesを使用し、EC2上のDocker ComposeまたはEKS上のKubernetesのいずれかと、Amazon RDS for PostgreSQLのデータベースを組み合わせています。この手順は、この組み合わせに対して検証されています。マネージドPostgreSQLと同等のコンピューティングを提供する他のプロバイダーや、オンプレミスのハードウェアにも、プロバイダー固有のコマンドを適宜変更すれば同じ手順を適用できます。

デプロイメントはお客様自身がホストするため、移行作業全体を通してデータはお客様自身の環境内にとどまります。エクスポートとリストアはお客様自身が実行しますが、DefectDojoサポートはどのステップでも支援できます。DefectDojo Proインスタンスがセルフホストではなく、DefectDojoによってクラウドホストされている場合は、代わりに[support@defectdojo.com](mailto:support@defectdojo.com)までご連絡ください。その場合はDefectDojoチームがリストアを代行します。

大まかな流れとしては、オープンソースインスタンスからデータベースとメディアファイルをエクスポートし、Proデプロイメントが使用するデータベースとストレージにリストアし、Proをリストア済みのデータベースに向けて設定した後、結果を検証します。

## 開始前に

エクスポートを行う前に、以下の点を確認してください。

データベースエンジン。DefectDojoはPostgreSQLをサポートしています。MySQLのサポートは非推奨となった後、[2.37.0で削除されました](/releases/os_upgrading/2.37/)。そのため、MySQLで稼働している古いインスタンスは、移行前にPostgreSQLへ変換する必要があります。該当する場合はサポートにお問い合わせください。

データベースの実行場所。デフォルトのDocker Composeセットアップのコンテナである場合もあれば、同じホスト上、別のVM上、またはAmazon RDSやCloud SQLなどのマネージドサービス上で動作する別サービスである場合もあります。どちらであるかによってエクスポートコマンドが異なります。

オープンソース版のバージョン。UIのフッター、またはデプロイメントのタグやイメージバージョンから確認できます。2.x系のすべてのリリースは、この手順で移行できます。3.0.0、3.0.1、3.0.2、または3.0.100を実行している場合は、開始前に[3.0.200](/releases/os_upgrading/3.0.200/)以降にアップグレードしてください。現在のバージョンからアップグレード先のバージョンまでの間にあるすべてのバージョンについて、[アップグレードノート](/releases/os_upgrading/upgrading_guide/)を確認してください。

バージョンの一致。オープンソース版のバージョンは、移行先のDefectDojo Proのバージョンと一致させるか、可能な限り近づけてください。初回起動時、Proはスキーマを自身のバージョンまで引き上げるデータベースマイグレーションを実行するため、バージョン差が大きいほど、マイグレーションが長時間化または失敗するリスクが高まります。ダンプを取得する前にバージョンを揃えてください。

移行先データベース。現在サポートされているPostgreSQLのメジャーバージョン(16以降)をプロビジョニングし、オープンソースインスタンスが稼働しているバージョンより古いものは使用しないでください。ダンプは、それより古いメジャーバージョンにはリストアできません。AWSの場合は、RDSインスタンスをProのコンピューティングと同じVPCに配置し、リストア元のホストからのポート5432への受信トラフィックを許可してください。

リストア用ホスト。データベースと同じネットワーク内にあり、PostgreSQLクライアントツールの`pg_restore`と`psql`がインストールされたマシンが必要です。AWSの場合は、同じVPC内、できればRDSインスタンスと同じアベイラビリティーゾーン内のEC2インスタンスを使用してください。

空きディスク容量。移行元サーバーには、データベースダンプと圧縮済みメディアアーカイブを転送する前に一時保存できる容量が必要です。

## ステップ1: データベースをエクスポートする

デフォルトのDocker Compose構成では、データベースのユーザー名とデータベース名の両方に`defectdojo`が使用されています。これらは変更可能なため、`docker-compose.yml`または`.env`ファイル内の`DD_DATABASE_URL`の値を確認してください。デフォルトの接続文字列は次のとおりです。

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

以下のコマンドでは、`<db_username>`、`<database_name>`、`<postgres_container_name>`をご自身の値に置き換えてください。コンテナ名は`docker ps`で確認できます。

圧縮されたカスタム形式のダンプを推奨します。`pg_restore`で直接読み込むことができ、マネージドデータベースへのリストア時に発生しがちな所有権やロールに関する問題のほとんどを回避できます。

コンテナ化されたPostgreSQLの場合(デフォルトのDocker Composeセットアップ)。

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

データベースにパスワードが必要な場合は、環境変数として渡します。

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

外部またはリモートのPostgreSQL(別のVM、Amazon RDS、Cloud SQLなど)の場合。

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

`-Fc`を省略して生成されるプレーンテキストのSQLダンプでも動作します。ただし、マネージドデータベースが拒否する`CREATE ROLE`、`ALTER ROLE`、`CREATE DATABASE`文が含まれる傾向があるため、これを使用する場合はステップ4の注記を参照してください。

## ステップ2: メディアファイルをエクスポートする

DefectDojoは、スクリーンショット、脅威モデル、リスク受容ドキュメントなど、アップロードされた成果物をメディアディレクトリに保存します。インポートおよび再インポートに使用されるスキャンファイルは、解析後に破棄されるため、オープンソース版DefectDojoではディスクに保持されません。したがって、メディアディレクトリにはユーザーがアップロードした成果物のみが含まれます。

ディレクトリの場所は、デプロイ方法によって異なります。

| Deployment method | Typical media path |
| --- | --- |
| Docker Compose | Named volume `defectdojo_media`, mounted at `/app/media` |
| Bare metal | `/opt/dojo/media`, or the path set in `DD_MEDIA_ROOT` |
| Kubernetes | Persistent volume mounted at `/app/media` |

ディレクトリを1つのアーカイブに圧縮します。名前付きボリュームの場合。

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

ディスク上のパスの場合。

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## ステップ3: ファイルに名前を付ける

リストア時にどのバージョンのものか明確にわかるよう、両方のファイル名にオープンソース版のバージョンを含めます。2.38.1で稼働しているインスタンスの例です。

| File | Renamed to |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

両方のファイルをリストア用ホストに転送します。`scp`などのツールで直接コピーするか、ご自身のアカウント内のプライベートオブジェクトストレージに一旦配置してからリストア用ホストに取得することもできます。AWSの場合は、プライベートS3バケットと`aws s3 cp`を使用します。いずれの方法でも、データはお客様自身の環境内にとどまります。

## ステップ4: データベースをリストアする

リストアは、データベースエンドポイントを指定してリストア用ホストから実行します。マネージドPostgreSQLサービスによって、この点でサポートする内容が異なります。Amazon RDSには、バケットからダンプファイルを一括インポートする機能がないため、クライアント側での`pg_restore`実行がサポートされている方法です。

1. データベースとアプリケーションロールを作成します。マスターユーザーとして接続し、移行先データベースとダンプが必要とするロールを作成します。両方ともデフォルトは`defectdojo`ですが、変更している場合はご自身の値を使用してください。

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. ダンプをリストアします。カスタム形式のダンプの場合、`--no-owner`と`--no-privileges`を使用することで、リストアが移行先に存在しないロールへ所有権を再割り当てしようとするのを防ぎます。マネージドデータベースでは真のスーパーユーザー権限が付与されないため、これを試みるリストアは失敗します。

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

プレーンテキストのSQLダンプの場合は、まず`CREATE ROLE`、`ALTER ROLE`、`CREATE DATABASE`、`ALTER DATABASE ... OWNER`の各文をコメントアウトまたは削除してから読み込みます。

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

リストアでエラーが報告された場合は、出力を保存した上で、それ以上ダンプから内容を削除する前にサポートまでご連絡ください。削除しすぎると、データベースが元のエラーよりも診断しづらい不整合な状態になる可能性があります。

## ステップ5: メディアファイルをリストアする

メディアアーカイブの内容を、Proデプロイメントがアップロード済みファイルを読み込む場所に配置します。アプリケーションは`/app/media`でファイルを探しますが、これはデプロイメントによってバインドマウントまたは永続ボリュームで裏付けられています。デプロイメントが使用するホストパスまたはボリュームについては、ライセンスに付属のインストールドキュメントを確認してください。

名前付きボリュームで構成されたDocker Composeデプロイメントの場合。

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

Kubernetesデプロイメントの場合は、アーカイブをローカルで展開し、`/app/media`にマウントされた永続ボリュームクレームに書き込むDjangoポッドにコピーします。

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## ステップ6: DefectDojo Proをリストア済みデータベースに向ける

データベース接続を更新して、Proがリストア済みのデータベースを使用するようにし、アプリケーションを起動します。初回起動時、Proはスキーマをオープンソース版のバージョンからProのバージョンへアップグレードするデータベースマイグレーションを実行します。データベースのサイズとバージョン差の大きさによっては、これに時間がかかることがあり、完了するまでアプリケーションは利用できません。

Docker Composeデプロイメントの場合は、デプロイメント構成でデータベースURLを設定し、スタックを再起動します。正確な構成キーとコマンドは、提供された`dojo-compose-cli`のバージョンによって異なるため、ライセンスに付属のインストールドキュメントに従ってください。接続文字列は次の形式です。

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Kubernetesデプロイメントの場合は、Helmの値でデータベースURLを設定し、再デプロイします。

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

どのPro機能をデプロイメントで利用できるかは、ライセンスとデプロイ方法によって異なります。一部の機能はセルフホスト型インストールには適用されないためです。DefectDojoは、移行の過程でお客様に適用される機能セットを確認します。

## ステップ7: データを検証する

アプリケーションがリストア済みデータベースに対して稼働したら、以下を行います。

1. DefectDojo Proデプロイメントにログインします。
2. Assets(アセット)、Organizations(組織)、Engagements(エンゲージメント)、Tests(テスト)、Findings(検出事項)が存在することを確認します。AssetsとOrganizationsは、オープンソース版ではProducts(製品)およびProduct Types(製品タイプ)と呼ばれていました。
3. メディアのリストアが正常に機能したことを確認するため、UIから代表的なアップロード済みファイル(例: Finding、Test、Engagementの添付ファイル)をダウンロードします。
4. ユーザーアカウントとグループが無事であることを確認します。SSOなどの認証設定は、通常、新しいデプロイメント用に再設定する必要があります。
5. 不一致が見つかった場合は、DefectDojoの担当者に報告してください。

## 切り替えの計画

ダンプはある時点でのスナップショットであるため、取得後にオープンソースインスタンスで作成されたものはProデプロイメントには反映されません。データの損失を避けるため、最終的なダンプと切り替えの間はオープンソースインスタンスを凍結するか、利用の少ない時間帯に移行を実施してください。

事前のドライランには時間をかける価値があります。まず最近のコピーを移行して検証し、その後本番の切り替えのために同じ手順を繰り返してください。2回目の実行はより速く完了し、ステップ6のスキーママイグレーションにどれくらい時間がかかるかを把握する材料にもなります。

## 移行チェックリスト

- データベースエンジン、データベースの場所、オープンソース版のバージョンを特定した
- オープンソース版のバージョンを移行先Proのバージョンに合わせた
- 移行先のPostgreSQLをプロビジョニングし、PostgreSQLクライアントツールを備えたリストア用ホストから到達可能であることを確認した
- 可能であればカスタム形式でデータベースをエクスポートした
- メディアディレクトリを特定し、圧縮した
- 両方のファイルにオープンソース版のバージョンを付けて命名した
- 移行先にデータベースとアプリケーションロールを作成した
- ダンプをリストアし、リストア出力にエラーがないか確認した
- デプロイメントが使用するパスまたはボリュームにメディアファイルをリストアした
- Proをリストア済みデータベースに向けて起動し、スキーママイグレーションを完了した
- 新しいデプロイメントでデータを検証した

## ご質問・サポート

DefectDojoはこの移行を最初から最後まで支援します。どのステップでもサポートが必要な場合は、担当のアカウント担当者、または[support@defectdojo.com](mailto:support@defectdojo.com)までご連絡ください。
