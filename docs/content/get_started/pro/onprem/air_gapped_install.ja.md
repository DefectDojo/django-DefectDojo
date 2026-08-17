---
title: エアギャップ環境への DefectDojo Pro のインストール
description: インターネットに接続できるホストで DefectDojo Pro のインストール用アーティファクトを準備し、エアギャップ環境のネットワークに移動します
draft: false
weight: 8
audience: pro
---

このページは、DefectDojo Pro のライセンスに付属するインストール手順を補足するものです。対象ホストがインターネットに接続できない場合に変更が必要となる点のみを扱います。ホストの前提条件や PostgreSQL のセットアップを含め、それ以外はすべて標準の手順に従います。

この方法では、2 台のホストを使用します。通常どおりインターネットに接続できるステージングホストで、デプロイ用アーティファクトとコンテナイメージをダウンロードします。次に、環境で許可されている任意の転送方法でそれらのアーティファクトをエアギャップ環境のネットワークに移動し、DefectDojo へのネットワークアクセスがない対象ホスト上でインストールを完了します。

ステージングホストは後で再び使用できるように用意しておいてください。アップグレード時にも同じ転送作業を繰り返すため、残しておく価値があります。

## 必要なもの

ステージングホストには、インターネットに接続できる Linux ホスト、Docker のインストール、そしてデプロイディレクトリと圧縮されたコンテナイメージ用の十分な空きディスク容量が必要です。容量の大部分はイメージが占め、1 つあたり数百メガバイトになります。

エアギャップホストには、Docker がインストールされ正常に動作していること、そしてすでにプロビジョニングされ到達可能な PostgreSQL サーバーが必要です。いずれも標準のインストール手順に従ってください。

両方のホストに、DefectDojo から提供された `dojo-compose-cli` アーカイブとライセンスファイルのコピーが必要です。CLI バージョン 2.1.0 以降を使用してください。それより前のバージョンにはエアギャップモードがなく、これがないと CLI はコマンドを実行するたびにコンテナレジストリへの接続を試み、問題の内容を伝えることなく名前解決エラーで失敗します。

## アーティファクトを準備する

これらの手順はステージングホストで実行します。

### 1. CLI を登録する

Docker がまだインストールされていない場合は、先にインストールしてください。ディストリビューション固有の手順については、[Docker のインストールドキュメント](https://docs.docker.com/engine/install/)を参照してください。

CLI アーカイブを展開し、登録します。

```bash
sudo ./dojo-compose-cli register
```

登録を行うと、CLI が `/usr/bin` にインストールされ、`dojosrv` グループが作成され、ユーザーが `dojosrv` グループと `docker` グループに追加され、ライセンスが検証され、DefectDojo のコンテナレジストリに対して Docker が認証されます。

`DOJO_CLI_KEY` の入力を求められます。これは CLI がディスク上に保存する設定を暗号化するためのキーです。コマンドを実行するたびに入力を求められないよう、環境変数として設定しておいてください。

```bash
export DOJO_CLI_KEY="your-key"
```

新しいグループメンバーシップは、現在のシェルにはすぐには反映されません。新しいセッションを開くか、その場でグループを反映させてください。

```bash
newgrp docker
```

`id` コマンドで `docker` と `dojosrv` の両方がリストされていることを確認してください。ユーザーが `docker` グループに属していれば、以降のコマンドに `sudo` は不要です。

ステージングホストが送信 HTTPS プロキシ経由でインターネットに接続する場合は、何かを pull する前にプロキシ用の変数を設定してください。詳細は[フォワード HTTPS プロキシ経由での DefectDojo の実行](/onprem_deployment/forward_proxy/)を参照してください。

### 2. バージョンを設定する

`x.y.z` を実際にインストールするリリースに置き換えて、デプロイバージョンとアプリケーションバージョンの両方を設定します。

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

両方のコマンドで同じバージョンを使用し、この後の手順全体でも一貫して同じバージョンを使用してください。デプロイ用アーティファクトとイメージの間でバージョンが混在すると、スタックが起動に失敗するか、誤ったイメージで起動してしまいます。

### 3. デプロイ用アーティファクトとイメージをダウンロードする

デプロイディレクトリをダウンロードします。

```bash
dojo-compose-cli deploy download
```

これにより `/opt/dojo` に、compose ファイル、nginx の設定、課題管理ツールのテンプレート、customizations ディレクトリ、そして選択したリリース用のバージョン別サブディレクトリが配置されます。

続いてコンテナイメージを pull します。

```bash
dojo-compose-cli app pull-images
```

取得された内容を確認します。

```bash
docker image ls
```

その出力の中で、DefectDojo のイメージに共通するリポジトリ接頭辞を確認してください。次の手順で必要になります。イメージの構成はリリースごとに異なるため、一覧を決め打ちせず、必ず自分の出力から読み取ってください。

### 4. 生成された設定を記録する

標準のインストールでは、初回実行時にいくつかの設定値が生成されます。エアギャップ環境でのインストールでは、これらを対象ホスト上で手動で設定する必要があるため、ここで記録しておきます。

```bash
dojo-compose-cli environment print | head -n 9
```

認証情報暗号化キーとシークレットキーを保管してください。どちらもランダムに生成された 64 文字の文字列で、特に認証情報キーは、認証情報の暗号化に使用したものと一致している必要があるため、正確に記録し、シークレットとして保存してください。同じ出力に含まれる uwsgi と celery の値は、対象ホストの設定の出発点として役立ちます。

この出力は機密情報として扱ってください。デプロイに保存された認証情報を保護するキーが含まれています。

### 5. すべてをパッケージ化する

転送用のディレクトリを作成します。後で内容が分かるように、名前にバージョンを含めてください。

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

権限を保持したまま、デプロイディレクトリをアーカイブします。

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

コンテナイメージを保存します。次のスクリプトは、手順 3 で確認したリポジトリ接頭辞を受け取り、一致する各イメージを保存して圧縮します。

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

実行権限を付与し、接頭辞を指定して実行します。

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

手順 3 の各イメージについてファイルが生成されたことを確認し、ディレクトリをまとめます。

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

`artifacts-x.y.z.tar.gz` を、通常の転送プロセスを使ってエアギャップ環境のネットワークに移動してください。CLI アーカイブとライセンスファイルがまだそちらにない場合は、それらも合わせて移動します。

## エアギャップホストにインストールする

### 6. CLI をインストールしてエアギャップモードを有効にする

CLI アーカイブを展開し、CLI が想定する場所にライセンスを配置します。

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

エアギャップモードを有効にします。これはこのホストで最初に実行する CLI コマンドで、CLI を `/usr/bin` にインストールし、ファイルからライセンスを検証し、その過程で保存される設定を暗号化します。

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

反映されたことを確認します。

```bash
dojo-compose-cli config print
```

出力には `Air Gapped Deploy` が true に設定されていることが表示されます。ここでも `DOJO_CLI_KEY` を環境変数として設定し、以降のコマンドで入力を求められないようにしてください。

このホストでは `register` を実行しないでください。登録はコンテナレジストリに対して認証するためのものですが、レジストリは定義上到達不能であり、エアギャップモードでは CLI はこれを試みるのではなく拒否します。レジストリにアクセスする他のコマンドについても同様です。

| Command | Behavior in air-gapped mode |
| --- | --- |
| `register` | 拒否されます。レジストリ認証は利用できません。 |
| `deploy download` | 拒否されます。代わりにステージングホストで実行してください。 |
| `app pull-images` | 拒否されます。代わりにステージングホストで実行してください。 |
| `app upgrade` | 拒否されます。下記のアップグレードのセクションを参照してください。 |
| `app start`、`app stop`、`app restart` | 利用可能です。これらはレジストリに接続しません。 |

拒否された各コマンドは、エアギャップモードであることを示すメッセージとともに終了します。したがって、ここで拒否されるのは不具合ではなく、CLI が意図どおりに動作している証拠です。

続行する前に、新しいグループメンバーシップを反映させてください。

```bash
newgrp docker
```

### 7. デプロイディレクトリを復元する

転送用バンドルを展開し、デプロイ用アーカイブを配置します。

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

CLI のセットアップにより、ライセンスのみを含むほぼ空の `/opt/dojo` が作成されている場合があります。存在する場合は、アーカイブがそこにマージされてしまわないよう、先に削除してください。

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

実際のデプロイディレクトリを展開し、所有権と media の権限を修正します。

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. 設定を手動で行う

エアギャップ環境でのインストールでは対話形式の初回インストールを使用しないため、本来自動生成される値を手動で設定する必要があります。手順 4 で記録したキーを使用してください。

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

移動したアーティファクトに合わせてバージョンを設定します。

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

サイト URL と許可ホストを設定します。サイト URL は、ネットワーク内でこのホストに解決されるアドレスである必要があります。

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

事前にプロビジョニングした PostgreSQL サーバーを使用して、データベース接続を設定します。

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. コンテナイメージをロードする

次のスクリプトは、images ディレクトリ内のすべてのイメージファイルをロードします。

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

展開したアーティファクトディレクトリの中から実行します。

```bash
chmod u+x load-images.bash
./load-images.bash
```

その後、`docker image ls` で、想定するバージョンのすべてのイメージがロードされたことを確認してください。

### 10. スタックを起動する

CLI でスタックを起動します。設定した内容を読み取り、レジストリに接続することなくローカルの compose ファイルを操作するため、これはエアギャップモードでも動作します。

```bash
dojo-compose-cli app start
```

`app stop` と `app restart` も同様に利用できます。環境変数の値を変更した後は `app restart` を使用してください。コンテナが再作成され、新しい値が反映されます。

スタックが起動しない場合は、次の 2 点を確認してください。このコマンドにはデプロイディレクトリが配置されている必要があるため、手順 7 で `/opt/dojo/docker-compose.yml` が存在することを確認してください。また、設定されたバージョンによってイメージタグが決まるため、手順 9 でロードしたイメージと一致している必要があります。

これで、サイト URL として設定したアドレスで DefectDojo にアクセスできるようになります。

## エアギャップ環境のデプロイをアップグレードする

`app upgrade` はコンテナレジストリからダウンロードを行うため、エアギャップモードで拒否されるコマンドの 1 つです。アップグレードは単一のコマンドで実行するのではなく、インストールと同じ手順に従って行います。

ステージングホストで新しいバージョンを設定し、手順 3 から 5 をそのバージョンについて繰り返します。新しいバンドルを転送して新しいイメージをロードした後、エアギャップホスト側で新しいバージョンを設定し、再起動します。

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

つまずきやすい点が 2 つあります。設定されたバージョンを変更せずに再起動すると、バージョンによってイメージタグが決まるため、既存のイメージのままスタックが起動してしまいます。また、イメージの構成はリリースごとに変わることがあるため、以前の一覧がそのまま通用すると仮定せず、ロードした内容を新しいバージョンの pull 結果と照合してください。

既存のデプロイディレクトリは、新しいバージョンの compose ファイルや nginx 設定を自動的には取り込みません。そのため、手順 7 と同様に新しい `/opt/dojo` の内容を復元しつつ、自分自身の customizations、証明書、media は保持してください。

アップグレードを行う前には必ずデータベースをバックアップし、現在のバージョンから目的のバージョンまでの間にあるすべてのバージョンについて[アップグレードノート](/releases/os_upgrading/upgrading_guide/)を確認してください。複数のリリースにわたって遅れている場合は、開始前にサポートへ連絡してください。

## 送信アクセスが必要な機能

エアギャップ環境のデプロイは、送信接続が一切ない状態で動作しますが、外部サービスに接続する機能は、ネットワークが切断されている間は動作できません。これは、クラウドでホストされているツールからデータを取得するコネクタおよびインテグレーター、Jira などの課題管理ツール連携、Slack や Microsoft Teams のようなサービスへの送信通知、そして通常はスケジュールに従って取得される脆弱性エンリッチメントデータに当てはまります。

これらはデフォルトで有効になっているわけではなく、デプロイごとに設定するものであるため、これらが機能しないことによってエアギャップ環境でのインストールが壊れることはありません。いずれかを有効にした場合、そのデプロイからサービスへの経路が確保されるまでは、名前解決エラーや接続エラーで失敗すると考えてください。送信経路は存在するもののプロキシを経由する場合は、[フォワード HTTPS プロキシ経由での DefectDojo の実行](/onprem_deployment/forward_proxy/)を参照してください。

### 内部ミラーからの EPSS と KEV データ

EPSS と KEV のエンリッチメントは、パブリックインターネットへの経路を必要としないため、設定しておく価値がある例外です。どちらも Tuner の Finding Enrichment 配下で設定でき、それぞれに個別の有効化トグルとルックアップ URL があります。URL フィールドは初期状態でパブリックのソースを指していますが、自社ネットワーク内でホストしているコピーを指すように変更できます。

ミラーは、パブリックのソースと同じファイルを同じ形式で提供する必要があります。ルックアップは、指定された URL からそこにあるものを自動検出するのではなく、特定のファイルを取得するため、データを再パッケージ化したり再構成したりしたミラーは機能しません。デプロイはミラーが提供する内容をそのまま読み取るだけなので、都合の良いスケジュールでコピーを更新してください。

## ご質問やサポートについて

エアギャップ環境でのインストールやアップグレードについてサポートが必要な場合は、担当のアカウント担当者、または [support@defectdojo.com](mailto:support@defectdojo.com) までご連絡ください。
