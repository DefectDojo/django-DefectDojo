---
title: OpenShiftへのDefectDojo Proのデプロイ
description: 'セルフホスト型DefectDojo ProをOpenShiftにデプロイする際に特有の事項: セキュリティコンテキスト制約、Route、ReadWriteManyストレージ'
draft: false
weight: 8
audience: pro
---

DefectDojo Proは、OpenShift Container Platform、ROSA、OKDを含むOpenShift 4.x上で動作します。

このページは、DefectDojo Proのライセンスに付属するインストールガイドを補足するものです。インストールガイドには、OpenShift専用のセクションを含む完全な手順が記載されています。このページでは、OpenShiftに特有の相違点を説明し、開始前に準備すべきものと、プラットフォーム固有の設定に関して何を期待すべきかを示します。

ライセンス資料には、OpenShiftブートストラップスクリプトが同梱されています。このスクリプトは既存のクラスターにインストールを行い、ストレージ、`fsGroup`の値、Route、インストール自体など、このページで説明する内容の大部分を処理します。冪等性があるため、再実行してもすでに作成済みのものが再利用され、また実際には何も変更せずに実行内容を表示するドライランにも対応しています。このページの残りの内容は、このスクリプトを使用する場合でも、ご自身でインストールを実行する場合でも当てはまります。

## セキュリティコンテキスト制約

DefectDojo Proは、デフォルトの`restricted-v2` SCCの下で動作します。サービスアカウントに`anyuid`、`privileged`、その他の昇格されたSCCを付与する必要はありません。

OpenShift向けに構成すると、DefectDojo Proは全体を通して非特権のセキュリティコンテキストで動作します。コンテナは特権なしで実行され、権限昇格はできず、すべてのcapabilityがドロップされます。ユーザーIDは、SCCが拒否するような固定UIDに固定するのではなく、名前空間に割り当てられた範囲からOpenShiftが割り当てるようになっています。

ポッドがSCC検証に失敗して拒否される場合、通常の原因は制約の付与が必要なことではなく、デプロイメントがOpenShift向けに構成されていないことです。

## ストレージはReadWriteManyである必要がある

DjangoポッドとCeleryワーカーポッドは、アップロードされたスキャン結果、スクリーンショット、生成されたレポートといった同じメディアファイルを読み書きします。これらには共有ボリュームが必要なため、マルチノードデプロイメントではReadWriteOnceストレージでは不十分です。

OpenShiftのデフォルトは、クラスターのデフォルトStorageClassに対するPersistentVolumeClaimです。デフォルトのクラスがReadWriteManyをプロビジョニングする場合はこれで機能します。これはOpenShift Data FoundationまたはNFSを基盤とするクラスターでは一般的です。デフォルトのクラスがReadWriteOnceであるマルチノードデプロイメントでは、代わりにNFSベースのストレージを構成してください。

### NFSベースストレージにおけるfsGroup

OpenShiftは`fsGroup`を、名前空間に割り当てられた範囲に制限します。NFSまたはEFSストレージを使用する場合、その範囲内の値を指定する必要があり、そうしないとボリュームのマウントが権限エラーで失敗します。

名前空間のアノテーションから範囲の開始値を読み取り、それを`fsGroup`として使用します。

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

このアノテーションには、開始値と長さで表された範囲が保持されています。開始値を使用してください。これはNFSおよびEFSストレージの場合にのみ必要であり、デフォルトのPersistentVolumeClaim方式では不要です。

## Route、TLS、Cookie

OpenShiftでは、DefectDojo ProはIngressではなくRouteを通じて公開され、エッジでのTLS終端とHTTPからのリダイレクトが行われます。

ROSAでは、Routeのホスト名は`<release-name>-<namespace>.apps.<cluster-domain>`という形式で生成されるため、`dojopro`名前空間内の`dojopro`リリースには`dojopro-dojopro.apps.<cluster-domain>`が割り当てられます。クラスターのappsドメインは次のコマンドで取得できます。

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

クラスターのappsドメイン配下のホスト名は、デフォルトのワイルドカード証明書でカバーされるため、証明書の設定は不要です。それ以外のホスト名を使用する場合は、独自の証明書を用意し、Routeのホスト名へのCNAMEを追加してください。

OpenShiftでは`dojo.secureCookies`を`false`に設定してください。エッジ終端のRouteでは、TLSはルーターで終端され、ルーターからポッドへの接続はプレーンなHTTPになります。そのため、secure指定のCookieは決して返送されず、ログインが失敗します。Routeがエッジ側でTLSを終端する場合、これは任意ではなく必須の設定です。

## リソースプロファイル

3種類のリソースプロファイルが用意されており、インストール時にいずれかを選択します。`minimal`は開発、CI、テスト向けです。`standard`は中程度の負荷での本番運用向けです。`performance`は高負荷の本番運用向けで、オートスケーリングを有効にします。

サイジングは個々の値を上書きするのではなく、プロファイルを通じて設定してください。そうすることで、ご自身の構成ファイルがプロファイルと競合しなくなります。

## 開始前に

ログイン済みのOpenShift 4.xクラスター。ローカル環境で`oc`、`helm`、`openssl`、`jq`が使用可能であること。

名前空間。NFSまたはEFSストレージを使用する場合は、そのsupplemental-groupsアノテーションの値。

ReadWriteManyをプロビジョニングするデフォルトのStorageClass、またはNFSサーバーの詳細情報。

評価目的を超える用途にはPostgreSQL 16。開発用には組み込みのPostgreSQLも利用できますが、本番運用の前に外部のマネージドデータベースへ移行してください。

DefectDojo Proのライセンスファイル。

使用予定のRouteホスト名。

## アウトバウンドのネットワークアクセス

送信制限のあるクラスターでは、DefectDojo Proのイメージをホストするコンテナレジストリへのポート443でのアウトバウンドHTTPSを許可してください。レジストリのホスト名は、ライセンスに付属のインストールガイドに記載されています。レジストリのエンドポイントはロードバランサーの背後にあり、アドレスが変化するため、固定アドレスではなくホスト名を許可してください。

クラスターは、PostgreSQLのポートでデータベースにも到達できる必要があります。

悪用可能性のエンリッチメントはオプション機能で、ポート443のHTTPSでさらに2つの宛先が必要です。EPSSスコアは`api.first.org`から、CISA KEVデータは`www.cisa.gov`から取得されます。どちらもアドレスが変化するコンテンツデリバリーネットワークから配信されるため、ホスト名を許可してください。これらを許可しない場合でもDefectDojoは正常に動作しますが、検出事項にEPSSやKEVのデータは付与されません。

アウトバウンドトラフィックが直接ではなくプロキシを経由する場合は、[フォワードHTTPSプロキシ経由でのDefectDojoの実行](/onprem_deployment/forward_proxy/)を参照してください。

## 初期化ジョブを先に完了させる必要がある

インストールでは、マイグレーションの適用、管理者ユーザーの作成、初期データの読み込みを行うKubernetesジョブが実行されます。これには15分ほどかかります。完了するまでは管理者ユーザーが存在しないためログインできませんが、Routeはすでに応答しています。

進捗を確認します。

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

`oc get job`が`1/1`の完了数を報告したら、ジョブは完了です。

他のポッドは、initコンテナを通じて初期化ジョブの完了を待機します。データベースの初期化が完了した後は、`dojo.skipInitContainer`を`true`に設定することで、以降のアップグレード時にこの待機をスキップできます。

## 確認

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

その後、Routeのホスト名を開いてサインインします。

## トラブルシューティング

### セキュリティコンテキスト制約によりポッドが拒否される

デプロイメントがOpenShift向けに構成されていなかった可能性が高く、その結果SCCが許可しないユーザーIDに固定するデフォルト設定にフォールバックしています。`anyuid`や`privileged`を付与することは解決策ではなく、また必要でもありません。

### ログインがログインページにリダイレクトされ続ける

エッジ終端のRouteの背後で`dojo.secureCookies`が`true`になっています。`false`に設定してアップグレードしてください。

### NFSでのボリュームマウント権限エラー

`fsGroup`が名前空間の許可範囲外です。supplemental-groupsアノテーションを読み取り、範囲の開始値を使用してください。

### Multi-Attachエラー、またはContainerCreatingで停止するポッド

ボリュームがReadWriteOnceであり、複数のポッドが同時にマウントしようとしています。クレームとその背後のクラスを確認してください。

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

ReadWriteManyクラス、またはNFSベースのストレージに移行してください。

### ブラウザでの証明書警告

デフォルトのRoute TLSはクラスターのワイルドカード証明書を使用しており、これはクラスターのappsドメイン配下の名前のみをカバーします。それ以外のホスト名を使用する場合は、独自の証明書を用意してください。

### ログの確認

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

より詳細な出力が必要な場合、`config.logLevel`と`celery.logLevel`はどちらも`DEBUG`を指定できます。

## アップグレード

アップグレードは標準の手順に従います。[DefectDojo Pro(オンプレミス)のアップグレード](/get_started/pro/onprem/upgrading/)を参照してください。

## ご質問・サポート

OpenShiftデプロイメントに関するサポートが必要な場合は、担当のアカウント担当者、または[support@defectdojo.com](mailto:support@defectdojo.com)までご連絡ください。
