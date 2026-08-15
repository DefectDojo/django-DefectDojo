---
title: DefectDojo Pro アップグレードガイド
description: 既存の DefectDojo Pro Helm リリースをアップグレードする方法。チャートの取得、アップグレードの実行、ロールバックを含みます
draft: false
weight: 14
audience: pro
aliases:
- /ja/get_started/pro/onprem/upgrading/
---

<!--
  DefectDojo Pro Helm チャートリポジトリから生成されています。
  ソース: チャートバージョン 3.1.304 の docs/UPGRADE_GUIDE.md
  このファイルではなく、ソースのガイドを編集してください。ローカルでの変更は
  次にチャートがリリースされた際に上書きされます。
-->
既存の DefectDojo Pro リリースを新しいチャートバージョンにアップグレードする方法について説明します。
推奨される方法は、DefectDojo OCI レジストリからチャートを直接プルすることです。この方法では
zip の展開は不要です。インストール時に使用したパッケージ化された zip によるワークフローも
アップグレードで利用でき、以下で説明します。

このガイドでは、以下について説明します。

- [アップグレード前に](#before-you-upgrade)
- [チャートの取得元: OCI レジストリ](#chart-source-oci-registry)
- [レジストリへの認証](#authenticate-to-the-registry)
- [OCI レジストリ経由でのアップグレード（推奨）](#upgrade-via-oci-registry-recommended)
- [展開済み zip 経由でのアップグレード](#upgrade-via-extracted-zip)
- [ArgoCD でのアップグレード](#upgrade-with-argocd)
- [アップグレードの検証](#verify-the-upgrade)
- [ロールバック](#rollback)
- [トラブルシューティング](#troubleshooting)

---

## アップグレードの対象範囲

DefectDojo Pro のリリースは、チャートバージョン、コンテナイメージのバージョン一式、Pro
設定ファイルから構成されます。これらは一緒にビルド・テストされており、常に一緒に更新する
必要があります。イメージタグだけを単独でアップグレードすることはサポートされておらず、
デプロイが壊れる原因になります。

設定についても同様です。ほぼすべてのリリースで新しい `pro_settings.py` が同梱されます。
アップグレードの際に古いコピーをそのまま持ち越したり、古いものを手作業でパッチ適用したり
しないでください。アプリケーションは、そのバージョンに対応した `pro_settings.py` を実行
する必要があります。独自のカスタマイズは `local_settings.py` に記述してください。この
ファイルはアップグレード時にも保持され、編集してよいのは両者のうちこちらだけです。

チャートを使用すればこの処理は自動的に行われます。チャートは対応する `pro_settings.py`
を同梱し、`local_settings.py` と並べてマウントするため、手動でコピーや移行を行う必要は
ありません。

## アップグレード前に

すべてのアップグレードは同じ手順で始めるべきです。これらの手順を省略することが、
アップグレード失敗の最も一般的な原因です。

1. 現在のリリースから移行先のバージョンまでの、すべてのバージョンの**リリースノートを
   読んでください**。破壊的変更、新たに必須となったフィールド、移行の前提条件はここに
   記載されています。各タグの GitHub リリースページから変更履歴へのリンクがあります。
2. **現在のチャートバージョンを確認してください。** これがアップグレードの起点になります。

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **データベースをバックアップしてください。** チャートのアップグレードには、スキーマを
   変更する Django マイグレーションが含まれる場合があります。作業を進める前に、
   PostgreSQL インスタンスの論理ダンプ（またはストレージレベルのスナップショット）を
   取得してください。
4. **values ファイルを用意してください。** アップグレードコマンドには、インストール時に
   使用したものと同じプラットフォームプリセット、プロファイルプリセット、顧客用 values
   ファイルを渡す必要があります。values ファイルが欠落していたり内容がずれていたりすると、
   予期しない差分が生じます。
5. **シークレットの参照が引き続き有効であることを確認してください。**
   `--set dojo.existingSecret=...` や `--set license.existingSecret=...` を指定して
   インストールした場合は、それらの Kubernetes シークレットが引き続きネームスペースに
   存在することを確認してください。
6. クラスターに手を加える前に、**まずアップグレードをローカルでレンダリングして**、
   フィールドの欠落、無効な値、テンプレートエラーがないかを確認してください。

   ```bash
   helm template dojopro $CHART_REF \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/<size>.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     > /tmp/dojopro-upgrade-render.yaml
   ```

   `$CHART_REF` は OCI 参照（下記参照）または展開済みのチャートパスです。

> `NAMESPACE` を一度設定してください。このガイド内のすべてのコマンドは `$NAMESPACE` を
> 使用します。
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **ネットワークポリシーのデフォルトが変更されました。** NetworkPolicies は現在
> `networkPolicy.profile` によって制御され、デフォルトは `standard` です。この設定では、
> すべての egress と、このリリース自身の Pod 間の ingress が許可されます（外部からの
> ingress は引き続き ingress パスに制限されます）。これは、これまでの常に細粒度だった
> egress 許可リストよりも寛容な設定です。ロックダウンされた挙動を維持したい場合は、
> `networkPolicy.profile: aggressive` を設定し、例外設定（`nodeLocalDns`、
> `dnsSelectors`、`externalAPIs`）を見直してください。詳細は
> [ネットワークポリシー](/get_started/pro/onprem/installing_on_kubernetes/#network-policies)
> を参照してください。

> **オーケストレーター用データベースの要件。** オーケストレーター（`ddorch`）は
> `<main-db-name>-ddorch` という名前の 2 つ目のデータベースを使用し、存在しない場合は
> 起動時に作成します。アプリケーションのロールに `CREATEDB` 権限がない場合は、ddorch を
> 有効にするチャートバージョンにアップグレードする前に、事前にデータベースを作成して
> おいてください（`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`）。作成して
> おかないと、ddorch の Pod は
> `permission denied to create database (SQLSTATE 42501)` で失敗します。詳細は
> [事前確認: オーケストレーター（ddorch）データベース](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database)
> を参照してください。

> **Organization/Asset のリラベルのデフォルト。**
> `dojo.V3EnableOrganizationAssetRelabel` のデフォルトは現在 `null`（自動）です。
> これは**新規インストールでは有効**、**アップグレードでは無効のまま**になることを意味し、
> 既存のリリースで UI のリラベル（ProductType/Product を Organization/Asset に
> 置き換える）が意図せず有効化されることはありません。アップグレード済みのリリースで
> これを有効にしたい場合は、`dojo.V3EnableOrganizationAssetRelabel: true` を明示的に
> 設定してください。明示的な `true`/`false` は常に自動デフォルトより優先されます。

---

## チャートの取得元: OCI レジストリ

チャートは、OCI アーティファクトとして DefectDojo の GCP Artifact Registry に
公開されています。

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

各リリースにはチャートバージョンのタグが付けられます（例: `2.57.2`）。チャートバージョンは
`Chart.yaml` 内のアプリバージョンと一致するため、`helm upgrade --version` に渡すタグは
GitHub リリースに表示されているバージョン番号と同じです。

利用可能なチャートバージョンの一覧を表示するには、次のようにします。

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **アップグレードに OCI を使う理由。** プリセット（`presets/platforms/*.yaml`、
> `presets/profiles/*.yaml`）はチャート内にパッケージ化されています。チャートを OCI
> URL で参照すると、対象チャートに対応した正しいバージョンのプリセットが自動的に
> 取得されます。再展開の手順は不要で、古いプリセットが使われる心配もありません。

---

## レジストリへの認証

このレジストリは非公開です。Helm がチャートをプルする前に、ログインしておく必要が
あります。GCP サービスアカウントキー、または DefectDojo サポートから提供される
短期間有効なアクセストークンを使用してください。

**方法 A — サービスアカウントの JSON キーを使う**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**方法 B — 対話的な gcloud ログインを使う（レジストリへのアクセス権を持つ担当者向け）**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

`gcloud auth print-access-token` で取得したアクセストークンは 1 時間で失効します。
アップグレード中に `401 Unauthorized` が表示された場合は、`helm registry login` を
再実行してください。

> **エアギャップ環境・ファイアウォールで隔離された環境の場合:** クラスターのノードは
> `us-south1-docker.pkg.dev` に到達できるが、作業用マシンからは到達できないという
> 場合は、以下の展開済み zip によるワークフローを使用してください。OCI による
> ワークフローは、`helm upgrade` を実行するホストがレジストリに到達できる場合にのみ
> 機能します。

---

## OCI レジストリ経由でのアップグレード（推奨）

`helm upgrade` の参照先として OCI URL を直接指定し、`--version` でチャートバージョンを
固定します。values ファイル、`--set` フラグ、`--set-file` フラグはすべて、元の
インストール時と同じものを使用します。

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
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> 上記のプラットフォームおよびプロファイルのプリセットパスは `presets/platforms/...`
> （`$CHART/` プレフィックスなし）です。Helm が OCI からチャートをプルすると、
> プリセットはプルされたチャート内に存在しますが、ここでの `-f` は**それらファイルの
> ローカルコピー**を指しています。プリセットのローカルコピーを保持していない場合は、
> まず `helm pull oci://... --version $VERSION --untar` でチャートを展開し、展開した
> ディレクトリから参照してください。あるいは、展開済み zip によるワークフローを
> 使用してください。

**シークレットとライセンスファイルをインラインで指定するバリエーション:**

```bash
helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> `--version` は必ず固定してください。省略すると、コマンド実行時点でレジストリが
> 解決したタグが使用されてしまい、再現性も監査可能性もありません。再実行、ロール
> バック、インシデント対応のすべてが同じアーティファクトを参照するように、
> バージョンを固定してください。

---

## 展開済み zip 経由でのアップグレード

OCI レジストリに到達できない作業用マシンの場合や、チャートをローカルファイルとして
用意しておきたい場合は、GitHub リリースからのパッケージ済み zip がインストール時と
同じ方法でアップグレード時にも機能します。インストール時との違いは、コマンドの動詞
（`helm install` ではなく `helm upgrade`）だけです。

1. GitHub リリースから `dojo-pro-helm-bundled-<version>.zip`（および分離署名の
   `.asc`）をダウンロードします。
2. インストールガイドに記載されている手順に従い、公開鍵
   （`dojo-pro-release-signing.asc`）を使って署名を検証します。
3. プリセットが古い展開結果と衝突しないように、チャートを**バージョンごとのパス**に
   展開します。

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. 展開したチャートパスを使ってアップグレードを実行します。values ファイルと
   フラグは元のインストール時と同じものを使用します。

   ```bash
   helm upgrade dojopro $CHART \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/standard.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     --set-file ddorch.tls.rootCa=orch_ca.crt \
     --set-file ddorch.tls.cert=orch_server.crt \
     --set-file ddorch.tls.key=orch_server.key \
     --wait --timeout 15m
   ```

> **アップグレードのたびに再展開してください。** プリセットファイルはチャート
> バージョン間で更新されます。古い展開結果を使い回すと、気付かないうちにアップ
> グレードが古いプリセットのデフォルト値に固定されてしまいます。

---

## ArgoCD でのアップグレード

DefectDojo Pro を ArgoCD で管理している場合、アップグレードは Application 仕様内の
`targetRevision` を変更するだけで完了します。プラットフォームおよびプロファイルの
プリセットはチャート内でバージョン管理されているため、連動して更新されます。

```yaml
spec:
  source:
    repoURL: us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2
    chart: dojopro
    targetRevision: <chart-version>    # bump this
    helm:
      valueFiles:
        - presets/platforms/aws-eks.yaml
        - presets/profiles/standard.yaml
      values: |
        # your environment-specific values
      parameters:
        - name: dojo.existingSecret
          value: dojopro-secrets
        - name: license.existingSecret
          value: dojopro-license
```

`targetRevision` を編集したら Application を同期してください。ArgoCD が OCI
レジストリから新しいチャートをプルし、リコンサイルを行います。

> ArgoCD は OCI レジストリ用に独自の認証情報を必要とします。リポジトリシークレットには
> `type: helm` と `enableOCI: "true"` を設定してください。Secret の正確な形式に
> ついては、ArgoCD の
> [Helm OCI ドキュメント](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support)
> を参照してください。

---

## アップグレードの検証

`helm upgrade` が完了したら（あるいは ArgoCD が Synced / Healthy を報告したら）、
新しいリビジョンが稼働していることを確認します。

```bash
# Chart revision bumped and status is deployed
helm list -n $NAMESPACE

# All pods Running and Ready — expect django, celery worker/beat,
# connectors, ddorch, ddorch-workers, and (if enabled) mcp-server
kubectl get pods -n $NAMESPACE

# Migrations succeeded — the initializer job should show Completed
kubectl get jobs -n $NAMESPACE

# App version matches the target
kubectl get deployment -n $NAMESPACE \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

ログインページにアクセスし、UI が表示され、管理者ユーザーが認証できることを
確認してください。プログラムによるチェックを行う場合、アプリケーションが
正常であれば `/login/` エンドポイントは 200 を返します。

---

## ロールバック

Helm はリビジョンごとにリリース履歴を保持します。アップグレードによって動作が
悪化した場合は、直前のリビジョンにロールバックしてください。

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **データベースマイグレーションはロールバックされません。** Helm のロールバックは
> マニフェストの状態（イメージ、設定、シークレット）を復元しますが、
> `migrate --revert` は実行しません。アップグレードで適用されたスキーマの
> マイグレーションを取り消す必要がある場合は、
> [アップグレード前に](#before-you-upgrade)で取得したバックアップから復元するか、
> Helm リリースをロールバックする前に DefectDojo サポートと調整のうえ、手動で
> マイグレーションを取り消してください。

ArgoCD を使用している場合は、git 上で `targetRevision` の変更を取り消す
（または `argocd app rollback` を使用する）ことでロールバックし、同期を行います。

---

## トラブルシューティング

**チャートのプル時に `401 Unauthorized` が発生する。**
アクセストークンが失効しています。`gcloud auth print-access-token` を再取得した
うえで、`helm registry login` を再実行してください。

**`Error: UPGRADE FAILED: cannot patch ... field is immutable`。**
セレクターなど、変更不可なフィールドがずれています。このチャートは安定した
セレクターラベルを固定しているため、通常はこれは以前に Deployment を直接
編集したことが原因です。差分を記録し、問題のあるリソースを削除してから、
Helm がそれを再作成するようアップグレードを再実行してください。

**`Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`。**
Helm 4 はサーバーサイド適用を使用しており、フィールドの所有権を追跡します。この
エラーは、`kubectl edit`、`kubectl scale`、または HPA コントローラー
（`kube-controller-manager`）など、別のマネージャーが Helm によってレンダリングされる
フィールド（最も多いのは `.spec.replicas`）を変更したことを意味します。次の
コマンドで一度だけ所有権を取り戻してください。

```bash
helm upgrade ... --force-conflicts
```

この修正が適用されたチャートバージョンでは、HPA が有効な Deployment から
`replicas` が省略されるため、HPA によるスケーリングがアップグレードと競合しなく
なります。`kubectl` で Deployment を手動でスケールした場合は、チャートが所有権を
保持し続けられるよう、対応する `replicas`/`horizontalpodautoscaler` の値を調整する
ことをお勧めします。

**`Error: UPGRADE FAILED: timed out waiting for the condition`。**
Pod が `--timeout` の時間内に Ready 状態にならなかった場合です。遅延している
ワークロードを確認してください。

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

よくある原因: イメージのプル失敗（レジストリ認証）、スキーマのマイグレーションが
まだ実行中（`--timeout` を増やす）、FQDN の設定ミスによる readiness プローブの
失敗などです。

**バージョン間でプリセットが変更され、values ファイルが競合するようになった。**
`helm template` で再レンダリングし（[アップグレード前に](#before-you-upgrade)を
参照）、`helm upgrade` を実行する前に、上書き設定を新しいプリセットのデフォルト
値と突き合わせて調整してください。

**`values don't meet the specifications of the schema ... got string, want boolean`。**
上書き設定内の on/off の値が引用符で囲まれています。Helm は `"false"` を空でない
文字列として扱い、空でない文字列は truthy と評価されるため、オフにしたつもりの
機能が**オン**になってしまいます。スキーマは現在、この引用符付きの形式を素通り
させず拒否するようになっています。引用符を外してください。

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

エラーメッセージには問題のあるパスが示されます。引用符なしの `false`、`no`、
`off` はいずれも実際のブール値として解釈され、受け入れられます。
