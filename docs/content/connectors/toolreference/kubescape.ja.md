---
title: "Kubescape"
description: "DefectDojo で Kubescape の Upstream Connector をセットアップする方法"
weight: 85
audience: pro
---
Kubescapeコネクタは、[Kubescapeオペレーター](https://kubescape.io/docs/install-operator/)によって生成されたKubernetesのposture(構成不備)結果を、クラスタのKubernetes APIから直接読み取ります — ARMO SaaSアカウントは不要です。オペレーターのクラスタ内ストレージ集約APIが提供する`WorkloadConfigurationScan`オブジェクト(`spdx.softwarecomposition.kubescape.io/v1beta1`)を読み取ります。posture結果を持つ各Kubernetesの**namespace**はRecord(Product)にマッピングされ、ワークロード上の失敗したcontrolはそれぞれFindingになります。

#### Prerequisites

- 対象クラスタでKubescapeオペレーターがインストールされ、構成スキャンが有効になっている必要があります([クラスタへのインストール](https://kubescape.io/docs/install-operator/)を参照)。`kubectl get workloadconfigurationscans -A`で結果が存在することを確認してください。
- 対象クラスタの`spdx.softwarecomposition.kubescape.io` APIグループ(`workloadconfigurationscans`に対するlist/get)への読み取りアクセスを許可する**kubeconfig**。

#### Connector Mappings

1. **Location**フィールドにクラスタのAPIサーバーURL(またはわかりやすいクラスタ識別子)を入力します。
2. `kubeconfig`フィールドに対象クラスタの**kubeconfig**を貼り付けます。必要に応じて`kube_context`でその中のコンテキストを選択し、`cluster_name`で検出されるProductにラベルを付けられます。
3. posture結果を持つ各namespaceがRecordとして検出されます。DefectDojoのProductにマッピングしたいものを選択してください。

検出事項は失敗したcontrolごとに導出されます。control名とワークロードがFindingを識別し、深刻度はcontrolのスコア係数から取得され、control IDが脆弱性IDになり、各Findingは`https://hub.armosec.io/docs/`のcontrolリファレンスにリンクします。
