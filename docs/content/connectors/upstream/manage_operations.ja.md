---
title: オペレーションの管理
description: コネクタの Discover & Sync オペレーションのステータスを確認する
aliases:
- /ja/import_data/pro/connectors/manage_operations/
- /ja/en/connecting_your_tools/connectors/manage_operations
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: アップストリームコネクタは DefectDojo Pro 限定の機能です。</span>

アップストリームコネクタがセットアップされると、次の 2 つのオペレーションを定期的に実行します:

* **Discover** は接続されたツールの構造を学習し、マッピングされていないデータについて DefectDojo に record を作成します。
* **Sync** はマッピングに基づいて、ツールから新しい検出事項をインポートします。

これら両方のオペレーションは、コネクタの Operations ページで管理されます。テーブルにはこれらのオペレーションの過去の実行履歴も記録されるため、コネクタが最新の状態であることを確認できます。

コネクタの Operations ページにアクセスするには、作業したいコネクタの **Manage Records & Operations** を開き、**</\> Operations From (tool)** タブに切り替えます。

![image](images/operations_discover.png)

**Manage Records & Operations** ページは、接続したツールの個々の製品マッピングである Record を扱うためにも使用できます。詳細は [Records の管理](../manage_records) を参照してください。

## Operations ページ

![image](images/operations_page.png)

Operations ページのテーブルにある各エントリは、オペレーションイベントの記録であり、以下の特性を持ちます:

* **Type** は、そのイベントが **Sync** オペレーションか **Discover** オペレーションかを示します。
* **Status** は、そのイベントが正常に実行されたかどうかを示します。
* **Trigger** は、そのイベントがどのようにトリガーされたかを示します \- 自動的に実行された **Scheduled** オペレーションだったのか、DefectDojo ユーザーによってトリガーされた **Manual** オペレーションだったのか。
* 各オペレーションの **Start \& End Time** も、**Duration** とあわせてここに記録されます。

## Discover オペレーション

DefectDojo のコネクタが最初に行う必要があるのは、ツールの環境を **Discover** して、スキャンデータをどのように整理しているかを把握することです。

例えば、5 つの異なるリポジトリの脆弱性をスキャンするように設定された BurpSuite ツールがあるとします。コネクタはこの組織構造を把握し、それらの個別のリポジトリを DefectDojo の Product/Engagement/Test 階層に変換するのに役立つ **Records** をセットアップします。

### 新しい Record の作成

コネクタが **Discover** オペレーションを実行するたびに、新しい **Vendor-Equivalent-Products (VEP)** を探します。DefectDojo は Vendor ツールがどのようにセットアップされているかを確認し、ツールの構成に基づいて VEP の **Records** を作成します。

![image](images/operations_discover_2.png)

### Discover を手動で実行する

**Discover** オペレーションは定期的に自動実行されますが、手動で実行することもできます。このコネクタを初めてセットアップする場合は、**Unmapped Records** 見出しの横にある **Discover** ボタンをクリックできます。ページを更新すると、最初の **Records** の一覧が表示されます。

![image](images/operations_discover_3.png)

record の操作や製品へのマッピングの設定について詳しくは、[Records の管理](../manage_records) のガイドを参照してください。

## Sync オペレーション

DefectDojo は毎日、各 **Mapped Record** で新しいスキャンデータがないか確認します。その後、DefectDojo は **Reimport** を実行し、既存のスキャンデータの状態を受信したレポートと比較します。

### 脆弱性データはどこに保存されるか

* DefectDojo は、**Record Mapping** で指定した製品の下にネストされた **エンゲージメント** を作成します。このエンゲージメントは **Global Connectors** という名前になります。
* **Global Connectors** エンゲージメントは、その製品に関連付けられた個々のコネクタをそれぞれ **テスト** として追跡します。
* この sync および以降の各 sync で、**テスト** はツールによって検出された各脆弱性を **検出事項** として保存します。

### Sync が新しい脆弱性データをどのように扱うか

Sync が実行されるたびに、最新のスキャンデータを既存の検出事項の一覧と比較して変更を確認します。

* 新しい検出事項が検出された場合、新しい検出事項としてテストに追加されます。
* 最新のスキャンで検出されなかった検出事項がある場合、テスト内で非アクティブ (Inactive) としてマークされます。

製品、エンゲージメント、テスト、検出事項について詳しくは、[製品階層の概要](/asset_modelling/os_hierarchy/product_hierarchy/) を参照してください。

### Sync を手動で実行する

スケジュール外で DefectDojo に Sync オペレーションを実行させるには:

1. 使用したいコネクタの **Manage Records \& Operations** ページに移動します。**Upstream Connectors** ページから、作業したいコネクタの **Manage Configuration** ドロップダウンメニューをクリックし、**Manage Records \& Operations** を選択します。
​
2. このページから **Sync** ボタンをクリックします。このボタンは **Mapped Records** 見出しの横にあります。

![image](images/operations_sync.png)
