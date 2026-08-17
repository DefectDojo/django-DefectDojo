---
title: アセット階層
description: DefectDojo Pro - 製品階層の刷新
audience: pro
weight: 1
aliases:
- /ja/en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
- /ja/asset_modelling/pro_hierarchy/assets_organizations
---

DefectDojo Proは、データモデルの柔軟性を高めるために、製品/製品タイプのオブジェクトクラスを拡張しています。

## Enabling the Hierarchy Feature

以下の2つの要素は別個のものであり、それぞれ異なる方法で制御されます。

### Asset Hierarchy

**アセット階層**は、アセット間の親子関係を可能にします。この階層は、ナビゲーションの**製品**タブから表示および管理できます。

アセット階層は一般提供されており、クラウド版・オンプレミス版を問わずすべてのインスタンスで有効になっています。特に有効化する操作は不要で、Feature Flagsページにも表示されなくなりました。

### Label Changes (optional)

**ラベル変更**は、UI全体で"Product Type"を"Organization"に、"Product"を"Asset"に名称変更します。これは階層機能の有効化とは別の手順であり、同時に行うことも、後から行うこともできます。

ラベル変更は、3.0以降デフォルトで有効になっています。アプリケーションの異なる部分をカバーする、2つの制御があります:

* **Pro UI**(デフォルトのUI): スーパーユーザーが、クラウド版・オンプレミス版の両方のインスタンスで**Settings > Feature Flags**の"Organization / Asset Relabeling"を切り替えます。新しいラベルは次回のページ読み込み時に表示されます。[Feature Flags](/admin/feature_flags/pro__feature_flags/)を参照してください。
* **クラシックUIのページと生成されるレポート**: これらのラベルとURLは、DefectDojoの起動時に読み込まれる`DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`デプロイメント設定によって決まります。オンプレミスの場合は、この設定を行いDefectDojoを再起動してください。[DefectDojo Pro (Cloud)](/get_started/pro/cloud/)の場合は、インスタンスのURLを添えて[support@defectdojo.com](mailto:support@defectdojo.com)までメールでお問い合わせください。

どちらもデフォルトで有効になっており、Feature Flagsの値はデプロイメント設定から初期値が設定されているため、どちらか一方を変更しない限り両者は一致します。Pro UIに加えてクラシックUIも使用している場合は、両者を同期させた状態に保ってください。

ラベル変更は見た目のみの変更である点に注意してください。APIエンドポイントとフィールド名は変更されないため、既存の自動化処理はそのまま動作し続けます。

## Significant Changes

* **製品タイプ**は"Organizations"に、**製品**は"Assets"に名称変更されました。3.0以降、この名称変更はデフォルトで有効です。これを無効にする方法については[Label Changes](#label-changes-optional)を参照してください。
* **アセット**は、Organizationのコンポーネントをさらに細かく分類するために、互いに親子関係を持てるようになりました。

### Organizations

製品タイプと同様に、**Organizations**はトップレベルのカテゴリーとして理解してください。これを使用して、自社のコアとなるソフトウェアアプリケーション、部門、または事業機能を分割できます。

例えば、複数のリポジトリのグループ化のためにOrganizationを作成できます。"Core Application"、"Infrastructure"、"DevOps"、"Analytics"、"SDK"はいずれも複数のコードリポジトリを含むことができます。

レポート作成の観点では、1つのOrganizationを複数の文書に分割するよりも、複数のOrganizationを1つの文書にまとめる方が容易であることに留意してください。そのため、チームのレポートに適した粒度で、できるだけ細かい単位でOrganizationを設定することを推奨します。例えば、ある事業部門内の個々の部署ごとにレポートを作成する予定であれば、その事業部門全体を1つのOrganizationとして表す必要はありません。

### Assets

AssetはOrganizationのサブディビジョンを表すためのものです。ただし、Productとは異なり、Assetは入れ子構造にでき、互いに親子関係を持つことができます。

## Asset Nesting Examples

### Asset-Level Branch Representation

開発ブランチやフィーチャーブランチは、さまざまな方法で表現できます。個別のエンゲージメントやテストを使う方法は、Production、Dev、その他のフィーチャーブランチの違いを表現する既存の手段です。

これらは、入れ子になったAssetを使って表現することもできます。次のAssetツリーを考えてみましょう:

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

この環境では、各ブランチ(`prod`、`dev`、`feature a`、`feature b`)は、他のAssetから分離された独自のエンゲージメントとテストを持つことができ、互いに重複排除されることがありません。また、Assetの名前をGit上のパスに直接対応させることができるため、ナビゲーションも容易になります。

### Mono-Repo: Separate Components

すべてのコードに単一のリポジトリを使用しているものの、そのリポジトリ内の各ディレクトリに異なるチームが貢献している場合、その構造を表現するためにAssetの入れ子構造を設定できます。

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

この図では、"Core Application"配下のすべての要素を、独自のビジネス重要度(参照: [Priority & Risk](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines))、RBAC、および対応するエンゲージメントとテストを持つ個別のAssetとして記録できます。親のAsset(例: `webapp-backend`)に対して引き続きテストを実施し、結果を保存することもできますが、特定の子Asset(例: `database`)に対して独立したテストを実行することもできます。

### Pen Tests: Isolated RBAC

単一のアセット内にペンテストの結果を保存したいものの、テスターにアセットのデータを閲覧させたくない場合は、各テストグループが結果をアップロードするための子アセットを作成できます。

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

重要な点として、ユーザーに単一の子Asset(例: `Pen Test Group A`)へのRBACアクセス権を付与しても、他の子Asset(例: `Pen Test Group B`)の検出事項を閲覧することはできず、親Asset(`webapp-frontend`)の検出事項を閲覧することもできません。

親Assetには、CI/CDの結果、内部テスト、履歴データ、その他の第三者に知られたくない検出事項データを表すエンゲージメントを含めることができます。特定のテスト結果用に子Assetを作成することで、社内チームは親Assetの状態と組み合わせてそれらの結果をレポートできます。

## Visualizing Assets - Hierarchy

DefectDojoでは、メニューのAsset Hierarchyオプションを使用して、Assetの構造を可視化したり、関係性を変更したりできます。

![image](images/asset_hierarchy.png)

Asset Hierarchyを開くと、フィルタリング可能なすべてのAssetのテーブルが表示されます。このテーブルから1つ以上のAssetを選択すると、階層図がレンダリングされます。

![image](images/asset_hierarchy_diagram.png)

### Diagram navigation

階層図の左上にあるアイコンで、ズームイン・ズームアウトができます。この図をクリックしてドラッグすると、図内をスクロールできます。

各Assetはこの図内で1つのノードとしてレンダリングされ、表示のために自由に移動させることができます。

Asset同士は、ノード間の関係の種類を表すラベル付きのパスで接続されます。現在サポートされているラベルは`parent`のみです。

### Exploring Asset nodes

各Assetノードは、青いボタンをクリックすることで操作できます。これらのボタンは、ノードをクリックしてAssetノードが選択されている場合にのみ表示されます。

![image](images/asset_hierarchy_node.png)

* 👁️ (eyeball icon) は、対応するAsset View(以前はProduct Viewと呼ばれていました)に直接移動します。
* ✏️ (pencil icon) は、Edit Assetフォーム(以前はEdit Productフォームと呼ばれていました)を含むモーダルを開きます。
* ➕ (plus icon) は、このAssetに新しい子Assetを追加できるようにします。追加先のAssetは現在図に表示されている必要はありませんが、同じOrganizationに属している必要があります。
* ✥ (four-arrows icon) は、現在選択されているAssetの親Assetを変更できるようにします。
* 🗑️ (trash can icon) は、Assetの親関係を削除できるようにします。このアイコンは、Assetにすでに親が設定されている場合にのみ表示されます。

図に、未選択の親Assetを持つAssetが表示されている場合は、Load Moreボタンをクリックすることで、その親Asset(および親Assetの子)を図に追加できます。

![image](images/assets_loadmore.png)

## Notes

* 重複排除の範囲は変更されていない点に注意してください。Assetは自身の内部でのみ検出事項を重複排除し、Parent/Child関係の有無にかかわらず、他のAssetの検出事項は考慮しません。
* RBACの範囲はこのシステムにおいて変更されていません。権限の割り当てにおいて、各Assetは引き続き個別のオブジェクトとして扱われます。新しいRBACの継承は作成されていません。
  * ユーザーにOrganization全体へのアクセス権を付与すると、そのOrganizationに含まれるすべてのAssetへのアクセス権も引き続き付与されます(製品タイプの場合と同様です)。
  * ユーザーに単一のAssetへのアクセス権を付与しても、関連する親または子のAssetへのアクセス権や、Organizationへのアクセス権は付与されません。
* 作成できるParent/Child関係の数に制限はありません。理論上は、リポジトリのディレクトリ構造全体を、望むのであれば個別のAssetとして表現することも可能です。
* 循環関係は許可されていません。親Assetは、自身の子Assetの子になることはできません。
