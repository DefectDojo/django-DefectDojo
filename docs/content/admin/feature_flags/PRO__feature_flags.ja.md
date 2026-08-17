---
title: 機能フラグ
description: DefectDojo UIからDefectDojo Proのオプション機能のオン/オフを切り替える
weight: 1
audience: pro
---

機能フラグを使うと、自分のインスタンス上でDefectDojo Proのオプション機能のオン/オフを切り替えることができます。これまではDefectDojoサポートに連絡しなければ有効化できなかった機能を、UIからセルフサービスで有効化できるようになりました。

機能フラグページは**スーパーユーザー**のみに表示されます。グローバルオーナーを含む他のユーザーには表示されません。

## 機能フラグページを開く

左サイドバーの**Settings > Feature Flags**に移動します。

このページには、すべてのオプション機能が以下の情報とともに一覧表示されます。

* **Name**(名前) — 機能名。まだベータ版の場合は**BETA**タグが付きます
* **Description**(説明) — その機能が何をするか
* **Documentation link**(ドキュメントリンク) — その機能のドキュメントがある場所
* **Toggle**(トグル) — 現在オンになっているかどうか

検索ボックスを使うと、機能名や説明で一覧を絞り込めます。

### 一覧に表示されない機能

このページには、選択して導入できる機能が一覧表示されます。2種類の機能はここには表示されません。

**常時オン。** 機能が一般提供(GA)に達すると、すべてのインスタンスでオンになり、選択の余地がなくなるため一覧から外れます。

* **Downstream Connectors** — [Downstream Connectors](/connectors/downstream/about/)を参照
* **Universal Parser** — [Universal Parser](/import_data/pro/specialized_import/universal_parser/)を参照
* **Asset Hierarchy** — [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)を参照
* **Appearance**と**Feature Flags** — 同名の2つのSettingsページ

これらの機能をすでにオンにしていた場合、インスタンスに変化はありません。オフにしていた場合は、現在はオンになっています。これらの機能はオプトインではなく、DefectDojo Proの一部となったためです。インスタンスにとって問題がある場合は、[DefectDojo Support](mailto:support@defectdojo.com)にお問い合わせください。

**依頼に応じてDefectDojoが有効化。** 一部の機能はインスタンスごとにプロビジョニングされるインフラに依存するため、このページからではなくDefectDojoによって有効化されます。

* **Scheduling Service** — [Scheduling Rules](/automation/rules_engine/scheduling/)を参照

これらの機能を有効化するには[DefectDojo Support](mailto:support@defectdojo.com)にお問い合わせください。すでにインスタンスでオンになっている場合は、そのままオンの状態が維持されます。

## 機能のオン/オフを切り替える

1. 一覧から該当の機能を見つけます。
2. トグルをクリックします。
3. 変更は即座に反映されます。他のユーザーには、次回のページ読み込み時に変更が反映されます。

一部の機能では、変更が適用される前に確認ダイアログが表示されます。これは、警告が伴う機能(たとえば再起動が必要なものや、既存データに影響する可能性があるもの)や、一度オンにすると元に戻せない機能を有効化する場合に発生します。

機能をオフにする操作は、通常はオンにする操作の逆にすぎません。例外については[トグルがロックされている場合](#when-a-toggle-is-locked)で説明します。

### Organization / Asset Relabeling

**Organization / Asset Relabeling**は、「Product Type」を「Organization」に、「Product」を「Asset」にリネームします。デフォルトでオンになっており、他の機能と同様にこのページから切り替えられますが、DefectDojoのどの部分がこのトグルの対象になるかを知っておく価値があります。

* **Pro UI**はこのトグルに従います。新しいラベルは次回のページ読み込み時に表示されます。
* **Classic UI**のページ、そのURL、生成されるレポートの命名は、DefectDojoの起動時に読み込まれる`DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`デプロイ設定(こちらもデフォルトでオン)に従います。このトグルはそれらを変更せず、再起動してもそれらは変わりません。

保存されているトグルはそのデプロイ設定から初期値を引き継いでいるため、どちらか一方を変更するまでは両者は一致しています。ここでリネームをオフにし、Classic UIも使用している場合は、デプロイ側で`DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False`を設定し、再起動して両方の画面を一致させてください。[DefectDojo Pro (Cloud)](/get_started/pro/cloud/)では、デプロイ設定の変更について[DefectDojo Support](mailto:support@defectdojo.com)にお問い合わせください。

この機能に機能フラグページで**Restart Recommended**(再起動推奨)タグが付いているのはこのためです。Pro UI以外で使われる名称は、プロセスの起動時に確定します。いずれにせよリネームは見た目だけのものです。データベースモデル、フィールド名、APIエンドポイントは変更されないため、既存の自動化は引き続き動作します。[Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)を参照してください。

## When a toggle is locked

変更できない機能には、その理由を説明するロックバッジが表示されます。

| Badge | What it means | What to do |
| --- | --- | --- |
| **Managed by DefectDojo** | DefectDojoがこの機能をインスタンスに対して一元的に設定しています。ユーザー側の設定で上書きすることはできません。 | 変更が必要な場合は[DefectDojo Support](mailto:support@defectdojo.com)にお問い合わせください。 |
| **Unavailable on This Deployment** | この機能はお使いのインストール形態では提供されていません。詳細は下記の[Feature availability](#feature-availability)を参照してください。 | 対応不要です。この機能はインスタンスに適用されません。 |
| **Cannot Be Disabled** | この機能はすでにオンになっており、一方向のみの変更です。元に戻す手段はありません。 | 対応不要です。これは想定された動作です。 |
| **Managed by deployment** | この機能はこのページではなく、デプロイ設定によって制御されます。 | 下記の[DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise)を参照してください。 |

## DefectDojo Pro (Cloud)

[DefectDojo Pro (Cloud)](/get_started/pro/cloud/)では、**Settings > Feature Flags**だけで完結します。機能をオンに切り替えれば、その場で有効になります。

次の2つはユーザーではなくDefectDojoが対応します。

* **Managed by DefectDojo** — 機能が一元的に固定されています。変更するには[DefectDojo Support](mailto:support@defectdojo.com)にお問い合わせください。
* **Managed by deployment** — 機能はインスタンスのプロビジョニング方法の一部です。Cloudインスタンスではデプロイ設定が顧客に公開されないため、こちらについてもSupportにお問い合わせください。

Cloudインスタンスでは、オンプレミスでは提供されていない機能も利用できます。詳細は[Feature availability](#feature-availability)を参照してください。

## DefectDojo Pro (On-Premise)

[DefectDojo Pro (On-Premise)](/get_started/pro/onprem/)では、ほとんどの機能はCloudとまったく同じように動作します。**Settings > Feature Flags**を開いて切り替えるだけです。

ごく一部の機能は、代わりにデプロイ設定から読み込まれます。これらはアプリケーションの起動方法を変えるため、実行時に切り替えることはできません。ページ上では読み取り専用として表示され、**Managed by deployment**というラベルが付き、それを制御する環境変数の名前(たとえば[Locations](/asset_modelling/locations/pro__locations_overview/)の場合は`DD_V3_FEATURE_LOCATIONS`)が示されます。

これらの機能は再起動が必要であり、一部は一度有効にすると元に戻せないため、変更する前にその機能自体のドキュメントを確認してください。いくつかは[DefectDojo Support](mailto:support@defectdojo.com)の支援を受けて有効化するのが最善です。

これらの機能のいずれかを変更するには、

1. DefectDojoのデプロイで環境変数を設定します。設定すべき変数はページに表示されます。
2. DefectDojoを再起動し、新しい値が起動時に読み込まれるようにします。
3. 機能フラグページを再読み込みし、新しい状態を確認します。

これらの値は起動時に読み込まれるため、UI上で変更することはできず、再起動せずに環境で切り替えても効果はありません。

Cloudでのみ提供されている機能は、オンプレミスインスタンスでは**Unavailable on This Deployment**と表示されます。これは想定された動作であり、ライセンスの問題ではありません。

## Feature availability

ほとんどの機能はどちらのインストール形態でも利用できます。例外は以下のとおりです。

| Feature | Availability | How it is controlled |
| --- | --- | --- |
| Request a New Connector | [DefectDojo Pro (Cloud)](/get_started/pro/cloud/)のみ | 機能フラグページ。オンプレミスでは**Unavailable on This Deployment**と表示されます。 |
| Locations | 両方 | 機能フラグページ。Locationsは一度有効にすると元に戻せない点に注意してください。[Locations Overview](/asset_modelling/locations/pro__locations_overview/)を参照してください。 |
| Organization / Asset Relabeling | 両方 | Pro UIについては機能フラグページ。Classic UI、そのURL、生成されるレポートは`DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`デプロイ設定に従います。[上記](#organization--asset-relabeling)を参照してください。 |

その他のオプション機能はすべて、CloudとOn-Premiseの両インスタンスで機能フラグページから直接切り替えられます。

## UIの外から機能フラグを読み取る

どの機能が有効になっているかを確認するために機能フラグページを開く必要はありません。フラグの状態はプログラムからも読み取れるため、自動化がある機能に依存する前にその可用性を確認したい場合に便利です。

```
GET /api/v2/defectdojo_information/feature_flags/
```

これは機能フラグごとに1つのオブジェクトを持つJSON配列を返します。各オブジェクトには、フラグの`key`、`title`、`description`に加えて、自動化が通常必要とする値、すなわち`effective`(このインスタンスで実際にオンになっているか)、`default`、`application_value`(インスタンス独自の設定。未設定の場合は`null`)、`editable`、そしてフラグを変更できない場合の`locked_reason`が含まれます。製品から廃止されたフラグは含まれません。

**認証済み**であればどのユーザーでも読み取ることができ、スーパーユーザー権限は不要です。お使いのバージョンでの正確なレスポンススキーマについては、実行中のビルドから生成されるインスタンスのインタラクティブAPIドキュメント`/api/v2/oa3/swagger-ui/`を参照してください。[API v2 documentation](/automation/api/api-v2-docs/)も参照してください。

同じ読み取り専用の一覧は、インスタンスの`/api/mcp/`エンドポイント`/api/mcp/defectdojo_information/feature_flags/`でも公開されています。

このエンドポイントは**読み取り専用**です。機能のオン/オフの切り替えは、引き続き機能フラグページから、あるいは前述のデプロイ設定される機能についてはデプロイ設定から行います。

## よくある質問

**使いたい機能が一覧にありません。**
この一覧にはオプション機能のみが表示されます。常時オンの機能は表示されません。表示されるはずの機能が見当たらない場合は、ライセンスにその機能が含まれているかを確認したうえで、[DefectDojo Support](mailto:support@defectdojo.com)にお問い合わせください。

**機能をオンにしたのに表示されません。**
ページを再読み込みしてください。メニュー項目やルートはページの読み込み時に評価されるため、新しく有効化した機能は現在の画面に即座には反映されず、次回の読み込み時に表示されます。

**アップグレードすると設定は変わりますか。**
いいえ。アップグレードしても、オンにした機能とオフにした機能はそのまま保持されます。
