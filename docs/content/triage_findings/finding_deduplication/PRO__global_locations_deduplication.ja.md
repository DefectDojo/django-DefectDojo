---
title: Global Locations Deduplication
description: 共有される位置情報(URL または依存関係)に基づき、すべての Product にわたって検出事項を重複排除します
weight: 6
audience: pro
---

Global Locations Deduplication は、**共有される場所**――URL、または(Package URL によって識別される)依存関係――のみに基づいて、**すべての Product** にわたる重複した検出事項を識別する DefectDojo Pro のアルゴリズムです。選択した種類の場所を共有する 2 つの検出事項は、タイトル、深刻度、CWE、脆弱性 ID にかかわらず重複として扱われます。場所そのものが識別子になります。

これは [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) の位置情報を意識した対応版であり、DefectDojo の Locations データモデルに適用されます。Global Component がコンポーネント名とバージョンのみでマッチングするのに対し、Global Locations は同じ依存関係を**完全な Package URL**でマッチングし、*さらに*共有される **URL** でもマッチングします。そのため、Global Component にはできない、Product をまたいだ DAST/Web の検出事項の重複排除が可能です。

スコープ付きのアルゴリズムとは異なり、Global Locations のマッチングは**単一の Product や Engagement に限定されません**。Product B にインポートされた検出事項が、たとえ 2 つの Product に関連がなくても、Product A にある古い検出事項の重複としてマークされることがあります。

## Requirements(要件)

Global Locations は DefectDojo の **Locations** データモデル上で定義されており、**Locations** 機能が有効な場合にのみ提供されます。Locations が無効になっているインスタンスでは、Global Locations のフィーチャーフラグはロックされた状態(「Requires Locations to be enabled」)で表示され、Tuner にこのアルゴリズムは表示されません。

## Enabling the Global Locations Algorithm(Global Locations アルゴリズムの有効化)

Global Locations Deduplication はフィーチャーフラグの背後にあり、**デフォルトでは無効**です。Locations が有効になっていれば、スーパーユーザーは Cloud インスタンスと On-Premise インスタンスの両方で **Settings > Feature Flags** から有効にできます。[Feature Flags](/admin/feature_flags/pro__feature_flags/) を参照してください。

この機能が有効になると、Tuner の Same Tool および Cross Tool の重複排除設定の **Deduplication Algorithm** ドロップダウンで、**Global Locations** がオプションとして利用できるようになります。

## Configuring Global Locations Deduplication(Global Locations Deduplication の設定)

Global Locations は Same-Tool Deduplication、Cross-Tool Deduplication、またはその両方に適用でき、**Settings > Finding Workflow**(以前のメニュー構成を使用しているインスタンスでは **Settings > Pro Settings > Deduplication Settings**。[The Settings Menu](/navigation/pro__settings_menu/) を参照)からセキュリティツールごとに設定します。

**Global Locations** を選択すると、Hash Code Fields セレクターは非表示になり(適用されないため)、代わりに **Location Types** セレクターが表示されます。

### Location Types(位置情報の種類)

マッチングに使用する位置情報の種類を選択します。

- **URLs** ―― 2 つの検出事項が URL を共有している場合にマッチします(設定されたエンドポイントフィールド `DEDUPE_ALGO_ENDPOINT_FIELDS` で比較されます)。
- **Dependencies** ―― 2 つの検出事項が、完全な Package URL の識別子で同じ依存関係を参照している場合にマッチします。

少なくとも 1 つの種類を選択する必要があり、デフォルトでは両方が選択されています。**URLs** のみを設定したツールは共有される依存関係を無視し、**Dependencies** のみを設定したツールは共有される URL を無視します。

### Same-Tool

単一のツールから得られる検出事項を複数の Product にわたって、共有される位置情報で重複排除したい場合は、Global Locations アルゴリズムを使った Same-Tool Deduplication を使用します。

1. **Same Tool Deduplication** タブを開きます。
2. **Security Tool** ドロップダウンからツールを選択します。
3. **Deduplication Algorithm** を **Global Locations** に設定します。
4. マッチングに使用する **Location Types** を選択します。
5. フォームを送信します。

### Cross-Tool

**異なる**ツールや Product にまたがって位置情報を共有する検出事項を重複排除したい場合は、Global Locations アルゴリズムを使った Cross-Tool Deduplication を使用します。

クロスツールでのマッチングは、インポート元のツールの位置情報タイプの選択を参照するため、参加させたい**それぞれの**ツールで、一致する Location Types とともに Global Locations を設定してください。

1. **Cross Tool Deduplication** タブを開きます。
2. 含めたいツールごとに: **Security Tool** ドロップダウンからそのツールを選択し、アルゴリズムを **Global Locations** に設定し、Location Types を選択して送信します。

## How Matching Works(マッチングの仕組み)

新しい検出事項は、インスタンス内のどこかにある既存の検出事項と、選択した種類の**具体的な場所を少なくとも 1 つ**共有している場合に、その重複としてマークされます。

- 設定されたエンドポイントフィールド(`DEDUPE_ALGO_ENDPOINT_FIELDS`)がすべて一致する **URL**、**または**
- 同じ Package URL を持つ**依存関係**(purl の完全一致であるため、`pkg:npm/timespan@2.3.0` は `pkg:npm/timespan@2.3.1` と**マッチしません**)。

このマッチングは**厳密であり、空同士では成立しません**。選択した種類の場所を持たない 2 つの検出事項は**決して**重複排除されません(スコープ付きの位置情報マッチングとは異なり、「両方とも空」はマッチとは見なされません)。エンドポイントフィールドの比較が無効になっている場合(`DEDUPE_ALGO_ENDPOINT_FIELDS = []`)、URL はまったくマッチを成立させることができず、共有される依存関係のみがマッチを成立させられます。

Same-Tool のマッチングは単一のツール(テストタイプ)内にとどまります。Cross-Tool のマッチングは意図的にツールをまたぎます。このアルゴリズムでは Engagement 単位の重複排除設定は無視され、マッチングは常にグローバルに行われます。また、`service` フィールドは他のグローバルアルゴリズムと同様に、引き続き重複排除を区分けします。

## Example(例)

DAST ツール(Same Tool)と、クロスツールの行のために 2 つ目の DAST ツールで、Global Locations(両方の位置情報の種類)が有効になっているとします。

| ステップ | インポート | インポート先の Product | 結果 |
| --- | --- | --- | --- |
| 1 | `https://shared.example.com/login` の DAST 検出事項 | Application 0 | アクティブな検出事項が 1 件作成される |
| 2 | 同じ URL、**異なる**脆弱性(タイトル + 深刻度) | Application 1 | 検出事項が 1 件作成され、Application 0 の検出事項の重複としてマークされる(場所のみでマッチ) |
| 3 | 2 つ目の DAST ツール、同じ URL | Application 2 | 検出事項が 1 件作成され、Application 0 の検出事項の重複としてマークされる(クロスツールでのマッチ) |
| 4 | `https://other.example.com/admin` の DAST 検出事項 | Application 3 | アクティブな検出事項が 1 件作成される ―― URL が異なり、共有される場所がない |
| 5 | URL も依存関係もない検出事項 | Application 4 | アクティブな検出事項が 1 件作成される ―― 共有できる場所がない |

重複した各検出事項は、Finding ページの下部に、重複チェーン内の元の検出事項を表示します。

## Global Component vs. Global Locations(Global Component と Global Locations の比較)

どちらもグローバル(Product 横断)なアルゴリズムであり、Engagement のスコープを無視し、ハッシュフィールドではなく単一の識別子でマッチングします。どちらを選ぶかは、ツールにとって何が重複を識別するかによって決めてください。

| | Global Component | Global Locations |
| --- | --- | --- |
| マッチング対象 | コンポーネントの**名前 + バージョン** | 共有される**場所**: URL および/または依存関係 |
| 依存関係の識別子 | 名前とバージョン | 完全な **Package URL**(type、namespace、name、version、qualifiers) |
| URL / DAST の検出事項 | マッチしない | マッチする(設定されたエンドポイントフィールドに基づく) |
| 設定可能性 | 不可 | 可能 ―― ツールごとに URLs、Dependencies、またはその両方を選択 |
| データモデル | Locations の有無にかかわらず動作 | **Locations**(Pro)が必要 |
| 向いている用途 | パッケージ名 + バージョンが識別子となる SCA ツール | Locations モデル配下の Web/DAST ツールおよび SCA で、URL または正確な依存関係が識別子となる場合 |

Locations データモデルを使用する新しいインスタンスでは、Global Locations が Global Component のより精緻な後継です。依存関係を正確な Package URL でキー化し、さらに URL ベースの検出事項も重複排除します。コンポーネント名 + バージョンを識別子としたいツールについては、Global Component が引き続き利用可能で、変更なく使用できます。

## Cross-Product Visibility(Product をまたいだ可視性)

Global Locations のマッチングは Product の境界をまたぐため、重複チェーン内の元の検出事項が、重複を閲覧しているユーザーがアクセス権を持たない Product に存在する場合があります。

その場合、検出事項は表示され重複としてラベル付けされますが、ユーザーは元の検出事項を開いたり、そこに移動したりすることはできません。検出事項が Product レベルのアクセス制御に対して機微なツールで Global Locations を有効にする前に、この点を考慮してください。

## Reverting(元に戻す)

特定のツールで Global Locations の使用を止めるには、その Deduplication Settings を開き、アルゴリズムをスコープ付きのオプションのいずれかに戻します。

**Same Tool** Deduplication の場合:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

**Cross Tool** Deduplication の場合:

- Hash Code
- Disabled

アルゴリズムを変更すると、そのツールの既存の検出事項に対する重複排除ハッシュのバックグラウンドでの再計算がトリガーされます。
