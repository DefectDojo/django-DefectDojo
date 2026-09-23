---
title: Global Component Deduplication
description: コンポーネント名とバージョンに基づき、すべての Product にわたって Software Composition Analysis の検出事項を重複排除します
weight: 5
audience: pro
---

Global Component Deduplication は、参照しているコンポーネント名とバージョンに基づいて**すべての Product** にわたる重複した検出事項を識別する DefectDojo Pro のアルゴリズムです。これは Software Composition Analysis(SCA)ツール向けで、同じ脆弱な依存関係(例えば `timespan@2.3.0`)が多数の Product に登場する場合に、DefectDojo にそれらの出現を単一の元の検出事項の重複として扱わせたいときに使用します。

他の重複排除アルゴリズムとは異なり、Global Component のマッチングは**単一の Product や Engagement に限定されません**。Product B にインポートされた検出事項が、たとえ 2 つの Product に関連がなくても、Product A にある古い検出事項の重複としてマークされることがあります。

> **Global Component と Global Locations の違い:** Global Component はコンポーネント名とバージョンのみでマッチングします。インスタンスが Locations データモデルを使用している場合、[Global Locations Deduplication](/triage_findings/finding_deduplication/pro__global_locations_deduplication/) がより精緻な後継です。これは依存関係を完全な Package URL でキー化し、さらに Product をまたいで URL/DAST の検出事項も重複排除します。どちらを選ぶべきかは、そのページの比較表を参照してください。

## Enabling the Global Component Algorithm(Global Component アルゴリズムの有効化)

Global Component Deduplication はフィーチャーフラグの背後にあり、**デフォルトでは無効**です。スーパーユーザーは、Cloud インスタンスと On-Premise インスタンスの両方で **Settings > Feature Flags** から有効にできます。[Feature Flags](/admin/feature_flags/pro__feature_flags/) を参照してください。

この機能が有効になると、Tuner の Same Tool および Cross Tool の重複排除設定の **Deduplication Algorithm** ドロップダウンで、**Global Component** がオプションとして利用できるようになります。

## Configuring Global Component Deduplication(Global Component Deduplication の設定)

Global Component は Same-Tool Deduplication、Cross-Tool Deduplication、またはその両方に適用でき、**Settings > Finding Workflow**(以前のメニュー構成を使用しているインスタンスでは **Settings > Pro Settings > Deduplication Settings**。[The Settings Menu](/navigation/pro__settings_menu/) を参照)からセキュリティツールごとに設定します。

### Same-Tool

単一の SCA ツールから得られる検出事項を複数の Product にわたって重複排除したい場合は、Global Component アルゴリズムを使った Same-Tool Deduplication を使用します。

1. **Same Tool Deduplication** タブを開きます。
2. **Security Tool** ドロップダウンから SCA ツールを選択します(例: `Dependency Track Finding Packaging Format (FPF) Export`)。
3. **Deduplication Algorithm** を **Global Component** に設定します。
4. フォームを送信します。

Hash Code Fields はこのアルゴリズムでは使用されず、選択すると非表示になります。

### Cross-Tool

異なる SCA ツールや Product にまたがって同じコンポーネントの検出事項を重複排除したい場合は、Global Component アルゴリズムを使った Cross-Tool Deduplication を使用します。

クロスツールでのマッチングには、参加させたい**それぞれの**ツールで Global Component が設定されている必要があります。

1. **Cross Tool Deduplication** タブを開きます。
2. 含めたいツールごとに: **Security Tool** ドロップダウンからそのツールを選択し、アルゴリズムを **Global Component** に設定して送信します。

## How Matching Works(マッチングの仕組み)

新しい検出事項は、次の場合に既存の検出事項の重複としてマークされます。

- コンポーネント名とコンポーネントバージョンが完全に一致し、**かつ**
- 同じコンポーネント名とバージョンを持つ古い検出事項が、DefectDojo インスタンス内のどこか(任意の Product や Engagement)に存在する場合。

コンポーネントバージョンのマッチングは完全一致です。`timespan@2.3.0` の検出事項は、`timespan@2.3.1` の検出事項とは重複排除され**ません**。

このアルゴリズムでは Engagement 単位の重複排除設定は無視され、マッチングは常にグローバルに行われます。

## Example(例)

`Dependency Track Finding Packaging Format (FPF) Export`(Same Tool)と Generic Findings Import ツール(Cross Tool)の両方で Global Component が有効になっているとします。

| ステップ | インポート | インポート先の Product | 結果 |
| --- | --- | --- | --- |
| 1 | `timespan@2.3.0` の Dependency Track スキャン | Application 0 | アクティブな検出事項が 1 件作成される |
| 2 | 同じ Dependency Track スキャン | Application 1 | 検出事項が 1 件作成され、Application 0 の検出事項の重複としてマークされる |
| 3 | `timespan@2.3.0` の Generic Findings Import | Application 2 | 検出事項が 1 件作成され、Application 0 の検出事項の重複としてマークされる(クロスツールでのマッチ) |
| 4 | `timespan@2.3.1` の Dependency Track スキャン | Application 3 | アクティブな検出事項が 1 件作成される ―― バージョンが異なるためマッチしない |

重複した各検出事項は、Finding ページの下部に、重複チェーン内の元の検出事項を表示します。

## Cross-Product Visibility(Product をまたいだ可視性)

Global Component のマッチングは Product の境界をまたぐため、重複チェーン内の元の検出事項が、重複を閲覧しているユーザーがアクセス権を持たない Product に存在する場合があります。

その場合、検出事項は表示され重複としてラベル付けされますが、ユーザーは元の検出事項を開いたり、そこに移動したりすることはできません。検出事項が Product レベルのアクセス制御に対して機微なツールで Global Component を有効にする前に、この点を考慮してください。

## Reverting(元に戻す)

特定のツールで Global Component の使用を止めるには、その Deduplication Settings を開き、アルゴリズムをスコープ付きのオプションのいずれかに戻します。

**Same Tool** Deduplication の場合:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

**Cross Tool** Deduplication の場合:

- Hash Code
- Disabled

アルゴリズムを変更すると、そのツールの既存の検出事項に対する重複排除ハッシュのバックグラウンドでの再計算がトリガーされます。
