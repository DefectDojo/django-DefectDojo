---
title: Deduplication Tuning
description: DefectDojo が重複した検出事項を識別および管理する方法を設定します
weight: 4
audience: pro
aliases:
- /ja/en/working_with_findings/finding_deduplication/tune_deduplication
---

Deduplication Tuning は、検出事項の重複排除方法をきめ細かく制御できる DefectDojo Pro の機能で、特定のセキュリティテストワークフローに合わせて重複検出を最適化できます。

## Deduplication Settings

DefectDojo Pro では、次の場所から Deduplication Tuning にアクセスできます。
**Settings > Finding Workflow**(以前のメニュー構成を使用しているインスタンスでは **Settings > Pro Settings > Deduplication Settings**)

![image](images/deduplication_tuning.png)

Deduplication Settings ページには、次の 3 つの主要な設定領域があります。
- Same Tool Deduplication(同一ツールでの重複排除)
- Cross Tool Deduplication(クロスツールでの重複排除)
- Reimport Deduplication(再インポート時の重複排除)

## Same Tool Deduplication(同一ツールでの重複排除)

Same Tool Deduplication は、すべてのセキュリティツールパーサーでデフォルトで有効になっています。これにより、同じツールを使った連続スキャンから得られる検出事項が適切に重複排除されます。

Same Tool Deduplication を調整するには、次の手順に従います。

1. ドロップダウンから特定の **Security Tool** を選択します
2. 利用可能なオプションから **Deduplication Algorithm** を選択します

![image](images/same_tool_deduplication.png)

### 利用可能な重複排除アルゴリズム

DefectDojo Pro では、同一ツールでの重複排除に次の方法を利用できます。

#### Hash Code

選択したフィールドの組み合わせを使って一意のハッシュを生成します。これを選択すると、ハッシュの計算に使用されるフィールドを示す 3 つ目のドロップダウンが表示されます。

##### Content Fingerprint

**Content Fingerprint** は選択可能なハッシュフィールドで(3 つの設定領域すべてで利用可能)、静的解析の検出事項に対して*位置に依存しない*識別子を提供します。これはツールが検出事項に含める脆弱なコードスニペットから導出され、インデント、行番号の注釈、フォーマットの違いによって値が変わらないように正規化されています。同じ脆弱なコードに関する 2 つの検出事項は、コードが別の行やファイルに移動しても同一のハッシュになります。

Content Fingerprint は、**Bandit**、**Gosec**、**Brakeman**、**Checkmarx One** をはじめ、検出事項の説明にフェンス付きコードブロックまたは SARIF スニペットを含むあらゆるツールなど、検出事項の説明にコードスニペットを含むツールに対して計算されます。

> **Content Fingerprint をハッシュフィールドとして選択する前に**、`./manage.py backfill_fingerprints` を実行して既存の検出事項にフィンガープリントを補完してください。この機能が導入された後にインポートされた検出事項には自動的にフィンガープリントが付与されますが、既存の検出事項には付与されていません。バックフィルせずにこのフィールドを選択すると、既存の検出事項と新規の検出事項のハッシュが異なる値になり、バックフィルが実行されるまですべてのマッチが分断されます。

Content Fingerprint は、タイトルにファイルパスや行番号を埋め込むツール(コードが移動するたびに他の識別フィールドが変化してしまうツール)で **CWE** と組み合わせるとよく機能します。[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools) を参照してください。

#### Unique ID From Tool

セキュリティツール自体が検出事項に付与する内部識別子を利用し、スキャナーが信頼できる一意の ID を提供する場合に完全な重複排除を実現します。

このアルゴリズムは、SAST スキャナーを使用する場合や、開発が進むにつれて検出事項がソースコード内で「移動」するような状況で役立ちます。

#### Unique ID From Tool or Hash Code

まずツールの一意の ID を使用しようとし、一意の ID が利用できない場合は hash code にフォールバックします。これは最も柔軟な重複排除オプションです。

#### Global Component

単一の Product や Engagement 内ではなく、インスタンス内の**すべての Product** を対象に、コンポーネント名とバージョンで検出事項を照合します。同じ脆弱な依存関係が多数の Product に登場する SCA ツール向けです。このアルゴリズムはデフォルトでは無効になっており、有効にするには DefectDojo Support に依頼する必要があります。詳細は [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) を参照してください。

#### Global Vulnerability ID

単一の Product や Engagement 内ではなく、インスタンス内の**すべての Product** を対象に、**脆弱性 ID**(CVE、GHSA など)で検出事項を照合します。同じ CVE を多数の Product にわたって報告するツール向けです。デフォルトでは無効で、有効にするには DefectDojo Support が対応します。

> **同じインスタンス全体アルゴリズムを使う 2 つのツールは、互いに重複排除の候補になります。** *異なる* 2 つのツールが両方ともインスタンス全体を対象とするアルゴリズム(Global Component または Global Vulnerability ID)で設定されている場合、それらの検出事項は共通のグルーピングハッシュを共有するため、一方のツールの検出事項はその共有次元(コンポーネントまたは脆弱性 ID)においてもう一方との重複排除の対象として検討されます。これは意図されたクロスツールの挙動です。両方のツールをまとめて重複排除したい場合にのみ有効にしてください。

### セットベースの Hash Code フィールド(脆弱性 ID と CWE)

検出事項の属性のうち、脆弱性 ID(CVE、GHSA など)と CWE の 2 つは、単一の値ではなく値の*集合*を保持します。**Hash Code** アルゴリズム(Same Tool または Cross Tool)を使用する場合、次のフィールドを **Hash Code Fields** に追加することで、これらの集合をどのように比較するかを制御できます。

| フィールド | 次の場合に検出事項は重複と見なされます… |
|-------|-------------------------------|
| `vulnerability_ids` | 脆弱性 ID の集合が**完全に一致する** |
| `vulnerability_ids_partial` | 脆弱性 ID を**少なくとも 1 つ**共有している |
| `vulnerability_ids_subset` | 一方の検出事項の脆弱性 ID が、もう一方の**部分集合**である |
| `cwes` | CWE の集合が**完全に一致する** |
| `cwes_partial` | CWE を**少なくとも 1 つ**共有している |
| `cwes_subset` | 一方の検出事項の CWE が、もう一方の**部分集合**である |

`_partial` および `_subset` のフィールドは、ハッシュに組み込まれるのではなく、検出事項のペアごとに比較されます。残りの Hash Code Fields が候補となる検出事項をグループ化し、その後に集合の比較によってそのグループが絞り込まれます(完全一致である `vulnerability_ids` と `cwes` は、直接ハッシュに組み込まれます)。

**空の値。** 設定されたマッチャーに対して検出事項に脆弱性 ID(または CWE)がない場合:

- Hash Code Fields に通常のフィールド(例えば `title`)も含まれている場合、そのフィールドが識別を担い、そのペアでは集合マッチャーはスキップされ、検出事項はハッシュの残りの部分でマッチする可能性があります。
- 集合マッチャーが**唯一の**フィールドである場合、値を持たない検出事項は何ともマッチしません。他に識別する手段がないため、空の集合は他のすべてとマッチするとは見なされません。

**設定ルール**(設定を保存する際に強制されます):

- 脆弱性 ID フィールド(`vulnerability_ids`、`vulnerability_ids_partial`、または `vulnerability_ids_subset`)は単独で使用できます。CVE や GHSA は特定の脆弱性インスタンスを識別するためです。
- CWE フィールド(`cwes`、`cwes_partial`、`cwes_subset`)は、唯一の基準には**できません**。CWE は特定のインスタンスではなく脆弱性の*クラス*であるため、CWE のみでマッチさせると無関係な検出事項が統合されてしまいます。CWE マッチャーは `title` や `file_path` などの識別フィールドと組み合わせてください。

## Cross Tool Deduplication(クロスツールでの重複排除)

異なるセキュリティツール間の重複排除は、ツールごとに同じ脆弱性の報告の仕方が異なるため慎重な設定が必要であり、Cross Tool Deduplication はデフォルトで無効になっています。

![image](images/cross_tool_deduplication.png)

Cross Tool Deduplication を有効にするには:

1. ドロップダウンから **Security Tool** を選択します
2. **Deduplication Algorithm** を「Disabled」から「Hash Code」に変更します
3. **Hash Code Fields** ドロップダウンで、ハッシュ生成に使用するフィールドを選択します

異なるツールが互換性のある一意の識別子を共有することは稀であるため、Cross Tool Deduplication は多くのワークフローに適した Hash Code アルゴリズムをサポートしています。同じ依存関係を報告する SCA ツールについては、[Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) もクロスツールのオプションとして利用できます(デフォルトでは無効)。

なお、Cross Tool Deduplication も個々の Asset 単位に限定されることに注意してください。

## Reimport Deduplication(再インポート時の重複排除)

**⚠️ 再インポート処理では、検出事項が記録される前に完全に破棄されることがあります。設定を誤るとデータ損失につながる可能性があるため、Reimport Deduplication の設定は慎重に変更してください。**

Reimport Deduplication Settings は、Universal Parser または Generic Findings Import Parser 向けにアルゴリズムを設定するために使用できます。

デフォルトでは、他のツールについて Reimport Deduplication を調整することはできません。インスタンス内の他のツールで Reimport Deduplication アルゴリズムを調整したいユーザーは、[DefectDojo Support](mailto:support@defectdojo.com) にお問い合わせください。

![image](images/reimport_deduplication.png)

Reimport Deduplication を設定する際は:

1. **Security Tool**(Universal または Generic Parser)を選択します
2. 適切な **Deduplication Algorithm** を選択します

Reimport Deduplication で利用できるアルゴリズムのオプションは次のとおりです。
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

再インポートでは検出事項が記録される前に完全に破棄されることがあるため、Reimport Deduplication の設定は慎重に変更してください。

### Track Findings as Locations Change(位置情報の変化に応じた検出事項の追跡)

ツールの Reimport Deduplication アルゴリズムが **Hash Code** の場合、**Track findings as locations change** という追加のトグルが表示されます。これを有効にすると、再インポートの間に位置情報が変化した検出事項(行のずれやファイル名の変更、URL の移動、依存関係のバージョンアップなど)は、ツールが深刻度を再評価した場合でも*同一の*検出事項として扱われます。古い検出事項をクローズして同一の新しい検出事項を作成する代わりに、1 つの検出事項がそのまま維持され、その位置情報の履歴が保持されます。

このトグルはデフォルトで無効であり、Hash Code の再インポートアルゴリズムにのみ適用されます(信頼できる Unique ID From Tool を持つツールは、すでに安定した ID を通じて移動を追跡しています)。有効にすると、そのツールの既存の検出事項がバックグラウンドで自動的に再ハッシュされ、過去のデータが即座に対象に含まれます。

マッチングの仕組み、何が保持されるか、大規模インスタンスで有効にする際のガイダンスについては、[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) を参照してください。

## Running Deduplication Retroactively on Existing Data(既存データに対する重複排除の遡及適用)

Deduplication Tuning を初めて有効にする際によくある状況として、重複排除の設定を変更する*前*にインポートされた検出事項の未処理分が大量に存在していることが挙げられます。DefectDojo Pro では、この過去のデータを重複排除するために別途コマンドを実行する必要はありません。**ツールの Deduplication Settings を変更すると、そのテストタイプに関連するすべての既存の検出事項に対して、バックグラウンドでの再ハッシュが自動的にトリガーされます**。

これが実際に意味することは次のとおりです。

- ツールの **Deduplication Algorithm** や **Hash Code Fields** を変更すると、DefectDojo はそのツールに由来するインスタンス内のすべての検出事項のハッシュを再計算するバックグラウンドジョブをキューに登録します。
- このジョブは非同期に実行されます。大規模なインスタンス(数百万件の検出事項)では、完了までに時間がかかることがあり、Findings テーブルにすぐに変化が現れるわけではありません。
- 新たに計算されたハッシュは、未処理分全体にわたるその後の重複排除の判断に適用されます。

短時間に複数回設定を変更すると、それぞれの変更ごとに個別の再ハッシュジョブがキューに登録されます。特に変更の前後で検出事項の件数を比較する場合は、結果を評価する前に前のジョブが完了するのを待ってください。

> **セルフホスト版 Pro に関する注記:** このバックグラウンドジョブは Celery ワーカープールで実行されます。ワーカーが不足していたり処理が滞っていたりする場合、再ハッシュに想定より時間がかかることがあります。インスタンスの規模から見て妥当な時間内に結果が現れない場合は、ワーカーの状態を確認してください。

> **フィーチャーフラグは既存の設定を制限しません。** ツールに保存された Deduplication Settings は、設定されている限り有効であり続けます。関連するフィーチャーフラグを無効にしても、そのツールの重複排除がデフォルトに遡って戻される**ことはありません**。ツールの重複排除の挙動を変更または停止するには、Deduplication Settings を直接更新してください(この場合も、前述のバックグラウンドでの再ハッシュがキューに登録されます)。

## Deduplication Best Practices(重複排除のベストプラクティス)

Deduplication Tuning で最適な結果を得るために:

- **デフォルトから始める**: あらかじめ設定された重複排除の設定は、ほとんどのシナリオでうまく機能します
- **変更は慎重にテストする**: 重複排除の設定を調整した後は、いくつかのインポートを監視して正しく動作することを確認してください
- **遡及的な再ハッシュを見込んでおく**: 重複排除の設定を変更すると、そのツールに由来する既存のすべての検出事項がバックグラウンドで再ハッシュされます。上記の [Running Deduplication Retroactively on Existing Data](#running-deduplication-retroactively-on-existing-data) を参照してください
- **クロスツールの重複排除には Hash Code を使用する**: クロスツールの重複排除を有効にする場合は、異なるツール間で同じ検出事項を確実に識別できるフィールド(脆弱性名、位置情報、深刻度など)を選択してください。**重要** クロスツールの重複排除を有効にした各ツールでは、同じフィールドが選択されている**必要があります**
- **クロスツールのソースは同じ Asset にまとめる**: Cross-Tool Deduplication は Asset 単位のスコープです。異なる Asset に分かれた検出事項は、ハッシュフィールドが一致していても重複排除されません。上記の [Cross Tool Deduplication](#cross-tool-deduplication) を参照してください
- **過度に広範な重複排除は避ける**: ハッシュフィールドが少なすぎるクロスツールの重複排除は、誤った重複を生む可能性があります
- **Content Fingerprint を選択する前にバックフィルする**: 先に `./manage.py backfill_fingerprints` を実行してからフィールドを選択してください。そうすることで、トリガーされる再ハッシュにフィンガープリントが揃った状態になります。上記の [Content Fingerprint](#content-fingerprint) を参照してください
- **スキャン実行間で位置情報の追跡を有効にする**: このトグルによる自動的な再ハッシュはツールの未処理分全体を対象とします。大規模インスタンスでは、次に予定されている再インポートの前に完了させてください。[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades) を参照してください

重複排除の設定を特定のツールに合わせてチューニングすることで、重複によるノイズを大幅に減らすことができます。

## Locked Findings(ロックされた検出事項)

あるツールの Deduplication Settings が変更されるたびに、そのツールに関する重複排除ハッシュは DefectDojo インスタンス全体で再計算されます。
