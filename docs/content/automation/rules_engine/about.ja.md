---
title: Rules Engine 自動化
description: Rules Engineの自動化機能の使い方
weight: 1
audience: pro
aliases:
- /ja/en/customize_dojo/rules_engine
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Rules EngineはDefectDojo Pro限定機能です。</span>

DefectDojoのRules Engineを使用すると、Findingやその他のオブジェクトを処理するためのカスタムワークフローや一括アクションを構築できます。Rules Engineでは、オブジェクトがルールに一致したときにトリガーされる自動化アクションを構築できます。

Rules Engineは[Pro UI](/get_started/about/ui_pro_vs_os/)からのみアクセスできます。

**グラフエディタをお探しですか？** [Rules Engine 2.0](/automation/rules_engine_2/about/)は、自動化をビジュアルなノードグラフとして構築できるようにし、分岐、チケットやメッセージなどのアウトバウンドアクション、実行ごとのトレース、配信台帳を追加します。両エンジンは並行して稼働しており、既存のルールは[変換](/automation/rules_engine_2/converting_from_rules_engine/)することができます。

## Rules Engineの有効化

Rules Engineはベータ版であり、デフォルトでは無効になっています。スーパーユーザーは、CloudとOn-Premiseの両方のインスタンスで**Settings > Feature Flags**から有効にできます。[Feature Flags](/admin/feature_flags/pro__feature_flags/)を参照してください。

現在のところ、ルールを作成できるのはFindingに対してのみですが、今後はより多くのオブジェクトタイプがサポートされる予定です。

ルールは**All Rules**ページから手動でトリガーすることも、定期的なスケジュールで自動的に実行されるようスケジュールすることもできます。ルールがトリガーされると、設定されたフィルター条件に一致するすべての既存Findingに適用されます。

## 設定可能なルールアクション
各ルールは、正常にトリガーされた場合（つまり、設定されたフィルター条件に一致した場合）に、以下の変更を1つ以上Findingに適用できます。

### フィールドの変更
* Findingの**フィールドを設定**する。対象はTitle（タイトル）、Description（説明）、Severity（深刻度）、CVSSv3 Vector、Active（アクティブ）、Verified（検証済み）、Risk Accepted（リスク受容済み）、False Positive（誤検知）、Mitigated（緩和済み）を含みます
* FindingのTitle（タイトル）またはDescription（説明）に**テキストを追記・先頭挿入**する
* **Priorityを設定** — Findingの算出されたPriority値を上書きする（自動的な優先度計算を上書きします）
* **Riskを設定** — Findingの算出されたRiskレベルを上書きする（自動的なリスク計算を上書きします）
* FindingのPriority値に対して、指定した数値で**加算、減算、乗算、除算**を行う

### 割り当てと所有権
* Findingを**レビューするユーザーを設定**する
* Findingの**所有者としてグループを割り当て**る
* Findingに**Mitigation Policyを設定**する — 事前設定されたMitigation PolicyをそのFindingに割り当てます
* **Risk Acceptance（リスク受容）に追加** — Findingを既存のRisk Acceptanceレコードに追加する（risk_accepted=True、active=Falseを設定し、Jira連携とエンドポイントのステータスを処理します）

### タグ、メモ、アラート
* Findingに**タグを追加**する
* Findingに**メモを追加**する
* カスタムテキストを添えてDefectDojo内に**アラートを作成**する

### フィルター条件
ルールは、Findingが特定のフィルター条件を満たしたときに自動的にトリガーされます。ルールアクションの作成に使用できるフィルターについての詳細は、[Filter Index](/navigation/pro__filter_index)ページを参照してください。

## 新しいルールの作成
この手順はNew Ruleページから開始します。[Pro UI](/get_started/about/ui_pro_vs_os/)で**Manage Category**の下にある**Rules Engine**ドロップダウンを展開し、**+ New Rule**をクリックします。

![image](images/rules_engine_1.png)

### ステップ1: ルールにラベルを付ける
新しいルールの識別子となるLabelを入力し、Nextをクリックします。

![image](images/rules_engine_2.png)

### ステップ2: フィルターでトリガー条件を設定する
All Findingsテーブルが表示されます。このAll Findingsテーブルを使用して、ルールを適用したいFindingの集合を絞り込むフィルター条件を設定します。テーブルへのフィルターの適用方法についての詳細は、[Pro UIガイド](/get_started/about/ui_pro_vs_os/#navigational-changes)を参照してください。

このテーブルには、フィルターした既存Findingの一覧がプレビュー表示されます。

例えば、このスクリーンショットでは「Product One」に含まれるすべてのFindingを絞り込んでいます。このフィルターを適用する（Filtersメニューの外側をクリックする）と、適用対象のフィルター一覧に追加されます。

![image](images/rules_engine_3.png)

上のスクリーンショットでは、Product「Product One」に含まれるすべてのFindingに対してアクションが実行されます。

適用したいフィルターのセットが揃ったら、Nextボタンをクリックします。

### ステップ3: ルールアクションを設定する
**Action**ドロップダウンから、ステップ2のすべてのフィルターに一致するFindingに適用したいアクションを選択します。複数のアクションを適用できます。

特定の条件が満たされた場合に追加のアクションを実行できる、追加のConditional Values（条件付き値）を設定することもできます。

![image](images/rules_engine_4.png)


例えば、上のスクリーンショットでは4つのルールアクションが設定されています。

このうち2つのアクションは条件付きです。

フィルター条件に一致するすべてのFindingは、以下の非条件付きアクションをトリガーします。

* Findingはユーザーグループ「Group 1」に割り当てられます
* Findingには`all_group_1`というタグが付けられます

フィルター条件に加えて、これらの**追加**条件にも一致するFindingは、上記の2つの非条件付きアクションに加えて、以下の条件付きアクションもトリガーします。

* **FindingのSeverityがCritical（重大）の場合**、`critical_group_1`というタグが付けられます。
* **FindingのSeverityがHigh（高）の場合**、`high_group_1`というタグが付けられます。

### ステップ4 - ルールをプレビューする

Rule Previewには、このルールを実行した場合に変更されるすべてのFindingと、実行されるアクションのプレビューが表示されます。提案された変更内容に問題がなければ、Submitをクリックしてルールを保存します。

このルールが正しく適用されていないと思われる場合は、Backボタンを選択して、前のいずれかのステップに戻ることができます。

![image](images/rules_engine_5.png)

例えば、上のスクリーンショットには、このルールを実行した場合に影響を受けるFindingの一覧が表示されています。Finding一覧の右側の列から、これらの各Findingに新しいTagsとOwnersが適用されることが分かります。

ルールを作成することを確認するよう再度プロンプトが表示されます。**ルールはすぐには適用されず**、手動でトリガーする必要があることに注意してください。

## ルールの実行
All Rulesページから、実行したいルールを選択できます。ルールのタイトルをクリックすると、詳細を確認できます。

![image](images/rules_engine_6.png)

このページでは、**Metadata**の下に、このルールが最後にトリガーされた日時などの詳細情報を確認できます。また、**Rule Preview**の下で、このルールを新たに実行した場合に影響を受けるFindingのプレビューも確認できます。

ルールを実行するには、緑色のRun Ruleボタンをクリックします。ルールを実行することを確認すると、ルールがバックグラウンドで実行キューに入った旨のメッセージが表示されます。

ルールの実行が正常に完了すると、ルールの説明のRule MetadataセクションにあるItems Changedの数が更新されます。

## ルールメタデータのリファレンス
* **Rule For**: このルールが対象とするオブジェクト。
* **Rule Name**: ルールの名前。
* **Filters**: このルールに適用されているフィルターの数。
* **Actions**: このルールが実行するアクションの数。
* **Owner**: このルールを作成したユーザー。
* **Status**: このルールが最後に実行された際のステータスレポート。
    「E」=「Error」、「R」=「Running」、「S」=「Success」。
* **Last Run**: このルールが最後に実行された日時。
* **Items Changed:** 直近のルール実行で変更されたオブジェクトの数。
* **Items Skipped:** 直近のルール実行でスキップされたオブジェクトの数。フィルターされたオブジェクトが、適用されるルールアクションの「結果」に既に一致している場合（例えば、ルールアクションによって付与されるはずのタグを既に持っている場合）、そのオブジェクトは単にスキップされます。
