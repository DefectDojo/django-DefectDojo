---
title: フィルターインデックス
description: DefectDojoのすべてのフィルターに関するリファレンス
weight: 5
aliases:
- /ja/en/working_with_findings/organizing_engagements_tests/filter_index
---

**注: 現在この記事では、DefectDojo Pro UIで利用可能な検出事項フィルターのみを扱っていますが、今後はOpen-Sourceのフィルターも含め、より多くのオブジェクトタイプを対象とするよう拡張される予定です。**

以下は、DefectDojo Pro UIで検出事項のリストを並べ替えるために適用できるフィルターの一覧です。DefectDojoのフィルターは、オブジェクトのリストをナビゲートしたり、カスタム[ダッシュボード](/metrics_reports/dashboards/custom-dashboards/)を構築したり、[ルールエンジン](/automation/rules_engine/about)による自動化を作成したりする際に役立ちます。

## 日付フィルターの評価方法

日付を指定するフィルター（**Date Created**、**SLA Expiration Date**、**Last Status Update**、**Planned Remediation Date**、および以下に挙げるJiraの日付フィルター）には、5つの演算子が用意されています。

| 演算子 | 一致条件 |
| --- | --- |
| **On** | 指定した日の全体。 |
| **Before** | 指定した日の開始時点までのすべて。指定した日自体は**含まれません**。 |
| **After** | 指定した日の開始時点以降のすべて — つまり指定した日は**含まれます**。 |
| **During** | 開始日から終了日まで、両方とも**含みます**。 |
| **Within** | 現在時点までの直近期間: 過去7日、14日、30日、90日、180日、または過去1年。 |

**Before**と**After**は意図的に対称になっていない点に注意してください。*Before 8 August*は8月8日を除外しますが、*After 8 August*は8月8日を含みます。

### 日付の境界とタイムゾーン

**On**、**Before**、**After**、**During**は、ブラウザから検出された**ご自身のタイムゾーン**を基準に日付の境界を解決します。したがって日付範囲は、UTCやサーバーのタイムゾーンではなく、*あなたが体験する*深夜0時から深夜0時までをカバーします。異なるタイムゾーンにいる2人のユーザーは、日付の境界付近にある検出事項について、同じフィルターでもわずかに異なる結果を目にすることがあります。

**Within**はこの影響を受けません。現在時点から遡って測定される直近期間であるため、解決すべき日付の境界がそもそも存在しないためです。

> **これが当てはまらないケース。** タイムゾーンが渡されるのはPro UIからのリクエストのみです。ブラウザを介さずに実行されるもの（`/api/v2` REST API、スケジュールレポート、ルールエンジン）は、サーバーに設定されたタイムゾーン（`DD_TIME_ZONE`。管理者が変更していなければ`UTC`）にフォールバックします。ブラウザのタイムゾーンがサーバーのものと異なる場合、同じ日付を使用していてもスケジュールレポートと画面上のフィルターでわずかに異なる行が返されることがあります。UI上のフィルター済みテーブルから開始したエクスポートはこの影響を受けません。表示していた内容と一致する、ご自身のタイムゾーンが使用されます。

## 数値フィルターの評価方法

**Age**や**SLA**を含む数値フィルターには、値とともに一致演算子（**Equals**、**Not Equals**、**Greater Than**、**Greater Than or Equal To**、**Less Than**、**Less Than or Equal To**、**In List**、**Not In List**）が用意されています。演算子を選択せずに値を入力すると、**Equals**として一致します。

## SLAフィルター

SLAに関するフィルターは3つあり、それぞれ異なる問いに答えます。

| フィルター | 種類 | 一致条件 |
| --- | --- | --- |
| **SLA Expiration Date** | 日付（上記の演算子を使用） | 検出事項のSLAが切れる日付。 |
| **SLA** | 数値（演算子を使用） | SLAクロックの**残り日数**。負の値は期限超過を意味するため、`Less Than 0`は現在期限を過ぎているものすべてを、`Less Than 7`は今週中に期限を迎えるものを見つけます。 |
| **Mitigated Within SLA** | True / False | **緩和済み**の検出事項が、SLAの期限切れ前に緩和されたかどうか。 |

**Mitigated Within SLAは、名前から想像されるより範囲が狭く、これに戸惑う人がよくいます。** どちらの値も、**すでに緩和済み**で、かつ**深刻度がInfoではない**検出事項にのみ一致します。

* **True** — SLAの期限日以前に緩和された。
* **False** — SLAの期限日より後に緩和された。

すでに期限を過ぎている**未対応（open）**の検出事項は、まだ緩和されていないため、どちらの値にも**一致しません**。それらを見つけるには、代わりに**SLA**の`Less Than 0`を使用してください。深刻度がInfoの検出事項は、どちらの側からも除外されます。

> 検出事項のSLA設定で**Cap SLA by CISA KEV Due Date**が有効になっている場合、**SLA**と**SLA Expiration Date**はどちらも、単純な深刻度ベースの期間ではなく、短縮されたKEV上限付きの期限を反映します。フィルター上ではこれを示す個別のインジケーターはありません。詳しくは[EPSS / KEV](/triage_findings/finding_scoring/epss_kev/)を参照してください。

## 検出事項
これらのフィールドはDefectDojoの検出事項に固有のもので、検出事項を整理するために使用されます。これらのフィルターはそれぞれ、All Findingsテーブルの個別の列に対応しています。

DefectDojoの検出事項は、以下によってフィルタリングできます。

### DefectDojoメタデータ
これらのフィルターは、DefectDojoのコア機能に直接関連しています。

##### 変更不可
これらのフィルターは、Issue作成時に割り当てられるもので、Edit Findingから直接変更することはできません。

* Finding Severity（情報、低、中、高、重大のいずれか）
* Product
* Product Type
* Engagement
* Engagement Version
* Test
* Test Type
* Test Version
* Date Created
* Age（検出事項の経過日数）
* SLA（SLAクロックの残り日数 — 負の値は期限超過を意味します。[SLAフィルター](#sla-filters)を参照）
* SLA Expiration Date（[SLAフィルター](#sla-filters)を参照）
* Mitigated Within SLA（True または False — これはすでに緩和済みの検出事項にのみ一致する点に注意してください。[SLAフィルター](#sla-filters)を参照）
* Reporter（検出事項を作成したユーザーまたはサービス）
* Found by（使用したツールを指します）

##### 変更可能
これらのフィールドはIssue作成時に設定されますが、Issueの進行に伴い変更できます。

* [Status](/triage_findings/findings_workflows/finding_status_definitions/)
* Last Status Update（タイムスタンプ）
* Mitigated（True または False）

##### その他のモデル機能
これらのDefectDojoの機能を使うと、検出事項をさらに整理したり、修復状況を追跡したりできます。

* Finding Tags
* Reviewers（割り当てられたユーザー）
* Has Notes（メモの有無：True/False）
* Group（存在する場合、[Finding Group](/triage_findings/findings_workflows/editing_findings/#finding-group-actions)を指します）
* Risk Acceptance（リストから既存のリスク受容を1つ以上選択）

### ツール固有のメタデータ
これらのフィールドはDefectDojoの機能に直接影響しませんが、Issueの説明や緩和に役立つ追加情報を提供します。検出事項の初回作成時（受信したレポートの情報を使用）に設定することも、ユーザーが後から変更することもできます。

* CWE Value
* Vulnerability ID（通常はCVE）
* EPSS Score
* EPSS Percentile
* Service
* Planned Remediation Date
* Planned Remediation Version
* Has Component（True/False）
* Component Name
* Component Version
* File Path
* Effort for Fixing

### Jiraメタデータ
Jira連携を使用している場合、これらのフィルターはリンクされたJira Issueの更新を追跡します。

* Jira Issue（検出事項に紐づいているかどうかでフィルタリング可能）
* Jira Age（Jira Issueの経過日数）
* Jira Change（Jiraに変更が最後にプッシュされた日時）
