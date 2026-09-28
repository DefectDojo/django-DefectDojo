---
title: PriorityとRiskおよびSLAの割り当て
description: DefectDojoが検出事項をどのようにランク付けするか
weight: 1
audience: pro
aliases:
- /ja/en/working_with_findings/finding_priority
- /ja/en/working_with_findings/priority_adjustments
---

![image](images/pro_finding_priority.png)

効果的なリスクベースの脆弱性管理には、ビジネスコンテキストと技術的な悪用可能性の両方を考慮したアプローチが必要です。DefectDojo ProのPriorityおよびRisk機能を使用すると、ユーザーは検出事項を意味のあるコンテキストへ自動的に分類し、影響度の高い脆弱性を優先的に対応できるようになります。

**Priority**は、DefectDojoインスタンス内のすべての検出事項に適用される、算出された数値ランクです。特に多数の検出事項や製品のセキュリティニーズを統括する大規模な組織において、脆弱性をコンテキストの中で素早く把握できるようにします。

**Risk**は、検出事項の悪用可能性をより重視した4段階のランク付けシステムです。これはPriorityよりも粒度が低く、より「経営層向け」のバージョンとして位置付けられています。

![image](images/pro_risk_example.png)

PriorityとRiskの値は、他のフィルタと組み合わせて、あらゆるコンテキストで検出事項を比較するために使用できます。例えば以下のような単位です。

* 単一の製品、エンゲージメント、またはテスト内
* DefectDojoの全製品にわたるグローバルな比較
* 特定の少数の製品間での比較

検出事項のPriorityとRiskを適用することで、チームは組織内で最も重要な脆弱性に対応しやすくなり、また規制標準への準拠を支援するフレームワークにもなります。


PriorityとRiskについて詳しくは、DefectDojo, Inc.の2025年5月のOffice Hoursをご覧ください。
<iframe width="560" height="315" src="https://www.youtube.com/embed/4SN0BWWsVm4?si=VYUzEGNeijjhoD22" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


## PriorityとRiskの計算方法
Priorityの値の範囲は0から1150です。数値が高いほど、その検出事項のトリアージまたは修復の緊急度が高いことを意味します。

深刻度と同様に、Riskは低 -> 中 -> 要対応 -> 緊急の順にスコア化されます。**Risk**はPriorityのフィールドを考慮するため、結果としてツールが報告した深刻度とは異なる場合があります。

![image](images/priority-overview.png)

## Priorityフィールド:製品レベル

DefectDojoの各製品には、ビジネス上の重要度やリスク要因を追跡するメタデータがあります。このメタデータは、関連する検出事項のPriorityとRiskを計算する際に使用されます。

これらのメタデータフィールドはすべて、対象の製品の**製品を編集**フォームで設定できます。

![image](images/priority_edit_product.png)

* **Criticality(重要度)**には、なし、非常に低い、低い、中程度、高い、非常に高いのいずれかの値を設定できます。Criticalityは主観的なフィールドであるため、この値を設定する際は、組織内の他の製品と比較してどうかを考慮してください。
* **User Records(ユーザーレコード)**は、データベース(またはそのデータベースにアクセスできるシステム)内のユーザーレコード数を数値で見積もったものです。
* **Revenue(収益)**は、その製品の年間収益を数値で見積もったものです。Priorityを計算するために、DefectDojoはこの製品の収益を、同じ製品タイプ内のすべての製品の合計収益と比較してパーセンテージを算出します。

DefectDojoでは通貨タイプを設定できないため、Revenueの見積もりはすべて同じ通貨単位で統一してください。(「50000」は50,000米ドルを意味する場合もあれば、50,000円を意味する場合もあります。すべての製品の収益が同じ通貨で計算されている限り、単位が何であるかは問題になりません。)
* **External Audience(外部利用者)**はtrue/falseの値です。この製品が顧客、ユーザー、または組織外の誰かなど、外部の利用者からアクセスされる場合はTrueに設定してください。
* **Internet Accessible(インターネットからアクセス可能)**はtrue/falseの値です。この製品がオープンなインターネットに接続できる場合は、この値をTrueに設定してください。

Priorityは「相対的な」計算であり、DefectDojoインスタンス内の異なる製品同士を比較することを目的としています。これらのフィルタをどのように設定するかは、最終的に組織の判断に委ねられます。これらの値はできるだけ正確であることが望ましいですが、主な目的は重要な製品を浮かび上がらせ、組織のポリシーに沿って脆弱性に優先順位を付けられるようにすることなので、これらのフィールドを完璧に設定する必要は必ずしもありません。

## Priorityフィールド:検出事項レベル

製品内の検出事項には、その検出事項のPriorityおよびRiskレベルをさらに調整できる追加のメタデータを持たせることができます。

* 検出事項が**EPSSスコア**を持っているかどうか。これはPro利用者向けに検出事項へ自動的に追加され、常に最新の状態に保たれます。Priorityスコアに寄与するフィールドは**EPSSスコア**であり、**EPSSパーセンタイル**は参考として検出事項上に記録されますが、計算に直接反映されるわけではありません。
* その検出事項の影響を受けるエンドポイントが製品内にいくつあるか
* 検出事項がUnder Review(レビュー中)かどうか
* 検出事項がKEV(Known Exploited Vulnerabilities)データベースに含まれているかどうか。これはDefectDojoが定期的にチェックしています
* ツールが報告した検出事項の深刻度(情報、低、中、高、重大)

#### EPSSスコア対EPSSパーセンタイル

可視化される要素(深刻度、Business Criticality、Internet Accessible、Exploit Available)がすべて同じに見える2つの検出事項でも、**EPSSスコア**が異なれば、Priorityスコアが異なる結果になることがあります。これは想定された挙動です。EPSSスコアは計算のコンテキスト入力の1つだからです。

EPSSパーセンタイルは参考情報として検出事項に表示されますが、Priorityスコアの計算には使用されません。2つの検出事項を比較してPriorityスコアの差を理解したい場合は、パーセンタイルの値ではなく、EPSSスコアの値を確認してください。

EPSSスコア(および他の要因)がPriorityスコアの計算においてどれだけの比重を占めるかについての正確な数値は、意図的に公開されていません。環境内でEPSSスコアがスコアリングに与える影響の大きさを調整したい場合は、[Prioritization Engine](#prioritization-engines)内の**Exploitability**スライダーで調整してください。


## 検出事項のRisk計算

![image](images/risk_table.png)

検出事項テーブルのRisk列は、検出事項に素早く優先順位を付けるためのもう1つの方法です。Riskは検出事項のPriorityレベルを使用して計算されますが、検出事項の悪用可能性をより重視して算出されます。これはPriorityよりも粒度が低く、より「経営層向け」のバージョンとして位置付けられています。

割り当て可能な4つのRiskレベルは以下の通りです。

![image](images/pro_risk_levels.png)

Risk計算では、検出事項のEPSS/悪用可能性がはるかに強く重視されます。その結果、検出事項がPriorityは高いのにRiskは低いという状態になることもあります。

Risk計算そのものは、現時点では直接調整することはできません。ただし、[Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/)が有効になっている場合、**Actively-Exploited Risk Floor**によって、最も重要なケースの結果を制御できます。実際に悪用が確認された検出事項は、基本の深刻度がLowであることを理由に低いバンドに留め置かれるのではなく、選択したRiskバンド以上に引き上げられます。デフォルトでは**Needs Action(要対応)**に設定されており、各Prioritization Engineでこれを引き上げたり、引き下げたり、またはクリアしてこのフロアを無効にしたりすることができます。詳細は[Actively-Exploited Risk Floor](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor)を参照してください。

## Priority Insightsダッシュボード

ユーザーは、Priority Insightsダッシュボード(サイドバーのMetrics > Priority Insights)を使用して、環境内のPriorityとRiskを経営層向けの視点で把握できます。

![image](images/priority_dashboard.png)

このダッシュボードは、特定の製品や日付範囲でフィルタすることができます。他のProダッシュボードと同様に、このダッシュボードもDefectDojoからPDFとしてエクスポートし、レポートとしてすぐに作成することができます。

## 規制コンプライアンスのためのPriorityとRiskの設定

以下は、脆弱性の優先順位付け方法を特に要求している規制標準の一部(すべてを網羅したものではありません)です。

* [SOX(Sarbanes-Oxley Act)](https://www.sarbanes-oxley-act.com/)への準拠には、財務データに影響を与えるシステムについて収益ベースの優先順位付けが求められます。DefectDojoでは、システムの収益を製品レベルで入力できます。
* [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/)への準拠には、リスク評価とカード会員データ環境に対する重要度に基づく優先順位付けが求められます。Business CriticalityとExternal Audienceは製品レベルで設定でき、また検出事項レベルのDefectDojoのEPSS同期がPCIのリスクベースのアプローチをサポートします。
* [NIST SP 800-40](https://csrc.nist.gov/pubs/sp/800/40/r4/final)は予防保守のガイドであり、ビジネスへの影響、製品の重要度、インターネットからのアクセス可能性の要因に基づく脆弱性の優先順位付けを特に求めています。これらはすべてDefectDojoの製品レベルで設定できます。
* [ISO 27001/27002](https://www.iso.org/standard/27001)の管理策A.12.6.1への準拠には、リスク評価に基づくPriorityによる技術的脆弱性の管理が求められます。
* [GDPR第32条](https://gdpr-info.eu/art-32-gdpr/)はリスクベースのセキュリティ対策を求めています。製品レベルのユーザーレコードとExternal Audienceフラグは、個人データを処理する組織内のシステムに優先順位を付ける際に役立ちます。
* [FISMA/FedRAMP](https://help.fedramp.gov/hc/en-us)への準拠には、継続的な監視とリスクベースの脆弱性修復が求められます。

DefectDojo ProのPriorityおよびRiskの計算は調整可能であり、検出事項のPriorityとRiskに関する組織内の基準に合わせてDefectDojo Proをカスタマイズできます。

## Prioritization Engine

SLA構成と同様に、Prioritization Engineを使用すると、PriorityとRiskの計算方法を管理するルールを設定できます。

![image](images/priority_default.png)

DefectDojoにはすべての製品に適用される組み込みのPrioritization Engineが用意されています。ただし、このPrioritization Engineを編集して**Finding(検出事項)**と**Product(製品)**の乗数の重み付けを変更することで、検出事項のPriorityとRiskの割り当て方を調整できます。

### 検出事項の乗数

検出事項のPriorityスコアには8つのコンテキスト要因が影響します。このうち3つは検出事項固有のものであり、残りの5つは検出事項が属する製品に基づいて割り当てられます。

これらの要因が最終的な計算にどのように反映されるかを調整することで、Prioritization Engineをチューニングできます。

![image](images/priority_sliders.png)

ボタンをクリックして要因を選択し、スライダーを調整することで、特定の要因が適用される割合を制御できます。スライダーを調整すると、それに応じてRiskのしきい値が変化する様子を確認できます。

#### 検出事項レベルの乗数

* **Severity(深刻度)** - 検出事項の深刻度レベル
* **Exploitability(悪用可能性)** - 検出事項のKEVおよび/またはEPSSスコア
* **Endpoints(エンドポイント)** - 検出事項に関連付けられたエンドポイントの数

#### 製品レベルの乗数

* **Business Criticality(ビジネス重要度)** - 関連する製品のBusiness Criticality(なし、非常に低い、低い、中程度、高い、非常に高い)
* **User Records(ユーザーレコード)** - 関連する製品のUser Records数
* **Revenue(収益)** - 関連する製品の収益。製品タイプ全体の収益合計に対する相対値
* **External Audience(外部利用者)** - 関連する製品に外部利用者がいるかどうか
* **Internet Accessible(インターネットからアクセス可能)** - 関連する製品がインターネットからアクセス可能かどうか

### Riskのしきい値

Priority Engineのチューニング内容に基づき、DefectDojoはRiskのしきい値を自動的に推奨します。ただし、このしきい値も調整可能であり、適切と判断する任意の値に設定できます。

![image](images/risk_threshold.png)

## 新しいPrioritization Engineの作成

複数のPrioritization Engineを使用し、それぞれを異なる製品に割り当てることができます。

![image](images/priority_engine_new.png)

新しいPrioritization Engineを作成すると、Prioritization Engineフォームが開きます。このフォームを送信すると、新しいPrioritization Engineがテーブルに追加されます。

## 製品へのPrioritization Engineの割り当て

各製品には、対象の製品の**製品を編集**フォームから、現在使用中のPrioritization Engineを設定できます。

![image](images/priority_chooseengine.png)

製品のPrioritization Engineが変更された場合、またはPrioritization Engine自体が更新された場合、優先順位付けの計算が完了するまで、その製品のPrioritization EngineまたはPrioritization Engine自体が「ロック」される点に注意してください。

DefectDojoの各製品は、組織が検出事項を修復またはその他の方法で対応するために要する日数を表す、独自のService Level Agreement(SLA)構成を持つことができます。

SLAは、**[検出事項の深刻度](/asset_modelling/os_hierarchy/product_hierarchy/#findings)**または(DefectDojo Proでは)**[検出事項のRisk](/asset_modelling/pro_hierarchy/priority_sla/)**のいずれかに基づいて設定できます。

![image](images/sla_multiple.png)

SLAは、検出事項がDefectDojo上で作成された日を起点として日数のカウントダウンを検出事項に適用します。カウントダウン期間内に検出事項がClosed(クローズ)にならない場合、その検出事項はSLA違反としてラベル付けされます。

## SLAの活用

SLAは組織の修復ポリシーを表す手段として利用できます。また、DefectDojoインスタンス内で最も長くアクティブな状態にある、最も重大な検出事項に優先順位を付ける手段としても利用できます。

* 検出事項テーブルをSLAの日数でソートまたはフィルタできます。
* SLA違反が発生した際に、関連する製品に割り当てられたDefectDojoユーザーへ[通知](/admin/notifications/about_notifications/)をトリガーするよう設定できます。
* **DefectDojo Pro**では、SLAのパフォーマンスも[Executive InsightsおよびRemediation](/metrics_reports/pro_metrics/pro__overview/)のMetricsダッシュボードで追跡されます。
* **DefectDojo Pro**では、SLAコンプライアンスをカスタム[ダッシュボード](/metrics_reports/dashboards/custom-dashboards/)上に表示することもできます。例えば、SLA BurndownウィジェットやフィルタされたCountウィジェットなどです。

### Mitigated Within SLAステータス

検出事項がSLAの期限内に正常にMitigated(緩和済み)になった場合、その検出事項のMitigated Within SLA列に✅の緑のチェックマークが記録されます。

![image](images/sla_mitigated_within.png)

検出事項がMitigatedになったものの、それがSLA違反の前でなかった場合、その検出事項のMitigated Within SLA列に❌の赤いXが記録されます。

### SLA違反

特定の検出事項に対するSLAが違反された場合(SLAの期間内に検出事項がClosedにならなかった場合)、✅の緑のチェックが❌の赤いXに切り替わります。SLAはその後もマイナスの数値で追跡が続けられ、SLAが何日違反されているかを表します。

![image](images/sla_breached.png)

## SLA構成の管理(Pro)

DefectDojo Proでは、1つ以上のSLA構成がサイドバーの**Configuration > Service Level Agreements**部分で管理されます。**All Service Level Agreements**ページから、**New Service Level Agreement**を作成したり、既存のSLA構成を編集したりできます。

![image](images/pro_sla_risk.png)

SLA構成は、Superuser、またはそれに相当する[Configuration Permission](/admin/user_management/user_permission_chart/#configuration-permission-chart)を持つユーザーのみが編集できます。

### SLAの構成

SLA構成には、DefectDojoの各**Severity(深刻度)**または**Risk**値に割り当てられた日数が含まれます。

![image](images/pro_new_sla.png)

各Service Level Agreementには、一意の名前と、任意の説明を設定できます。

**Restart SLA on Finding Reactivation**:このオプションを有効にすると、検出事項がReopened(再オープン)された際にSLAが最初からやり直されます。無効の場合、SLAは検出事項が作成された時点を基準にします。

SLAを編集する際、Days To Remediate(修復までの日数)を割り当てる基準として、そのSLAが**Severity(深刻度)**と**Risk**のどちらを使用するかを選択できます。これはフォームの**Service Level configuration Type**セクションから該当のオプションを選択することで設定します。

ここから、**Severity**または**Risk**の各レベルに許容される日数を設定できます。また、**Enforce ___ Finding Days**のチェックを外すことで、特定の深刻度またはRiskレベルについてSLA計算を選択的に除外することもできます。

## 製品へのSLA構成の適用(Pro)

DefectDojoで新しく作成された製品には、常に**Default SLA Configuration(デフォルトSLA構成)**が適用されます。これは必要に応じて別の値に設定できます。

SLA構成が複数ある場合、**製品を編集**フォームから、どのSLA構成を製品に適用するかを選択できます。

![image](images/pro_sla_product.png)

### SLAの再計算

製品に新しいSLAが選択されると、関連するすべての検出事項のSLAはDefectDojoによって再計算される必要があります。この処理が実行されている間、その製品のSLAを変更することはできません。

## SLAに関する注意事項

* [Risk Accepted(リスク受容済み)](/triage_findings/findings_workflows/pro__risk_acceptance/)の検出事項が再アクティブ化された際、SLAを任意で再開させることができます。これはRisk Acceptanceを作成する際に**Restart SLA Expired**フィールドを設定することで指定します。
* 検出事項をReimport(再インポート)してもSLAは再開されません。**Restart SLA on Finding Reactivation**が有効になっていない限り、SLAは常に検出事項が最初に検出された時点から計算されます。
* Risk Acceptanceの期限切れ、またはClosedになった検出事項の再アクティブ化のみが、(製品のSLA構成を変更せずに)検出事項のSLAをリセットまたは再計算する方法です。
