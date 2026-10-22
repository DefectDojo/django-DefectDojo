---
title: SLA設定
description: 製品ごとにサービスレベルアグリーメントを設定する
weight: 2
audience: opensource
aliases:
- /ja/en/working_with_findings/sla_configuration
---

DefectDojoの各製品には、独自のサービスレベルアグリーメント(SLA)設定を持たせることができます。これは、検出事項を修復またはその他の方法で管理するために組織に与えられた日数を表します。

SLAは、**[検出事項の深刻度](/asset_modelling/os_hierarchy/product_hierarchy/#findings)**、または(DefectDojo Proの場合)**[検出事項のリスク](/asset_modelling/pro_hierarchy/priority_sla/)**のいずれかに基づいて設定できます。

![image](images/sla_multiple.png)

SLAは、DefectDojo内で検出事項が作成された日を基準として、検出事項に日数のカウントダウンを適用します。カウントダウン期間内に検出事項がクローズされない場合、その検出事項はSLA違反としてラベル付けされます。

## SLAの操作

SLAは、組織の修復ポリシーを表現する手段として使用できます。また、DefectDojoインスタンス内で最も長くアクティブな状態にある、最も重大な検出事項を優先順位付けする手段としても使用できます。

* 検出事項テーブルをSLA日数でソートまたはフィルタリングできます。
* SLA違反が発生した際に、関連する製品に割り当てられたDefectDojoユーザーへ[通知](/admin/notifications/about_notifications/)をトリガーするよう設定できます。
* **DefectDojo Pro**では、SLAのパフォーマンスは[Executive InsightsおよびRemediation](/metrics_reports/pro_metrics/pro__overview/)メトリクスダッシュボードでも追跡されます。
* **DefectDojo Pro**では、SLAの遵守状況をカスタム[ダッシュボード](/metrics_reports/dashboards/custom-dashboards/)上に表示することもできます。例えば、SLA BurndownウィジェットやフィルタリングされたCountウィジェットを使用します。

### Mitigated Within SLAステータス

検出事項がSLAの期限までに正常に緩和された場合、その検出事項にはMitigated Within SLA列に✅の緑色のチェックマークが記録されます。

![image](images/sla_mitigated_within.png)

検出事項が緩和されたものの、SLA違反となった後だった場合、その検出事項にはMitigated Within SLA列に❌の赤色のXが記録されます。

### SLA違反

ある検出事項のSLAが違反された場合(SLAの期限内に検出事項がクローズされなかった場合)、✅の緑色のチェックは❌の赤色のXに切り替わります。SLAは引き続き負の数値で追跡され、SLAが何日超過しているかを示します。

![image](images/sla_breached.png)

## SLA設定の管理(Pro)

DefectDojo Proでは、1つ以上のSLA設定がサイドバーの**Configuration > Service Level Agreements**部分で管理されます。**New Service Level Agreement**を作成することも、**All Service Level Agreements**ページから既存のSLA設定を操作することもできます。

![image](images/pro_sla_risk.png)

SLA設定は、スーパーユーザー、または対応する[Configuration Permission](/admin/user_management/user_permission_chart/#configuration-permission-chart)を持つユーザーのみが編集できます。

### SLAの設定

SLA設定には、DefectDojoの各**深刻度**または**リスク**の値に割り当てられた日数が含まれます。

![image](images/pro_new_sla.png)

各サービスレベルアグリーメントには、一意の名前と、任意の説明を設定できます。

**Restart SLA on Finding Reactivation**: このオプションを有効にすると、検出事項が再オープンされた際にSLAが最初からやり直されます。無効の場合、SLAは検出事項が作成された時点を基準とします。

SLAを編集する際、そのSLAが修復までの日数を割り当てる基準として**深刻度**と**リスク**のどちらを使用するかを選択できます。これは、フォームの**Service Level configuration Type**セクションから該当するオプションを選択することで行います。

ここから、各**深刻度**または**リスク**レベルに許容される日数を設定できます。また、SLAを選択的に適用することもできます。**Enforce ___ Finding Days**のチェックを外すことで、該当する深刻度またはリスクのレベルについてSLA計算を無視できます。

## 製品へのSLA設定の適用(Pro)

DefectDojoで新規作成された製品には、常に**Default SLA Configuration**が適用されますが、必要に応じて異なる値に設定することもできます。

SLA設定がある場合、**Edit Product**フォームから、どの設定を製品に適用するかを選択できます。

![image](images/pro_sla_product.png)

### SLAの再計算

製品に新しいSLAが選択されると、関連するすべての検出事項のSLAをDefectDojoが再計算する必要があります。この処理が実行されている間は、製品のSLAを変更することはできません。

## SLAに関する補足事項

* [リスク受容済み](/triage_findings/findings_workflows/os__risk_acceptance/)の検出事項が再度アクティブ化した場合、SLAを再開するかどうかを任意で設定できます。これは、リスク受容を作成する際に**Restart SLA Expired**フィールドを設定することで行います。
* 検出事項を再インポートしてもSLAは再開されません。**Restart SLA on Finding Reactivation**が有効になっていない限り、SLAは検出事項が最初に検出された時点から常に計算されます。
* 検出事項が作成された後にSLAをリセットまたは再計算する方法は、リスク受容の期限切れ、またはクローズされた検出事項の再アクティブ化のみです(製品のSLA設定を変更しない場合)。
