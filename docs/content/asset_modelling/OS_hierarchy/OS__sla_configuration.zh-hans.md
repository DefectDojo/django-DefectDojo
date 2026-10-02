---
title: SLA 配置
description: 为不同产品配置服务级别协议
weight: 2
audience: opensource
aliases:
- /zh-hans/en/working_with_findings/sla_configuration
---

DefectDojo 中的每个产品都可以拥有自己的服务级别协议（SLA）配置，该配置表示您的组织修复或以其他方式管理某个发现项所拥有的天数。

SLA 可以基于**[发现项严重程度](/asset_modelling/os_hierarchy/product_hierarchy/#findings)**或**[发现项风险](/asset_modelling/pro_hierarchy/priority_sla/)**（在 DefectDojo Pro 中）来设置。

![image](images/sla_multiple.png)

SLA 会根据发现项在 DefectDojo 中创建的日期，为其应用天数倒计时。如果发现项未能在倒计时内关闭，该发现项将被标记为违反 SLA。

## 使用 SLA

您可以使用 SLA 来体现您组织的修复策略。您也可以使用它们来对 DefectDojo 实例中活动时间最长、最严重的发现项进行优先排序。

* 您可以按 SLA 天数对发现项表格进行排序或筛选。
* 可以将 SLA 违规配置为向分配到相关产品的 DefectDojo 用户触发[通知](/admin/notifications/about_notifications/)。
* 在 **DefectDojo Pro** 中，SLA 表现还会在[高管洞察与修复](/metrics_reports/pro_metrics/pro__overview/)指标仪表板中进行跟踪。
* 在 **DefectDojo Pro** 中，SLA 合规情况也可以在自定义[仪表板](/metrics_reports/dashboards/custom-dashboards/)中呈现——例如通过 SLA 燃尽图或经过筛选的计数小组件。

### “在 SLA 内已缓解”状态

如果发现项在 SLA 截止日期前成功缓解，该发现项会在“在 SLA 内已缓解”列中记录一个 ✅ 绿色对勾。

![image](images/sla_mitigated_within.png)

如果发现项已缓解，但是在 SLA 被违反之后才缓解的，该发现项会在“在 SLA 内已缓解”列中记录一个 ❌ 红叉。

### SLA 违规

当某个发现项的 SLA 被违反时（即发现项未能在 SLA 时限内关闭），✅ 绿色对勾会切换为 ❌ 红叉。系统会继续以负数跟踪该 SLA，以表示 SLA 已被违反了多少天。

![image](images/sla_breached.png)

## 管理 SLA 配置（Pro）

在 DefectDojo Pro 中，一个或多个 SLA 配置在侧边栏的**配置 > 服务级别协议**部分进行管理。您可以创建**新服务级别协议**，也可以在**所有服务级别协议**页面中处理现有的 SLA 配置。

![image](images/pro_sla_risk.png)

SLA 配置只能由超级用户，或拥有相应[配置权限](/admin/user_management/user_permission_chart/#configuration-permission-chart)的用户进行编辑。

### 配置 SLA

SLA 配置包含分配给 DefectDojo 中每个**严重程度**或**风险**值的天数。

![image](images/pro_new_sla.png)

每个服务级别协议都可以拥有一个唯一的名称，以及一个可选的描述。

**发现项重新激活时重启 SLA**：如果启用此选项，当某个发现项被重新打开时，其 SLA 将重新开始计算。否则，SLA 将以发现项的创建时间为准。

在编辑 SLA 时，您可以选择该 SLA 使用**严重程度**还是**风险**作为分配修复天数的基准。这是通过在表单的**服务级别配置类型**部分选择相应的选项来完成的。

在此处，您可以为每个**严重程度**或**风险**级别设置允许的天数。您还可以选择性地强制执行 SLA；取消勾选**强制执行 ___ 发现项天数**，即可忽略对该严重程度或风险级别的 SLA 计算。

## 为产品应用 SLA 配置（Pro）

DefectDojo 中新创建的产品始终会应用**默认 SLA 配置**，如果您愿意，可以将其设置为不同的值。

如果您已经有多个 SLA 配置，可以在**编辑产品**表单中选择将哪一个应用于您的产品。

![image](images/pro_sla_product.png)

### SLA 重新计算

为某个产品选择新的 SLA 后，DefectDojo 需要重新计算所有相关发现项的 SLA。此过程运行期间，无法更改该产品的 SLA。

## 关于 SLA 的说明

* 当[风险已接受](/triage_findings/findings_workflows/os__risk_acceptance/)的发现项重新激活时，SLA 可以选择性地重新开始。这是在创建风险接受时通过设置**过期后重启 SLA**字段来配置的。
* 重新导入某个发现项不会重启其 SLA - 除非启用了**发现项重新激活时重启 SLA**，否则 SLA 始终从该发现项首次被发现的时间开始计算。
* 风险接受到期或已关闭发现项的重新激活，是在不更改产品 SLA 配置的情况下，重置或重新计算某个发现项 SLA 的唯一方式（该发现项一旦创建）。
