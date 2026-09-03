---
title: 筛选器索引
description: DefectDojo 中所有筛选器的参考
weight: 5
aliases:
- /zh-hans/en/working_with_findings/organizing_engagements_tests/filter_index
---

**注意:目前本文仅涵盖 DefectDojo Pro UI 中可用的发现项筛选器,未来本文将扩展到涵盖更多对象类型,以及开源版筛选器。**

以下是可在 DefectDojo Pro UI 中应用于排序发现项列表的筛选器列表。DefectDojo 筛选器可帮助您浏览对象列表、构建自定义[仪表板](/metrics_reports/dashboards/custom-dashboards/),或通过[规则引擎](/automation/rules_engine/about)创建自动化。

## 日期筛选器的评估方式

接受日期的筛选器——**Date Created**、**SLA Expiration Date**、**Last Status Update**、**Planned Remediation Date**,以及下文列出的 Jira 日期筛选器——提供五种运算符:

| Operator | Matches |
| --- | --- |
| **On** | 指定日期的全天。 |
| **Before** | 指定日期开始之前的所有内容。**不**包含指定日期本身。 |
| **After** | 指定日期开始之后的所有内容——因此**包含**指定日期本身。 |
| **During** | 从起始日到结束日,两端均**含**。 |
| **Within** | 以当前时刻为终点的滚动时间窗口:过去 7、14、30、90 或 180 天,或过去一年。 |

请注意,**Before** 和 **After** 刻意并非彼此的镜像:*Before 8 August*(8 月 8 日之前)不包含 8 月 8 日,而 *After 8 August*(8 月 8 日之后)则包含 8 月 8 日。

### 日期边界与您的时区

**On**、**Before**、**After** 和 **During** 会根据从您的浏览器检测到的**您自己的时区**来确定日期边界。因此,日期范围涵盖的是*您*所体验到的从午夜到午夜,而不是 UTC 时间或服务器时区的午夜到午夜。对于恰好落在日期边界附近的发现项,处于不同时区的两个人使用同一个筛选器可能会看到略有不同的结果。

**Within** 不受影响——它是从当前时刻向前推算的滚动时间窗口,因此不涉及需要确定的日期边界。

> **不适用的情形。** 只有来自 Pro UI 的请求会携带您的时区信息。任何在没有浏览器的情况下运行的操作——`/api/v2` REST API、计划报告以及规则引擎——都会回退到服务器配置的时区(`DD_TIME_ZONE`,除非您的管理员更改过,否则为 `UTC`)。如果您的浏览器时区与服务器时区不同,使用相同日期的计划报告和界面筛选器可能会返回略有不同的行。从 UI 中已筛选的表格发起的导出不受此影响——它们使用您的时区,与您当时看到的内容一致。

## 数字筛选器的评估方式

数字筛选器——包括 **Age** 和 **SLA**——在提供数值的同时还提供匹配运算符:**Equals**、**Not Equals**、**Greater Than**、**Greater Than or Equal To**、**Less Than**、**Less Than or Equal To**、**In List** 和 **Not In List**。如果输入数值而不选择运算符,则默认按 **Equals** 匹配。

## SLA 筛选器

共有三个筛选器涉及 SLA,它们分别回答不同的问题:

| Filter | Type | What it matches |
| --- | --- | --- |
| **SLA Expiration Date** | 日期,使用上述运算符 | 发现项 SLA 到期的日期。 |
| **SLA** | 数字,带运算符 | SLA 计时器上**剩余的天数**。负值表示已逾期,因此 `Less Than 0` 会找出当前所有已超过截止日期的项目,而 `Less Than 7` 会找出一周内到期的项目。 |
| **Mitigated Within SLA** | 是 / 否 | **已缓解**的发现项是否在其 SLA 到期前完成缓解。 |

**Mitigated Within SLA 的适用范围比听起来要窄,这一点常常让人措手不及。** 无论取哪个值,都只匹配**已经被缓解**且**严重程度不是信息级**的发现项:

* **True(是)**——在 SLA 到期日当天或之前完成缓解。
* **False(否)**——在 SLA 到期日之后才完成缓解。

一个已经逾期的**未关闭**发现项这两个值都**不**匹配,因为它尚未被缓解。要查找这类发现项,请改用 **SLA** 的 `Less Than 0`。信息级严重程度的发现项在两种取值中都会被排除。

> 如果发现项的 SLA 配置启用了 **Cap SLA by CISA KEV Due Date**,则 **SLA** 和 **SLA Expiration Date** 都会反映经过收紧的、以 KEV 为上限的截止日期,而不是仅基于严重程度的普通窗口。筛选器中没有单独的标识来说明这一点——参见 [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/)。

## 发现项
这些字段专用于 DefectDojo 的发现项,用于组织发现项。每个筛选器在“所有发现项”表格中都对应一个单独的列。

DefectDojo 中的发现项可按以下方式筛选:

### DefectDojo 元数据
这些筛选器直接与 DefectDojo 的核心功能相关。

##### 不可修改
这些筛选器在问题创建时被赋值,无法通过“编辑发现项”直接修改。

* 发现项严重程度(信息、低、中、高、严重 中的任意一种)
* 产品
* 产品类型
* 测试活动
* 测试活动版本
* 测试
* 测试类型
* 测试版本
* 创建日期
* 存续时间(发现项存在的天数)
* SLA(SLA 计时器上剩余的天数——负值表示已逾期;参见 [SLA 筛选器](#sla-filters))
* SLA 到期日期(参见 [SLA 筛选器](#sla-filters))
* Mitigated Within SLA(是或否——请注意这仅匹配已经被缓解的发现项;参见 [SLA 筛选器](#sla-filters))
* 报告人(创建该发现项的用户或服务)
* 发现工具(指扫描工具)

##### 可以修改
这些字段在问题创建时设置,但可以随着问题的推进而修改。

* [状态](/triage_findings/findings_workflows/finding_status_definitions/)
* 最近状态更新(时间戳)
* 已缓解(是或否)

##### 其他模型功能
这些 DefectDojo 功能可用于进一步组织您的发现项或跟踪修复情况。

* 发现项标签
* 审核人(已分配用户)
* 是否有备注(是/否)
* 组(指[发现项组](/triage_findings/findings_workflows/editing_findings/#finding-group-actions),如果存在的话)
* 风险接受(从列表中选择一个或多个现有的风险接受)

### 工具特定元数据
这些字段对 DefectDojo 的功能没有直接影响,但可以提供额外信息,帮助解释和缓解问题。它们可以在发现项首次创建时设置(使用传入报告中的信息),也可以由用户修改。

* CWE 值
* 漏洞 ID(通常为 CVE)
* EPSS 分数
* EPSS 百分位
* 服务
* 计划修复日期
* 计划修复版本
* 是否有组件(是/否)
* 组件名称
* 组件版本
* 文件路径
* 修复工作量

### Jira 元数据
如果使用了 Jira 集成,这些筛选器可跟踪关联的 Jira 问题的更新情况。

* Jira 问题(可按发现项是否关联了 Jira 问题进行筛选)
* Jira 存续时间(Jira 问题的存续时间)
* Jira 更改(上次推送更改到 Jira 的时间)
