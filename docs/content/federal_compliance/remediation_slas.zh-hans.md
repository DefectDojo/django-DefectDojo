---
title: 整改截止日期
description: FedRAMP Rev 5 和 FedRAMP VDR SLA 预设
weight: 4
audience: pro
---

该功能自带两套现成的 SLA 配置。您可以在 SLA 配置设置中将其中任意一套分配给您的产品,也可以复制一套后再进行调整。

## FedRAMP Rev 5

| 严重程度 | 截止时间 |
| --- | --- |
| 严重 | 发现后 30 天内 |
| 高 | 发现后 30 天内 |
| 中等 | 90 天 |
| 低 | 180 天 |

截止日期是强制执行的,列入 CISA KEV 目录的发现项,其排期永远不会晚于其 CISA 截止日期。

## FedRAMP VDR

基础时限相同,但会根据可利用性和暴露程度进一步收紧:

| 条件 | 截止时间 |
| --- | --- |
| 可可信利用**且**可通过互联网访问 | 4 天 |
| 仅可可信利用 | 14 天 |
| 仅可通过互联网访问 | 30 天 |
| 两者均非 | 上述 FedRAMP Rev 5 的时限 |

**可可信利用**指该发现项已列入 KEV,或其 EPSS 分数达到或超过您设定的阈值。**可通过互联网访问**由发现项标签标示——默认标签为 `internet-reachable`。

所有阈值、标签名称和天数均可在 SLA 配置中编辑。

**FedRAMP VDR 将于 2026 年 12 月 7 日起强制实施。** 届时,FedRAMP 的漏洞检测与响应(Vulnerability Detection and Response)标准将对云服务提供商强制生效。建议在此之前提前采用 VDR 预设。

## 与台账的关系

SLA 截止日期决定了 POA&M 项目的计划完成日期,并决定了在某次快照的月度环比指标中哪些项目会被计为逾期。它们还决定了**仅逾期**扫描项目策略所包含的内容——参见[合规配置文件](../compliance_profile)。

关于优先级和 SLA 在联邦语境之外的运作方式,请参见[分配优先级、风险和 SLA](/asset_modelling/pro_hierarchy/priority_sla/)。
