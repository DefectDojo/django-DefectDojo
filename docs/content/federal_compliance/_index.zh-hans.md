---
title: 联邦合规
description: FedRAMP POA&M 与 ConMon 交付物、CMMC 二级评估，以及 NIST 800-53 控制覆盖情况
summary: ''
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
audience: pro
exclude_search: true
---

DefectDojo Pro 可以承担联邦合规计划中漏洞管理这一部分的工作。它会为每个系统维护一份 FedRAMP 风格的行动计划与里程碑（Plan of Action and Milestones，POA&M），以官方的 Excel 和 OSCAL 格式生成每月的持续监控（Continuous Monitoring，ConMon）交付物，对 CMMC 二级自评估进行评分，并展示您的扫描器实际测试到了哪些 NIST 800-53 控制项。

本节所述的所有内容都位于资产（Asset）的 **Compliance**（合规）标签页中。

## 启用此功能

联邦合规功能默认隐藏在 **Compliance** 功能标志之后，该标志目前处于测试版且默认关闭。管理员可以从功能标志菜单中开启它——参见[功能标志](/admin/feature_flags/pro__feature_flags/)。启用后，每个资产上都会出现一个 Compliance 标签页。

## 测试版：使用前请先确认结果

**此功能目前处于测试版。** 内置的 NIST 800-171 和 800-53 控制声明、DoD SPRS 分值权重，以及 POA&M 资格规则，均旨在帮助您跟踪和评估自身的合规态势，目前仍有待对照权威源文档进行独立验证。

SPRS 评分、有条件合格结果以及控制覆盖情况均仅供**参考**。在将其用于认证、评估提交或任何合同用途之前，请先对照官方的 DoD NIST SP 800-171 评估方法论和现行 FedRAMP 指南进行确认。

## 本节内容

| 页面 | 内容概述 |
| --- | --- |
| [合规档案](compliance_profile) | 将资产注册为一个系统，并设置出现在每份交付物中的基本信息 |
| [POA&M 台账](poam_ledger) | POA&M 条目如何从发现项创建，以及该台账遵循的约定 |
| [ConMon 快照](conmon_snapshots) | 采用 FedRAMP Excel 和 OSCAL 格式的每月交付物，以及可选的 OSCAL 验证服务 |
| [整改截止时间](remediation_slas) | FedRAMP Rev 5 与 FedRAMP VDR 的 SLA 预设 |
| [CMMC 二级评估](cmmc_assessments) | 依据 NIST 800-171 Rev 2 对自评估进行评分 |
| [控制覆盖情况](control_coverage) | 您的扫描器测试了哪些 800-53 控制项，以及各控制项下未解决的弱点 |
