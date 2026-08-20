---
title: ☑️ 新用户核对清单
description: 开始使用 DefectDojo
draft: 'false'
weight: 3
audience: opensource
---

以下是一份快速参考指南，可帮助您从零开始成功实施，直至拥有一个功能齐全的应用。本文假设您已在您的环境中安装并运行了 **DefectDojo 社区版（Community Edition）**。

DefectDojo 的核心理念是导入安全数据、对其进行组织，并将其呈现给需要了解这些信息的人员。以下是在 DefectDojo 开源版中实现这些目标的方法：

### DefectDojo 开源版

1. 开源版用户可以先创建首个[产品类型和产品](/asset_modelling/os_hierarchy/product_hierarchy/)。创建完成后，即可通过 UI 将[文件导入](/import_data/import_scan_files/os__import_scan_ui/)到其中一个产品中。

2. 现在您已经在 DefectDojo 中拥有数据，可以考虑扩展您的产品布局——参见[产品层级概述](/asset_modelling/os_hierarchy/product_hierarchy/)。产品层级会为您的应用创建一个可用的清单，帮助您将数据划分为逻辑分类。这些分类可用于应用访问控制规则，或将报告细分给正确的团队。

3. 使用[报告构建器](/metrics_reports/reports/using-the-report-builder/#opening-the-report-builder)来汇总您已导入的数据。报告可用于快速与产品负责人等相关方共享发现项（Findings）。

这就是 DefectDojo 的核心理念——导入安全数据、组织数据，并将其呈现给需要了解的人员。

所有这些功能都可以实现自动化，并且由于 DefectDojo 能够处理超过 500 种工具（截至本文写作时），您应该完全能够为整个组织的产出创建一份可用的安全清单。

### 开源版功能
- 您的组织使用 Jira 吗？了解如何使用我们的 [Jira 集成](/connectors/os_jira/os__jira_guide/)，根据您导入的数据创建 Jira 工单。
- 您计划让组织内许多用户共同使用 DefectDojo 吗？请查阅我们的[用户管理](/admin/user_management/about_perms_and_roles/)指南，并设置基于角色的访问控制（RBAC）。
- 准备好深入了解自动化了吗？了解如何使用 [DefectDojo API](/import_data/import_scan_files/api_pipeline_modelling/) 自动导入新数据，并构建强大的 CI/CD 管道。
