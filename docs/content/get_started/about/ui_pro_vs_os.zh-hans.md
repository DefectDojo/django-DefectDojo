---
title: 🎨 Pro UI 变更
description: 在 DefectDojo 中使用不同的 UI
draft: 'false'
weight: 5
audience: pro
aliases:
- /zh-hans/en/about_defectdojo/ui_pro_vs_os
---

2023 年末，DefectDojo, Inc. 为 DefectDojo Pro 发布了全新的 UI，该 UI 现已成为该版本的默认 UI。

Pro UI 为 DefectDojo 带来了以下增强：

- 使用 Vue.js 打造的现代简洁设计。
- 优化的数据传输和加载时间，尤其是在处理大型数据集时。
- 可访问新的 Pro 功能，包括[上游连接器](/connectors/upstream/about/)、[Universal Importer](/import_data/pro/specialized_import/external_tools/) 以及 [Pro 指标](/metrics_reports/pro_metrics/pro__overview/)视图。
- 改进的 UI 工作流：更好的筛选、仪表板和导航。

## 切换到 Pro UI

要访问 Pro UI，请从右上角打开您的用户选项菜单。您也可以通过同一菜单切换回经典 UI。

![image](images/beta-classic-uis.png)

## 导航变更

![image](images/pro_ui_overview.png)

1. **侧边栏**已重新组织为四个父类别：Dashboards（仪表板）、Import（导入）、Manage（管理）和 Settings（设置）。

2. 主页、[AI 驱动的原生 API 连接能力](/metrics_reports/ai/mcp_server_pro/)、Pro 指标以及日历视图均可在 Dashboards 下访问。

4. 导入方法可以在 Import 部分找到：设置[连接器](/connectors/about/)以从您的扫描器拉取发现项（上游），或将其推送到问题跟踪系统（下游）；使用 [Add Findings](/import_data/import_scan_files/pro__import_scan_ui/) 表单添加发现项；使用[智能上传](/import_data/pro/specialized_import/smart_upload/)处理基础设施扫描工具；或使用我们的外部工具——[Universal Importer 和 DefectDojo CLI](/import_data/pro/specialized_import/external_tools/)——来简化发现项及相关对象的导入和重新导入流程。

5. **Manage** 部分让您可以查看[产品层级结构](/asset_modelling/os_hierarchy/product_hierarchy/)中的不同对象，包含产品类型、产品、测试活动、测试、发现项、风险接受、端点和组件的视图。此外还有用于生成报告（Report Builder）、使用调查问卷（Surveys）的部分，以及一个[规则引擎](/automation/rules_engine/about/)。

5. **Settings** 部分让您可以配置 DefectDojo 实例，包括许可证、云设置、用户、功能配置以及管理员级别的企业设置。（Integrations 已移至 **Import > Connectors > Downstream Connectors**。）

6. **Settings** 部分包含管理页面，分为 System、Users & Permissions、Finding Workflow、Configuration、Notifications、Operations 和 License & Support，并配有一个 **All Settings** 页面，可以列出并搜索所有这些内容。参见[设置菜单](/navigation/pro__settings_menu/)。

7. Pro UI 还具有**全新的表格格式**，用于[产品层级结构](/asset_modelling/os_hierarchy/product_hierarchy/)以辅助导航。点击每一列即可应用相应的筛选条件，列也可以重新排序，按您期望的方式呈现数据。

8. 该表格还提供一个**"Toggle Columns"（切换列）**菜单，可用于在表格中添加或移除列。

## 筛选表格

在此截图中，我们正在筛选所有属于"Sam's Awesome Product"的发现项。点击 Apply 后，此发现项列表的内容将更新，以反映所选的筛选条件。

![image](images/pro_ui_sams_filter.png)

## 全新仪表板

Pro UI 中包含全新的指标可视化。所有这些报告都可以进行筛选，并导出为 PDF，以便与更广泛的受众分享。

![image](images/program_insights.png)

- **Executive Insights** 仪表板显示您的产品和产品类型的当前状态。
- **Priority Insights** 显示最关键的发现项，并可按不同时间范围、产品类型、产品和标签进行筛选。
- **Program Insights** 仪表板显示您安全团队的成效，以及从可操作发现项中区分出重复项和误报所带来的成本节约。
- **Remediation Insights** 显示您团队修复发现项的成效。
- **Tool Insights** 显示您的工具套件（以及上游连接器流水线）在检测和报告漏洞方面的成效。
