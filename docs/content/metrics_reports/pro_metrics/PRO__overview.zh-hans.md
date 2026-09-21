---
title: Pro 指标概览
description: 如何在 DefectDojo Pro 中利用指标
audience: pro
weight: 2
---

DefectDojo Pro 界面提供多种指标仪表板，帮助您可视化当前的安全态势。每个仪表板都能让组织内不同层级的相关方在无需解读原始数据或逐条查看发现项的情况下做出明智决策。这些仪表板包括：
* [高管洞察](/metrics_reports/pro_metrics/pro__executive_insights/#main-content)
* [优先级洞察](/metrics_reports/pro_metrics/pro__priority_insights/#main-content)
* [项目洞察](/metrics_reports/pro_metrics/pro__program_insights/#main-content)
* [修复洞察](/metrics_reports/pro_metrics/pro__remediation_insights/#main-content)
* [工具洞察](/metrics_reports/pro_metrics/pro__tool_insights/#main-content)

![指标概览](images/metrics_image1.png)

## 指标功能

在详细介绍每个具体仪表板之前，有必要先了解一下所有仪表板的一些共通之处。

### 筛选

所有指标都可以按时间范围、组织、资产和标签进行筛选。按需调整筛选条件后，必须点击“应用筛选”（Apply Filter）才能使筛选生效。如果您希望将仪表板上当前筛选状态下的所有图表、表格导出为 PDF，请点击“导出为 PDF”（Export as PDF）。

筛选的时间范围最长为过去一年，但也可以调整为过去 7 天、14 天、30 天、90 天或 180 天。

请注意，筛选参数会体现在 URL 中，因此您可以将带有不同筛选参数的多个页面添加为书签。这对于快速查阅，或持续生成某种特定类型的报告都很有用。

### 子菜单

每个图表右上角都有一个 ⋮ 三点菜单（kebab 菜单），提供以下功能：
* 强制刷新（Force Refresh）— 手动刷新以纳入数据中的任何最新更新。
* 展开图表（Expand Plot）— 在更大的弹出窗口中打开同一图表。
* 下载为 SVG（Download Plot as SVG）— 将图表下载为 SVG 文件。
* 以表格查看（View as Table）— 以表格形式显示图表中的数据。
    * 点击表格的每一列均可切换升序或降序排列。您也可以下载每张表格。

![三点菜单内容](images/metrics_image2.png)

### 访问权限

“指标”部分仅呈现每位用户拥有相应查看权限的组织和资产的数据。如果某用户的访问权限仅限于单个资产，则该用户只能看到该资产的指标；如果其无权访问所属组织内的其他资产，那么这些资产的数据将不会出现在指标中。

### 在图表中查看数据

折线图的 X 轴始终代表当前的时间范围筛选条件。将光标悬停在折线图上时，会弹出一个窗口，显示该时间点 Y 轴上对应数值的计数。

![图表弹出窗口](images/metrics_image3.png)

### 切换显示结果

用户可以通过点击图表顶部对应的颜色/名称，在图表中切换显示或隐藏某些类别的发现项。

例如，在下方的“按严重程度划分的活动发现项”图表中，如果您只想查看严重程度为高或严重的发现项，可以点击顶部的“中”“低”和“信息”，将这些结果从图表中移除。再次点击“中”“低”和“信息”即可让这些结果重新显示。

![切换图表结果的动图](images/metrics_image4.gif)
