---
title: 📊 Pro 功能列表
description: DefectDojo 中 Pro 功能的列表
draft: 'false'
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
- /zh-hans/en/about_defectdojo/pro_features
---

以下是 DefectDojo Pro 众多附加功能的列表,并附有相关文档链接,便于您了解这些功能的实际使用方式:

## 改进的用户体验

### Pro 用户界面

DefectDojo Pro 对 DefectDojo 的用户界面进行了重新设计,使其速度更快、功能更丰富、完全可定制,并且更擅长处理企业级数据量的浏览。它还包含深色模式。  
更多信息请参阅我们的 [Pro 用户界面指南](/get_started/about/ui_pro_vs_os/)。

![image](images/enabling_deduplication_within_an_engagement_2.png)

### 全局搜索

通过顶部栏中的单一搜索框查找任何发现项、资产、测试活动等。DefectDojo Pro 的全局搜索利用快速、容错拼写错误的 Postgres 全文搜索,覆盖您的所有对象。

更多信息请参阅我们的[全局搜索指南](/navigation/pro__global_search/)。

### 资产/组织

DefectDojo Pro 为大量代码仓库列表或其他业务结构提供了改进的组织可视化功能。详情请参阅[资产/组织文档](/asset_modelling/pro_hierarchy/asset_hierarchy/)。

![image](images/asset_hierarchy_diagram.png)

### 发现项优先级

DefectDojo Pro 可以按优先级和风险对您的发现项进行预分类,使您的团队能够优先识别并修复最关键的问题。
更多详情请参阅我们的[发现项优先级指南](/asset_modelling/pro_hierarchy/priority_sla/)。

### 规则引擎

DefectDojo Pro 的规则引擎允许您编写自动化批量操作脚本,并构建自定义工作流来处理发现项和其他对象,无需任何编程经验。

更多信息请参阅我们的[规则引擎指南](/automation/rules_engine/about)。

![image](images/rules_engine_4.png)

### Sensei

DefectDojo Pro 的 **Sensei**(测试版)是一项由 AI 驱动的扫描并修复功能:通过 GitHub 应用连接代码仓库后,Sensei 会对其进行扫描、导入发现项,并创建用于修复这些问题的拉取请求——采用先预览后执行的工作流程,因此在您批准之前不会执行任何操作(也不会产生任何 LLM 费用)。

更多信息请参阅我们的 [Sensei 指南](/sensei/about_sensei/)。

### Pro 仪表板与报告

生成[即时报告和指标](/get_started/about/ui_pro_vs_os/#new-dashboards),用以分享您的应用和代码仓库的安全态势、评估您的安全工具,并分析您团队在处理安全问题方面的表现。

首页上的图表可以导出为 SVG 文件,用于生成这些图表的数据也可以导出为表格。

此外,DefectDojo Pro 还包含多个新的[洞察仪表板](/metrics_reports/pro_metrics/pro__overview/),为您安全项目的不同受众提供增强的指标。

### 去重调优

高级去重设置允许您微调 DefectDojo 识别和管理重复发现项的方式。调整同工具、**跨工具**以及重新导入去重设置,以在您所选择的所有安全工具和漏洞发现项之间实现精确匹配。

更多信息请参阅我们的[去重调优指南](/triage_findings/finding_deduplication/pro__deduplication_tuning/)。

![image](images/deduplication_tuning.png)

## 精简的导入流程

### 更多导入选项

DefectDojo Pro 包含四种额外的导入方式:[通用导入器](/import_data/pro/specialized_import/external_tools/)、[上游连接器](/connectors/upstream/about/)、[通用解析器](/supported_tools/parsers/universal_parser/)以及[智能上传](/import_data/pro/specialized_import/smart_upload/)。

![image](images/pro_import_methods.png)


### 后台导入

对于企业级报告,DefectDojo Pro 提供了一种经过优化的上传方式,可在后台处理发现项。

### CLI 工具

使用我们的通用导入器和 DefectDojo-CLI 应用程序,快速构建命令行流水线,以便向您的 DefectDojo Pro 实例导入、重新导入和导出数据;无需编写 API 脚本(支持 Windows、Macintosh 或 Linux)。

更多信息请参阅我们的[外部工具指南](/import_data/pro/specialized_import/external_tools/)。

### 上游连接器

DefectDojo 可以即时连接到企业级扫描工具以导入新的发现项数据,从而创建一个开箱即用的自动化导入流水线,无需设置任何 API 调用或定时任务。

更多信息请参阅我们的[上游连接器指南](/connectors/upstream/about/)。

![image](images/add_edit_connectors_2.png)

上游连接器支持的工具包括:

* Anchore
* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### 通用解析器(测试版)

如果您使用的是不受支持/经过定制的扫描工具,或者只是希望 DefectDojo 以稍有不同的方式处理报告,可以使用 DefectDojo Pro 的通用解析器,将任何 .json 或 .csv 报告转换为一组可操作的发现项。您的解析器可以按照您喜欢的方式解析和映射数据。

更多信息请参阅我们的[通用解析器指南](/import_data/pro/specialized_import/universal_parser//)。

![image](images/universal_parser_3.png)

## 管理可选功能

上述许多功能都是可选的,并以功能标志的形式提供,因此您可以在准备就绪时再启用它们。超级用户无需联系支持团队,即可直接从**设置 > 功能标志**中开启或关闭其中大多数功能。

请参阅[功能标志](/admin/feature_flags/pro__feature_flags/)指南,了解如何启用某项功能,以及为何某项功能在您的安装类型下可能被锁定或不可用。

## 支持

DefectDojo Pro 订阅为本地部署和云端安装均提供世界一流的支持服务。我们的团队随时准备协助您的组织实施并充分利用 DefectDojo Pro。您的订阅包含:

- **全面支持**:提供无限量的支持工单和坐席数量,以协助您的整个团队。
- **专属工程关注**:用户报告的问题、缺陷和功能请求将获得我们工程团队的优先处理。
- **SaaS 管理**:我们为所有 SaaS 实例提供监控、维护和备份服务。
