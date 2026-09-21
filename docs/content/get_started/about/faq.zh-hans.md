---
title: ❓ 常见问题
description: DefectDojo 常见问题
draft: 'false'
weight: 2
chapter: true
aliases:
- /zh-hans/en/about_defectdojo/faq
---

以下是关于使用 DefectDojo 的一些常见问题——涵盖 DefectDojo Pro 和 DefectDojo OS。

## 常见问题

### 我应该如何在 DefectDojo 中组织我的安全测试？

虽然 DefectDojo 可以支持任何安全或测试环境，但每个安全团队和运营方式各不相同，因此没有放之四海而皆准的使用方法。我们有一篇非常详细的文章介绍了[常见用例](/get_started/common_use_cases/common_use_cases/)，其中包含不同组织如何应用 RBAC 和 DefectDojo 数据模型来满足自身需求的示例。

### DefectDojo 中安全测试的推荐工作流是什么？

DefectDojo 旨在成为您组织安全态势的核心真实来源，并可以根据您组织的需求满足不同的需要，例如：

- 让用户能够识别跨扫描和工具的重复发现项，从而减少告警疲劳。
- 对漏洞强制执行 SLA，确保您的组织在适当的时间范围内处理每个发现项。
- 将[工单发送](/connectors/issue_tracking/)到 Jira、ServiceNow 或其他项目跟踪软件，让您的开发团队能够将问题修复纳入其标准发布流程，而无需学习另一个项目管理工具。
- 集成到自动化的 [CI/CD 流水线](/import_data/import_scan_files/api_pipeline_modelling/)中，自动从代码库摄取报告数据，甚至可以细分到分支级别。
- 针对任意一组漏洞或软件上下文创建[报告](/metrics_reports/reports/)，以便快速与利益相关者分享扫描结果或状态更新。
- 建立接受与缓解工作流，支持正式的风险管理跟踪。


DefectDojo 旨在支持并标准化您当前的安全工作流。所有这些方法都可以用来增强您团队的流程，并适应您当前的运作方式。

### DefectDojo Pro 提供哪些功能？

DefectDojo Pro 在上述工作流的基础上进一步扩展，新增了：

- [改进的 UI](/get_started/about/ui_pro_vs_os/)，专为在浏览企业级数据量时提供速度和效率而设计，同时还包含深色模式。
- 能够按优先级和风险[对发现项进行预分类](/asset_modelling/pro_hierarchy/priority_sla/)，让您的团队优先识别并修复最关键的问题。
- [规则引擎](/automation/rules_engine/about)，可编写脚本以实现自动化批量操作，并构建自定义工作流来处理发现项和其他对象，无需编程经验。
- [增强的报告和指标生成能力](/get_started/about/ui_pro_vs_os/#new-dashboards)，轻松分享您应用和代码库的安全态势。
- [高级去重设置](/triage_findings/finding_deduplication/pro__deduplication_tuning/)，可微调 DefectDojo 识别和管理重复发现项的方式。
- 精简的导入能力，例如：
  - 一种优化的上传方式，可在后台处理发现项。
  - 能够使用我们的 Universal Importer 和 DefectDojo CLI 应用快速构建[命令行流水线](/import_data/pro/specialized_import/external_tools/)，让您可以轻松地向 DefectDojo Pro 实例导入、重新导入和导出数据。
  - [通用解析器](/import_data/pro/specialized_import/universal_parser/)，可将任何 .json 或 .csv 报告转换为可操作的发现项集合，DefectDojo Pro 会按您期望的方式解析数据。
  - [连接器](/connectors/upstream/about/)，可与受支持的工具即时连接以导入新的发现项数据，让您无需设置任何 API 调用或 cron 任务即可建立自动化的导入流水线。

### DefectDojo 如何处理访问控制？

DefectDojo 可供大型团队使用，我们强烈建议设置[基于规则的访问控制（RBAC）](/admin/user_management/about_perms_and_roles/)，这既能为每位团队成员妥善建立上下文，也能控制对基础设施某些部分的访问。

角色和权限分配通常发生在产品类型/产品级别。每位团队成员可以被分配到一个或多个产品或产品类型，并被赋予一个角色，用于管理其在其中与漏洞数据的交互方式（只读、读写或完全控制）。有关更多信息，请参阅我们的 [RBAC 指南](/admin/user_management/about_perms_and_roles/)。

### DefectDojo 如何为一个用户团队处理访问控制？

无论您是小型组织中的一人安全团队，还是负责监督大量软件项目的 CISO，您都可以轻松组织[基于角色的访问控制（RBAC）](/admin/user_management/about_perms_and_roles/)，以便为每位团队成员妥善建立上下文，并控制对基础设施某些部分的访问。

通常，角色和权限分配发生在[产品类型/产品级别](/asset_modelling/os_hierarchy/product_hierarchy/)。每位团队成员可以被赋予与一个或多个产品或产品类型相关的角色，用于管理其在其中与漏洞数据的交互方式（例如只读、读写或完全控制）。

## 导入工作流

### DefectDojo 支持哪些工具？

DefectDojo 支持来自[超过 500 种](/supported_tools/)商业和开源安全工具的报告。

如果您希望在工具套件中添加新工具，我们提供了一份推荐的开源工具列表，您可以在[此处](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards)查看。

### Import 和 Reimport 有什么区别？

有两种不同的方法可以从安全工具导入单份报告：

- **Import（导入）**将报告作为单一时间点的记录处理。导入一份报告会创建一个包含相应发现项的测试。
- **[Reimport（重新导入）](/import_data/import_intro/reimport/)**用于使用一组新的结果更新现有测试。如果您的测试流程更为开放式，可以持续将报告的最新版本重新导入到现有测试中。DefectDojo 会将传入报告的结果与现有数据进行比较，记录任何变化，然后调整测试中的发现项以匹配最新报告。

要理解两者的区别，可以将 Import 看作是记录一次扫描事件的单一实例，而 Reimport 则是更新一份持续的扫描记录。

打个比方：如果您是一名会计，您可以用 Import 来记录一张单独的收据，而用 Reimport 来记录一份持续更新的费用账本

这两种方法在去重方面的使用也不同：同一产品下两个各自独立的已导入测试会分别识别并标记重复的发现项，而 Reimport 则不会在测试中创建它识别为[重复项](/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport/)的任何发现项。

一般来说，如果您需要的是某个时间点的报告，Import 是最佳方法。如果您在持续运行并摄取来自某个工具的报告，Reimport 则更适合保持数据的条理性。

### 如何排查导入错误？

DefectDojo 支持种类繁多的工具。如果您在导入报告时遇到行为不一致的情况，我们建议您检查文件结构是否与该工具所期望的一致。请参阅我们的[解析器列表](/supported_tools/)，确认您使用的工具受支持，并检查文件格式是否与该工具的预期相符。您也可以将文件结构与我们的单元测试进行比对。

DefectDojo Pro 提供通用解析器导入方式，可处理任何 JSON、CSV 或 XML 文件。DefectDojo OS 用户可以为相同目的编写自定义解析器。

最后，第三方报告格式有时会在没有预先通知的情况下发生变化：我们的开源社区非常欢迎[提交 PR 和贡献](/get_started/contributing/how-to-write-a-parser/)，以保持我们的解析器与时俱进。

### 我应该如何处理大型扫描文件？

将大型报告导入 DefectDojo 可能是一个耗时的过程。2MB 的报告包含大量数据，根据安全工具的报告格式不同，将其转换为发现项可能需要很长时间。

我们建议的做法是在导入前将大型报告拆分，以反映可用数据的不同子部分。如果您的安全工具可以按软件项目、应用程序或其他上下文筛选结果，导出较小的报告会让 DefectDojo 更容易处理和分类数据。这样做还有一个额外好处：可以根据数据拆分方式主动组织您的发现项，从而生成更相关、更快速的报告。

DefectDojo Pro 可以在后台处理报告。不过，文件仍需先上传并由 DefectDojo 验证，之后才能开始后台发现项创建流程。

### 如何将 CI/CD 流水线连接到 DefectDojo？

DefectDojo 的许多核心功能都可以完全自动化。CI/CD（或任何形式的自动化导入）都可以通过调用 [DefectDojo REST API](/import_data/import_scan_files/api_pipeline_modelling/) 来完成。

**DefectDojo Pro** 用户还可以使用 **Universal Importer / DefectDojo CLI** [命令行工具](/import_data/pro/specialized_import/external_tools/)，可以将其安装并在许多自动化环境中运行。

## 发现项管理

### 发现项的状态意味着什么？

发现项可以有多种状态。发现项始终会被设置为活动或非活动状态，而已验证、误报或超出范围等其他状态则可以根据您的判断自行应用。

这些状态在我们的[发现项状态定义](/triage_findings/findings_workflows/finding_status_definitions/)指南中有更详细的说明，其中还介绍了如何使用它们。

### 如何从 DefectDojo 中删除发现项？

一般来说，我们建议将已关闭的发现项保留为"非活动"状态，而不是直接删除，因为在 AppSec 工作中保留历史记录非常重要。直接删除某个发现项会彻底移除该发现项的所有备注和指标跟踪记录，这可能导致报告不准确或存档不完整。

DefectDojo 中的发现项可以通过以下几种方式删除：
- 对您想要删除的发现项运行[批量删除](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings)操作
- 通过 API 调用 `DELETE /findings/{id}`
- 通过删除父对象，例如测试、测试活动、产品类型或产品。
  - 请注意，子类对象不会独立于其父对象保留：删除父对象（如产品类型）将删除该产品类型下的所有产品、测试活动、测试、发现项和端点。相反，删除测试活动会保留其上层的产品和产品类型。

## 报告与 Jira

### 如何在 DefectDojo 中生成报告？

您可以使用[报告生成器](/metrics_reports/reports/)在 DefectDojo 中快速创建自定义报告。

DefectDojo Pro 用户还可以使用[高管级指标仪表板](/get_started/about/ui_pro_vs_os/#new-dashboards)，实时报告产品类型、产品或其他数据。

### 如何将项目管理工具与 DefectDojo 集成？

无论是 DefectDojo 的 Pro 版还是开源版，DefectDojo 中的发现项都可以作为 Issue 推送到 Jira，从而让您将问题修复工作与开发团队集成起来。

DefectDojo Pro 增加了对[其他项目跟踪集成](/connectors/issue_tracking/)**: ServiceNow、Azure DevOps、GitHub 和 GitLab。
