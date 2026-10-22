---
title: 关于 DefectDojo
date: 2021-02-02 20:46:29+01:00
draft: false
type: docs
weight: 1
aliases:
- /zh-hans/en/about_defectdojo/about_docs
---

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

![image](images/Introduction_to_Dashboard_Features.png)

</div>


<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo, Inc. 及开源贡献者共同维护本文档，以支持 DefectDojo 的社区版和 Pro 版。</span>

## 什么是 DefectDojo？

DefectDojo 是一个开发者安全运营（DevSecOps）平台。DefectDojo 通过充当您整套安全工具的自动聚合器来简化 DevSecOps 流程，让您可以轻松组织安全工作，并向其他利益相关者报告组织的安全态势。

尽管安全流程自动化和集成开发流水线是 DefectDojo 的最终目标，但从本质上说，本软件是一个面向安全漏洞的缺陷跟踪系统，用于摄取、组织并标准化来自众多安全工具的报告。

### DefectDojo 能做什么？

DefectDojo 具备智能功能，可以增强并调优来自安全工具的结果，包括以下能力：

- 在上下文中跟踪并报告安全发现项
- 在上下文中强制执行 SLA
- 处理误报、风险已接受及其他分类决策
- 使用 DefectDojo 的去重算法提炼重复项
- 与外部项目跟踪软件集成。
- 通过 CI/CD 集成，跨代码库和开发分支提供指标/报告。
- 协调传统的渗透测试管理。
- 为漏洞修复流程设置并强制执行 SLA。
- 为安全漏洞创建并跟踪风险接受。

最终，DefectDojo 的产品:测试活动模型让您可以对开发环境进行盘点，并立即将新的安全发现项置于上下文之中。

---
以下是 DefectDojo 联合创始人兼 CTO Matt Tesauro 介绍的一些 DefectDojo 实施方式示例：
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo 开源版

DefectDojo 的核心功能可在 DefectDojo 开源版中使用。

该版本的 DefectDojo 包括：

- 支持全部 500 多种受支持工具的导入/重新导入
- REST API
- 去重功能
- 有限的 UI、指标和报告功能
- Jira 集成能力

对于管理较少发现项数量的团队来说，DefectDojo 开源版是一个很好的起点。

### 安装指南

有几种受支持的方式可以安装 DefectDojo 的开源版（[可在 Github 上获取](https://github.com/DefectDojo/django-DefectDojo)）：

[Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) 是安装运行 DefectDojo 所需核心程序和服务的最简单方法。
我们的[架构](/get_started/open_source/architecture/)指南概述了 DefectDojo 使用的各项服务和组件。
[在生产环境中运行](/get_started/open_source/running-in-production/)列出了在生产服务器上运行 DefectDojo（使用 Docker Compose）所需的系统要求、性能调优和维护流程。

Kubernetes 在开源版层面尚未得到完全支持，但该指南可作为参考，作为将 DefectDojo 集成到 Kubernetes 架构中的起点。

如果您在安装开源版时遇到问题，我们强烈建议您在 [OWASP Slack](https://owasp.org/slack/invite) 上提问。我们的社区成员活跃在 #defectdojo 频道，可以帮助您解决遇到的问题。

## 🟧 DefectDojo Pro 版

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

DefectDojo, Inc. 出于商业目的托管本软件的 Pro 版。除了简洁现代的 UI 之外，DefectDojo Pro 还包括：

* [连接器](/connectors/upstream/about/)：与企业级扫描器（如 Checkmarx One、BurpSuite、Semgrep 等）的开箱即用 API 集成
* **可配置的导入方式**：[通用解析器](/supported_tools/parsers/universal_parser/)、[智能上传](/import_data/pro/specialized_import/smart_upload/)
* **[CLI 工具](/import_data/pro/specialized_import/external_tools/)**，可快速与您的系统集成
* **[其他项目跟踪集成](/connectors/issue_tracking/)**：ServiceNow、Azure DevOps、GitHub 和 GitLab
* **[改进的指标](/metrics_reports/pro_metrics/pro__overview/)**，用于高管报告和高层分析
* **[优先级与风险](/asset_modelling/pro_hierarchy/priority_sla/)**，用于在全系统范围内识别紧急程度最高的发现项
* **高级支持**及面向您组织的实施指导

Pro 版既提供云托管的 SaaS 形式，也支持本地部署安装。

有关 DefectDojo Pro 的更多信息，请查看我们的[定价页面](https://defectdojo.com/pricing)。

## 在线演示

DefectDojo 的开源版和 Pro 版均提供在线演示。两者均可使用以下凭据访问：

- 用户名：`admin`
- 密码：`1Defectdojo@demo#appsec`

这些演示环境已预加载示例数据，并每天重置一次。

### 开源版演示

DefectDojo（开源版）的运行示例可在 [https://demo.defectdojo.org/](https://demo.defectdojo.org/) 访问。

### Pro 版演示

DefectDojo Pro 的运行示例可在
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/) 访问。

## 学习 DefectDojo

无论您是 Pro 版还是开源版用户，我们都提供了许多资源来帮助您上手 DefectDojo。

* 查看我们支持的[安全工具集成](/supported_tools/)，帮助您将 DefectDojo 融入自己的 DevSecOps 项目。
* 我们的团队维护着一个 [YouTube 频道](https://www.youtube.com/@defectdojo)，其中包含教程、往期 Office Hours 活动存档以及其他内容。

## 联系我们

如需联系 DefectDojo, Inc. 团队，您可以随时通过 [hello@defectdojo.com](mailto:hello@defectdojo.com) 与我们取得联系。

我们会定期在 [LinkedIn](https://www.linkedin.com/company/33245534) 上发布动态，并为 AppSec 从业者举办线上演示，您可以观看直播或点播回放。您可以在我们的[活动页面](https://defectdojo.com/events)了解即将举行的活动，或在我们的 [YouTube 频道](https://www.youtube.com/@defectdojo)上观看往期演示。

### 贴纸

想要酷炫的 DefectDojo 笔记本电脑贴纸吗？作为对您成为 DefectDojo 社区一员的感谢，您可以注册领取一些免费的 DefectDojo 贴纸。欲了解更多信息，请查看[此链接](https://defectdojo.com/defectdojo-sticker-request)。
