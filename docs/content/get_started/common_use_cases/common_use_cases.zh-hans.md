---
title: 常见用例
description: 用例和示例
draft: 'false'
weight: 2
chapter: true
aliases:
- /zh-hans/en/about_defectdojo/examples_of_use
---

本文基于 DefectDojo, Inc. 2025 年 2 月 Office Hours 活动:“处理常见用例”。
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=ilRBlfo-wvX5DPVg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## 用例示例

无论您的安全团队规模、IT 复杂程度或报告量如何,DefectDojo 都能够处理任何安全实施方案。以下场景旨在为您自己的需求提供切入点,它们均基于我们社区和 DefectDojo Pro 团队的真实案例。

### 大型企业:RBAC 与测试活动

“BigCorp”是一家大型跨国企业,拥有首席信息安全官(CISO)和一个包含应用安全(AppSec)职能的集中式 IT 安全团队。

BigCorp 的安全管理高度集中化。某些事项会委派给业务信息安全官(BISO)负责。

BigCorp 关注的核心问题包括:

- 在组织内所有业务部门中制定并维持一致的测试方法
- 满足合规要求,避免监管问题

#### 测试模型

BigCorp 处理来自多个来源的安全数据:

- 自动运行 SAST、SCA 和密钥扫描工具的 CI/CD 任务
- 针对特定产品的第三方渗透测试
- 针对特定产品的 PCI 合规审计

在 DefectDojo 中,这些报告类别中的每一种都可以由单独的测试活动来处理,每种扫描类型对应一个单独的测试。

![image](images/example_product_hierarchy_bigcorp.png)

- 如果某个产品拥有 CI/CD 流水线,该流水线的所有结果都可以持续导入到同一个开放式测试活动中。所使用的每个工具都会在该 CI/CD 测试活动中创建一个单独的测试,并可持续导入新数据进行更新。  
(参见我们的[重新导入](/import_data/import_intro/reimport/)指南)
- 每次渗透测试工作都可以创建一个单独的测试活动来存放所有结果,例如“2024 年第一季度渗透测试”“2024 年第二季度渗透测试”等。
- BigCorp 可能希望自行进行模拟 PCI 审计,以便为正式审计做好准备。这些审计的结果同样可以作为单独的测试活动进行存储。

#### RBAC 模型

- 每位 BISO 都被分配了其负责的每个业务部门(产品类型)的读者权限。
- 每位产品负责人对其负责的产品拥有写入权限。在其产品范围内,产品负责人可以通过记录备注、设置 [CI/CD 流水线](/import_data/import_scan_files/api_pipeline_modelling/)、创建风险接受以及使用其他功能来与 DefectDojo 交互。
- BigCorp 的开发人员完全没有 DefectDojo 的访问权限,他们也不需要。产品负责人可以直接从 DefectDojo 推送包含所有相关漏洞信息的 Jira 工单。由于开发人员已经在使用 Jira,他们无需以不同于其他开发任务的方式来跟踪修复工作。

### 嵌入式系统:版本受控的报告

Cyber Robotics 是一家销售配备嵌入式软件系统的制造硬件的公司。他们拥有一位首席产品官(CPO),全面负责产品和网络安全事务。

尽管他们需要管理的安全信息种类不如 BigCorp 那样多样化,但正确地对安全信息进行情境化仍然至关重要,这样他们才能主动应对任何重大发现项。

Cyber Robotics 关注的核心问题:

- 他们的产品线有限,但每个产品都有**许多**版本需要妥善分类归档。
- 他们产品的维护工作复杂且成本高昂,因此需要避免不必要的工作。

#### 测试模型

Cyber Robotics 为其所有嵌入式系统制定了标准化的测试流程:

- 运行 CI/CD、SAST 和 SCA 测试
- 安全控制审查
- 网络扫描
- 第三方代码审查

然而,由于他们软件的每个版本都是相互隔离的,他们不可避免地会有大量数据需要整理,其中许多数据仅在单一情境下(即他们正在运行的特定软件版本)才有意义。

Cyber Robotics 可以通过使用产品类型来代表单一产品线,并为每个独立版本创建单独的产品来解决这一问题。这将使他们能够深入分析,确定哪些产品与某个漏洞相关联。

![image](images/example_product_hierarchy_robotics.png)

将软件版本分配给产品而非测试活动,使 Cyber Robotics 在必要时能够限制对特定软件版本的访问。现场技术人员和支持人员可以获得对单一软件版本的访问权限,而无需授予他们对整条产品线的访问权限。

#### RBAC 模型

此处的 AppSec 团队被分配了全局角色,用以管控其交互权限级别。

- CPO 拥有 DefectDojo 的全局读者权限,与 BigCorp 中的 CISO 相同。
- 各产品负责人对 DefectDojo 中的任何产品都拥有全局读者权限,并对其自己负责的产品拥有写入权限。

在支持方面:

- 支持人员会被临时授予对其负责维护的特定产品的读者权限,但无法访问 DefectDojo 的全部数据。

### 动态 IT 环境与微服务:云服务公司

Kate's Cloud Service 运营着一个使用 Kubernetes、微服务和自动化技术、快速变化的环境。Kate's Cloud Service 设有一位云计算副总裁(VP),负责监督云安全事务。他们还有一位 CISO 负责管理所提供软件的开发工作,但在本示例中,我们将专门关注他们的云安全问题。

Kate's Cloud Service 已将其所有报告工作完全自动化,报告一旦生成便会立即将数据导入 DefectDojo。

Kate's Cloud Service 关注的核心问题:

- 管理多租户云安全,在实现共享服务交付的同时防止跨客户交互。
- 应对其云环境中的快速变化。

#### 为共享服务打标签

由于 Kate 的模型中包含许多可能影响其他产品的共享服务,团队会为其产品打上[标签](/asset_modelling/tags/os__tagging_objects/),以标明哪些云产品依赖于这些服务。这样一来,共享服务出现的任何问题都可以跨产品进行筛选,并上报给相关团队。所有这些共享服务都归入单一的产品类型中,与主要云产品区分开来。

![image](images/example_product_hierarchy_microservices.png)

由于公司发展迅速,技术负责人也频繁变动,Kate 可以使用标签来跟踪当前负责每个云产品的技术负责人,从而避免不断手动更新其 DefectDojo 系统。这些技术负责人的关联信息由 DefectDojo 外部的一项服务进行跟踪,该服务可以管理导入流水线或调用 DefectDojo API。

有关标签功能的更多信息,请参阅我们的[标签](/asset_modelling/tags/os__tagging_objects/)指南。

#### RBAC 模型

在安全/合规方面:

- 拥有 DefectDojo 所有权的产品安全团队对整个系统拥有管理员权限。
- 为云计算副总裁工作的分析师被授予整个系统的只读权限,使他们能够生成必要的报告和指标,供副总裁评估各类云产品的安全状况。

在开发方面:

- 每个特定云产品(如计算、存储、共享服务)的技术负责人对其被分配的产品拥有**维护者权限**,以便对与其特定云产品相关的安全结果进行分类处理。他们可以在自己的产品范围内审查发现项并采取行动,还可以对发现项数据进行大幅重组。
- 从事特定产品工作的开发人员会被授予其所参与产品的**写入权限**,使他们能够对发现项发表评论、请求同行评审并创建风险接受。

### 新收购公司的引入:SaaSy Software

SaaSy Software 是一家快速发展的公司,经常收购其他软件公司。每次收购新公司时,质量工程总监和 AppSec 团队都会突然要负责大量新的代码仓库、开发人员和流程。他们的 DefectDojo 模型确保他们能够尽快熟悉情况并投入运作。

SaaSy Software 关注的核心问题:

- 在维持合规项目(如 SOC2)的同时避免公开的安全问题。
- 能够放心地引入来自新产品的工具和流程。
- 能够对生产分支和开发中分支上的漏洞进行报告和分类。

#### 测试模型

SaaSy 的测试工作侧重于宏观把控,而非标准化的工具使用,因为每次收购都会带来各自的 AppSec 工具和流程。SaaSy 需要同时进行内部评估(CI/CD、DAST、容器扫描和威胁建模)和外部评估(第三方渗透测试、合规审计)。

为了协助引入新应用,SaaSy Software 对其数据模型采用了标准化方法:每次引入新应用时,他们都会为该应用创建一个新的产品类型,并为构成该应用的各个代码仓库(前端、后端 API 等)创建子产品。

![image](images/example_product_hierarchy_saas.png)

这些产品中的每一个都会进一步细分为多个测试活动,一个用于主分支,其余每个开发分支各对应一个。这些测试活动中的测试用于对测试工作进行分类。开发分支拥有单独的测试,用于存储 CI/CD 和 SCA 扫描的结果。主分支同样拥有这些测试,此外还增加了用于存储人工代码审查和威胁模型报告的测试。

所有这些测试都是开放式的,可以使用重新导入功能定期更新。[去重](/triage_findings/finding_deduplication/about_deduplication/)仅在测试活动层面进行处理,这可以防止一个代码分支中的发现项关闭另一个分支中的发现项。

通过持续应用这一模型,SaaSy 拥有了一套可以套用于任何新软件收购的模型,AppSec 团队也能够迅速开始监控数据以确保合规。

#### RBAC 模型

在安全/合规方面:

- SaaSy Software 的 AppSec 团队拥有 DefectDojo 的所有权,并对该软件拥有完整的管理员权限。
- QE 和合规团队对整个系统拥有只读权限,以便在需要时提取报告并深入研究数据。

在开发方面:

- 每位产品负责人对其在 DefectDojo 中拥有的产品拥有写入权限,这使他们能够撰写风险接受并查看该产品的指标。
- 开发人员对其参与工作的每个产品拥有只读权限。他们可以针对正在尝试修复的发现项或问题请求同行评审。
