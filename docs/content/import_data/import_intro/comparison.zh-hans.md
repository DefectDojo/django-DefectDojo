---
title: 导入方式对比
description: 了解如何手动、通过 API 或通过连接器导入数据
weight: 1
aliases:
- /zh-hans/en/connecting_your_tools/import_intro
---

DefectDojo 深知，每家公司的安全需求都截然不同，不存在放之四海而皆准的方法。随着组织的变化，采取灵活的方式至关重要，而 DefectDojo 允许您以灵活的方式连接安全工具，以适应这些变化。

## 扫描上传方式

当 DefectDojo 从安全工具接收到漏洞报告时，会根据该报告中包含的漏洞创建发现项。DefectDojo 充当这些发现项的中央存储库，您和您的团队可以在此对其进行分类、修复或以其他方式处理。

DefectDojo 主要有两种上传发现项报告的方式。

* 通过界面直接**导入**
* 通过 **API** 端点（支持自动化数据摄取）：参见 [API 文档](/automation/api/api-v2-docs/)

#### DefectDojo Pro 方式

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> 用户还有另外三种处理报告和数据的方式：

* 通过 **通用导入器** 或 **DefectDojo CLI**（利用 DefectDojo API 的命令行工具）：参见 [通用导入器与 DefectDojo-CLI 指南](/import_data/pro/specialized_import/external_tools/)
* 通过针对特定工具的 **连接器**，实现“开箱即用”的数据集成：参见 [连接器指南](/connectors/upstream/about/)
* 通过针对特定工具的 **智能上传**，这是一种专为处理基础设施扫描而设计的导入器：参见 [智能上传指南](/import_data/pro/specialized_import/smart_upload/)

### 上传方式对比

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **支持的扫描类型** | 全部：参见 [受支持的工具](/supported_tools/) | 全部：参见 [受支持的工具](/supported_tools/) | Akamai API Security, Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, IriusRisk, JFrog Xray, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **自动化？** | 可通过 API 的 `/reimport` `/import` 端点实现 | 由 [CLI 工具](/import_data/pro/specialized_import/external_tools/) 或外部代码触发 | 连接器本身就是一项自动化功能 | 可通过 API 的 `/smart_upload_import` 端点实现 |

### 产品层级结构与组织

上述每种方式都可以即时创建产品层级结构。产品层级结构指的是 DefectDojo 的产品类型、产品、测试活动或测试：这些对象有助于将您的数据组织到相关的上下文中。

* **漏洞数据可以导入到现有的产品层级结构中**。产品类型、产品、测试活动和测试都可以提前创建，然后再将数据导入到 DefectDojo 中的相应位置。
* **也可以在导入时创建对应的产品层级结构上下文。** 导入报告时，您可以创建新的产品类型、产品、测试活动和/或测试。DefectDojo 通过“自动创建上下文”选项来处理这一过程。在 DefectDojo OS 中，此选项只能通过 API 访问；DefectDojo OS 中的界面导入需要事先创建好产品层级结构。
