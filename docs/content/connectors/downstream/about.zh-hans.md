---
title: 下游连接器
weight: 1
audience: pro
aliases:
- /zh-hans/en/share_your_findings/integrations
- /zh-hans/issue_tracking/pro_integration/integrations/
---

**可用性：** 下游连接器现已全面开放，并在每个 DefectDojo Pro 实例（无论是云端还是本地部署）上默认启用。无需任何操作即可启用，并且它们已不再列在功能开关页面中。

下游连接器可让您将发现项和发现项组推送到工单跟踪系统，从而轻松将安全修复工作整合进团队现有的开发流程中。

支持的下游连接器：
- Azure Devops
- Bitbucket
- Freshservice
- GitHub
- GitLab Boards
- Jira
- Linear
- Opsgenie
- PagerDuty
- ServiceDesk Plus
- ServiceNow
- ServiceNow SecOps / Vulnerability Response
- Shortcut
- Zendesk

## 打开下游连接器页面

下游连接器页面位于侧边栏的 **Import > Connectors > Downstream Connectors** 下。

![image](images/integrators_3.png)

## 设置下游连接器

下游连接器由三个关键组件配置而成：

- **集成实例（Integration Instance）**：这是 DefectDojo 与第三方系统建立连接所使用的主要方式。该实例将包含标签、位置以及用于连接的凭据等详细信息，同时还包括供应商可能要求的其他任何信息。
- **工单跟踪器映射（Issue Tracker Mapping）**：这里存储着映射信息——定义了连接到供应商内某个特定“项目”所需的详细信息。这些详细信息包括该“项目”的名称或 ID，以及从 DefectDojo 发现项严重程度和状态到供应商“工单”中对应字段的映射关系。如果您想将发现项推送到多个“项目”位置，可以配置多个映射。
- **工单跟踪器分配（Issue Tracker Assignment）**：这里将 DefectDojo 产品和测试活动分配给指定的工单跟踪器映射，并可按产品/测试活动单独设置发现项推送到指定供应商系统的方式。

这些组件是分层级的：每个**实例（Instance）**拥有一个或多个**映射（Mapping）**，而每个映射又拥有一个或多个**跟踪器分配（Tracker Assignment）**。

![image](images/integrators_2.png)

## 推送发现项和发现项组

配置好这些组件后，发现项和发现项组可以通过两种方式发送到指定的工单跟踪器：手动或自动。

- **手动**：在已分配**工单跟踪器映射**的产品/测试活动中所包含的发现项和发现项组，将会出现“推送到集成器（Push to Integrator）”的选项。该操作会在工单跟踪器中创建一个包含相应发现项/发现项组信息的工单。“推送到集成器”同样可用于更新现有工单。

### 自动推送发现项

发现项也可以自动推送，具体推送方式由**工单跟踪器分配**决定。共有以下四个选项：

- **仅显式发布目标变更（Only Explicitly Publish Changes to Target）**：此选项会禁用已分配的产品或测试活动中的所有自动行为。推送发现项或发现项组的唯一方式将是如上所述的显式手动操作。
- **自动将新发现项关联到目标（Automatically Link New Finding to Target）**：当已分配的产品或测试活动中**创建**新的发现项或发现项组时，DefectDojo 会自动将该对象推送到工单跟踪器。创建之后，这些发现项或发现项组在没有手动执行“推送到集成器”操作的情况下将不会被更新。
- **在编辑发现项时自动更新现有关联（Automatically Update Existing Link on Finding Edit）**：当已分配的产品或测试活动中的发现项或发现项组被**更新**时，如果已手动创建了现有关联，则自动将该对象推送到工单跟踪器。
- **在编辑发现项时自动关联新项并更新现有关联（Automatically Link New and Update Existing Link on Finding Edit）**：当已分配的产品或测试活动中创建**或**更新发现项或发现项组时，自动将该对象推送到工单跟踪器。

#### 推送筛选条件

每个工单跟踪器分配都可以选择性地缩小**自动**推送的发现项范围：

- **最低严重程度（Minimum Severity）**：仅自动为达到或超过所选严重程度的发现项创建工单。留空则包含所有严重程度。
- **仅活动发现项（Active findings only）**：仅自动为活动状态的发现项创建工单，跳过在该分配首次识别到它们时已处于已缓解、误报或风险已接受状态的发现项。

这些筛选条件仅适用于自动**创建**。对已关联工单的发现项进行的更新始终会被发送，因此状态变更（包括关闭）会持续同步。手动执行的**推送到集成器**操作始终会忽略这些筛选条件。将两项都保留为默认值即可保留推送所有发现项的原有行为。

#### 分配多个产品

一个工单跟踪器分配只能面向单个产品或测试活动。如需覆盖多个资产，请为每个产品（或测试活动）分别创建一个分配。如果您还需要针对不同资产使用不同的供应商字段——例如不同的 ServiceNow **分配组（Assignment group）**或**受理人（Assigned to）**，或不同的 Jira 项目——请为每个资产创建单独的工单跟踪器映射（及其各自的自定义字段映射），并让每个分配指向对应的映射。

## 工单跟踪器工单的呈现方式

在查看和列出发现项与发现项组时，工单跟踪器工单会以“集成器工单（Integrator Tickets）”列下的一系列图标来呈现。

从左到右依次为图标：

- **集成类型（Integration Type）**：该工单所关联的工单跟踪器类型
- **工单 ID（Ticket ID）**：由工单跟踪器定义的工单 ID
- **工单链接（Ticket Link）**：由工单跟踪器定义的、指向该工单的直接链接
- **变更日志（Changelog）**：指明该工单跟踪器工单与发现项或发现项组建立关联的时间，以及 DefectDojo 上一次对该工单进行更改的时间

![image](images/integrators_1.png)

## 各供应商的特定要求

每个供应商对 DefectDojo 与其交互的方式都有不同的要求，可能体现为身份验证机制、按“项目”设置的额外字段，或严重程度/状态映射等形式。

如需查看完整要求列表，请打开下方各供应商专属页面：

- [Azure Devops](/connectors/downstream/downstream_toolreference/#azure-devops-boards)
- [Bitbucket](/connectors/downstream/downstream_toolreference/#bitbucket)
- [Freshservice](/connectors/downstream/downstream_toolreference/#freshservice)
- [GitHub](/connectors/downstream/downstream_toolreference/#github)
- [GitLab Boards](/connectors/downstream/downstream_toolreference/#gitlab)
- [Jira](/connectors/downstream/downstream_toolreference/#jira)
- [Linear](/connectors/downstream/downstream_toolreference/#linear)
- [Opsgenie](/connectors/downstream/downstream_toolreference/#opsgenie)
- [PagerDuty](/connectors/downstream/downstream_toolreference/#pagerduty)
- [ServiceDesk Plus](/connectors/downstream/downstream_toolreference/#servicedesk-plus)
- [ServiceNow](/connectors/downstream/downstream_toolreference/#servicenow)
- [ServiceNow SecOps / Vulnerability Response](/connectors/downstream/downstream_toolreference/#servicenow-secops)
- [Shortcut](/connectors/downstream/downstream_toolreference/#shortcut)
- [Zendesk](/connectors/downstream/downstream_toolreference/#zendesk)

## 错误处理与调试

下游连接器可能因连接、身份验证、权限等多种原因产生错误。为协助排查这些错误，每个工单跟踪器映射都有一份错误表，列出了错误发生的时间、发生原因，以及推送失败的发现项或发现项组。

您可以在“所有工单跟踪器映射与分配”页面的 ⚠️ 错误总数列中查看这些错误。

![image](images/integrators_4.png)

点击错误总数条目，将跳转到一个页面，其中包含与该下游连接器相关的更详细错误描述。

### 在一处查看所有失败情况

按映射划分的错误表仅涵盖单个下游连接器。[诊断](/admin/diagnostics/pro__diagnostics/) 则涵盖实例上的所有此类信息，以及上游连接器、导入、Jira、SSO 和规则引擎在内的每一次集成尝试，并提供相同的筛选和排序功能，覆盖全部内容。

在以下情况下请使用该功能，因为它所涵盖的范围比单个映射更广：

* 一次**从未完成**而非失败的尝试——由于没有产生任何错误，任何错误表都不会报告它
* 判断某次失败是特定于某一个集成，还是同时发生在多个集成上
* 查明是谁或什么触发了某次尝试，以及针对哪项配置触发的

错误中引用的凭据会在该记录存储之前被移除，完整的技术细节仅限超级用户查看。

## 下游连接器页面布局

下游连接器分为两个部分列出：**已配置连接器（Configured Connectors）**和**可用连接器（Available Connectors）**，各部分均按字母顺序排序，并在标题旁显示所列条目的数量。一个工具可以拥有多个配置；每个配置都是独立的一个方块，标题格式为 `<Tool> - <label>`，按标签排序。DefectDojo Pro Cloud 上的**申请下游连接器（Request Downstream Connector）**方块不计入该数量。
