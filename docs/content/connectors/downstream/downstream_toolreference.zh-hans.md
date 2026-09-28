---
title: 下游连接器工具参考
description: 下游连接器的详细设置指南
weight: 1
audience: pro
aliases:
- /zh-hans/en/share_your_findings/integrations_toolreference
- /zh-hans/issue_tracking/pro_integration/integrations_toolreference/
---

以下是有关如何为第三方问题跟踪器设置 DefectDojo 下游连接器的具体说明。

## Azure DevOps Boards

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为您的 Azure URL，例如 `https://dev.azure.com/{your organization}`
- **令牌**应设置为来自 Azure 的个人访问令牌。

使用 Azure DevOps 进行身份验证需要一个[个人访问令牌](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)，该令牌需要针对您要使用的 Azure 项目，将“工作项”的权限设置为“读取、写入和管理”。

### 问题跟踪器映射

以下详细信息决定了 DefectDojo 如何将发现项或发现项组的属性映射到 Azure DevOps 中的指定项目：

#### 问题跟踪器映射详情

`Project ID` 字段对应于 Azure 中该项目的名称或 ID。

#### 严重程度映射详情

表单中的这些属性作为默认值提供，具体如下：

- **严重程度字段名称**：`/fields/Microsoft.VSTS.Common.Priority`
- **信息映射**：`4`
- **低映射**：`4`
- **中映射**：`3`
- **高映射**：`2`
- **严重映射**：`1`

#### 状态映射详情

表单中的这些属性作为默认值提供，具体如下：

- **状态字段名称**：`/fields/System.State`
- **活动映射**：`To Do`
- **已关闭映射**：`Done`
- **误报映射**：`Done`
- **风险已接受映射**：`Done`

## Bitbucket

Bitbucket 集成允许您将问题推送到 Bitbucket Cloud 仓库的[问题跟踪器](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/)。

Bitbucket 中的问题跟踪器是可选功能，必须先在仓库上启用，DefectDojo 才能在其中创建问题。要启用它，请在 Bitbucket 中打开该仓库，选择**仓库设置**，然后在**功能**下启用问题跟踪器。

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为 `https://bitbucket.org`。
- **电子邮件**应为该 API 令牌所属 Atlassian 账户的电子邮件地址。
- **API 令牌**应设置为一个限定范围的 Atlassian API 令牌。

Bitbucket 应用密码已被 Atlassian 弃用，无法用于此集成。要创建 API 令牌：

1. 打开 [Atlassian 账户设置](https://id.atlassian.com/manage-profile/security/api-tokens)，选择**安全性**，然后选择**创建和管理 API 令牌**。
2. 选择**创建具有权限范围的 API 令牌**，为令牌命名，并设置到期日期。
3. 选择 **Bitbucket** 作为应用。
4. 授予该令牌读取仓库以及读写问题的权限。

### 问题跟踪器映射

- **工作区**应为包含该仓库的工作区的 slug，即其在 bitbucket.org 网址中显示的形式。
- **仓库 Slug**应为您要在其中创建问题的仓库的 slug。

### 严重程度映射详情

此项映射到 Bitbucket 问题的优先级字段。表单中的这些属性作为默认值提供，且每个值都必须是 Bitbucket 的优先级之一：`trivial`、`minor`、`major`、`critical` 或 `blocker`。

- **严重程度字段名称**：`priority`
- **信息映射**：`trivial`
- **低映射**：`minor`
- **中映射**：`major`
- **高映射**：`critical`
- **严重映射**：`blocker`

### 状态映射详情

此项映射到 Bitbucket 问题的状态字段。每个值都必须是 Bitbucket 的问题状态之一：`new`、`open`、`resolved`、`on hold`、`invalid`、`duplicate`、`wontfix` 或 `closed`。

- **状态字段名称**：`state`
- **活动映射**：`new`
- **已关闭映射**：`resolved`
- **误报映射**：`invalid`
- **风险已接受映射**：`wontfix`

## GitHub

GitHub 集成允许您将问题添加到 [GitHub 项目](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects)中，这也会在关联的仓库中打开相应的问题。这些仓库/项目可以关联到某个 GitHub 组织，也可以关联到个人 GitHub 账户。

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为您的 GitHub 用户或组织 URL（取决于您希望在何处创建问题），例如 `https://github.com/{your-organization}`
- **令牌**应设置为来自 GitHub 的个人访问令牌。

GitHub 的个人访问令牌可以在 https://github.com/settings/tokens 创建。该令牌必须具有仓库和项目权限范围。

### 问题跟踪器映射

- **问题跟踪器映射标签**应设置为用于标识您希望在其中创建问题的项目或仓库。
- **项目编号**应为您要发送项目条目的 GitHub 项目的 ID。您可以在查看某个项目时从其 URL 中获取该编号，例如 `https://github.com/orgs/{your-org}/projects/{project number}`。
- **仓库名称**应为与您的组织（或用户）相关联、且您希望向其推送问题的仓库名称。


### 严重程度映射详情

**要设置此集成，该项目必须创建一个自定义字段来表示问题优先级，否则严重程度将无法正确映射，问题也无法推送到 GitHub。**

请按照本指南创建[自定义字段](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority)。
每个严重程度都需要有一个对应的单选选项。例如，DefectDojo 开箱即用地建议将 P0、P1、P2、P3、P4 作为可能的优先级值，这些值都需要添加到 Priority 自定义字段中。

- **严重程度字段名称**：`Priority`
- **信息映射**：`P0`
- **低映射**：`P1`
- **中映射**：`P2`
- **高映射**：`P3`
- **严重映射**：`P4`

### 状态映射详情

默认情况下，新的 GitHub 项目中问题的状态包括“进行中”和“已完成”。如果需要，还可以在项目中添加额外的状态，用于跟踪误报或风险已接受状态。实现这一点的方法之一是在项目看板中添加一个新的状态列。

- **状态字段名称**：`Status`
- **活动映射**：`In Progress`
- **已关闭映射**：`Done`
- **误报映射**：`Done`
- **风险已接受映射**：`Done`

## GitLab

GitLab 集成允许您将问题添加到 [GitLab 项目](https://docs.gitlab.com/ee/user/project/)中。

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为指向您的 GitLab 服务器的链接，例如 `https://gitlab.com/`。
- **令牌**应设置为来自 GitLab 的个人访问令牌。该令牌必须具有 API 权限范围。请参阅 [GitLab 关于创建个人访问令牌的指南](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token)。

### 问题跟踪器映射

- **项目名称**：您要将问题发送到的 GitLab 项目的名称。

### 严重程度映射详情

此项映射到 GitLab 的优先级字段。
- **严重程度字段名称**：`Priority`
- **信息映射**：`1`
- **低映射**：`2`
- **中映射**：`3`
- **高映射**：`4`
- **严重映射**：`5`

### 状态映射详情

默认情况下，GitLab 的状态包括“已打开”和“已关闭”。如果您希望跟踪误报或风险已接受状态，可以添加额外的状态标签。详情请参阅 [GitLab 文档](https://docs.gitlab.com/user/work_items/status/)。

- **状态字段名称**：`Status`
- **活动映射**：`opened`
- **已关闭映射**：`closed`
- **误报映射**：`closed`
- **风险已接受映射**：`closed`

## Jira

Jira 集成会将 DefectDojo 的发现项和发现项组作为问题推送到 Jira 项目中，使每个问题的状态与该发现项保持同步，并将发现项链接回所创建的问题。系统同时支持 Jira **Cloud** 和 **Data Center / Server**，但不支持 Jira Service Management。

### 选择身份验证方法

请先设置**Jira 部署**，然后选择**身份验证方法**：

**Jira Cloud**
- **API 令牌（电子邮件 + 令牌）**——使用 Atlassian 账户电子邮件和 [API 令牌](https://id.atlassian.com/manage-profile/security/api-tokens) 进行 HTTP 基本身份验证。请求会直接发送到您的站点 URL。
- **OAuth 2.0（推荐）**——只需一次性的浏览器授权同意；DefectDojo 会为您获取并刷新令牌。
- **服务账户令牌**——为 Atlassian [服务账户](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/)创建的一个限定范围的 API 令牌。

**Jira Data Center / Server**
- **个人访问令牌（推荐）**
- **用户名 + 密码**

> **Cloud 身份验证如何访问 Jira：**OAuth 2.0 和服务账户都以 Bearer 令牌的形式向 Atlassian 的网关进行身份验证——`https://api.atlassian.com/ex/jira/{cloudId}`——该网关与您的站点 URL `https://your-site.atlassian.net` 是*不同的主机*。DefectDojo 在每次 API 调用时都使用该网关，但在发现项上显示的工单链接始终基于您的**站点 URL**构建，因此用户点击的链接是一个正常的、可浏览的 `.../browse/{ISSUE-KEY}` 链接。（API 令牌和 Data Center 身份验证方式会直接调用站点 URL，因此不存在这种分离。）

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为您的 Jira **站点 URL**，例如 `https://your-organization.atlassian.net`。此地址用于生成可浏览的工单链接；对于 API 令牌和 Data Center 身份验证方式，它还会作为 API 的基础 URL。
- 其余字段取决于您上面选择的身份验证方法（电子邮件 + API 令牌、OAuth 客户端凭据、服务账户令牌、PAT，或用户名 + 密码）。

### OAuth 2.0 设置（Cloud）

请在 [Atlassian 开发者控制台](https://developer.atlassian.com/console/myapps/)中创建一个专用应用，然后从 DefectDojo 发起连接。

1. 选择**创建 → OAuth 2.0 集成**。该应用必须是 *OAuth 2.0 集成*——Connect 或 Forge 应用无法使用 3LO 授权码授予流程（否则会出现 `grant_type is not enabled for client` 错误）。
2. 系统提示选择**访问类型**时，请选择**资源级别**。这会将令牌的作用范围限定在用户授权的单个 Jira 站点上，而这正是每个 DefectDojo 连接所需要的范围。（**账户级别**会授予对该 Atlassian 账户下所有站点的访问权限——超出实际所需范围。）
3. 在**权限**下，添加 **Jira platform REST API**，并授予下面列出的权限范围。请注意：此处不会列出 `offline_access`——它是 DefectDojo 在授权 URL 中请求的标准 OAuth 权限范围，并非需要您在此屏幕上添加的内容。
4. 在**授权**下，点击 **OAuth 2.0（3LO）**旁边的**配置**，并将**回调 URL**设置为 `https://<your-defectdojo-host>/integrators/jira/oauth/callback`——该地址必须与您的 DefectDojo 站点 URL 完全一致。启用此项才能开启授权码授予流程和刷新令牌；如果跳过此步骤，则会导致 `grant_type is not enabled` / `Client is not allowed to use offline_access` 错误。
5. 将**客户端 ID**和**客户端密钥**复制到 DefectDojo 表单中，然后点击**提交**以保存该连接。
6. 点击**与 Jira 连接**，并在同意页面中批准授权。Atlassian 会重定向回 DefectDojo，DefectDojo 会存储令牌并自动解析您的 `cloudId`。成功后会显示“已连接”提示。

> 回调主机就是您 DefectDojo 的 `SITE_URL`。Atlassian 必须能够将浏览器重定向到该地址，且该值必须与 DefectDojo 发送的值完全一致——因此请使用用户实际访问 DefectDojo 时所用的真实主机名，而不是仅能在内网访问的地址。

#### 最小 OAuth 权限范围

DefectDojo 默认会请求以下四个经典权限范围，它们也是所需的**绝对最小值**——每一个都对应一种特定的行为：

| Scope | Required for |
|-------|--------------|
| `read:jira-work` | 读取项目、问题以及可用的状态流转（用于连接验证和状态同步）。 |
| `write:jira-work` | 创建和编辑问题，以及执行状态流转。 |
| `read:jira-user` | 用于连接的身份检查——DefectDojo 在验证访问权限时会调用 `/myself`。 |
| `offline_access` | 用于签发**刷新令牌**。如果没有它，访问令牌会在您连接后大约 1 小时过期，且连接将无法继续工作，因为 DefectDojo 将无法再刷新它。 |

Atlassian 建议优先使用经典权限范围而非细粒度权限范围；上述四项已将该应用所需的权限范围降到最低，并足以支持此集成的全部功能。

##### 细粒度权限范围替代方案

如果您的组织要求使用**细粒度**权限范围而非经典权限范围，则最小等效集合如下：

| Granular scope | Required for |
|----------------|--------------|
| `read:user:jira` | `/myself` 身份检查。 |
| `read:project:jira` | 验证目标项目是否存在。 |
| `read:issue:jira` | 在同步过程中读取问题的当前状态。 |
| `write:issue:jira` | 创建和编辑问题**以及执行状态流转**——不存在单独的状态流转写入权限范围；状态流转本身就是对该问题的一次写入。 |
| `read:issue.transition:jira` | 列出某个问题上可用的状态流转。 |
| `offline_access` | 刷新令牌（与经典权限范围相同）。 |

根据您站点的字段配置，某些接口可能还需要配套的读取权限范围才能展开字段——最常见的是 `read:status:jira` 和 `read:field:jira`（创建操作还需要 `read:issue-meta:jira`）。如果推送因 `403` “scope does not match” 错误而失败，请添加错误信息中指明的确切权限范围。正是这种配套权限范围不断增加的问题，使得经典权限范围成为推荐的选择。

对于**服务账户令牌**方式，请为该令牌授予 `read:jira-work` 和 `write:jira-work`（以及 `read:jira-user`）——或授予上述细粒度权限范围中除 `offline_access` 以外的等效项。`offline_access` 在此不适用——服务账户令牌是长期有效的，DefectDojo 不会对其进行刷新。

### 问题跟踪器映射

- **项目关键字**：要在其中创建问题的 Jira 项目的关键字，例如 `SEC`。
- **问题类型**：要创建的问题类型，例如 `Bug` 或 `Task`。默认值为 `Bug`。

### 严重程度映射详情

默认值与 Jira 的默认优先级方案相匹配。请根据您项目中的优先级名称对其进行编辑：

- **严重程度字段名称**：`priority`
- **信息映射**：`Lowest`
- **低映射**：`Low`
- **中映射**：`Medium`
- **高映射**：`High`
- **严重映射**：`Highest`

### 状态映射详情

状态因项目工作流而异，因此这些默认值仅供参考，请根据**您自己**工作流中的状态名称进行编辑：

- **状态字段名称**：`status`
- **活动映射**：`To Do`
- **已关闭映射**：`Done`
- **误报映射**：`Done`
- **风险已接受映射**：`Done`

### 自定义字段（可选）

您可以在映射的**自定义字段**步骤中映射其他 Jira 字段——例如关闭时必填的 `resolution`，或 `labels`。每个自定义字段映射都包含四个部分：

- **来源**——值的来源：可以是被推送的**发现项**、**测试**、**测试活动**或**资产**的某个属性，也可以是**静态值**。
- **值**——对于对象类型的来源，指要读取的具体属性，从该对象各字段的列表中选择，这些字段都带有便于理解的标签（例如 *Severity*、*CVE*、*Mitigation*）。对于**静态值**来源，这是一个自由文本框，您可以在其中输入字面值。
- **供应商字段**——要写入的 Jira 字段。由于 DefectDojo 可以读取 Jira 的字段目录，这里是一个可搜索的选择器，会按每个字段的**显示名称**列出，并自动为您解析出对应的内部 ID——因此您只需选择 *DD Close Justification*，DefectDojo 便会存储 `customfield_10255`。该选择器的内容来自该连接，因此只有在连接已保存并通过验证后才能正常使用。
- **应用时机**——*何时*发送该字段：在**创建工单时**、在**每次更新时**，或作为特定状态**流转**（活动 / 已关闭 / 误报 / 风险已接受）的一部分发送。范围限定于某次状态流转的字段，会随该次流转的编辑一起发送——这样您就可以提供一个 Jira 只在状态流转界面上才接受的值，最常见的情形是工作流要求在问题被解决时填写 `resolution`。

### 工单模板（可选）

默认情况下，Jira 问题使用 DefectDojo 内置的标题和正文。如需自定义，请在映射的**工单模板**步骤中为其附加一个**工单模板**。模板定义了四个各自独立、均为可选的部分——**发现项**的摘要和描述，以及**发现项组**的摘要和描述。留空的部分会回退使用内置默认值，因此您可以只覆盖标题、只覆盖正文，或者四项全部覆盖。保存前，可在模板编辑器中使用**测试渲染**功能，针对示例数据预览渲染输出——从而发现未知占位符或超出字段长度限制的值等错误。如果之后删除了某个模板，使用过它的映射会自动恢复为内置默认值。

### 工作原理

- **创建 / 更新 / 删除：**创建操作会推送一个新问题，并将链接记录在该发现项上；更新操作会编辑现有问题；删除某个发现项会强制关闭其对应的问题（Jira 中不会删除任何内容）。推送既可以是手动的（“推送到集成工具”），也可以根据问题跟踪器分配设置自动执行。
- **状态协调：**创建之后（以及每次更新时），DefectDojo 都会读取该问题的当前状态；如果该状态与映射的目标状态不同，就会查找一个可以到达目标状态的工作流状态流转并加以应用。如果不存在这样的流转，该映射会记录一个错误，而不会静默失败。任何范围限定于该流转的自定义字段都会随该流转一起发送。
- **工单链接：**发现项上显示的链接是 `https://your-site.atlassian.net/browse/{ISSUE-KEY}`——始终使用您的公共站点 URL，绝不会使用内部网关。
- **令牌生命周期（OAuth）：**整个流程均由 DefectDojo 管理——它负责执行授权码交换、存储访问令牌和刷新令牌，并在每次推送前按需刷新，且每次都会持久化保存新的刷新令牌（Atlassian 每次刷新都会轮换该令牌）。
- **凭据存储：**所有连接凭据（密码、令牌、客户端密钥、OAuth 令牌）都会进行静态加密存储，并且永远不会通过 API 返回——编辑连接时，已存储的密钥会显示为“留空以保持不变”的占位提示。

## Linear

Linear 集成允许您将 DefectDojo 的发现项作为 [Linear](https://linear.app/) 问题推送。问题会创建在您 Linear 工作区中的某个团队下。

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为 `https://api.linear.app/graphql`。
- **API 密钥**应设置为一个 Linear 个人 API 密钥。您可以在 Linear 中依次进入设置、安全与访问权限、[API](https://linear.app/settings/account/security) 来生成密钥。该密钥会通过 `Authorization` 请求头发送给 Linear 的 GraphQL API。

### 问题跟踪器映射

- **团队（组）ID** 应设置为将在其下创建问题的 Linear 团队的 ID。您可以通过调用 Linear 的 GraphQL API 来列出您的团队及其 ID：

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### 严重程度映射详情

Linear 问题使用的是数字型的**优先级**，而不是严重程度字段。每个 DefectDojo 严重程度都会映射到一个 Linear 优先级，其中 `1` 表示紧急，`4` 表示低：

- **严重程度字段名称**：`Priority`
- **信息映射**：`4`
- **低映射**：`4`
- **中映射**：`3`
- **高映射**：`2`
- **严重映射**：`1`

### 状态映射详情

每个状态值都必须设置为您 Linear 团队中某个工作流状态的 ID。工作流状态 ID 在每个工作区中都是唯一的，因此没有默认值。您可以通过调用 Linear 的 GraphQL API 来列出工作流状态及其 ID：

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **状态字段名称**：`Workflow State ID`
- **活动映射**：某个“已开始”或“未开始”状态的 ID，例如 `Todo` 或 `In Progress`。
- **已关闭映射**：某个“已完成”状态的 ID，例如 `Done`。当某个发现项在 DefectDojo 中被删除时，其对应的问题会被移动到此状态。

## Opsgenie

Opsgenie 集成允许您将 DefectDojo 的发现项和发现项组作为 Opsgenie 告警推送，并可选择将其路由给某个 Opsgenie 团队作为响应人。

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为 `https://api.opsgenie.com`。如果您的 Opsgenie 账户托管在欧盟服务区域，请改用 `https://api.eu.opsgenie.com`。如果您的告警位于 Jira Service Management Operations 中（Atlassian 正在将 Opsgenie 并入 JSM），请使用 `https://api.atlassian.com/jsm/ops/integration`。
- **API 密钥**应设置为一个 Opsgenie **API 集成**密钥。账户管理员可以在 Opsgenie 网页应用的**设置 > 集成**下创建：添加一个类型为 **API** 的集成，并为其授予*创建和更新权限*（以及*读取权限*，以便 DefectDojo 可以验证该连接）。请注意，这是一个集成密钥，而不是个人 API 密钥——DefectDojo 使用 `GenieKey` 授权方式进行身份验证，而这只有集成密钥才支持。

### 问题跟踪器映射

- **团队名称** *（可选）*应为要添加为已创建告警响应人的 Opsgenie 团队名称。您也可以将其留空：如果该 API 集成密钥的作用范围限定于某个团队，告警会自动路由给该团队；否则将由您账户自身的路由规则决定响应人。

### 严重程度映射详情

严重程度会映射到 Opsgenie 告警的**优先级**字段，该字段使用 Opsgenie 固定的从 `P1`（严重）到 `P5`（信息性）的量表：

- **严重程度字段名称**：`Priority`
- **信息映射**：`P5`
- **低映射**：`P4`
- **中映射**：`P3`
- **高映射**：`P2`
- **严重映射**：`P1`

如果某个严重程度被映射到一个无法识别的值，优先级字段会被省略，Opsgenie 将应用其自身的默认值（`P3`）。

### 状态映射详情

Opsgenie 告警的状态为 `open` 或 `closed`，处于 `open` 状态的告警还可以进一步被标记为 `acknowledged`：

- **状态字段名称**：`Status`
- **活动映射**：`open`
- **已关闭映射**：`closed`
- **误报映射**：`closed`
- **风险已接受映射**：`acknowledged`

请注意，`closed` 在 Opsgenie 中是一个最终状态——已关闭的告警无法重新打开，其别名也会被释放。与其他一些工具不同，Opsgenie 确实允许在创建后编辑内容，因此推送更新后的发现项时，会将其消息、描述和优先级与状态一并同步。

DefectDojo 会将每个告警的**别名**设置为一个从该发现项或发现项组派生出的稳定键，而 Opsgenie 会按别名对处于打开状态的告警进行去重——因此重新推送同一个发现项时，会更新现有的打开状态告警，而不会创建重复项。

## PagerDuty

PagerDuty 集成允许您将 DefectDojo 的发现项和发现项组作为 PagerDuty 事件推送，并在您选择的 PagerDuty 服务上创建。

### 实例设置

- **标签**应为您希望用来标识此集成的标签。
- **位置**应设置为 `https://api.pagerduty.com`。如果您的 PagerDuty 账户托管在欧盟服务区域，请改用 `https://api.eu.pagerduty.com`。
- **API 令牌**应设置为一个 PagerDuty REST API 密钥。账户管理员可以在 PagerDuty 网页应用的**集成 > API 访问密钥 > 创建新 API 密钥**下创建。请不要勾选“只读”——DefectDojo 需要创建和更新事件。
- **发件人电子邮件**应为您 PagerDuty 账户中某个有效用户的电子邮件地址。PagerDuty 在创建或更新事件时需要此地址，并会将其显示为事件的发起人。

### 问题跟踪器映射

- **服务 ID**应为将在其上创建事件的 PagerDuty 服务的 ID。您可以在 PagerDuty 中查看该服务时，从其 URL 末尾找到该 ID，例如 `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`。

### 严重程度映射详情

默认情况下，此项映射到 PagerDuty 事件的**紧急程度**字段，该字段仅接受 `high` 或 `low`：

- **严重程度字段名称**：`Urgency`
- **信息映射**：`low`
- **低映射**：`low`
- **中映射**：`low`
- **高映射**：`high`
- **严重映射**：`high`

另外，如果您的 PagerDuty 账户启用了[优先级](https://support.pagerduty.com/main/docs/incident-priority)功能，您也可以改为将严重程度映射到优先级名称。此时请将**严重程度字段名称**设置为 `Priority`，并使用您账户中的优先级名称（例如 `P1` 到 `P5`）作为映射值。映射到优先级时，事件的紧急程度将由您服务自身的紧急程度规则决定。

### 状态映射详情

PagerDuty 事件有三种状态：`triggered`、`acknowledged` 和 `resolved`。

- **状态字段名称**：`Status`
- **活动映射**：`triggered`
- **已关闭映射**：`resolved`
- **误报映射**：`resolved`
- **风险已接受映射**：`acknowledged`

请注意，`resolved` 在 PagerDuty 中是一个最终状态——已解决的事件无法重新打开。另请注意，PagerDuty 不允许在创建后编辑事件的标题或描述，因此推送更新后的发现项只会同步其状态、紧急程度和优先级，而不会同步内容上的更改。

## ServiceNow

ServiceNow 集成允许您将 DefectDojo 发现项推送为 ServiceNow 事件(Incident)。

### 实例设置

DefectDojo 通过 OAuth 2.0 对 ServiceNow 进行身份验证。创建 OAuth 凭据的方式取决于您所使用的 ServiceNow 版本——较新的版本(Zurich 及更高版本)使用客户端凭据授权,较早的版本则使用刷新令牌。

#### ServiceNow Zurich 及更高版本(客户端凭据)

较新的 ServiceNow 版本已弃用经典的“Create an OAuth API endpoint for external clients”选项,改为使用 **New Inbound Integration Experience**,该功能会签发绑定到某个服务账号的 OAuth **客户端凭据** 授权:

1. 在左侧导航栏中搜索“Application Registry”并选中它。
2. 点击 **New**,然后选择 **New Inbound Integration Experience**。
3. 选择 **New Integration → OAuth - Client credentials grant**。
4. 将 **OAuth Application User** 设置为将要创建事件的服务账号。该账号的角色决定了 DefectDojo 被允许写入的内容。
5. 保存该注册信息。ServiceNow 会自动生成**客户端 ID**和**客户端密钥**(创建注册信息时请将这两个字段留空)。

然后,在 DefectDojo 中:

- **实例标签**应设置为您想用来标识此集成的标签。
- **地址**应设置为您的 ServiceNow 服务器的 URL,例如 `https://your-organization.service-now.com/`。
- **客户端 ID** 应为该 OAuth 注册信息中的客户端 ID。
- **客户端密钥** 应为该 OAuth 注册信息中的客户端密钥。

将刷新令牌、用户名和密码字段留空——DefectDojo 会在每次同步时请求一个全新的客户端凭据令牌。

#### 更早的 ServiceNow 版本(刷新令牌)

在仍提供经典注册方式的版本上,获取一个与将要向 ServiceNow 推送事件的用户或服务账号相关联的刷新令牌:

1. 在左侧导航栏中搜索“Application Registry”并选中它。
2. 点击“New”。
3. 选择“Create an OAuth API endpoint for external clients”。
4. 填写必填字段:
    * Name:为您的应用程序提供一个有意义的名称(例如 Vulnerability Integration Client)。
    * (可选)调整令牌有效期:
    * Access Token Lifespan:默认值为 1800 秒(30 分钟)。
    * Refresh Token Lifespan:默认值为 8640000 秒(约 100 天)。
5. 点击 Submit 以创建该应用程序记录。
6. 提交后,从列表中选中该应用程序,并记下**客户端 ID 和客户端密钥**字段。

接下来,您需要使用此注册信息获取一个刷新令牌,该令牌只能通过 ServiceNow API 获取。打开一个终端窗口并粘贴以下内容(将 `{{}}` 中包裹的变量替换为您用户的实际信息)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

如果您的 ServiceNow 凭据正确,且具备 ServiceNow 的管理员级别访问权限,您应该会收到一个包含 RefreshToken 的响应。完成与 DefectDojo 的集成需要用到该令牌。

- **实例标签**应设置为您想用来标识此集成的标签。
- **地址**应设置为您的 ServiceNow 服务器的 URL,例如 `https://your-organization.service-now.com/`。
- **刷新令牌**是应填入该刷新令牌的位置。
- **客户端 ID** 应为 OAuth 应用注册信息中设置的客户端 ID。
- **客户端密钥** 应为 OAuth 应用注册信息中设置的客户端密钥。

### 严重程度映射详情

这会映射到 ServiceNow 的 Impact 字段。
- **信息映射**:`1`
- **低映射**:`1`
- **中映射**:`2`
- **高映射**:`3`
- **严重映射**:`3`

### 状态映射详情

- **状态字段名称**:`State`
- **活动映射**:`New`
- **已关闭映射**:`Closed`
- **误报映射**:`Resolved`
- **风险已接受映射**:`Resolved`

每个映射可以接受一个标准状态标签(`New`、`In Progress`、`On Hold`、`Resolved`、`Closed`、`Cancelled`)或一个数字状态值。在事件状态经过自定义的实例上——或目标表不是 `incident` 时——请使用您实例选择列表中的数字**状态值**;不在标准集合内的数字值会按配置原样发送给 ServiceNow。内置的 Resolution code 默认值只会随标准的已解决/已关闭状态一起发送,因此请将自定义状态值与下方的关闭及解决字段映射搭配使用。

### 关闭与解决字段

部分 ServiceNow 实例强制执行一项数据策略(Data Policy),使得诸如 **Resolution code**(`close_code`)之类的字段在事件转为已解决或已关闭状态时成为必填项。如果 DefectDojo 在未提供这些字段的情况下关闭某个事件,ServiceNow 会以 HTTP 403 *“Data Policy Exception”* 拒绝该写入操作,原因会记录在该集成的 Errors 视图中。

使用**自定义字段映射**将所需字段附加到状态变更上,并将 **Apply On** 设置为应携带这些字段的处置结果:

- **Transition to Closed** — 在发现项被缓解/关闭时发送。
- **Transition to False Positive** — 在发现项被标记为误报时发送。
- **Transition to Risk Accepted** — 在发现项的风险被接受时发送。

例如,要满足必填的 Resolution code:

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

说明:

- Field Name 是 ServiceNow 的列名——`close_code`、`close_notes`,或自定义的 `u_...` 字段。
- 转换类映射会在记录状态实际发生变化时触发:发现项在首次推送时就已关闭、某次更新使记录关闭或重新打开,以及删除工单关联时的强制关闭。这些映射不会在未变更记录的例行更新中重复发送,因此像 `work_notes` 这样的日志(journal)字段每次转换只会收到一条记录。
- `assignment_group` 和 `assigned_to` 等引用字段需要的是 **sys_id**,而不是显示名称。
- 可解析为 JSON 的值会按类型发送:`true`、`42`、`[...]`、`{...}`——以及会清空该字段的 `null`。若要将此类文本作为字面字符串发送,请用双引号将其括起来(例如 `"null"`)。
- `short_description`、`description`、`state`、`impact`、`urgency` 和 `priority` 由描述模板以及严重程度/状态映射所掌控,因此无法通过自定义字段映射来设置。
- 在 `incident` 以外的表上,与标准事件集合相匹配的状态值(`1`、`2`、`3`、`6`、`7`、`8`)仍会按照事件语义进行解释——包括在 `6`/`7`/`8` 上自动附加 Resolution code 默认值。建议在自定义表上使用该范围之外的状态值,或者像上文那样显式提供关闭字段。

## ServiceNow SecOps

ServiceNow SecOps 集成(也称为 **ServiceNow SecOps / Vulnerability Response**)会将 DefectDojo 的发现项和发现项组推送到 ServiceNow 的某个安全表中——**安全事件**(`sn_si_incident`)或**漏洞项**(`sn_vul_vulnerable_item`)——并随着发现项的变化(创建、更新、解决/关闭)保持同步。它是上文 ServiceNow 问题跟踪器集成在安全运营方面的对应产品;当您运行 Security Incident Response(SIR)或 Vulnerability Response(VR)应用程序时,请使用 ServiceNow SecOps。

### 实例设置

- **实例标签**应设置为您想用来标识此集成的标签。
- **地址**应设置为您的 ServiceNow 服务器的 URL,例如 `https://your-organization.service-now.com/`。

ServiceNow SecOps 支持三种身份验证方式,请提供**其中一种**:

- **OAuth 2.0** — 输入**客户端 ID**、**客户端密钥**和**刷新令牌**。获取方式与上文 [ServiceNow](#servicenow) 一节所述完全相同(在 Application Registry 中创建一个 OAuth API 端点,然后在 `/oauth_token.do` 处用您的凭据换取刷新令牌)。您也可以提供**客户端 ID**和**客户端密钥**,并配合**用户名**与**密码**,使用 OAuth 密码授权方式来代替刷新令牌。
- **API 密钥** — 输入一个 **API 密钥**,它会以 `x-sn-apikey` 请求头的形式发送。在该实例上为此密钥关联一个 Inbound Authentication Profile 和一个 REST API Access Policy 之前,该密钥不会对任何内容进行身份验证。
- **HTTP Basic** — 输入该服务账号的**用户名**和**密码**。

该服务账号(或 OAuth 客户端)需要对目标表具有写入权限。

### 问题跟踪器映射

- **目标表**用于选择记录将写入的 ServiceNow 表:**安全事件**(`sn_si_incident`,默认值)或**漏洞项**(`sn_vul_vulnerable_item`)。

### 严重程度映射详情

对于安全事件,这会映射到 **Impact** 字段;ServiceNow 会根据 Impact 和 Urgency 推导出事件的 Priority,因此除非您自行映射 Urgency,否则它会与映射后的 Impact 保持一致。对于漏洞项,请将严重程度映射到您实例所使用的风险字段。下面的默认值与标准 SIR 的 Impact 等级(`1` High、`2` Medium、`3` Low)相对应,且可以编辑。

- **严重程度字段名称**:`impact`
- **信息映射**:`3`
- **低映射**:`3`
- **中映射**:`2`
- **高映射**:`1`
- **严重映射**:`1`

### 状态映射详情

这会映射到记录的 **State** 字段。State 的取值为数字代码,在安全事件表和漏洞项表之间有所不同,并且可按实例自定义,因此请对照您自己的配置核对这些值。下面的默认值使用标准的 SIR 状态代码(`16` Analysis、`3` Closed)。

- **状态字段名称**:`state`
- **活动映射**:`16`
- **已关闭映射**:`3`
- **误报映射**:`3`
- **风险已接受映射**:`3`

当某条记录被关闭时,DefectDojo 还会设置 ServiceNow 的 **Close Code** 和 **Close Notes**(已关闭的发现项对应 `Resolved`,误报和风险已接受这两种状态分别对应 `False positive` 和 `Risk accepted`)。

### ServiceNow SecOps 特有行为

- **去重** — 每条记录都会在其 `correlation_id` 中标记上该发现项或发现项组的 DefectDojo 标识符。DefectDojo 在创建记录之前会先按 `correlation_id` 进行查找;若找到匹配项,则会采用并更新该记录而不是重复创建,因此重新同步具有幂等性。
- **更新**会发布到该记录的 **Work notes** 日志(仅内部可见),而不会发布到客户可见的 Comments 中。
- **删除时解决** — 在 DefectDojo 中删除某个发现项时,会解决/关闭对应的 ServiceNow 记录(State + Close Code),而不是将其删除;记录永远不会被硬删除。
- **引用字段** — 可选字段 `cmdb_ci`、`assignment_group` 和 `assigned_to` 的值可以以显示名称的形式提供,DefectDojo 会将每个值解析为对应的 `sys_id`。无法解析的名称会被丢弃并给出警告,而不会导致本次推送失败。

## Shortcut

Shortcut 集成允许您将 DefectDojo 发现项推送为 [Shortcut](https://www.shortcut.com/) 的 Story。Story 会以 Bug 这一 story type 创建,并分配给您 Shortcut 工作区中的一个 Team。

### 实例设置

- **标签**应设置为您想用来标识此集成的标签。
- **地址**应设置为 `https://api.app.shortcut.com`。
- **API 令牌**应设置为一个 Shortcut API 令牌。可以在 Shortcut 中依次进入 Settings、Your Account、[API Tokens](https://app.shortcut.com/settings/account/api-tokens) 来生成令牌。

### 问题跟踪器映射

- **Team(组)ID** 应设置为将要为其创建 Story 的 Shortcut Team 的 UUID。您可以通过在 Shortcut 中打开该 Team 的页面并从 URL 中复制标识符来找到此 UUID,也可以通过调用 Shortcut API 来获取:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### 严重程度映射详情

每个严重程度值都会作为标签应用到 Story 上。如果 Shortcut 中尚不存在相应标签,会自动创建,因此下面的默认值可以直接使用,也可以替换为您自己选择的标签名称。当某个发现项的严重程度发生变化时,Story 上旧的严重程度标签会被移除,并添加新的标签。

- **严重程度字段名称**:`Label`
- **信息映射**:`sev-info`
- **低映射**:`sev-low`
- **中映射**:`sev-medium`
- **高映射**:`sev-high`
- **严重映射**:`sev-critical`

### 状态映射详情

每个状态值都必须设置为您 Shortcut 工作区中某个 Workflow State 的数字 ID。Workflow State ID 在每个工作区中都是唯一的,因此没有默认值。您可以通过调用 Shortcut API 来列出所有 Workflow State 及其 ID:

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **状态字段名称**:`Workflow State ID`
- **活动映射**:用于未完成工作的状态 ID,例如 Backlog 或 To Do 状态。
- **已关闭映射**:某个 Done 类型状态的 ID。当某个发现项在 DefectDojo 中被删除时,其 Story 会被移动到此状态。
- **误报映射**:用于误报发现项的状态 ID。
- **风险已接受映射**:用于风险已接受发现项的状态 ID。

## Freshservice

Freshservice 集成允许您将 DefectDojo 发现项和发现项组推送为 Freshservice 工单,并分配给您指定的代理组。

### 实例设置

- **标签**应设置为您想用来标识此集成的标签。
- **地址**应设置为您的 Freshservice URL:`https://yourcompany.freshservice.com`。
- **API 密钥**应为一个 Freshservice API 密钥。获取方式是点击右上角的头像 > **Profile settings**,完成验证码验证后,该密钥会显示在右侧 **Delegate Approvals** 部分下方。如果那里没有显示密钥,说明账号级别可能已禁用 API 访问,需要先由管理员启用。
- **请求者邮箱**应为代表其发起工单请求的邮箱地址。Freshservice 要求每个工单都有一个请求者,因此 DefectDojo 会以此邮箱地址作为请求者来创建工单。

### 问题跟踪器映射

- **组 ID** 应为工单将被分配到的 Freshservice 代理组的数字 ID。可以在 **Admin > Agent Groups** 下查看该组时从 URL 中找到它。
- **工作区 ID**(可选)会在多工作区账号中将工单路由到指定的工作区。留空则使用主工作区。

### 严重程度映射详情

这会映射到 Freshservice 工单的 **Priority** 字段,该字段使用数字代码(`1` Low、`2` Medium、`3` High、`4` Urgent)。也可以使用优先级名称:

- **严重程度字段名称**:`Priority`
- **信息映射**:`1`
- **低映射**:`1`
- **中映射**:`2`
- **高映射**:`3`
- **严重映射**:`4`

### 状态映射详情

这会映射到工单的 **Status** 字段,该字段使用数字代码(`2` Open、`3` Pending、`4` Resolved、`5` Closed)。也可以使用状态名称:

- **状态字段名称**:`Status`
- **活动映射**:`2`
- **已关闭映射**:`5`
- **误报映射**:`5`
- **风险已接受映射**:`3`

以下是一些需要注意的 Freshservice 特有行为:

- 更新会同步完整的工单内容——Freshservice 允许在创建后编辑主题和描述。
- 发现项被移除时,工单会被关闭而不是删除;已经处于 Resolved 或 Closed 状态的工单不会被改动。关闭时会自动附加一条解决说明,因此对此有强制要求的账号(一种常见的业务规则)会接受该关闭操作。
- 部分账号会根据 Impact/Urgency 矩阵或某项业务规则来计算工单的优先级,而忽略创建时发送的优先级。DefectDojo 会检测到这种情况,并通过一次后续更新重新应用映射后的优先级,因此映射仍然会生效。

## ServiceDesk Plus

ManageEngine ServiceDesk Plus 集成允许您将 DefectDojo 发现项和发现项组推送为 ServiceDesk Plus 请求,并分配给您指定的支持组。**云端**版(ServiceDesk Plus OnDemand)和**本地部署**版由同一个集成支持——您提供的凭据决定了使用哪种模式。

### 实例设置

- **标签**应设置为您想用来标识此集成的标签。
- **地址**应设置为您的 ServiceDesk Plus URL:云端版为 `https://sdpondemand.manageengine.com`(或您所在区域的对应地址),本地部署安装则为您服务器的地址。

然后提供以下两套凭据中的**一套**:

#### 本地部署:技术员密钥

- **技术员密钥**应为在您服务器的 **Admin > General Settings > API** 下为某个技术员生成的 API 密钥。请将 Zoho OAuth 相关字段留空。

#### 云端:Zoho OAuth

云端版通过 Zoho Accounts OAuth 进行身份验证:

1. 打开 [Zoho API Console](https://api-console.zoho.com/) 并创建一个 **Self Client**。
2. 记下**客户端 ID**和**客户端密钥**。
3. 在该 Self Client 的“Generate Code”标签页中,输入作用域 `SDPOnDemand.requests.ALL`,选择有效期,然后生成代码。
4. 用该代码换取刷新令牌:

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. 在实例表单中输入**客户端 ID**、**客户端密钥**以及返回的**刷新令牌**。如果您的账号托管在美国数据中心以外,请将**令牌 URL**设置为您所在区域的 Zoho Accounts 端点(例如 `https://accounts.zoho.eu/oauth/v2/token`)。

### 问题跟踪器映射

- **组名称**应为请求将被分配到的 ServiceDesk Plus 支持组的名称,须与其在 **Admin > Users > Support Groups** 下显示的名称完全一致。

### 严重程度映射详情

这会按名称映射到 ServiceDesk Plus 请求的 **Priority** 字段,使用您账号中的优先级名称:

- **严重程度字段名称**:`Priority`
- **信息映射**:`Low`
- **低映射**:`Normal`
- **中映射**:`Medium`
- **高映射**:`High`
- **严重映射**:`High`

### 状态映射详情

这会按名称映射到请求的 **Status** 字段。默认值使用内置状态:

- **状态字段名称**:`Status`
- **活动映射**:`Open`
- **已关闭映射**:`Closed`
- **误报映射**:`Closed`
- **风险已接受映射**:`On Hold`

以下是一些需要注意的 ServiceDesk Plus 特有行为:

- 更新会同步完整的请求内容——与大多数问题跟踪器不同,ServiceDesk Plus 允许在创建后编辑主题和描述。
- 发现项被移除时,请求会被关闭而不是删除;已经处于 Closed 或 Resolved 状态的请求不会被改动。
- 如果您的账号要求在关闭时必须填写某些字段(例如解决方案),DefectDojo 推送的关闭操作可能会被这些规则拒绝,并会显示在 Integration errors 表中。

## Zendesk

Zendesk 集成允许您将 DefectDojo 发现项和发现项组推送为 Zendesk 工单,并分配给您指定的 Zendesk Group。

### 实例设置

- **标签**应设置为您想用来标识此集成的标签。
- **地址**应设置为您的 Zendesk 账号 URL,例如 `https://your-subdomain.zendesk.com`。
- **邮箱**应为该 API 令牌所属的 Zendesk 代理的电子邮件地址。
- **API 令牌**应设置为一个 Zendesk API 令牌。管理员可以在 Zendesk Admin Center 的 **Apps and integrations > APIs > Zendesk API** 下创建令牌(必须先启用令牌访问)。

### 问题跟踪器映射

- **组 ID** 应为工单将被分配到的 Zendesk Group 的数字 ID。您可以在 Admin Center 的 **People > Team > Groups** 下找到它,或在查看该组时从 URL 中找到。

### 严重程度映射详情

这会映射到 Zendesk 工单的 **Priority** 字段,该字段接受 `low`、`normal`、`high` 和 `urgent`:

- **严重程度字段名称**:`Priority`
- **信息映射**:`low`
- **低映射**:`low`
- **中映射**:`normal`
- **高映射**:`high`
- **严重映射**:`urgent`

### 状态映射详情

Zendesk 工单支持 `new`、`open`、`pending`、`hold`、`solved` 和 `closed` 这些状态。请注意,`hold` 必须先在您的账号上启用才能使用。

- **状态字段名称**:`Status`
- **活动映射**:`new`
- **已关闭映射**:`solved`
- **误报映射**:`solved`
- **风险已接受映射**:`pending`

以下是一些需要注意的 Zendesk 特有行为:

- 工单描述在 Zendesk 中是第一条评论,创建后无法编辑,因此推送发现项的更新只会同步工单的主题、优先级和状态,而不会同步描述内容的变更。
- 发现项被移除时,工单会被标记为 `solved` 而不是删除;Zendesk 会在一段时间后自动关闭已解决(solved)的工单。
- `closed` 是一个最终状态——已关闭的工单完全无法再更新,如果推送的发现项所对应的工单已关闭,将会报告一个错误。
