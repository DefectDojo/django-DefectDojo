---
title: 上游连接器工具参考
description: 我们支持的连接器工具列表，以及如何在 DefectDojo 中完成设置
aliases:
- /zh-hans/import_data/pro/connectors/connectors_tool_reference/
- /zh-hans/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：上游连接器是 DefectDojo Pro 专属功能。</span>

在为受支持的工具设置连接器时，您需要向 DefectDojo 提供与该工具 API 相关的特定信息。基本上，您需要：

* **位置** ——该字段通常是指此工具在您网络中的 URL，
* **密钥** ——通常是一个 API 密钥。

部分工具除**位置**和**密钥**外，还需要提供额外的 API 相关字段，也可能要求您在其系统一侧进行相应设置，以便接受来自 DefectDojo 的连接器接入。

![图片](images/connectors_tool_reference.png)

每种工具的 API 配置方式各不相同，本指南旨在帮助您设置该工具的 API，以便 DefectDojo 能够与之建立连接。

如条件允许，我们建议您在所使用的安全工具中新建一个"DefectDojo Bot"账户，专供该连接器使用。这样可以更清楚地区分团队成员手动执行的操作与连接器自动执行的操作。

# **资产连接器**

大多数连接器从安全工具中导入**发现项**。**资产连接器**的工作方式则不同：它们导入的是您的**资产清单**。资产连接器会枚举外部平台中存在的资产（例如 GitLab 群组中的仓库），并在 DefectDojo 中自动创建和维护相应的**产品**（资产）与**产品类型**（组织）。资产连接器不会导入任何发现项。

* **发现**与**同步**都会对资产列表进行协调。新资产会以 `NEW` 记录的形式出现；一旦完成映射（如果启用了自动映射，则会自动完成），DefectDojo 便会创建相应产品，并将其归入一个从该工具派生出的产品类型下——例如 GitLab 的命名空间或 Azure DevOps 的项目。
* 如果某个资产之后在上游被移除（例如某个仓库被删除），其对应的已映射记录会在下一次同步时被标记为 `MISSING`，以便您的团队进行处理。DefectDojo 绝不会静默删除某个产品。

Azure DevOps、Backstage、Bitbucket、GitHub、GitLab、Jira Service Management Assets 以及 ServiceNow CMDB 均为资产连接器。runZero 主要是一个资产连接器，但也可以选择将漏洞作为发现项导入。下面列出的其他所有连接器均导入发现项。

# **支持的连接器**

## **Acunetix 360**

Acunetix 360 连接器从 Acunetix 360 云平台（Invicti 平台）导入 **DAST 漏洞发现项**。DefectDojo 会发现您账户下已扫描的网站，并为每个**网站**创建一条记录；某个网站的发现项来自其最近一次已完成的扫描。

**请注意：** 此连接器适用于 **Acunetix 360**（即 `online.acunetix360.com` 上的云产品），不适用于本地部署的 Acunetix Standard/Premium 扫描器，后者使用不同的 API。

#### 前提条件

一个 Acunetix 360 账户和一个 **API 凭据**：在 Acunetix 360 中，打开您的账户菜单 \> **API Settings**，记下 **API User ID** 并生成一个 **API Token**。该连接器会以 HTTP Basic 凭据的形式使用这两项进行身份验证，因此建议使用专用服务账户，以便将自动化操作与团队的手动操作区分开来。

#### 连接器映射

1. 在**位置**字段中输入您的 Acunetix 360 URL：`https://online.acunetix360.com`。
2. 在 **API User ID** 字段中输入 API 用户 ID。
3. 在 **API Token** 字段中输入 API 令牌。
4. （可选）设置**最低严重程度**以限制导入的发现项范围。

每个已扫描的网站都会成为一条记录。发现项来自该网站最近一次已完成的扫描；Acunetix 360 中已标记为**风险已接受**或**误报**的漏洞仍会被导入，但会被标记为非活动状态（风险已接受或误报），以便 DefectDojo 中的产品数据能够反映供应商一方的处理结果。

## **Akamai API Security**

Akamai API Security 连接器使用 API 密钥从 Akamai API 中提取安全发现项。DefectDojo 会发现您的 Akamai 环境，并为您账户中配置的每个**应用程序**和**主机**分别创建独立的记录。

#### 前提条件

您需要一个可访问 Akamai API 的 API 密钥。我们建议为 DefectDojo 创建一个专用服务账户，以便清楚区分自动化操作与团队的手动操作。

#### 连接器映射

1. 在**位置**字段中输入您的 Akamai API 基础 URL。该 URL 因您的 Akamai 实例而异，例如
2. 在**密钥**字段中输入有效的 **API 密钥**。

DefectDojo 会将**应用程序**和**主机**分别映射为独立的记录。每个应用程序都会在您的记录列表中显示为 `{name} (application)`，每个主机则显示为 `{name} (host)`。

## **Anchore**

Anchore 连接器使用用户的 API 令牌从 Anchore Enterprise 中提取数据。产品会根据 "Applications" 进行映射和发现，"Applications" 由 Anchore 中的多个 Image 组成——更多信息请参阅 [Anchore Enterprise 文档](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/)。

#### 连接器映射

1. 在**位置**字段中填写 Anchore URL：即您访问 Anchore 的 URL。
2. 在**密钥**字段中输入有效的 API 密钥。这是与您的 Burp 服务账户关联的 API 密钥。

如需了解为 Anchore 创建令牌的更多信息，请参阅官方 [Anchore 文档](https://docs.anchore.com/current/docs/)。

## **AWS Security Hub**

AWS Security Hub 连接器使用 AWS 访问密钥与 Security Hub API 进行交互。

#### 前提条件

我们建议您在 AWS 账户中专门为 DefectDojo 创建一个 IAM 用户，并将该用户的权限限制为与 Security Hub 交互所需的最小权限，而不要使用团队成员个人的 AWS 访问密钥。

AWS 的"**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)** 策略"即可为连接器提供所需的访问级别。如果您想为连接器编写自定义策略，则需要包含以下权限：

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

一个可用的策略定义示例如下：

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**请注意：** 为了在未来提供最佳体验，我们可能需要使用额外的 API 操作，这将需要对此策略进行更新。

创建 IAM 用户并通过适当的策略/角色为其分配必要权限后，您需要生成一个访问密钥，然后使用该访问密钥创建连接器。

#### 连接器映射

1. 在**位置**字段中输入适用于您所在区域的 [AWS API 端点](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region)**：** 例如，若要获取 `us-east-1` 区域的结果，您应填写

`https://securityhub.us-east-1.amazonaws.com`
2. 在**访问密钥**字段中输入有效的 **AWS 访问密钥**。
3. 在**私密密钥**字段中输入匹配的**私密密钥**。

DefectDojo 可以借助 Security Hub 的**跨区域聚合**功能从多个区域拉取发现项。如果已启用[跨区域聚合](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html)，您应提供**聚合区域**对应的 API 端点。其他关联区域会根据您的 AWS 账户 ID 和区域名称，在 DefectDojo 中创建相应的 ProductRecords。

## **Azure DevOps**

Azure DevOps 连接器是一个**资产连接器**：它会枚举您 Azure DevOps 组织中每个项目下的 git 仓库，并为每个仓库创建一个 DefectDojo 资产，按 Azure DevOps 项目分组到相应组织下。系统不会导入任何发现项。

#### 前提条件

您需要为该组织提供一个个人访问令牌（PAT）。我们建议使用专用服务账户生成该令牌。只需具备只读权限范围即可：

1. 在 Azure DevOps 中，打开 **User settings \> Personal access tokens \> New Token**。
2. 点击 **Show all scopes**，然后选择 **Code: Read** 和 **Project and Team: Read**。

目前仅支持 Azure DevOps Services（dev.azure.com），暂不支持本地部署的 Azure DevOps Server。

#### 连接器映射

1. 在**位置**字段中输入您的组织 URL：`https://dev.azure.com/{your-organization}`。系统同样接受旧版 `https://{your-organization}.visualstudio.com` 格式的 URL，并且会忽略任何额外的路径部分（例如指向特定项目的链接）。
2. 在**密钥**字段中输入该 PAT。

每个仓库都会成为一条以该仓库命名的记录，并按其所属的 Azure DevOps **项目**进行分组。已停用的仓库会被跳过，因此停用或删除某个仓库会导致其记录在下一次同步时被标记为 `MISSING`。

## **Backstage**

Backstage 连接器是一个**资产连接器**：它不导入发现项，而是将您的 [Backstage](https://backstage.io) 软件目录拉取到 DefectDojo 中，并使您的产品层级结构和团队所有权与之保持同步。它专为那些在 Backstage 中维护服务清单和组织结构、并希望 DefectDojo 镜像该结构而非手动维护的组织而设计。

#### 映射内容

| Backstage | DefectDojo |
|---|---|
| **System** | 产品类型（没有 System 的组件会被归入一个可配置的 "Backstage / Uncategorized" 产品类型下） |
| **Component** | 产品——根据实体的 `title` 命名（回退到 `name`），并带有目录中的描述 |
| **Owning Group**（`ownedBy` 关系） | 与该产品关联的 DefectDojo 组（默认角色：Maintainer，可配置） |
| **Owner email**（组的个人资料邮箱，或某个用户所有者的邮箱） | 一个产品成员——前提是已存在使用该邮箱地址的 DefectDojo 用户（系统绝不会自动创建用户） |
| `metadata.tags`、`spec.type`、`spec.lifecycle`、命名空间、域 | 带有 `backstage:` 前缀的产品标签 |
| `metadata.annotations` | 存储在该记录上（有长度限制）；可以通过**注释映射**将部分注释提升为一级属性或标签 |

记录以该实体由服务器分配的 `metadata.uid` 作为键，因此 Backstage 中的重命名操作会在下一次同步时**原地**更新已映射的产品——不会产生重复项。产品名称会始终跟随目录变化：若要重命名由该连接器管理的产品，应在 Backstage 中重命名相应的组件（在 DefectDojo 一侧所做的重命名，或在人工映射时指定的自定义名称，只要不会与其他产品冲突，就会在下一次同步时被还原为目录中的名称）。所有权变更会相应调整产品的组分配。从目录中消失的组件（或被标记了 `backstage.io/orphan` 注释的组件）会被标记为 `MISSING`——DefectDojo 不会自行删除任何产品。域和组的层级结构（上级团队）仅作为标签/元数据被记录，不会创建额外的层级。

#### 前提条件

该连接器通过针对 Backstage 后端的**静态外部访问令牌**进行身份验证。请在您的 Backstage 应用配置中定义一个令牌，并（建议）将其限制在 catalog 插件范围内：

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

生成一个强随机令牌（例如使用 `openssl rand -hex 32`），并将其保存在您 Backstage 部署环境的环境变量中。详情请参阅 [Backstage 服务间身份验证文档](https://backstage.io/docs/auth/service-to-service-auth)。

#### 连接器映射

1. 在**位置**字段中输入您的 **Backstage 后端根 URL**，例如 `https://backstage.example.com`（该连接器会自动附加 `/api/catalog`）。此处必须填写**后端** URL，而不是前端 Web 界面的地址。
2. 在**密钥**字段中输入该静态外部访问令牌。

可选字段（留空则使用默认值）：

* **命名空间** —— 以逗号分隔的目录命名空间列表，用于指定要导入的内容；留空则导入所有命名空间。
* **组件类型** —— 以逗号分隔的 `spec.type` 值（例如 `service,website`）；留空则导入所有类型。
* **页面大小** —— 目录查询的分页大小（1-500，默认值为 250）。
* **TLS 验证** —— 仅当 Backstage 提供的证书 DefectDojo 无法验证时（例如内部 CA），才应将其设为 `false`；不建议这样做。
* **未分类产品类型** —— 用于没有 System 的组件的产品类型（默认值为 `Backstage / Uncategorized`）。
* **所有者组角色** —— 授予拥有团队在已映射产品上的角色（默认值为 `Maintainer`）。
* **注释映射** —— 一个 JSON 对象，将注释键映射到记录属性名称，或映射到 `"tag"` 以将某注释作为产品标签导入，例如 `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`。

启用**自动映射**后，一次发现 + 同步操作即可自动构建完整的产品类型/产品/所有权结构，无需任何人工步骤。禁用自动映射时，已发现的组件会以记录形式出现，等待您进行映射决策。

#### 限制 (v1)

* Backstage 的**组成员关系不会被同步**：该连接器会将所属团队创建/关联为一个 DefectDojo 组，但该组用户的填充工作则留给您的身份提供方或管理员处理。
* 只有组件才会成为产品；API、资源和域不会作为资产被导入（域会以标签形式呈现）。
* 标签和注释会被规范化处理，并被限制在 DefectDojo 的字段长度限制内（超长的值会被截断）。

**关于反向方向的说明：** 在 Backstage *内部*（在实体页面上）展示 DefectDojo 的发现项和评级是一个自然而然的后续方向，可以构建为一个消费 DefectDojo REST API 的 Backstage 前端插件——但这有意不在本连接器的范围内，本连接器只负责将目录数据拉取到 DefectDojo 中。

## **Black Duck**

Black Duck 连接器从 Black Duck（Synopsys / Black Duck）Hub 实例中导入**软件成分分析 (SCA)** 发现项。DefectDojo 会发现该实例中的每个项目，并为每个**项目**创建一条记录；某个项目的发现项来自其所选版本中存在漏洞的 BOM 组件。

#### 前提条件

需要一个 Black Duck **API 令牌**，该令牌所属用户须能够查看您想要导入的项目。在 Black Duck 中，打开您的用户菜单 \> **My Access Tokens** \> **Create New Token**，为其授予（至少）读取权限，并在令牌显示时立即复制——它只会显示一次。该连接器会在每次同步时用此令牌换取一个短期持有者令牌；除了连接器自身的密钥字段外，该令牌不会以明文形式存储。

#### 连接器映射

1. 在**位置**字段中输入您的 Black Duck hub URL——例如 `https://your-company.app.blackduck.com`。
2. 在**密钥**字段中输入该 API 令牌。
3. （可选）设置**最低严重程度**以限制导入的发现项范围。

每个 Black Duck 项目都会成为一条记录。默认情况下，连接器会导入该项目的**已发布版本**（若无已发布版本，则回退到其第一个版本）；该版本中每个存在漏洞的 BOM 组件都会成为一条发现项，标题格式为 `{vulnerability} in {component}:{version}`。

该连接器不同于基于文件的 Black Duck 解析器——其发现项使用专用的 **Black Duck - Connectors Import** 扫描类型。

## **Bitbucket**

Bitbucket 连接器是一个**资产连接器**：它会枚举您指定的 Bitbucket Cloud 工作区中的仓库，并为每个仓库创建一个 DefectDojo 资产，按 Bitbucket 项目分组到相应组织下。系统不会导入任何发现项。

#### 前提条件

Bitbucket Cloud 需要使用限定了作用域的 Atlassian API 令牌——经典（未限定作用域）的 Atlassian API 令牌会被 Bitbucket 拒绝，并提示 "API Token provided has no Bitbucket scopes" 错误。

1. 前往 [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)，选择 **Create API token with scopes**。
2. 选择 **Bitbucket** 应用，然后授予以下只读作用域：`read:account:bitbucket`、`read:workspace:bitbucket`、`read:repository:bitbucket` 和 `read:project:bitbucket`。

目前仅支持 Bitbucket Cloud（bitbucket.org）。Bitbucket Server 已于 2024 年停止支持，Bitbucket Data Center 目前也不受支持。

#### 连接器映射

1. 在**位置**字段中输入 `https://bitbucket.org`。
2. 在**电子邮箱**字段中输入该令牌所属的 Atlassian 账户邮箱。
3. 在**密钥**字段中输入该限定范围的 API 令牌。
4. 在**工作区 Slug**字段中输入一个或多个工作区 slug（以逗号分隔）。此字段为必填项：Bitbucket 的限定范围 API 令牌无法自动列出工作区，因此需要告知 DefectDojo 应读取哪些工作区。

每个仓库都会成为一条以该仓库命名的记录，并按其所属的 Bitbucket **项目**进行分组。

## **Bugcrowd**

Bugcrowd 连接器使用 Bugcrowd REST API，从您的漏洞赏金和漏洞披露计划中导入提交内容。DefectDojo 会发现您的 API 令牌可访问的各个计划，并为每个计划创建一条记录，将该计划的提交内容作为发现项导入。

#### 前提条件

您需要一个可访问目标计划的 Bugcrowd **API 令牌**。我们建议为 DefectDojo 创建一个专用服务账户，以便轻松区分自动化操作与人工操作。请在 Bugcrowd 的 **Organization settings \> API credentials** 下生成该令牌；只需具备对提交内容、计划和目标的读取权限即可。

#### 连接器映射

1. 在**位置**字段中输入 `https://api.bugcrowd.com`。
2. 在**密钥**字段中输入您的 Bugcrowd API 令牌。它会以 `Authorization: Token` 请求头的形式发送。
3. （可选）设置**最低严重程度**以限制导入的发现项范围。

每个 Bugcrowd **计划**都会成为一条记录，其提交内容会作为发现项导入，并保留 Bugcrowd 原有的严重程度。重复提交的内容会被排除，因此重新导入不会为同一问题创建重复的发现项。

## **Bright Security**

Bright Security 连接器使用 [Bright](https://brightsec.com)（原 NeuraLegion）API 导入 **DAST 发现项**。DefectDojo 会发现该令牌可访问的每一次扫描，并为每次已完成的扫描创建一条记录，然后将该次扫描的问题作为发现项导入。

#### 前提条件

您需要一个 Bright **API 密钥**，可在 Bright 应用的 **User settings → API keys** 下创建（可以是 `Org` 密钥或个人密钥）。该密钥会通过 `Authorization: Api-Key` 请求头发送，且不会被记录到日志中。

#### 连接器映射

1. 将**位置**字段留空即可使用 `https://app.brightsec.com`，或显式输入您的 Bright 主机地址。
2. 在**密钥**字段中输入该 Bright API 密钥。
3. （可选）设置**最低严重程度**以限制导入的发现项范围。

DefectDojo 会将每次已完成的**扫描**映射为一条记录，并将每个**问题**映射为一条发现项：严重程度来自 Bright 自身的评级（严重/高/中/低），CVSS 分数、CWE 和修复建议都会被保留，受影响的入口点会成为端点，请求/响应证据也会包含在描述中。发现项会被记录为动态发现项，并根据 Bright 的问题 ID 进行去重。

更多信息请参阅 [Bright API 文档](https://docs.brightsec.com/)。

## **BurpSuite**

DefectDojo 的 Burp 连接器会调用 Burp 的 GraphQL API 来获取数据。

#### 前提条件

在设置此连接器之前，您需要一个来自 Burp 服务账户的 API 密钥。Burp 用户账户默认没有 API 密钥，因此您可能需要专门为此新建一个用户。

有关如何为服务账户用户设置 API 密钥的指南，请参阅 [Burp 文档](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user)。

#### 连接器映射

1. 在**位置**字段中输入 Burp 的根 URL：即您访问 Burp 工具的 URL。
2. 在**密钥**字段中输入有效的 API 密钥。这是与您的 Burp 服务账户关联的 API 密钥。

有关 Burp API 的更多信息，请参阅官方 [Burp 文档](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html)。

## **Censys**

Censys 连接器从 Censys Platform 中读取主机资产，并将每台主机上暴露的服务作为发现项导入。它使用 Censys Platform 的全局搜索 API 来枚举您所限定范围内的主机。

#### 前提条件

您需要一个具备 API 访问权限的 Censys **Platform** 账户：

* 一个**个人访问令牌**，在 Censys Platform Console 的 Personal Access Tokens 下创建。
* 您的**组织 ID**，显示在同一设置页面的 "Current Organization" 下。访问搜索端点的 API 需要具备组织，因此需要 Starter 层级或更高层级。免费层级的令牌没有组织 ID，无法使用搜索 API。

每台主机的 CVE 和风险数据仅在 Censys Core（企业版）层级中提供，因此在较低层级中，发现项代表的是暴露的服务，而非漏洞。

更多信息请参阅 [Censys Platform API 文档](https://docs.censys.com/reference/get-started)。

#### 连接器映射

1. 在**位置**字段中输入 `https://api.platform.censys.io`。
2. 在 **API 密钥**字段中输入您的个人访问令牌。
3. 输入您的**组织 ID**。
4. 输入一个**搜索查询**，将导入范围限定为您自己的资产，例如 `host.autonomous_system.asn: <your ASN>` 或 `host.ip: 203.0.113.0/24`。
5. （可选）设置**最低严重程度**以限制导入的发现项范围。

DefectDojo 会为每台主机创建一条记录，并将其暴露的服务作为发现项导入。

## **Checkmarx ONE**

DefectDojo 的 Checkmarx ONE 连接器会调用 Checkmarx API 来获取数据。

#### **连接器映射**

1. 在 **Checkmarx Tenant** 字段中输入您的**租户名称**。该名称应显示在 Checkmarx ONE 登录页面的右上角：
" Tenant: \<**your tenant name**\> "
​
![图片](images/connectors_tool_reference_2.png)

2. 输入有效的 API 密钥。如有需要，您可能需要生成一个新密钥：详情请参阅 [Checkmarx API 文档](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08)。
3. 在**位置**字段中输入您的租户地址。该 URL 格式如下：
​`https://<your-region>.ast.checkmarx.net/` 。您所在的区域会显示在使用 Checkmarx 应用时 Checkmarx URL 的开头。**<https://ast.checkmarx.net>** 是主要的美国服务器（不带区域前缀）。

#### **分支处理**

默认情况下，每次同步都会导入某个项目**最近一次已完成的扫描（无论分支为何）**中的发现项。如果您的 CI 会扫描多个分支，那么最后被扫描的分支就会在该次同步中"胜出"：仅存在于其他分支上的发现项不会被导入，而且同步的旧发现项关闭协调机制可能会导致发现项在不同分支轮流成为"最新扫描"时反复打开和关闭。

有两个可选字段可以控制这一行为：

- **分支**：将每个项目固定为某一个分支名称——只会导入该分支的扫描结果。这是适用于整个连接器的单一全局值，因此适合所有项目都使用同一长期分支（例如 `main`）的场景。
    - 支持使用 **`*` 通配符**。包含 `*` 的分支值会匹配*所有*符合条件的分支，而不仅仅是单个分支——例如 `release/*` 会导入每个 release 分支，`*` 则匹配所有分支。将其与**跟踪已扫描分支**结合使用，就可以在不逐一跟踪的情况下跟踪一整个分支族。
    - 如果通配符在扫描窗口内**没有**匹配到任何分支，该次同步会被**跳过**，而不会被当作"该分支没有发现项"处理——因此某个模式暂时匹配不到任何内容时，也不会导致资产上的所有发现项被关闭。
- **跟踪已扫描分支**：启用后，每次同步都会在项目最近的扫描历史中找出每个有已完成扫描的分支，并导入**每个分支最近一次已完成的扫描**，每个分支各重新导入一次。每个分支的发现项都存放在已映射资产上各自独立的测试活动中，命名为"\<default engagement\> \- \<branch\>"，因此清理过时发现项的操作是按分支隔离的：合并到某个分支的修复，永远不会关闭另一个分支的发现项。项目的主分支（由 Checkmarx 报告）会最先被导入，因此同一发现项在其他分支上再次出现时，会与主分支上的原始记录进行去重。

关于**跟踪已扫描分支**的说明：

- **请确认适用于您的默认设置。** 分支跟踪功能在**新安装环境中默认开启**。早于此变更就已存在的安装环境会保留其原有行为，因此该开关对它们而言默认是关闭的，直到有人手动开启为止。
- 当两个字段都被设置时，只有被固定的**分支**会被跟踪——即使该分支值是一个通配符模式，此时所有匹配该模式的分支都会被跟踪。
- 停止被扫描的分支（无论是已合并还是已删除）将不再收到更新：其测试活动仍会保留可见，并显示其最后一次已知的发现项，您可以查看并批量关闭它们。
- 之后关闭该开关是安全的：按分支划分的测试活动只会停止接收导入，默认测试活动会在下一次同步时恢复。
- 连接器按同步计划来协调状态。分支跟踪能让每次同步跨分支保持完整；但它并不能让数据在两次同步之间保持实时更新。

## **Cloudflare**

Cloudflare 连接器导入 **Security Center** 的洞察结果——即 Cloudflare 针对您的账户和区域所发现的安全态势问题，例如缺失 DMARC 记录、未启用 DNSSEC，或存在证书问题。DefectDojo 会为每个存在未解决洞察结果的区域（域名）创建一条记录，并为那些不属于特定区域的洞察结果创建一条账户级别的记录。

#### 前提条件

您需要一个 Cloudflare **API 令牌**（而非旧版的 Global API Key）。请在 Cloudflare 控制台的 **My Profile > API Tokens > Create Token** 下创建一个。最快捷的方式是使用 **"Read all resources"** 模板；如果需要最小权限的令牌，则应授予 **Zone > Zone > Read**（所有区域）以及 Security Center 所需的账户级读取权限。

#### 连接器映射

1. 在**位置**字段中输入 `https://api.cloudflare.com/client/v4`。
2. 在**密钥**字段中输入该 API 令牌。
3. （可选）设置**最低严重程度**以限制导入的发现项范围。

DefectDojo 会自动发现该令牌可访问的账户和区域——无需提供账户 ID。系统只会导入未解决（活动、未忽略）的洞察结果，因此您在 Cloudflare 中解决或忽略的洞察结果，会在下一次同步时自动在 DefectDojo 中被标记为已缓解。

## **Cobalt.io**

Cobalt.io 连接器使用 Cobalt.io API（v2）从您的 Cobalt.io 组织中拉取渗透测试发现项。DefectDojo 会发现您的 API 令牌可以访问的每个组织，并为每个**资产**（Cobalt 进行渗透测试的单位）创建一条单独的记录。

#### 前提条件

您需要一个 Cobalt.io **个人 API 令牌**。我们建议为 DefectDojo 创建一个专用服务账户，以便清楚区分自动化活动与团队的手动操作。在 Cobalt.io 界面中，通过 **Settings > API Tokens** 生成令牌。组织令牌会被自动发现 —— 您无需手动提供。

#### 连接器映射

1. 在**位置**字段中输入 Cobalt.io API 基础 URL：`https://api.cobalt.io`（或您所在区域的主机地址，例如 `https://api.us.cobalt.io`）。
2. 在**密钥**字段中输入您的**个人 API 令牌**。
3. （可选）在 **Organization Token** 字段中输入组织令牌，将同步限定到单个组织。留空时，DefectDojo 会同步该个人 API 令牌可访问的所有组织。

DefectDojo 会将每个 Cobalt.io **资产**映射为一条独立的记录。系统会为每个已映射的资产导入发现项，并根据其在 Cobalt.io 中的状态（例如 `valid_fix`、`wont_fix`、`invalid`）驱动该发现项在 DefectDojo 中的状态。

## **Contrast**

Contrast 连接器使用 Contrast Assess REST API 导入应用程序漏洞。DefectDojo 会发现您 Contrast 组织中的应用程序，并为每个应用程序创建一条记录。

#### 前提条件

您需要从 Contrast 获取四个值。我们建议创建一个专用服务账户，以便轻松区分自动化活动与团队的手动操作。在 Contrast 界面的 **User Settings > Profile > Your Keys** 下，您可以找到：

* 您的组织 **API Key**。
* 您的个人 **Service Key**。
* 这些凭据所属的**用户名**（该账户的登录邮箱）。
* 您的 **Organization ID** —— 要导入的组织的 UUID，也会显示在 **Organization Settings** 下。

#### 连接器映射

1. 在**位置**字段中输入您用于访问 Contrast 的基础 URL —— 对于托管产品，通常为 `https://app.contrastsecurity.com`（或您所在区域/自托管的 Team Server URL）。
2. 在**用户名**字段中输入账户登录邮箱。
3. 在 **API Key** 字段中输入组织 **API Key**。
4. 在 **Service Key** 字段中输入个人 **Service Key**。
5. 在 **Organization ID** 字段中输入 **Organization ID**（UUID）。
6. （可选）设置**最低严重程度**，以限制导入哪些发现项。

每个 Contrast 应用程序都会成为一条记录，其漏洞将作为发现项导入。

## **Coverity**

Coverity 连接器从 **Coverity Connect** 服务器导入发现项。DefectDojo 会为每个 Coverity **项目**创建一条记录。

#### 连接器映射

1. 在**位置**字段中输入您的 Coverity Connect 服务器 URL。
2. 在**用户名**字段中输入 Coverity Connect 用户名。
3. 在**密钥**字段中输入该用户的密码或身份验证密钥。
4. （可选）设置 **View Name**，以选择连接器读取哪个已保存的问题视图。留空则使用默认视图 **Outstanding Issues**。
5. （可选）将 **Import All Issue Kinds** 设置为 `true`，以将导入范围扩大到默认的安全与质量（`RESOURCE_LEAK`）问题过滤器之外。

## **CrowdStrike Falcon**

CrowdStrike Falcon 连接器从 Falcon 平台导入 **Spotlight 漏洞**和 **EDR 检测结果**，作为两种独立的发现项类型（`CrowdStrike:Spotlight` 和 `CrowdStrike:Detections`）。DefectDojo 会为每个 Falcon **主机**创建一条记录。

#### 前提条件

一个 Falcon **API 客户端**（Client ID 和密钥），在 Falcon 控制台的 **Support > API Clients and Keys** 下创建。请为其授予您想要导入的数据所需的权限范围：**Hosts: Read**（必需，用于主机发现）、**Vulnerabilities (Spotlight): Read**（用于 Spotlight 发现项）以及 **Alerts: Read**（用于 EDR 检测结果）。这两种发现项类型是相互独立的 —— 如果客户端缺少某个权限范围，对应的发现项类型会被跳过，而不会导致同步失败，因此没有 **Alerts: Read** 权限的客户端仍然可以导入 Spotlight 漏洞。

#### 连接器映射

1. 在**位置**字段中输入与您控制台区域相匹配的 Falcon 云 API 基础 URL —— 例如 `https://api.crowdstrike.com`（US-1）、`https://api.us-2.crowdstrike.com`（US-2）、`https://api.eu-1.crowdstrike.com`（EU-1）或 `https://api.laggar.gcw.crowdstrike.com`（US-GOV-1）。
2. 在 **Client ID** 字段中输入 API 客户端的 Client ID。
3. 在 **Client Secret** 字段中输入 API 客户端的密钥。
4. （可选）设置**最低严重程度**，以限制导入哪些发现项。

每个 Falcon 主机都会成为一条记录，以其主机名、操作系统和类型命名。系统只会导入处于 **open** 和 **reopened** 状态的 Spotlight 漏洞，因此重新导入会关闭已修复的发现项。

## **Deepfence ThreatMapper**

Deepfence ThreatMapper 连接器使用 [ThreatMapper](https://github.com/deepfence/ThreatMapper) 管理控制台 REST API 导入**漏洞扫描**结果。DefectDojo 会发现 ThreatMapper 扫描过的每一个节点 —— 容器镜像、主机或容器 —— 并为每个节点创建一条记录，然后将该节点最近一次已完成的扫描导入为发现项。

#### 前提条件

您需要一个 ThreatMapper **API 令牌**，可在控制台的 **Settings → User Management** 下找到（您用户的 API 密钥）。连接器会在每次同步时将其兑换为一个短期有效的访问令牌；该 API 令牌本身不会被记录到日志中。

#### 连接器映射

1. 在**位置**字段中输入您的 ThreatMapper 控制台 URL（例如 `https://threatmapper.example.com`）。
2. 在**密钥**字段中输入 ThreatMapper API 令牌。
3. 如果您的控制台使用自签名证书，请将 **Skip TLS Verification** 设置为 `true`。
4. （可选）设置**最低严重程度**，以限制导入哪些发现项。

DefectDojo 会将每个已扫描的**节点**映射为一条记录，并将其最近一次已完成的漏洞扫描中的每个 **CVE** 映射为一条发现项。严重程度来自 ThreatMapper 自身的评级，受影响的软件包、CVSS 评分、修复版本（作为缓解措施）、参考链接以及详情信息块都会一并带入。发现项会被记录为动态发现项，并基于节点、CVE、软件包及软件包路径进行去重。

更多信息请参阅 [ThreatMapper 文档](https://community.deepfence.io/threatmapper/docs/v2.5/)。

## Dependency-Track

该连接器通过 REST API 从本地部署的 Dependency-Track 实例获取数据。

**连接器映射**

1. 在**位置**字段中输入您本地 Dependency-Track 服务器的 URL。
2. 在**密钥**字段中输入一个有效的 API 密钥。

生成 Dependency-Track API 密钥的步骤：

1. **访问管理**：在 Dependency-Track 界面中，进入 Administration > Access Management > Teams。
2. **团队设置**：您可以新建一个团队，也可以选择一个现有团队。团队可让您根据组成员身份来管理 API 访问权限。
3. **生成 API 密钥**：在所选团队的详情页面中，找到“API Keys”部分。点击 + 按钮以生成一个新的 API 密钥。
4. **分配权限**：在团队页面的“Permissions”部分，点击 + 按钮以打开权限选择器。选择 **VIEW_PORTFOLIO** 和 **VIEW_VULNERABILITY** 权限，以启用对项目组合和漏洞详情的 API 访问。
5. 点击“**Select**”以确认并保存这些权限。

更多信息请参阅**[Dependency-Track Documentation](https://docs.dependencytrack.org/integrations/rest-api/)**。

## **Docker Scout**

Docker Scout 连接器使用 Docker Scout 指标导出器 API，报告您组织镜像的漏洞状况。DefectDojo 会发现每个 Docker Scout **数据流**（即您的运行时环境），并为每个数据流导入一份漏洞与策略合规性摘要。

#### 前提条件

您需要一个由 Docker 组织的**所有者**创建的 Docker 个人访问令牌，且该组织必须已**启用 Docker Scout**。指标导出器是一项组织级功能，因此个人账户，或未启用 Docker Scout 的组织，都不会返回数据。

请在 Docker 账户设置的 **Personal access tokens** 下创建该令牌，并记下您的 Docker **组织命名空间**，稍后也会用到。

#### 连接器映射

1. 在**位置**字段中输入 `https://api.scout.docker.com`。
2. 在**密钥**字段中输入您的 Docker 个人访问令牌。
3. 输入您的 Docker **组织**命名空间。
4. （可选）设置**最低严重程度**，以限制导入哪些发现项。低于所选严重程度的发现项将不会被导入。

DefectDojo 会为每个 Docker Scout 数据流创建一条独立的记录，并针对该数据流中 Docker Scout 统计到的漏洞，为每个严重程度导入一条发现项，此外还会为每个未通过您 Docker Scout 策略的镜像导入一条发现项。Docker Scout 的指标 API 报告的是汇总计数，而非单个 CVE，因此这些发现项反映的是某个数据流的整体状况。如需查看每个镜像、每个 CVE 的详细信息，请在 Docker Scout 中打开该数据流。

更多信息请参阅 [Docker Scout 文档](https://docs.docker.com/scout/)。

## **Endor Labs**

Endor Labs 连接器使用 Endor Labs REST API 同步整个 Endor Labs **命名空间**。DefectDojo 会将每个 Endor **项目**发现为一条记录，并导入该项目的发现项，同时带入 Endor 的**可达性**判定结果，以便您优先处理那些受影响代码确实可达的漏洞。

#### 前提条件

您需要一个 Endor Labs **API 密钥**（一个密钥标识符及其密钥）以及要同步的**命名空间**。请在 Endor Labs 平台的 **Settings > Access > API Keys** 下创建该密钥；该密钥需要对该命名空间下的项目和发现项具有读取权限。

该连接器通过用 API 密钥和密钥换取一个短期有效的 Bearer 令牌来完成身份验证 —— 密钥仅用于此次交换，且不会以明文形式存储。

#### 连接器映射

1. 在**位置**字段中输入 `https://api.endorlabs.com`。如果您的租户托管在其他区域，请改用该区域的 API 基础 URL。
2. 输入要同步的 Endor Labs **Namespace**（例如 `your-org` 或 `your-org.team`）。
3. 输入 **API Key** 标识符。
4. 输入与该密钥配对的 **API Secret**。
5. （可选）将 **Traverse Child Namespaces** 设置为 `true`，以同时导入所配置命名空间下子命名空间中的发现项。
6. （可选）设置**最低严重程度**，以限制导入哪些发现项。低于所选严重程度的发现项不会被导入。

DefectDojo 会为命名空间中的每个 Endor Labs 项目创建一条记录并导入其发现项，将 Endor 的严重程度级别映射为 DefectDojo 的严重程度，并带入每个漏洞的 CVE/GHSA 标识符和 CVSS 评分，以及 Endor 的可达性标签。可达性判定结果（例如*可达 —— 存在漏洞的函数被调用*或*不可达*）会体现为该发现项的 Impact（影响）字段和一个标签。

更多信息请参阅**[Endor Labs REST API documentation](https://docs.endorlabs.com/rest-api/)**。

## **Edgescan**

Edgescan 连接器使用 Edgescan REST API，导入您整个 Edgescan 账户中处于打开状态的漏洞。DefectDojo 会枚举每一个 Edgescan **资产**并为其创建一条记录，然后将该资产处于打开状态的漏洞作为发现项导入 —— 无需按资产单独配置。

#### 前提条件

您需要一个 Edgescan API 令牌。请在您的 Edgescan 账户中，通过 **Account settings > API tokens** 创建：输入一个标签，点击 **Create**，然后复制生成的令牌（该令牌仅显示一次）。我们建议为连接器使用专用账户，以便更容易区分自动化活动。

#### 连接器映射

1. 在**位置**字段中输入您的 Edgescan URL —— 标准托管平台为 `https://live.edgescan.com`，如果不同，请使用您租户的主机地址。
2. 在**密钥**字段中输入您的 Edgescan API 令牌。它会作为 `X-API-TOKEN` 请求头发送。
3. （可选）设置**最低严重程度**，以限制导入哪些发现项。

每个 Edgescan 资产都会成为一条记录，该资产上处于打开状态的每个漏洞都会作为发现项导入。严重程度会从 Edgescan 的数值评分（1–5）映射为 DefectDojo 的信息级到严重级，并在 Edgescan 提供相应信息时包含 CVE 引用、CWE 以及 CVSS v3 向量。

## **Escape**

Escape 连接器使用 [Escape](https://escape.tech) API 导入 **API 安全（DAST）发现项**。DefectDojo 会枚举该令牌可访问的每个组织，以及其中的每个应用程序，为每个存在扫描记录的应用程序创建一条记录，并导入该应用程序最近一次扫描的问题作为发现项 —— 无需按应用程序单独配置。

#### 前提条件

您需要一个 Escape **API 密钥**，在 Escape 应用的 **Settings → API keys** 下创建。该密钥会在 `Authorization: Key` 请求头中发送，且不会被记录到日志中。

#### 连接器映射

1. 将**位置**字段留空以使用 `https://public.escape.tech/v2`，或显式输入您的 Escape API 主机地址。
2. 在**密钥**字段中输入 Escape API 密钥。
3. （可选）设置**最低严重程度**，以限制导入哪些发现项。

DefectDojo 会将每个**应用程序**映射为一条记录，并将每个扫描**问题**映射为一条发现项：严重程度来自 Escape 的评级（严重/高/中/低），CWE 会一并带入，OWASP 类别和 HTTP 方法会成为标签，受影响的 URL 会成为端点，修复建议也会包含在内。发现项会被记录为动态发现项，并基于 Escape 的问题 ID 进行去重。

更多信息请参阅 [Escape API 文档](https://docs.escape.tech/)。

## **Fairwinds Insights**

Fairwinds Insights 连接器使用 [Fairwinds Insights](https://insights.fairwinds.com) REST API，导入您整个组织的 **Kubernetes 安全发现项**。DefectDojo 会枚举每个处于活动状态的**集群**并为其创建一条记录，然后导入该集群的安全**操作项**（来自 Polaris、Trivy、Kube-bench、OPA 及其他 Insights 报告）作为发现项 —— 无需按集群单独配置。

#### 前提条件

您需要一个 Fairwinds Insights **组织**名称和一个 **API 令牌**。请在 Insights 应用的 **Organization Settings > Tokens** 下创建该令牌；`read_only` 级别的令牌即可满足需求。该令牌的作用域为组织级别，并以 Bearer 令牌形式发送；不会被记录到日志中。

#### 连接器映射

1. 将**位置**字段留空以使用 `https://insights.fairwinds.com`，或显式输入您的 Insights 主机地址。
2. 输入您的 Insights **组织**名称（即您仪表板 URL 中显示的 slug）。
3. 在**密钥**字段中输入 Insights API 令牌。
4. （可选）设置**最低严重程度**，以限制导入哪些发现项。

DefectDojo 会将每个处于活动状态的**集群**映射为一条记录，并将每个安全**操作项**映射为一条发现项：严重程度来自 Fairwinds 的数值评分（映射为 DefectDojo 的信息级到严重级），产生该操作项的 Fairwinds 报告（`polaris`、`trivy`、`kube-bench` 等）会成为工具标签，受影响的 Kubernetes 资源和容器镜像会一并包含，任何 CVE 标识符也会被提取出来。发现项会被记录为静态发现项，并基于 Fairwinds 的操作项 ID 进行去重。

更多信息请参阅 [Fairwinds Insights API 文档](https://insights.docs.fairwinds.com/technical-details/api/)。

## **Fortify**

Fortify 连接器从 Fortify（OpenText/Micro Focus）导入 SAST/DAST 结果，涵盖共用同一平台的两个版本：**SSC**（Software Security Center，自托管版）和 **Fortify on Demand（FoD）**（SaaS 版）。它会同步整个账户：DefectDojo 会发现每个应用程序（SSC 的 project version / FoD 的 release）并为每个应用程序创建一条记录，然后将该应用程序的问题作为发现项导入。

#### 前提条件

- **SSC**：一个 **FortifyToken** —— 在 SSC 界面的 **Administration → Token Management** 下创建（CIToken/UnifiedLoginToken）。
- **FoD**：一个 **OAuth2 API 密钥** —— 在 **Settings → API** 下获取的 Client ID 和 Client Secret（需要 `api-tenant` 权限范围）。

该令牌和 OAuth 密钥不会被记录到日志中。

#### 连接器映射

1. 在**位置**字段中输入 Fortify 基础 URL：对于 SSC，输入您的服务器主机地址（连接器会自动附加 `/ssc/api/v1`）；对于 FoD，输入您所在区域的 API 主机地址，例如 `https://api.ams.fortify.com`。
2. 将 **Edition** 设置为 `SSC` 或 `FoD`。
3. 对于 **FoD**，输入 OAuth **Client ID**；SSC 则留空。
4. 在 **Token / Client Secret** 字段中，输入 SSC 的 FortifyToken 或 FoD 的 OAuth 客户端密钥。
5. （可选）设置**最低严重程度**，以限制导入哪些发现项。

DefectDojo 会将每个 Fortify **应用程序**映射为一条记录，并将每个**问题**映射为一条发现项：严重程度来自 Fortify 自有的 **friority**（综合优先级）评级（严重/高/中/低），标题由问题类别与其文件和行号组合而成，文件路径、行号、kingdom、分析器和引擎类型都会一并带入。来自静态分析引擎（SCA）的问题会被记录为静态发现项，WebInspect（DAST）问题记录为动态发现项；已抑制、已移除和已隐藏的问题会被跳过，审核为“Not an Issue”的问题会被标记为误报，“Exploitable”/已复核的问题会被标记为已验证。

更多信息请参阅 [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) 和 [Fortify on Demand](https://api.ams.fortify.com/swagger/ui) 的 API 文档。

## **GitGuardian**

GitGuardian 连接器使用 GitGuardian REST API 导入**密钥事件** —— 即 GitGuardian 在您监控的来源中检测到的已泄露凭据。DefectDojo 会为每个当前存在未结事件的受监控来源（仓库或边界）创建一条记录，并将每个未结事件作为发现项导入。

出于安全考虑，连接器只会导入事件的**元数据** —— 检测器、严重程度、有效性、状态，以及指向 GitGuardian 的链接。泄露的密钥值本身不会被 DefectDojo 获取或存储；请通过每条发现项中的链接前往 GitGuardian 查看受影响的位置。

#### 前提条件

您需要一个 GitGuardian API 密钥。我们建议使用**服务账户令牌**（而非个人访问令牌），以便更容易区分自动化活动。请在 GitGuardian 控制台的 **API** 下创建该令牌，并授予以下只读权限范围：

* `incidents:read`
* `sources:read`

#### 连接器映射

1. 在**位置**字段中输入您的 GitGuardian API URL：SaaS 平台为 `https://api.gitguardian.com`，或您自托管实例的 API URL。
2. 在**密钥**字段中输入该 API 密钥。

系统只会导入处于**打开**状态（状态为 `TRIGGERED` 或 `ASSIGNED`）的事件；您在 GitGuardian 中解决或忽略的事件，会在下一次同步时在 DefectDojo 中自动被标记为已缓解。已确认仍然有效的密钥（有效性为 *valid*）会作为已验证的发现项导入。

## **GitHub**

GitHub 连接器是一个 **Asset Connector**（资产连接器）：它会枚举该令牌可访问的仓库，并为每个仓库创建一个 DefectDojo 资产，按 GitHub **所有者**（组织或用户）分组到组织中。不会导入任何发现项。

**请注意：** 此连接器仅导入您的仓库**清单**。如需将 GitHub 安全告警 —— 代码扫描（code scanning）、Dependabot、密钥扫描（secret scanning）—— 作为发现项导入，请使用下方单独的 **GitHub Advanced Security** 连接器。两者相互独立，可以同时运行。

#### 前提条件

该连接器使用 GitHub **个人访问令牌**进行身份验证，并且只读取仓库**元数据**（名称、描述、URL 和所有者）—— 不会访问您的代码、议题（issue）或安全告警。它会导入该令牌所属账户拥有、协作或作为组织成员参与的每一个仓库，因此请确认该令牌的账户能够看到您想要镜像的仓库。我们建议使用专用服务账户。

该令牌只需要对仓库元数据的只读访问权限：

- *细粒度（fine-grained）*令牌需要 **Repository permissions → Metadata: Read-only** 权限，并授予您想要导入的仓库（或整个组织）。
- *经典（classic）*令牌需要 **`repo`** 权限范围以包含私有仓库（如果只需要公共仓库，使用 **`public_repo`**），另外还需要 **`read:org`**，以便解析组织拥有的仓库。

仅支持 GitHub.com（包括 GitHub Enterprise Cloud）。此连接器目前不支持 GitHub Enterprise **Server**。

#### 连接器映射

1. 在**位置**字段中输入 `https://api.github.com`。
2. 在**密钥**字段中输入个人访问令牌。

无需输入任何组织或仓库列表 —— DefectDojo 会导入该令牌可以看到的每一个仓库。每个仓库都会成为一条以仓库名命名的记录，并按其 GitHub **所有者**（组织或用户）分组。如果某个仓库之后被删除，或该令牌失去了对它的访问权限，其对应的已映射记录会在下一次同步时被标记为 `MISSING`，而不会被移除 —— DefectDojo 绝不会静默删除某个产品。

## **GitHub Advanced Security**

GitHub Advanced Security 连接器从 GitHub 导入**代码扫描（code scanning）**、**Dependabot** 和**密钥扫描（secret scanning）**告警，作为三种独立的发现项类型（`GitHub:CodeScanning`、`GitHub:Dependabot` 和 `GitHub:SecretScanning`）。DefectDojo 会发现所配置组织中每一个未归档的仓库，并为每个仓库创建一条记录。

#### 前提条件

您想要导入的仓库必须已启用 GitHub Advanced Security 功能。该连接器使用 GitHub **个人访问令牌**进行身份验证：

1. 在 GitHub 中，打开 **Settings > Developer settings > Personal access tokens**，创建一个由目标组织拥有（或有权访问该组织）的令牌。
2. 为其授予安全告警的读取权限：*细粒度*令牌需要对目标组织仓库的 **Code scanning alerts**、**Dependabot alerts** 和 **Secret scanning alerts** 具有**只读**权限；*经典*令牌需要 **`repo`** 和 **`security_events`** 权限范围。
3. 请确认该令牌的所有者能够看到您打算导入的仓库 —— 连接器只能看到该令牌可访问的仓库。

#### 连接器映射

1. 在**位置**字段中输入 `https://api.github.com`。对于 GitHub Enterprise Server，请使用 `https://<your-host>/api/v3`。
2. 在**组织**字段中输入组织登录名。
3. 在**密钥**字段中输入个人访问令牌。
4. （可选）设置**最低严重程度**，以限制导入哪些发现项。

每个未归档的仓库都会成为一条记录，系统会在三类告警中查询未结告警。如果某个仓库未启用某个告警类别，该类别会被跳过，而不会被报告为已解决，因此被禁用的功能不会导致误报的关闭。

## **GitLab**

GitLab 连接器是一个 **Asset Connector**（资产连接器）：它会枚举该令牌可访问的每一个项目（仓库），并为每个项目创建一个 DefectDojo 资产，按 GitLab **命名空间**（群组或用户）分组到组织中。不会导入任何发现项。

#### 前提条件

您需要一个具有 **read_api** 权限范围的个人访问令牌。我们建议使用专用服务账户创建该令牌；连接器会列出该账户所属的项目。

#### 连接器映射

1. 在**位置**字段中输入您的 GitLab URL：`https://gitlab.com`，或您自托管实例的基础 URL。
2. 在**密钥**字段中输入个人访问令牌。

每个项目都会成为一条以项目名命名的记录，并按其**命名空间**分组。在 GitLab 中处于待删除状态的项目（已被用户删除，但尚未被 GitLab 的后台任务清除）会被自动排除，因此删除某个项目会在下一次同步时将其记录标记为 `MISSING`，而不会留下一个被重命名的“幽灵”资产。

## **Google Cloud Security Command Center**

Google Cloud SCC 连接器使用 Security Command Center v2 REST API，导入您 Google Cloud 组织、文件夹或项目中处于活动状态的安全发现项。DefectDojo 会为每个存在未结发现项的 Google Cloud **项目**创建一条记录。

#### 前提条件

您的组织必须已**启用** Security Command Center（Standard 层级是免费的）。之后，您需要一个能够列出发现项的服务账户，以及该服务账户的 JSON 密钥：

1. 在 Google Cloud 中创建一个服务账户 —— 建议为 DefectDojo 使用专用账户。
2. 在您想要导入的范围（组织、文件夹或项目）上，为其授予 **Security Center Findings Viewer** 角色（`roles/securitycenter.findingsViewer`）。
3. 为该服务账户创建一个 **JSON 密钥**并下载。

#### 连接器映射

1. 除非您使用非标准的接入点，否则请将**位置**字段保留为默认值 `https://securitycenter.googleapis.com`。
2. 在 **Parent Resource** 字段中输入要导入的范围：`organizations/{id}`、`folders/{id}` 或 `projects/{id}`。
3. 将服务账户 **JSON 密钥**文件的完整内容粘贴到 **Service Account Key** 字段中。
4. （可选）设置**最低严重程度**，以限制导入哪些发现项。

系统只会导入状态为 `ACTIVE` 且未被静音的发现项，因此您在 SCC 中停用或静音的发现项，会在下一次同步时在 DefectDojo 中自动被标记为已缓解。每条发现项受影响的 GCP 项目会成为其对应的记录。

## **Group-IB ASM**

Group-IB ASM（Attack Surface Management，攻击面管理）连接器使用 Group-IB ASM REST API，将外部攻击面的 **issues**（问题，即发现项）拉取到 DefectDojo 中。DefectDojo 会将每个 Group-IB **company/tenant**（公司/租户）发现为一条独立的记录，并按计划以增量方式导入该公司的问题。每个问题所关联的资产（域名、IP 或 URL）会作为 **端点** 附加到生成的发现项上。

#### 前提条件

您需要拥有 Group-IB ASM 登录账号和一个 API 密钥。我们建议为 DefectDojo 创建专用的服务账户，以便将自动化活动与人工操作区分开来。

生成 API 密钥的步骤：

1. 打开 Group-IB Attack Surface Management，点击左下角的 **Help**，然后选择 **API**。
2. 点击 **Generate API Key**（右上角，用户名下方）。
3. 输入您的 SSO 密码并点击 **Next**，然后点击 **Copy token**。
4. 将密钥保存在密钥管理器中，并制定定期轮换计划。

#### 连接器映射

Group-IB ASM 使用 HTTP Basic Auth 进行身份验证，其中用户名是您的 ASM 登录账号，密码是您的 API 密钥。**两个值都是必填的** —— 仅有 API 密钥是不够的。

1. 在 **Location** 字段中输入 `https://asm.group-ib.com`。所有 Group-IB ASM 租户都使用相同的地址。
2. 在 **Username** 字段中输入您的 ASM 登录账号（通常是电子邮件地址）。
3. 在 **API Key**（Secret）字段中输入您的 API 密钥。
4. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。低于所选严重程度的发现项将不会被导入。

DefectDojo 会将每个 Group-IB **company**（公司）映射为一条独立的记录，并使用公司 ID 作为标识符。首次同步时，DefectDojo 会回填近期的问题历史记录；之后的同步则以增量方式进行，仅拉取自上次同步以来发生变化的问题（通过每个问题最新的 `lastSeen` 时间戳来跟踪）。

#### 限定单个公司范围（可选）

默认情况下，连接器会自动发现您的 API 凭据可访问的所有公司（通过 ASM 的 `clients` 端点），并为每个公司创建一条记录。这是推荐的配置方式，无需额外设置。

如果您的租户无法使用 `clients` 端点 —— 例如该端点仅对合作伙伴/MSP 账户开放 —— 则可以在连接器配置中通过 `company_id` 这一工具专属字段提供其 **company ID**（公司 ID），将连接器限定为单个公司。设置了 `company_id` 后，DefectDojo 会直接使用该公司，而不再枚举所有公司。若不设置该字段，则使用自动发现。

有关更多信息，请参阅 Group-IB ASM REST API 手册（可在产品内通过 **Help → API** 访问）。

## **HackerOne**

HackerOne 连接器使用 HackerOne REST API，从您的漏洞赏金或漏洞披露计划中导入报告。DefectDojo 会为令牌可访问的每个计划创建一条记录，并将其报告作为发现项导入。

#### 前提条件

该连接器使用 HackerOne 的 **customer** API，此 API 需要 **organization API token**（组织级 API 令牌）—— 您在用户设置中生成的个人令牌仅适用于 hacker API，无法用于此处的身份验证。

1. 在 HackerOne 中，进入 **Organization Settings > API Tokens**。
2. 创建一个令牌，并记下其 **identifier**（标识符）和 **token**（令牌）值。对该计划具有读取权限即可。

#### 连接器映射

1. 在 **Location** 字段中输入 `https://api.hackerone.com`。
2. 在 **API Token Identifier** 字段中输入令牌的标识符。
3. 在 **API Token** 字段中输入令牌值。
4. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。

每个计划都会成为一条记录，其报告将作为发现项导入，并保留 HackerOne 的严重程度评级。

## **Harbor**

Harbor 连接器使用 Harbor v2.0 REST API，导入整个镜像仓库中的容器镜像漏洞。DefectDojo 会枚举每个 Harbor **project**（项目）并为其创建一条记录，然后遍历该项目下的仓库和制品，导入每个 **已扫描** 制品中的漏洞 —— 并将镜像信息（仓库 + 标签/摘要）作为发现项的上下文一并带入。该连接器不支持按镜像单独配置。

#### 前提条件

您需要一个具有拉取/读取权限的 Harbor 账户（或 **robot account**，机器人账户），以访问要导入的项目。我们建议使用专用的机器人账户：在 Harbor 中打开一个项目（系统级机器人则进入 **Administration > Robot Accounts**），创建一个对仓库和制品具有 **pull**（拉取）权限的机器人账户，并复制其完整名称和密钥。机器人账户名称默认以 `robot$` 开头，但该前缀因 Harbor 实例而异（有些使用 `robot_`）—— 请按 Harbor 显示的名称原样复制。使用常规的用户名/密码也可以。

#### 连接器映射

1. 在 **Location** 字段中输入您的 Harbor URL，例如 `https://harbor.example.com`。DefectDojo 会自动附加 `/api/v2.0` API 路径。
2. 在 **Username** 字段中输入 Harbor 用户名，或按 Harbor 显示的原样输入机器人账户名称（默认格式为 `robot$<name>`）。
3. 在 **Secret** 字段中输入密码或机器人账户密钥。该值会通过 HTTP Basic 身份验证方式发送。
4. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。

每个 Harbor 项目都会成为一条记录。对于每个已完成扫描的制品，其漏洞都会作为发现项导入；如果 Harbor 提供了受影响的软件包/版本、基于 CVSS 得出的严重程度、CVE、CWE 以及修复建议（已修复版本），这些信息也会一并带入。系统只会导入已扫描的制品 —— 对于尚未扫描的镜像，请在 Harbor 中触发扫描。

## **Have I Been Pwned**

Have I Been Pwned（HIBP）连接器使用 HIBP REST API，报告您组织自有域名下的哪些账户曾出现在已知数据泄露事件中。DefectDojo 会发现您在 HIBP 中已验证的每个域名，并为影响该域名的每起数据泄露事件导入一条发现项。

#### 前提条件

您需要一个支持域名搜索的 Have I Been Pwned API 密钥，这要求订阅 **Core** 级别或更高的套餐。您可以从您的 [Have I Been Pwned 账户](https://haveibeenpwned.com/API/Key)获取密钥。

您还必须在 HIBP 账户中 **验证至少一个域名**，之后才能获取数据泄露信息。HIBP 允许您在账户的 **Domain search**（域名搜索）中，通过 DNS TXT 记录、meta 标签、文件上传或电子邮件等方式验证域名。在域名验证完成之前，连接器不会发现任何域名，也不会导入任何发现项。

#### 连接器映射

1. 在 **Location** 字段中输入 `https://haveibeenpwned.com`。
2. 在 **Secret** 字段中输入您的 API 密钥。
3. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。低于所选严重程度的发现项将不会被导入。

DefectDojo 会为您在 HIBP 中验证过的每个域名创建一条独立的记录，并为影响该域名下账户的每起数据泄露事件导入一条发现项。每条发现项的严重程度反映了该数据泄露事件所暴露的数据类型，其描述中会列出您域名下受影响的账户，以便您的团队采取相应措施。

如需了解更多信息，请参阅 [Have I Been Pwned API 文档](https://haveibeenpwned.com/API/v3)。

## **HCL AppScan**

HCL AppScan 连接器使用 AppScan v4 REST API，从 **AppScan on Cloud（ASoC）** 或自托管的 **AppScan 360°**（两者共用同一套 API）导入问题。它会同步整个账户：DefectDojo 会发现所有应用程序并为每个应用程序创建一条记录，然后将该应用程序的问题（DAST、SAST 和 IAST）作为发现项导入。

#### 前提条件

您需要一个 AppScan **API key**（API 密钥）—— 即在 AppScan 账户设置（API Key）中生成的 Key ID 和 Key Secret。连接器会在每次运行时用它们换取一个短期有效的会话令牌；Key ID、Key Secret 和该令牌都不会被记录到日志中。

#### 连接器映射

1. 在 **Location** 字段中输入 AppScan 控制台 URL：ASoC 请使用 `https://cloud.appscan.com`（欧盟区域使用 `https://eu.cloud.appscan.com`）；AppScan 360° 请使用您实例的主机地址。
2. 将 **Provider** 设置为 `ASOC`（用于 AppScan on Cloud）或 `A360`（用于自托管的 AppScan 360°）。
3. 输入 **API Key ID** 和 **API Key Secret**。
4. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。

DefectDojo 会将每个 AppScan **application**（应用程序）映射为一条记录（VEP），并将每个 **issue**（问题）映射为一条发现项：标题为问题类型，并附加其 domain / entity / cause-id / URL / path；严重程度按以下方式映射：Informational 映射为 Info（信息），Low（低）、Medium（中）、High（高）、Critical（严重）则直接保留不变；CWE、带标签的描述、修复建议与安全公告，以及主机/端口端点信息都会一并带入。静态分析得出的问题记录为静态发现项，动态/交互式问题记录为动态发现项；未关闭的问题为活动状态，已修复/已通过的问题则为已缓解状态。

如需了解更多信息，请参阅 [AppScan REST API 文档](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html)。

## **Intigriti**

Intigriti 连接器使用 Intigriti 的外部公司 API，将漏洞赏金/渗透测试 **submissions**（提交项）导入 DefectDojo。它会同步整个公司账户：DefectDojo 会发现令牌可访问的所有计划，并为每个计划创建一条记录，然后将该计划的提交项作为发现项导入。

#### 前提条件

您需要一个 Intigriti **公司 API 令牌**。在 Intigriti 公司门户中，进入 **Company Settings > API**（`company_external_api` 权限范围），生成一个对您的计划和提交项具有读取权限的访问令牌。建议为 DefectDojo 使用专用令牌。该令牌以 Bearer 令牌的形式发送，且不会被记录到日志中。

#### 连接器映射

1. 在 **Location** 字段中输入 Intigriti 外部公司 API 的基础 URL：`https://api.intigriti.com/external/company`。该 URL 必须使用 HTTPS。
2. 在 **Secret** 字段中输入公司 API 令牌。
3. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。

DefectDojo 会将每个 Intigriti **program**（计划）映射为一条记录，并将每个 **submission**（提交项）映射为一条发现项，以提交编号作为键。发现项的严重程度遵循 Intigriti 的评级（Exceptional/Critical → 严重，其次是 High（高）/Medium（中）/Low（低），其余则归为 Informational），提交项的生命周期状态会映射为发现项的状态：处于 open 或 triage 状态的提交项为活动状态，已接受的提交项为已验证状态，已关闭的提交项则根据其关闭原因分别归类为已缓解、重复、超出范围、误报或风险已接受。发现项的描述中包含报告的漏洞类型、受影响资产、概念验证（proof of concept）以及研究人员的回答。

如需了解更多信息，请参阅 [Intigriti API 文档](https://kb.intigriti.com/en/articles/6117846-intigriti-api)。

## **Intruder**

Intruder 连接器使用 [Intruder REST API](https://developers.intruder.io/)，将您整个账户的安全态势拉取到 DefectDojo 中。每个 Intruder **target**（目标）都会被发现为一条记录（产品）；目标上每次出现的 **occurrence**（问题实例）都会成为一条发现项。

#### 连接器映射

1. 将 **Location** 字段保留为 `https://api.intruder.io/`（Intruder 的默认 API 服务器地址）。
2. 在 **Secret** 字段中输入 Intruder 的 **API access token**（API 访问令牌）。

在 Intruder 中，进入 **My account > API Access Tokens** 生成访问令牌（创建时需要输入账户密码，且令牌仅显示一次）。详情请参阅 [Intruder API 文档](https://developers.intruder.io/docs/creating-an-access-token)。

发现项按每次 occurrence（问题实例）生成：严重程度来自该问题的严重程度评级，CVE 和 CVSS 来自该 occurrence，位置信息来自目标/端口；被搁置（snoozed）的 occurrence 会作为非活动状态（误报或风险已接受）的发现项导入。

## **IriusRisk**

IriusRisk 连接器使用 API 令牌，从您的 IriusRisk 实例中拉取威胁建模数据。

#### 前提条件

您需要从 IriusRisk 账户中获取一个 API 令牌。我们建议为 DefectDojo 创建专用的服务账户，以便清晰区分自动化活动和人工操作。

在 IriusRisk 中生成 API 令牌的步骤：

1. 登录您的 IriusRisk 实例。
2. 在右上角菜单中进入 **User Profile**。
3. 选择 **API Token** 并生成一个新令牌。

如需了解更多信息，请参阅 [IriusRisk API 文档](https://support.iriusrisk.com/hc/en-us/categories/360001148511)。

#### 连接器映射

1. 在 **Location URL** 字段中输入您的 IriusRisk 实例 URL。对于云托管实例，该地址通常为 `https://{your-subdomain}.iriusrisk.com`；对于本地部署，请使用您实例的基础 URL。
2. 在 **Secret** 字段中输入您的 **API Token**。
3. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。低于所选严重程度的发现项将不会被导入。

## **JFrog Xray**

JFrog Xray 连接器使用 JFrog Xray REST API，从您的 Artifactory 仓库中获取漏洞数据。DefectDojo 会发现您 JFrog 实例中的所有仓库，并通过 Xray 生成漏洞报告，按计划导入发现项。

#### 前提条件

您需要一个同时具有 Artifactory 和 Xray API 访问权限的 API 令牌。我们建议为 DefectDojo 创建专用的服务账户。该账户需要具备：

* 对 Artifactory 仓库的读取权限
* 生成和查看 Xray 漏洞报告的权限（Xray 中的 `Apply on Watches` 权限，或等效权限）

#### 连接器映射

1. 在 **Location** 字段中输入您的 JFrog 实例基础 URL。这应为您 JFrog 实例的根 URL，例如 `https://your-instance.jfrog.io`。请勿包含末尾路径 —— DefectDojo 会自动构建相应的 API 路径。
2. 在 **Secret** 字段中输入一个有效的 **Reference Token**（引用令牌）。可以在 JFrog Platform UI 的 **User Management > Access Tokens** 中生成令牌。
您需要生成一个 **Reference Token** 并使用该值。

JFrog Xray 所需的令牌权限范围：

- **All Services**，因为 DefectDojo 需要同时访问 XRay 和 Artifactory 服务
- 至少需要 **Manage Reports + Manage Resources**。

默认情况下，DefectDojo 会将每个 Artifactory **仓库** 映射为一条独立的记录。每次同步都会通过 Xray 为每个仓库生成一份完整的漏洞报告，因此 DefectDojo 中的发现项状态始终反映仓库的当前状态。

#### 仓库过滤器（可选）

默认情况下，连接器会发现您 JFrog 实例中的 **所有** 仓库。对于仓库数量庞大的实例 —— 其中许多仓库可能与安全审查无关 —— 可以通过连接器表单中 **Import Filters**（导入过滤器）下的可选字段 **Repository Filter**（仓库过滤器），缩小发现范围。

该过滤器在发现阶段应用，**先于任何针对单个仓库的处理**。不在过滤范围内的仓库不会产生任何开销：不会为其生成 Xray 报告，在制品模式下，也不会枚举其一级制品。因此，这是缩短同步时间、降低 DefectDojo 对 JFrog 实例负载的最有效方式 —— 比同步后期应用的任何设置都更有效。在大型实例上，特别建议将其与 **Artifact-Level Records**（制品级记录）搭配使用。

**语法：** 以逗号分隔的仓库键列表。每个条目均可使用 `*` 通配符：

* 包含 `*` 的条目将作为模式进行匹配 —— `releases-*` 匹配所有以 `releases-` 开头的仓库键，`*docker-pr-local*` 匹配任何包含 `docker-pr-local` 的键。`*` 可匹配任意长度的字符序列，包括 `/`。
* 不含 `*` 的条目必须与某个仓库键 **完全匹配**。
* 只要某个仓库匹配列表中的 **任意** 一个条目，就会被发现。逗号前后的空格会被忽略。

```
releases-*, snapshots
```

上面的示例会发现所有键以 `releases-` 开头的仓库，以及名称恰好为 `snapshots` 的单个仓库。

说明：

* 该过滤器是一个 **允许列表（allow-list）** —— 匹配即表示选中该仓库。它不支持排除或否定语法，因此无法直接表达"除 X 之外的全部"这类需求。
* 匹配区分大小写（**case-sensitive**），无论是精确匹配的条目还是通配符均如此。`*` 是唯一支持的通配符；不支持 `?` 或字符范围。
* **留空则会发现所有仓库。** 仅包含空格或逗号的值将被视为空。
* 如果过滤器未匹配到任何内容，则不会发现任何仓库 —— 系统不会报错。如果某次同步意外未发现任何仓库，请检查连接器日志中的 `repository filter scoped discovery` 条目，该条目会报告在全部仓库中有多少个匹配成功。
* 该字段可以在连接创建后随时修改。

**之后修改过滤器：** 一旦收紧后的过滤器不再包含某些仓库，这些仓库将不再被发现，其现有记录会按照工具不再报告某产品时的正常生命周期处理 —— 已映射的记录会在下一次同步时被标记为 `MISSING`，未映射的 `NEW` 记录则会被移除。已导入 DefectDojo 的发现项不会被删除；过滤器仅控制发现范围。

#### 制品级记录

**Artifact-Level Records**（制品级记录）开关会将发现粒度下移一级，细化到仓库之下：仓库根目录下的每个一级条目（对于 Docker 仓库，即每个镜像；对于通用仓库，即每个顶层文件或文件夹）都会成为独立的记录。每次同步仍然只会为每个仓库生成一份 Xray 报告 —— DefectDojo 会将每个漏洞归属到其影响的具体制品，因此不会增加对您 JFrog 实例的负载。

> **在首次同步前，请确认您当前处于哪种模式。** 对于新安装的实例，制品级记录 **默认处于开启状态**。在该功能推出之前就已存在的安装则会保留其原有的仓库级布局，因此该开关默认处于关闭状态，直到有人手动开启。无论哪种情况，该开关都可以随时更改 —— 详见下文的 *切换现有连接*。

启用制品级记录后：

* 仓库仍作为记录存在，但会转变为 **父资产**：仓库本身不再直接携带发现项，但当启用了资产层级（Asset Hierarchy）功能后，DefectDojo 会自动通过 `parent`（父级）关系，将每个制品资产关联到其所属的仓库资产。此后即可按父/子关系筛选资产，发现项也会沿层级向上汇总。
* 若某个漏洞影响多个制品，则会被导入到每个受影响制品各自的资产中，因此每个资产都会显示影响它的完整发现项集合。
* 发现项的范围限定在每个制品的 **最新构建版本**，因此某个制品的发现项反映的是其当前构建版本，而不会累积 Xray 曾经扫描过的所有历史构建的结果。
* 连接器创建的层级关系不会覆盖您手动创建的关系。如果某个资产已经被您指定了父级，连接器将不会改动它。
* 该令牌还需要具备对 Artifactory 存储 API 的读取权限（已包含在上述权限范围内）。

**将现有连接切换为制品级记录：** 该开关可以随时更改。切换后首次同步时，会出现新的制品记录等待映射 —— 在切换开关的同时启用连接上的 **Auto Map**（自动映射），可使发现项的迁移不出现空档期。仓库级资产将停止接收发现项，其此前导入的发现项会在下一次同步时被关闭（相同的发现项会以全新状态重新导入到新的制品资产下）；旧的仓库级发现项上的备注和历史记录仍保留在仓库资产上。切回原状态则会反转这一过程：仓库记录将恢复承载发现项（此前关闭的发现项会在重新匹配后重新打开），而制品记录会被标记为 MISSING —— 其资产和发现项会被保留但不再更新，您可以在方便时将其归档。

如需了解更多信息，请参阅 [JFrog Xray REST API 文档](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis)。

## **Jira Service Management Assets**

JSM Assets 连接器是一个 **Asset Connector**（资产连接器）：它会枚举您 Jira Service Management Assets（原 Insight）工作区中的对象，并为每个对象创建一个 DefectDojo 资产，按对象架构（schema）分组到 Organizations（组织）中。此连接器不导入任何发现项。

#### 前提条件

* Assets 需要 **Jira Service Management Premium 或 Enterprise** 套餐。在 Free 或 Standard 套餐下，Assets API 会返回 `403 "Access to Assets API was denied"`，即便站点的其他部分可以正常使用。
* 所使用的 Atlassian 账户必须在该站点上拥有 **Jira Service Management 产品访问权限**（即坐席/agent seat）—— 仅有站点访问权限是不够的。
* 在 [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) 创建一个经典 Atlassian API 令牌。我们建议使用专用的服务账户。

#### 连接器映射

1. 在 **Location** 字段中输入您的 Atlassian 站点 URL：`https://{your-site}.atlassian.net`。
2. 在 **Email** 字段中输入该令牌所属的 Atlassian 账户电子邮件。
3. 在 **Secret** 字段中输入 API 令牌。

每个 Assets 对象都会成为一条以该对象标签命名的记录，并按其 **object schema**（对象架构）分组。

## **Kubescape**

Kubescape 连接器直接从集群的 Kubernetes API 读取由 [Kubescape operator](https://kubescape.io/docs/install-operator/) 生成的 Kubernetes 安全态势（配置错误）结果 —— 无需 ARMO SaaS 账户。它读取的是由该 operator 的集群内存储聚合 API 提供的 `WorkloadConfigurationScan` 对象（`spdx.softwarecomposition.kubescape.io/v1beta1`）。每个存在态势结果的 Kubernetes **namespace**（命名空间）都会被映射为一条记录（产品）；工作负载上每个未通过的控制项都会成为一条发现项。

#### 前提条件

- 目标集群中必须已安装 Kubescape operator，并启用配置扫描功能（参见[在您的集群中安装](https://kubescape.io/docs/install-operator/)）。可使用 `kubectl get workloadconfigurationscans -A` 确认是否存在结果。
- 一份对目标集群的 `spdx.softwarecomposition.kubescape.io` API 组具有读取权限（对 `workloadconfigurationscans` 具有 list/get 权限）的 **kubeconfig**。

#### 连接器映射

1. 在 **Location** 字段中输入集群的 API 服务器 URL（或一个便于识别的集群标识符）。
2. 将目标集群的 **kubeconfig** 粘贴到 `kubeconfig` 字段中。您可以选择设置 `kube_context` 以选择其中的某个上下文，并设置 `cluster_name` 为发现的产品打标签。
3. 每个存在态势结果的命名空间都会被发现为一条记录；请将您想要导入的命名空间映射到 DefectDojo 产品。

发现项按每个未通过的控制项生成：控制项名称和工作负载共同标识该发现项，严重程度来自该控制项的评分系数，控制项 ID 将作为漏洞 ID，每条发现项都会链接到其位于 `https://hub.armosec.io/docs/` 的控制项参考文档。

## **Mend**

Mend 连接器（原 **WhiteSource**）使用 Mend API，从您的 Mend 组织中导入安全发现项。DefectDojo 会为每个 Mend **project**（项目）创建一条记录。

#### 前提条件

您需要一个拥有 **User Key**（个人访问令牌）的 Mend（服务）用户，以及您的 Mend **Organization UUID**（组织 UUID）。我们建议使用专用的服务账户，以便清晰区分自动化活动和人工操作。您可以在 Mend 应用的 **Administration > Organization UUID** 中找到组织 UUID。

#### 连接器映射

1. 在 **Location** 字段中输入您的 Mend API URL。该 URL 是 **区域相关的（region-specific）** —— 请使用您 Mend 组织所在区域对应的 API 基础 URL。
2. 在 **Email** 字段中输入 Mend 用户的登录邮箱。
3. 在 **Organization UUID** 字段中输入您的 Mend **Organization UUID**。
4. 在 **User Key** 字段中输入 Mend 的 **User Key**。
5. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。

## **Lacework / FortiCNAPP**

Lacework / FortiCNAPP 连接器使用 Lacework v2 API，为您整个 Lacework 账户导入 **主机和容器漏洞**。

#### 前提条件

您需要一个 Lacework **API key**（API 密钥）—— 即在 Lacework 控制台的 **Settings → API keys** 中创建的 API key id 和 secret。连接器会在每次同步时用它们换取一个短期有效的访问令牌；key id、secret 和该令牌都不会被记录到日志中。

#### 连接器映射

1. 在 **Location** 字段中输入您的 Lacework 账户 URL，例如 `https://YOUR-ACCOUNT.lacework.net`（也接受仅填写账户名）。
2. 输入 **API Key ID** 和 **API Secret**。
3. 您可以选择设置 **Minimum Severity**，以限制导入哪些发现项。

DefectDojo 会将 Lacework **account**（账户）映射为一条记录（范围为整个账户）。每个 **container**（容器）和 **host**（主机）漏洞都会成为一条发现项：严重程度来自 Lacework 自身的评级，受影响的软件包和版本将作为组件，修复版本将作为缓解措施，受影响的镜像/主机会记录为标签。容器漏洞记录为静态发现项（镜像扫描），主机漏洞记录为动态发现项（运行中主机的扫描）。

如需了解更多信息，请参阅 [Lacework API 文档](https://docs.lacework.net/api/v2/docs)。

## **Microsoft Defender**

Microsoft Defender 连接器从 **Microsoft Defender Vulnerability Management (MDVM)** 导入设备漏洞发现项——每个设备/软件版本/CVE 组合对应一条发现项，其中包含严重程度、CVSS 分数、可利用性级别以及推荐的安全更新。DefectDojo 会发现您的 Defender **设备组**，并为每个设备组创建一个 Record；未分配到任何设备组的设备会被归入一个名为 **Unassigned** 的合成分组。

**请注意：** 该连接器不同于基于文件的 “MSDefender Parser” 扫描类型，后者导入手动导出的 Defender 文件。请为每个 Product 只选择一种导入方式，以避免产生重复发现项。

#### Prerequisites

您的 Microsoft 租户需要具备包含 Defender 漏洞导出 API 的有效许可证：**Defender for Endpoint Plan 2**、**Microsoft Defender Vulnerability Management Standalone**，或带有 MDVM 附加组件的 MDE P1/P2。（仅有 MDVM *Add-on* SKU 本身并不够——它还需要底层的 Defender for Endpoint Plan 2。）

该连接器以 Microsoft Entra ID **应用注册** 的身份，使用客户端凭据流程进行身份验证。创建方法如下：

1. 在 [Azure 门户](https://portal.azure.com) 中，打开 **App registrations > New registration**。为其命名（例如 `defectdojo-connector`），保留默认设置，然后选择 **Register**。
2. 在应用的 **Overview** 页面上，记下 **Application (client) ID** 和 **Directory (tenant) ID**。
3. 打开 **API permissions > Add a permission > APIs my organization uses**，搜索 **WindowsDefenderATP**。如果未出现该选项，说明您租户的 Defender 后端尚未完成预配置：请确认许可证已激活，打开一次 [security.microsoft.com](https://security.microsoft.com)，几分钟后再重试。
4. 选择 **Application permissions**（*不是* Delegated——Delegated 权限不会出现在连接器的服务令牌中），展开 **Vulnerability**，勾选 **Vulnerability.Read.All**，然后选择 **Add permissions**。
5. 选择 **Grant admin consent** 并确认。Status 列必须显示绿色对勾——若跳过此步骤，每次 API 调用都会返回 403 错误。
6. 打开 **Certificates & secrets > New client secret**，设置有效期，并立即复制密钥 **Value**（该值仅显示一次）。密钥过期后连接器将停止工作，请记下到期日期。

#### Connector Mappings

1. 在 **Location** 字段中输入 `https://api.security.microsoft.com`。
2. 在 **Tenant ID** 字段中输入 **Directory (tenant) ID**。
3. 在 **Client ID** 字段中输入 **Application (client) ID**。
4. 在 **Client Secret** 字段中输入客户端密钥的值。
5. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

每个 Defender 设备组都会成为一个 Record。Microsoft 大约每 6 小时重新生成一次连接器所读取的漏洞快照，新接入的设备最长可能需要约 24 小时才能生成首批漏洞数据——因此全新租户在设备完成接入和评估之前，Sync 得到零条发现项属于正常现象。许可证激活本身也可能需要约 20 分钟或更长时间才能同步到 API（在此期间出现的 “No active license found” 错误会自行消失）。

## **Microsoft Defender for Cloud**

Microsoft Defender for Cloud 连接器导入由 Defender for Cloud 呈现的 **Microsoft Defender Vulnerability Management (MDVM)** 漏洞发现项——既包括 **服务器** 发现项（Azure 虚拟机操作系统及已安装软件的 CVE），也包括 **容器镜像仓库** 发现项（容器镜像 CVE），并包含严重程度、CVSS 分数、受影响的软件包或镜像以及修复建议。DefectDojo 会发现您的服务主体（service principal）有读取权限的 Azure **订阅**，并为每个已启用的订阅创建一个 Record。

**请注意：** 该连接器不同于 **Microsoft Defender** 连接器，后者从 Defender for Endpoint API 导入设备发现项。Defender for Cloud 是一款 Azure 产品，拥有不同的 API 接口（Azure Resource Manager / Resource Graph）和权限模型（Azure RBAC）。请根据您的发现项所在位置运行相应的连接器——如果两种产品都在使用，也可以两者都运行。

#### Prerequisites

您需要一个或多个 **已启用 Microsoft Defender for Cloud 的 Azure 订阅**，并为想要扫描的资源开启相应的 Defender 方案（在 **Microsoft Defender for Cloud > Environment settings** 下选择您的订阅）：

* **Defender for Servers (Plan 2)** —— Azure 虚拟机操作系统及软件 CVE 发现项（无代理漏洞扫描）。
* **Defender for Containers** —— 容器镜像仓库镜像 CVE 发现项。

SQL 漏洞评估以及配置/安全态势相关的发现项将被有意 **排除在外**——此连接器仅导入 CVE 漏洞。

该连接器以 Microsoft Entra ID **应用注册** 的身份，使用客户端凭据流程进行身份验证：

1. 在 [Azure 门户](https://portal.azure.com) 中，打开 **App registrations > New registration**。为其命名（例如 `defectdojo-connector`），保留默认设置，然后选择 **Register**。
2. 在应用的 **Overview** 页面上，记下 **Application (client) ID** 和 **Directory (tenant) ID**。
3. 打开 **Certificates & secrets > New client secret**，设置有效期，并立即复制密钥 **Value**（该值仅显示一次）。密钥过期后连接器将停止工作，请记下到期日期。
4. 为应用授予对每个要导入的订阅的读取权限：打开 **Subscriptions**，选择您的订阅，然后进入 **Access control (IAM) > Add > Add role assignment**。选择 **Security Reader** 角色（或 **Reader**），并在 **Members** 选项卡中将其分配给您创建的应用——请通过应用的 **name** 或 **object ID** 搜索，因为选择器不支持按 client ID 匹配。对每个订阅重复此操作。

与基于设备的 Microsoft Defender 连接器不同，此处不需要任何 API 权限或管理员同意：Defender for Cloud 的访问权限完全由上述 Azure RBAC 角色分配决定。

#### Connector Mappings

1. 在 **Location** 字段中输入 `https://management.azure.com`。（对于主权云，请使用对应的 ARM 终结点，例如 `https://management.usgovcloudapi.net`。）
2. 在 **Tenant ID** 字段中输入 **Directory (tenant) ID**。
3. 在 **Client ID** 字段中输入 **Application (client) ID**。
4. 在 **Client Secret** 字段中输入客户端密钥的值。
5. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

每个已启用的 Azure 订阅都会成为一个 Record。发现项通过 Azure Resource Graph 读取，因此一旦 Defender for Cloud 扫描完您的资源，发现项就会很快显示出来——但扫描本身是按 Microsoft 的计划运行的：容器镜像仓库中的镜像通常会在推送后一小时内完成扫描，而虚拟机的首次无代理漏洞扫描则可能需要数小时。新启用的订阅在其资源完成扫描之前，Sync 得到零条发现项属于正常现象。

## **MobSF**

MobSF 连接器使用 [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) REST API 导入移动应用（APK/IPA）静态分析结果。DefectDojo 会发现您 MobSF 实例上已扫描过的每个应用，为每个应用创建一个 Record，然后导入该应用的静态分析发现项。

#### Prerequisites

您需要准备好 MobSF 的 **REST API key**。可在 MobSF 主页的 **API** 部分找到它（在 MobSF 文档中也显示为 `Authorization` 值）。该密钥会随每次请求发送，且不会被记录到日志中。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 MobSF 基础 URL（例如 `https://mobsf.example.com`）。
2. 在 **Secret** 字段中输入 MobSF REST API key。
3. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

DefectDojo 将每个已扫描的 **应用** 映射为一个 Record，并从 MobSF 的 JSON 报告中导入多个部分的发现项——应用权限、代码分析、签名证书、Android manifest、Android API 使用情况以及二进制分析。每条发现项都会打上 **CWE 919**（移动）标签，其严重程度来自 MobSF 自身的评级（high、warning、info、secure/good）——*dangerous* 权限将被视为高严重程度。发现项会被记录为静态发现项，并按扫描、分区、标题、严重程度和文件路径进行去重。

更多信息请参见 [MobSF REST API documentation](https://mobsf.github.io/docs/#/rest_api)。

## **NeuVector**

NeuVector 连接器使用 [NeuVector](https://github.com/neuvector/neuvector) 控制器 REST API 导入容器 **镜像漏洞扫描** 结果。DefectDojo 会发现 NeuVector 已扫描过的每个镜像，为每个镜像创建一个 Record，然后将该镜像的扫描报告导入为发现项。

#### Prerequisites

您需要一个具有读取扫描结果权限的 NeuVector 控制器账户的 **用户名和密码**。连接器会使用这些凭据登录以获取会话令牌；密码和令牌均不会被记录到日志中。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 NeuVector 控制器 URL，需包含 REST API 端口——例如 `https://neuvector.example.com:10443`。
2. 输入控制器的 **Username** 和 **Password**。
3. 如果您的控制器使用自签名证书，请将 **Skip TLS Verification** 设置为 `true`。
4. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

DefectDojo 将每个已扫描的 **镜像** 映射为一个 Record，并将其扫描报告中的每个 **CVE** 映射为一条发现项。严重程度来自 NeuVector 自身的评级，同时会带入受影响的软件包及其版本、CVSSv3 分数和向量、修复版本（作为缓解措施）以及参考链接。发现项会按镜像、CVE、软件包、版本和严重程度进行去重。

更多信息请参见 [NeuVector API documentation](https://open-docs.neuvector.com/automation/automation)。

## **Nuclei (ProjectDiscovery Cloud)**

Nuclei 连接器使用 ProjectDiscovery Cloud Platform (PDCP) REST API 从您的 PDCP 账户中拉取 [nuclei](https://github.com/projectdiscovery/nuclei) 扫描结果。DefectDojo 会发现账户中的每个扫描，并为每个 **scan** 创建一个单独的 Record。

#### Prerequisites

您需要一个 ProjectDiscovery Cloud 的 **API key**。建议为 DefectDojo 创建一个专用的服务账户，以便清楚区分自动化活动和团队的手动操作。在 ProjectDiscovery Cloud 界面（[cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)）中，通过 **Settings > API Key** 生成密钥。扫描结果既可以来自托管扫描，也可以来自以 `-dashboard` 参数运行的 nuclei CLI。

#### Connector Mappings

1. 在 **Location** 字段中输入 PDCP API 的基础 URL：`https://api.projectdiscovery.io`。
2. 在 **Secret** 字段中输入您的 **API key**。
3. （可选）输入 **Team ID** 以将同步范围限定到某个团队工作区（可在 **Settings > Team** 下找到）。留空时，DefectDojo 将同步您的个人工作区。
4. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

DefectDojo 会将每个 PDCP **scan** 映射为一个单独的 Record，并导入该扫描中所有严重程度（包括信息级别）的发现项。

## **OpenVAS / Greenbone**

OpenVAS / Greenbone 连接器从 Greenbone（Greenbone Community Edition 或 Greenbone Enterprise）实例导入 **网络漏洞发现项**。它通过 **GMP（Greenbone Management Protocol）** 与 `gvmd` 通信——这是一种基于 TLS 套接字而非 HTTP 的 XML 协议——并同步整个实例：枚举扫描 **任务（tasks）**，为每个任务创建一个 DefectDojo product，并导入该任务最新报告中的结果。

#### Prerequisites

需要一个 Greenbone **GMP 用户**（用户名 + 密码），以及可访问 gvmd 的 GMP TLS 端口（默认 **9390**）的网络权限。Greenbone Community Edition 的 compose 技术栈通过 unix 套接字对外提供 gvmd，因此若要从网络化的连接器访问它，您需要在能够访问该套接字的位置运行连接器，或者暴露 GMP TLS 端口（例如通过 `socat` 建立一个到 `gvmd.sock` 的 TLS 桥接）。

#### Connector Mappings

1. 在 **Location** 字段中输入 gvmd 主机地址（host 或 `host:port`）。
2. 输入 GMP 的 **Username** 和 **Password**。
3. （可选）设置 **GMP Port**（默认为 9390）。
4. 对于 gvmd 默认的自签名证书，可以提供 **CA Certificate (PEM)** 以进行验证，或将 **Skip TLS Verification** 设置为 `true`。
5. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

每个 Greenbone 任务都会成为一个 Record。发现项来自该任务最新完成的报告——每个 `<result>` 对应一条。严重程度取自结果的威胁等级（Greenbone 的 `Log`/`Debug` 信息级别会映射为信息），并记录数值型 CVSS 分数；CVE 引用会成为 vulnerability id，NVT 的解决方案会成为缓解措施，每个结果的 host/port 会成为一个端点。

## Probely

该连接器使用 Probely REST API 获取数据。

​**Connector Mappings**

1. 在 **Location** 字段中输入相应的 API 服务器地址。（可以是 <https://api.us.probely.com/> 或 <https://api.eu.probely.com/> ）
2. 在 **Secret** 字段中输入有效的 API key。

您可以在 Probely 的 User > API Keys 菜单下找到 API key。  
更多信息请参见 [Probely documentation](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key)。

## Prowler

Prowler 连接器使用 **Prowler App** REST API，从自托管的 Prowler App 实例导入云安全态势管理（CSPM）发现项。DefectDojo 会将每个 Prowler **provider**（云账户）发现为一个 Record，并导入该 provider 最近一次已完成扫描中的 **FAIL** 发现项。

#### Prerequisites

您需要一个正在运行的自托管 **Prowler App** 实例，以及用户邮箱 + 密码（用于 JWT 身份验证）或 Prowler App 的 **API key** 二者之一。只有在 Prowler App 中连接了云账户（AWS、GCP、Azure、Kubernetes 等）并运行过扫描后，才会出现发现项。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 Prowler App URL（例如 `https://prowler.your-company.com`）。
2. 若使用 JWT 身份验证，请输入 Prowler App 用户的 **Email** 和 **Password**。或者，也可以将这两项留空，改为输入 Prowler App 的 **API Key**。如果两者都提供了，将使用 email/password（JWT）方式。
3. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。低于所选严重程度的发现项不会被导入。

DefectDojo 会为每个 Prowler provider 创建一个 Record，并导入其最近一次已完成扫描中的 FAIL 发现项，将 Prowler 的严重程度映射为 DefectDojo 的严重程度，将受影响的云资源（ARN/resource id）映射为 component，并将检查项的修复建议和风险内容并入发现项。已静音的发现项会被跳过。云账户、区域和服务会作为标签附加。

更多信息请参见 **[Prowler App API documentation](https://api.prowler.com/api/v1/docs)**。

## Qualys

Qualys 连接器从 Qualys Cloud Platform 导入 **VMDR 主机漏洞检测结果**——每条结果都会与其 Qualys KnowledgeBase（QID）元数据相关联。DefectDojo 会为您订阅中的每个 Qualys **主机** 创建一个 Record。

#### Prerequisites

需要一个具有 **VMDR API 访问权限** 的 Qualys 用户账户，以及您订阅对应的 **API 服务器（平台）URL**——不同订阅的地址不同。可在 Qualys 界面的 **Help > About** 下找到该地址，或参见 Qualys 的 [Platform Identification](https://www.qualys.com/platform-identification/) 页面（例如 US Platform 1 对应 `https://qualysapi.qualys.com`，US Platform 2 对应 `https://qualysapi.qg2.apps.qualys.com`）。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 Qualys API 服务器 URL（例如 `https://qualysapi.qualys.com`）。
2. 在 **Username** 字段中输入 Qualys API 用户名。
3. 在 **Secret** 字段中输入 Qualys API 密码。
4. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

每个 Qualys 主机都会成为一个 Record。Qualys 标记为 **已修复** 的检测结果会被排除，因此重新导入时会关闭已修复的发现项。

## **Quay**

Quay 连接器使用 Project Quay REST API 发现容器仓库，并导入由 Quay 内置的 **Clair** 扫描器生成的漏洞报告。DefectDojo 会为每个 Quay **仓库（repository）** 创建一个 Record，并在每次 Sync 时读取每个活动标签（tag）镜像清单（manifest）的 Clair 安全报告。

#### Prerequisites

您的 Quay 实例必须已启用安全扫描（Clair），并且需要一个 Quay 的 **OAuth 2 access token**：

* 在 Quay 中创建（或打开）一个 Organization，进入 **Applications**，创建一个 OAuth application，然后使用至少 **Read repositories** 权限范围 **Generate Token**。建议为 DefectDojo 创建一个专用的 application。
* 该令牌会作为 Bearer token 随每次请求发送，且不会被记录到日志中。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 Quay 基础 URL，例如 `https://quay.io` 或您自托管的 `https://quay.example.com`。该 URL 必须使用 HTTPS；请勿包含末尾的 API 路径——DefectDojo 会自动构造 API 路径。
2. 在 **Secret** 字段中输入 OAuth access token。
3. （可选）设置 **Namespace**，将发现范围限制为单个 Quay organization 或用户。留空则会发现该令牌可读取的所有仓库。
4. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

DefectDojo 将每个 Quay **仓库** 映射为一个 Record。对于每个仓库，它会列出所有活动标签，将其去重为各自唯一的镜像清单（多个标签共用的清单只会被扫描一次），然后读取每个清单的 Clair 报告。Clair 尚未完成扫描的清单（例如多架构 manifest list，或仍在排队的镜像）会被跳过，留待之后的 Sync 处理。每个 Clair 漏洞都会成为一条发现项——受影响的软件包即为 component，修复版本会成为缓解措施，Clair 的 **Negligible**/**Unknown** 严重程度会被记录为 **信息**。

更多信息请参见 [Project Quay API documentation](https://docs.projectquay.io/api_quay.html) 和 [Clair documentation](https://quay.github.io/clair/)。

## **Rapid7 InsightAppSec**

Rapid7 InsightAppSec 连接器从 InsightAppSec 云平台导入 **DAST 漏洞发现项**，并附带攻击模块元数据（例如 *SQL Injection*）、CVSS 分数以及扫描收集到的证据。DefectDojo 会为每个 InsightAppSec **app** 创建一个 Record。

**请注意：** 该连接器不同于下文的 **Rapid7 InsightVM** 连接器——InsightAppSec 是 Rapid7 在 Insight 平台上提供的云端 DAST 产品，而 InsightVM 的发现项则来自您自己的 Security Console。

#### Prerequisites

需要一个已开通 InsightAppSec 的 Insight 平台账户，以及一个平台 **API key**：在 [Rapid7 Insight platform](https://insight.rapid7.com) 中，打开设置（齿轮）菜单 > **API Keys**，生成一个 **User Key**（任意角色均可）或 **Organization Key**（平台管理员）。密钥显示时请立即复制——它只会显示一次。

您还需要知道平台的 **region**，可在您的 Insight URL 中查看（例如 `us`、`us2`、`us3`、`eu`、`ca`、`au` 或 `ap`）。

#### Connector Mappings

1. 在 **Location** 字段中输入您所在区域的 API 终结点——例如 `https://us.api.insight.rapid7.com`（将 `us` 替换为您所在的区域）。
2. 在 **API Key** 字段中输入 Insight 平台的 API key。
3. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

每个 InsightAppSec app 都会成为一个 Record。仅导入处于开放状态（未审查或已验证）的漏洞——Rapid7 标记为已修复、误报、已忽略或重复的发现项会被排除，因此重新导入会在 DefectDojo 中关闭这些发现项。严重程度直接映射（`SAFE` 和 `INFORMATIONAL` 会作为信息导入）。

## **Rapid7 InsightVM**

Rapid7 InsightVM 连接器从您的 InsightVM **Security Console**（API v3）导入资产漏洞发现项，并结合控制台的全局漏洞目录进行补充。DefectDojo 会为每个 InsightVM **site** 创建一个 Record。

#### Prerequisites

需要 DefectDojo 能够通过网络访问您的 Security Console，以及一个控制台 **用户账户**——其登录信息用于 HTTP Basic 身份验证。控制台 API 默认在 **3780** 端口提供服务。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 Security Console URL（包含端口）——例如 `https://console.example.com:3780`。
2. 在 **Username** 字段中输入控制台用户名。
3. 在 **Secret** 字段中输入控制台密码。
4. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

每个 InsightVM site 都会成为一个 Record；连接器会遍历该 site 的资产，并导入其存在漏洞的发现项。

## **runZero**

runZero 连接器使用 runZero Export API，将您整个组织的资产清单同步到 DefectDojo 中。它主要是一种 **资产** 连接器：DefectDojo 会发现每一项资产并为其创建一个 Record，并按其 runZero **site** 分组到相应的 Product Type 下。它也可以选择性地将 runZero 的漏洞作为发现项导入。

#### Prerequisites

您需要从 runZero 获取一个组织级的 **Export Token**（Account → API），该令牌以 `XT` 为前缀。该令牌的作用域限定在组织级别（组织信息已编码在令牌中），为只读令牌，并以 Bearer token 的形式发送——不会被记录到日志中。runZero 提供社区版/入门版套餐。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 runZero 控制台 URL，例如 `https://console.runzero.com`。该 URL 必须使用 HTTPS。
2. 在 **Secret** 字段中输入 Export Token。
3. （可选）将 **Import Vulnerabilities** 设置为 `true`，以同时将 runZero 的漏洞导入为发现项；留空则仅同步资产。
4. （可选）设置 **Minimum Severity** 以限制导入哪些漏洞发现项（仅在导入漏洞时生效）。

DefectDojo 会将每个 runZero **资产** 映射为一个 Record（VEP）：显示名称来自该资产的名称或地址，其 site、type、OS、地址和标签会作为属性附加；该资产的 **site** 会成为其 Product Type。资产通过完整导出进行同步，DefectDojo 会据此进行协调（增加/移除）。启用 **Import Vulnerabilities** 后，每个 runZero 漏洞都会成为其资产上的一条发现项——并映射严重程度、CVSS 分数、CVE、受影响服务（`protocol://address:port`）端点以及修复建议。

更多信息请参见 [runZero API documentation](https://help.runzero.com/)。

## **Semgrep**

该连接器使用 Semgrep REST API 获取数据。

#### Connector Mappings

在 **Location** 字段中输入 `https://semgrep.dev/api/v1/`。

1. 在 **Secret** 字段中输入有效的 API key。您可以在 Tokens 页面找到它：   
​  
在左侧导航栏中依次选择 “Settings” > Tokens > Create new token（[https://semgrep.dev/orgs/-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens)）

更多信息请参见 [Semgrep documentation](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list)。

## **ServiceNow CMDB**

ServiceNow CMDB 连接器是一种 **资产连接器**：它不导入发现项，而是从您的 ServiceNow Configuration Management Database 中读取配置项（Configuration Items，CI），为每个 CI 创建一个 DefectDojo Asset，并按 CI 类别分组到 Organizations 下。不会导入任何发现项。

#### Prerequisites

您需要一个 ServiceNow 实例，以及一个可以通过 ServiceNow Table API 读取 CMDB 表的账户。建议为 DefectDojo 使用一个专用的只读服务账户。该账户需要对要导入的 `cmdb_ci` 表具有读取权限。

#### Connector Mappings

1. 在 **Location** 字段中输入您的 ServiceNow 实例 URL：`https://{your-instance}.service-now.com`。
2. 选择或创建一个包含实例凭据（ServiceNow 用户名和密码）的 ServiceNow **Tool Configuration**。

每个配置项都会成为一个以该 CI 命名的 Record，并按其 **CI class** 分组（例如 application、server 或 business service）。Discovery 和 Sync 会协调 CI 列表：新的 CI 会以 `NEW` Record 的形式出现，而从 CMDB 中移除的 CI 会在下一次 Sync 时被标记为 `MISSING`，以便您的团队进行处理。DefectDojo 不会静默删除 Product。

## **Shodan**

Shodan 连接器使用 Shodan REST API，导入 Shodan 在您暴露于互联网的主机上观测到的漏洞（CVE）。您需要提供一个 Shodan 搜索查询，将导入范围限定到您自己的资产；DefectDojo 会为每个匹配的主机创建一个 Record，并将其 CVE 导入为发现项。

#### Prerequisites

您需要一个 Shodan API key，可在您的 Shodan **Account** 页面找到。带漏洞数据的主机搜索需要 Shodan 会员资格或付费 API 套餐——免费套餐无法翻页浏览搜索结果。

#### Connector Mappings

1. 在 **Location** 字段中输入 `https://api.shodan.io`。
2. 在 **API Key** 字段中输入您的 Shodan API key。
3. 在 **Search Query** 字段中，输入一个将导入范围限定到您组织资产的 Shodan 查询——例如 `hostname:example.com`、`net:203.0.113.0/24` 或 `org:"Example Inc"`。只有匹配该查询的主机才会被导入，因此请将其限定在您自己拥有的基础设施范围内。
4. （可选）设置 **Minimum Severity** 以限制导入哪些发现项。

每个匹配的主机都会成为一个 Record，Shodan 在该主机暴露服务上检测到的每个 CVE 都会被导入为一条发现项——严重程度根据 CVSS 分数推导得出，并在可用时附带 EPSS 和 CISA KEV 上下文信息。每一页搜索结果都会消耗一个 Shodan 查询额度。

## SonarQube

SonarQube 连接器既可以从 SonarCloud 账户获取数据，也可以从本地 SonarQube 实例获取数据。

**对于 SonarCloud 用户：**

1. 在 Location 字段中输入 https://sonarcloud.io/。
2. 在 Secret 字段中输入有效的 **API key**。

**对于 SonarQube（本地部署）用户：**

1. 在 Location 字段中输入您 SonarQube 实例的基础 URL：例如 `https://my.sonarqube.com/`
2. 在 Secret 字段中输入有效的 **API key**。该密钥需要是 **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** 类型的 [API Token Type](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)。

该令牌需要具备访问 Sonar 中 Projects、Vulnerabilities 和 Hotspots 的权限。

可以在 SonarQube 应用中通过 **My Account -> Security -> Generate Token** 查找并生成 API 令牌。更多信息请参见 [SonarQube documentation](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)。

## **Snyk**

Snyk 连接器使用 Snyk REST API 获取数据。

#### Connector Mappings

1. 在 **Location** 字段中输入 **[https://api.snyk.io/rest](https://api.snyk.io/v1)** 或（针对欧盟区域部署）**[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)**。
2. 在 **Secret** 字段中输入有效的 API key。API 令牌可以在 Snyk 中用户的 **[Account Settings](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)** [页面](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)找到。

更多信息请参见 [Snyk API documentation](https://docs.snyk.io/snyk-api)。

## **Socket**

Socket 连接器使用 [Socket.dev](https://socket.dev) API 导入**软件供应链发现项**——即 Socket 针对您依赖项发出的告警(恶意软件、仿冒包、安装脚本、已知漏洞及其他 70 多个类别)。DefectDojo 会发现您的令牌可访问的各个组织中的每一个仓库,并为每个仓库创建一条记录,然后导入该仓库最近一次完整扫描中的告警。

#### Prerequisites

您需要一个 Socket **API 令牌**——在 Socket 控制台的**设置 → API 令牌**下创建的组织令牌(需要具有 `repo:list` 及完整扫描读取权限范围)。该令牌以 bearer 令牌形式发送,且不会被记录到日志中。

#### Connector Mappings

1. 将**位置**字段留空以使用 `https://api.socket.dev/v0`,或显式输入该地址。
2. 在**密钥**字段中输入 Socket API 令牌。
3. (可选)设置**最低严重程度**以限制导入哪些发现项。

DefectDojo 会将每个**仓库**映射为一条记录,并导入其最近一次完整扫描中的告警。每条告警都会成为一个发现项:严重程度来自 Socket 自身的评级(低、中、高、严重),受影响的包会成为组件并生成 PURL,告警类别(供应链风险、质量、维护、漏洞、许可证)会记录为标签,告警详情则会写入描述信息。发现项会被记录为静态发现项,并按 Socket 的告警键进行去重。

如需了解更多信息,请参阅 [Socket API 文档](https://docs.socket.dev/reference)。

## **Sonatype IQ**

Sonatype IQ 连接器使用 Sonatype IQ Server(Nexus Lifecycle)REST API 导入开源组件漏洞。它会枚举您 IQ 组织中的每一个应用程序,并针对每个应用程序,从您所配置的生命周期阶段的最新报告中导入组件漏洞。DefectDojo 会自动为每个应用程序创建一条记录——无需按应用程序单独配置。

#### Prerequisites

您需要一个 Sonatype IQ 用户账户,并对要导入的应用程序拥有 **View IQ Elements** 权限。Sonatype 建议使用**用户令牌**(在 IQ Server 的**我的个人资料 > 用户令牌**下生成)进行身份验证,而不是使用密码;该令牌的两个部分分别对应下方的“用户名”和“用户令牌”字段。该连接器同时支持自托管 IQ Server 和 Sonatype 托管(SaaS)实例。

#### Connector Mappings

1. 在**位置**字段中输入您的 IQ Server 基础 URL——对于自托管服务器,填写 `https://iq.example.com`;对于 Sonatype 托管实例,填写 `https://<tenant>.sonatype.app/platform`。
2. 在**用户名**字段中输入 IQ 用户(或用户令牌中的用户代码部分)。
3. 在**用户令牌**字段中输入 IQ 用户令牌(或密码)。
4. (可选)设置**阶段**以选择按应用程序导入哪个生命周期阶段的报告(`build`、`stage-release`、`release` 等)。留空则使用 `build`。
5. (可选)设置**最低严重程度**以限制导入哪些发现项。

每个应用程序都会成为一条记录,该应用程序在所选阶段的最新报告中的每个安全问题都会作为发现项导入。严重程度根据问题的数字评分得出,并在可用的情况下包含 CVE 引用、CWE、CVSS 向量以及受影响组件的包 URL(PURL)。
## **Sysdig Secure**

Sysdig Secure 连接器通过 Sysdig Secure 的漏洞管理 API 导入**容器 / CNAPP 漏洞发现项**。它会跨所配置的范围同步整个账户,并为每个扫描资产分组创建一个 DefectDojo 产品。

#### Prerequisites

一个 Sysdig Secure **API 令牌**:在 Sysdig Secure 中,依次转到**设置 > Sysdig Secure API 令牌**并复制该令牌。您还需要 Sysdig 的**区域 URL**(例如 `https://us2.app.sysdig.com`、`https://eu1.app.sysdig.com`,或您的本地部署主机地址)。

#### Connector Mappings

1. 在**位置**字段中输入您的 Sysdig 区域/基础 URL。
2. 在**密钥**字段中输入 API 令牌。
3. (可选)设置**范围**——以逗号分隔的列表,取值为 `runtime`、`registry` 和/或 `pipeline`(留空则默认为 `runtime`,即已部署工作负载范围)。
4. (可选)设置**运行时产品分组**——即运行时结果如何映射到产品:`cluster`、`namespace`、`workload` 或 `image`(留空则默认为 `namespace`)。Registry 和 pipeline 结果始终按镜像仓库分组。
5. (可选)设置**最低严重程度**以限制导入哪些发现项。

每个资产分组都会成为一条记录。对于每个扫描结果,连接器都会将每个存在漏洞的包作为发现项导入。**Runtime**(已部署的工作负载)发现项会被记录为动态发现项,并使用其 Kubernetes 集群/命名空间/工作负载/容器上下文进行标记;**registry** 和 **pipeline** 发现项会被记录为静态镜像扫描发现项。Sysdig 的 `NEGLIGIBLE` 严重程度对应“信息”。

## Tenable

Tenable 连接器使用 **Tenable.io** REST API 获取数据。扫描数据从 Tenable VM 的 `/scans` 端点拉取。

目前不提供本地部署的 Tenable 连接器。

#### **Connector Mappings**

1. 在 Location 字段中输入 <https://cloud.tenable.com>。
2. 在 Secret 字段中输入有效的 **API 密钥**。

请参阅 [Tenable 的 API 文档](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm)了解更多信息。

## **Tenable Web App Scanning**

Tenable Web App Scanning 连接器从 Tenable Web App Scanning 导入 **Web 应用程序(DAST)发现项**。它是一个独立于 Tenable(Vulnerability Management)的连接器:这两款产品覆盖不同的资产,配置也彼此独立,因此您可以单独使用其中一个,也可以两者都用。

DefectDojo 会为每个**已扫描的 Web 应用程序**创建一条记录。应用程序是从您的 Web App Scanning 扫描配置中发现的;从未运行过的配置在其首次扫描完成之前不会生成记录。当多个配置扫描同一个应用程序时,它们会共用同一条记录。

#### Prerequisites

具有 Web App Scanning 权限的用户的 Tenable **API 密钥**(一个访问密钥和一个密钥)。在 Tenable 中,转到**我的账户 > API 密钥**即可生成这些密钥,并确认该用户可以查看您要导入的扫描——仅限于 Vulnerability Management 权限范围的密钥无法读取 Web App Scanning 数据。

目前不提供本地部署的 Tenable 连接器。

#### Connector Mappings

1. 在**位置**字段中输入 <https://cloud.tenable.com>。
2. 输入您的**访问密钥**和**密钥**。
3. (可选)设置**最低严重程度**以限制导入哪些发现项。

发现项导入时会使用 Tenable 针对您账户报告的严重程度,包括您团队已重新评定的任何严重程度。每个发现项都会将受影响的 URL 记录为端点,并包含触发该发现项的请求参数和有效载荷,以及 Tenable 提供的验证信息和输出作为重现步骤,在检测插件提供相应数据的情况下,还会包含 CWE、CVE、CVSS 和 EPSS 值。

系统只会导入当前处于打开或重新打开状态的发现项。Tenable 标记为已修复的发现项,会在下一次同步时在 DefectDojo 中被关闭。

## **Veracode**

Veracode 连接器从 Veracode 平台导入应用程序发现项,并按扫描类型划分为 **SAST**、**DAST**、**SCA** 和 **Manual** 发现项类型。DefectDojo 会为每个 Veracode **应用程序**创建一条记录。

#### Prerequisites

为可以查看您要导入的应用程序的账户生成一个 Veracode **API 凭据**:在 Veracode Platform 中,打开账户菜单 > **API 凭据**,然后选择**生成 API 凭据**(参见[管理 Veracode API 凭据](https://docs.veracode.com/r/c_api_credentials3))。同时复制 **API ID** 和 **API Secret Key**——该密钥仅显示一次。

#### Connector Mappings

1. 在**位置**字段中输入 Veracode API 基础 URL:`https://api.veracode.com`(商业区域)、`https://api.veracode.eu`(欧洲区域)或 `https://api.veracode.us`(美国联邦区域)。
2. 在 **API ID** 字段中输入 API ID。
3. 在**密钥**字段中输入 API 密钥。
4. (可选)设置**最低严重程度**以限制导入哪些发现项。

每个 Veracode 应用程序都会成为一条记录。系统只会导入处于打开状态的发现项,因此重新导入会关闭 Veracode 报告为已解决的发现项。

## **Wazuh**

Wazuh 连接器使用 Wazuh Indexer(OpenSearch)获取漏洞发现项。Wazuh 4.8 及更高版本会将检测到的 CVE 存储在 Indexer 中,而不是 Wazuh 服务器 API 中,因此该连接器会直接从 `wazuh-states-vulnerabilities-*` 索引读取数据。

DefectDojo 会为每个 Wazuh 代理(端点)创建一条记录,并按计划定期导入该代理检测到的 CVE 作为发现项。

#### Prerequisites

您需要准备:

* Wazuh Indexer 的基础 URL(包含端口;Indexer 默认监听 9200 端口)。DefectDojo 会直接连接到 Indexer,因此该端点必须能够从 DefectDojo 访问。对于自行管理的部署,这是运行 Wazuh Indexer 的主机。对于 Wazuh Cloud,请使用您 Wazuh Cloud 控制台中显示的 Indexer 端点,该端点与 Wazuh 仪表板 URL 不同。
* 一个对 `wazuh-states-vulnerabilities-*` 索引具有读取权限的 Indexer 用户及其密码。我们建议为 DefectDojo 创建专用用户。

必须在 Wazuh 中启用漏洞检测,以便填充漏洞状态索引。如需了解更多信息,请参阅 [Wazuh 漏洞检测文档](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html)。

#### Connector Mappings

1. 在**位置**字段中输入您的 Wazuh Indexer 基础 URL,需包含协议和端口,例如 `https://your-indexer.example.com:9200`。请勿包含末尾路径。DefectDojo 会自动构造搜索路径。
2. 在**用户名**字段中输入 Indexer 用户名。
3. 在**密码**字段中输入 Indexer 密码。
4. (可选)设置**最低严重程度**以限制导入哪些发现项。低于所选严重程度的发现项将不会被导入。

## Wiz

使用 Wiz 连接器需要您先创建一个服务账户:更多信息请参阅 [Wiz 文档](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account)。您需要拥有 Wiz 账户才能访问该文档。

该服务账户必须满足以下所有要求。缺少其中任何一项的服务账户仍可以成功进行身份验证,但不会导入任何内容:

* **类型**:Custom Integration(GraphQL API)。
* **API 范围**:至少需要 `read:projects`、`read:issues` 和 `read:vulnerabilities`。
* **项目可见性**:该服务账户的作用域必须涵盖您要导入的每一个 Wiz 项目(或全部项目)。连接器会先发现您的 Wiz 项目,然后再拉取每个项目的发现项——如果某个账户可以读取问题但没有项目可见性,则会发现零个项目,因此没有任何内容可导入,双方也都不会报告错误。

#### **Connector Mappings**

1. 在 Client ID 字段中输入您的 Wiz Client ID。
2. 在 Secret 字段中输入 Wiz Client Secret。

## **YesWeHack**

YesWeHack 连接器使用 YesWeHack REST API,从您的漏洞赏金和漏洞披露计划中导入报告。DefectDojo 会为您的令牌可访问的每个计划创建一条记录,并将其报告作为发现项导入。

#### Prerequisites

您需要一个 YesWeHack **个人访问令牌(Personal Access Token,PAT)**。拥有对您计划的读取权限即可。部分账户在创建令牌时需要 TOTP/MFA;令牌创建完成后,连接器使用的就是该令牌值本身。

1. 在 YesWeHack 中,打开账户设置并转到 **API / 个人访问令牌**。
2. 创建一个令牌并复制其值。该值仅显示一次。

#### Connector Mappings

1. 在**位置**字段中输入 `https://api.yeswehack.com/`。
2. 在**密钥**字段中输入您的个人访问令牌。
3. (可选)设置**最低严重程度**以限制导入哪些发现项。低于所选严重程度的发现项将不会被导入。

DefectDojo 会为您的令牌可访问的每个计划创建一条单独的记录,并将每份报告作为发现项导入。发现项的严重程度取自报告的 CVSS 评级(如无法获取则回退使用分诊优先级),其状态则反映报告的工作流状态——例如,已解决的报告会作为“已缓解”导入,被标记为无效或超出范围的报告会作为“非活动”导入。
