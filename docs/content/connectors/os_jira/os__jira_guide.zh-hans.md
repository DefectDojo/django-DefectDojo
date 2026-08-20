---
title: Jira
description: 使用 Jira 集成
weight: 2
audience: opensource
aliases:
- /zh-hans/issue_tracking/jira/os__jira_guide/
---

DefectDojo 的 Jira 集成可用于将发现项数据推送到一个或多个 Jira 空间。通过这种方式，您可以将 DefectDojo 集成到标准的开发工作流程中。以下是几个使用示例：

* AppSec 团队可以有选择地将发现项推送到开发人员使用的 Jira 空间，使问题修复能够与常规开发工作一起获得合理的优先级排序。使用该看板的开发人员无需访问 DefectDojo，就可以把所有工作集中在一个地方。
* DefectDojo 可以将所有发现项推送到 AppSec 团队使用的双向同步 Jira 空间，从而让团队可以分工进行问题验证。该看板会与 DefectDojo 保持同步，并支持复杂的修复工作流程。
* DefectDojo 还可以有选择地将不同产品和（或）测试活动中的发现项推送到不同的 Jira 空间，使各项内容保持在恰当的上下文中。

# 设置 Jira

设置 Jira 需要执行以下步骤：
1. 在系统设置中启用 Jira 集成。在启用之前，DefectDojo 中其余的 Jira 设置都会被隐藏。
2. 使用用户名/密码或 API 令牌连接一个 Jira 实例。可以链接多个实例。
3. 将该 Jira 实例添加到 DefectDojo 中的一个或多个产品或测试活动。
4. 如果您希望使用双向同步，请创建一个将更新发送到 DefectDojo 的 Jira Webhook。

## 第 1 步：在系统设置中启用 Jira 集成

Jira 集成默认处于关闭状态，在关闭期间，DefectDojo 会隐藏界面中所有其他 Jira 相关控件。这是需要配置的第一项内容：在启用之前，下面的其他步骤均无法进行。

在集成被禁用期间，侧边栏中不会出现 ⚙️ **配置 \> JIRA** 条目，因此无法添加 Jira 实例：

![图片](images/jira-config-menu-hidden-os.png)

### 启用集成

1. 从 DefectDojo 侧边栏导航到 ⚙️ **配置 \> 系统设置**。
​
2. 勾选 **启用 JIRA 集成**。
​
3. 集成一旦启用，就需要提供 **Jira webhook 密钥**。点击字段旁边的 🔄 图标即可生成一个。如果您在没有密钥的情况下提交表单，表单会被拒绝，并提示 *"This field is required when enable Jira Integration is True"*：

![图片](images/jira-webhook-secret-required-os.png)

该密钥是 Jira 发送请求所用 webhook URL 的一部分（`https://<YOUR DOJO DOMAIN>/jira/webhook/<SECRET>`），因此请将生成的值当作凭据对待。只有在按照[第 4 步](#step-4-configure-bidirectional-sync-jira-webhook)设置双向同步时，才需要将其提供给 Jira；现在生成它只是为了满足表单要求。

4. 点击 **提交**。⚙️ **配置 \> JIRA** 现在会出现在侧边栏中：

![图片](images/jira-enable-system-settings-os.png)

### 该设置的作用范围

勾选 **启用 JIRA 集成** 后，才会显示其余的 Jira 界面。开启该设置后，您将获得：

* ⚙️ **配置 \> JIRA** 页面，用于添加和编辑 Jira 实例
* 编辑产品（资产）和编辑测试活动表单中的 **JIRA** 部分，用于将产品或测试活动关联到某个 Jira 空间
* 发现项、发现项组和批量编辑表单中的 **推送到 Jira** 控件，以及发现项、测试活动和产品列表中的 Jira 列与筛选器

例如，只有在启用集成后，**JIRA** 部分才会出现在编辑产品表单的底部：

![图片](images/jira-asset-settings-visible-os.png)

该设置同样会在界面之外控制整个集成：在其关闭期间，DefectDojo 不会将发现项推送到 Jira（包括通过 API 发送的 `push_to_jira` 请求），传入的 Jira webhook 也会被忽略。

系统设置页面上其余的 Jira 字段（**启用 JIRA web hook**、**Jira 最低严重程度**、**Jira 标签**、**将漏洞 ID 添加为 JIRA 标签**）无论集成是开启还是关闭都会保持可见，但在集成启用之前不会生效。

## 第 2 步：连接 Jira 实例

启用集成后，连接 Jira 实例是设置 DefectDojo Jira 集成的下一步。请注意，目前尚不支持 Jira Service Management。

#### 需要从 Jira 获取的信息

Atlassian 在 Jira Cloud 和 Jira Data Center 之间使用不同的身份验证方式。

对于 **Jira Cloud**，您需要：
* 一个 Jira URL，例如 https://yourcompany.atlassian.net/
* 一个在您的 Jira 实例中拥有创建和更新问题权限的账户。可以是：
    * 标准的 **用户名/密码** 组合
    * **用户名/API 令牌** 组合

对于 **Jira Data Center（或 Server）**，您需要：
* 一个 Jira URL，例如 https://jira.yourcompany.com
* 一个在您的 Jira 实例中拥有创建和更新问题权限的账户。可以是：
    * 标准的 **用户名/密码** 组合

您还可以选择映射：
* 用于触发发现项重新打开和关闭的 Jira 转换
* 可以将风险已接受和误报状态应用到发现项的 Jira 解决结果（可选）

只要 DefectDojo 使用的 Jira 账户/令牌在相应的 Jira 空间中拥有创建问题的权限，一个 Jira 实例连接就可以处理多个 Jira 空间。

### 添加 Jira 实例

1. 请确保已按照[第 1 步](#step-1-enable-the-jira-integration-in-system-settings)中的说明，在系统设置中勾选 **启用 JIRA 集成**。在勾选之前，侧边栏不会出现 ⚙️ **配置 \> JIRA** 选项。
​
2. 从 DefectDojo 侧边栏导航到 ⚙️ **配置 \> JIRA** 页面。
​
![图片](images/Connect_DefectDojo_to_Jira.png)

3. 您将看到当前已链接到 DefectDojo 的所有 Jira 空间配置列表。要添加新的项目配置，请点击扳手图标，然后选择 **添加 Jira 配置（快速）** 或 **添加 Jira 配置** 选项。

#### 添加 Jira 配置（快速）

快速方式可以更快地完成空间关联。如果您只是想快速连接一个 Jira 空间，且不涉及复杂的 Jira 工作流程，可以使用快速方式。

![图片](images/Connect_DefectDojo_to_Jira_2.png)

1. 为此 Jira 配置选择一个将在 DefectDojo 中使用的名称。该名称只是 DefectDojo 中该实例连接的标签，不需要与任何 Jira 数据相关联。
​
2. 选择您公司 Jira 实例的 URL——如果您使用的是 Jira Cloud，该 URL 可能类似于 `https://**yourcompany**.atlassian.net`。
​
3. 在 Jira 的用户名/密码字段中输入合适的身份验证方式：
    * 如果使用标准的 **用户名/密码 Jira 身份验证**，请在这些字段中输入 Jira 用户名和对应的密码。
    * 如果使用 **用户 API 令牌进行身份验证（Jira Cloud）**，请输入用户名，并在密码字段中输入对应的 **API 令牌**。
​
4. 选择您希望在 Jira 中创建问题时使用的默认问题类型。可选项为 **Bug、Task、Story** 和 **Epic**（均为标准 Jira 问题类型），以及 **Spike** 和 **Security**（这两种为自定义问题类型）。如果您希望使用其他问题类型，请联系 [support@defectdojo.com](mailto:support@defectdojo.com) 寻求帮助。
​
5. 选择您的问题模板，它将决定在 Jira 中创建问题时的问题描述内容。

这两种类型是：
- **Jira\_full**，将在 Jira 问题中包含所有发现项信息
- **Jira\_limited**，仅包含少量发现项信息和元数据。

如果将此字段留空，将默认使用 **Jira\_full。**

6. 选择一个或多个 Jira 解决结果类型，当问题上触发相应解决结果时，会将发现项状态更改为风险已接受。如果不希望使用此自动化功能，可以将该字段留空。
​
7. 选择一个或多个 Jira 解决结果类型，当问题上触发相应解决结果时，会将发现项状态更改为误报。如果不希望使用此自动化功能，可以将该字段留空。
​
8. 决定是否希望以评论形式在 Jira 问题上发送 SLA 通知。
​
9. 决定是否希望自动将发现项与 Jira 同步。如果启用此选项，Jira 问题将自动与相关发现项保持同步。如果未启用，则在 Jira 中创建问题后，您需要手动推送对发现项所做的任何更改。
​
10. 选择您的问题键。在 Jira 中，这是与某个问题关联的字符串（例如，在名为 **EXAMPLE\-123** 的问题中，**'EXAMPLE'** 这个词）。如果您不知道自己的问题键，请在该 Jira 空间中创建一个新问题。在下方截图中可以看到，我们这个 Jira 空间的问题键是 **DEF**。
​
![图片](images/Connect_DefectDojo_to_Jira_3.png)
​
11. 点击 **提交。** DefectDojo 将自动在 Jira 中查找合适的映射，并将其添加到该配置中。现在，您可以将此配置关联到 DefectDojo 中的一个或多个产品了。

#### 添加 Jira 配置（标准）

标准 Jira 配置增加了一些额外步骤，可以更精确地控制 Jira 映射和交互方式。即使某个 Jira 配置是使用快速方式创建的，之后也可以改用标准方式进行调整。
​
### 其他表单选项

* **Epic Name ID：** 如果您的 Jira 中有多种 Epic 类型，可以在 Jira 字段规范中找到相应 ID，从而指定要使用的类型。
​
要获取 'Epic name id'，请访问 `https://<YOUR JIRA URL>/rest/api/2/field` 并搜索 Epic Name。从 `number` 中复制出数字，并粘贴到此处。
​  ​
* **Reopen Transition ID：** 如果您希望使用特定的 Jira 转换来重新打开某个问题，可以在此处指定转换 ID。如果使用快速 Jira 配置，DefectDojo 将自动查找合适的转换并创建映射。
​
访问 `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` 以查找适用于您 Jira 实例的 ID。将其粘贴到 Reopen Transition ID 字段中。
​
* **Close Transition ID：** 如果您希望使用特定的 Jira 转换来关闭某个问题，可以在此处指定转换 ID。如果使用 **快速 Jira 配置**，DefectDojo 将自动查找合适的转换并创建映射。
​
访问 `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` 以查找适用于您 Jira 实例的 ID。将其粘贴到 Close Transition ID 字段中。
​
* **Mapping Severity Fields：** 每个 Jira 问题都有一个关联的优先级，DefectDojo 会根据发现项的严重程度自动指定该优先级。请为信息、低、中、高和严重这几个严重程度分别输入要映射到的优先级名称。

* **Finding Text**——如果您希望在每个创建的问题中添加额外的标准化文本，可以在此处输入。这段文本不会映射到 Jira 中的任何字段，而是作为附加内容添加到问题描述中，例如「**Created by DefectDojo**」。

Jira 中的评论与 DefectDojo 中的备注可以保持同步。在将 Jira 配置添加到某个产品后，可以通过 **编辑产品** 表单启用此设置。

## 第 3 步：将产品或测试活动连接到 Jira

DefectDojo 中的每个产品或测试活动都有各自的设置，用于控制发现项如何转换为 JIRA 问题。您可以在此处确定关联的 Jira 空间，并设置创建问题、Epic、标签及其他 JIRA 元数据的默认行为。

### 将 Jira 添加到产品或测试活动

在经典界面中，您可以通过打开编辑产品或编辑测试活动表单来找到 Jira 设置，即页面上 **设置** 下的「**📝 Edit**」按钮：

![图片](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### Jira 设置列表

Jira 设置位于产品设置页面的底部附近。

![图片](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Jira 实例

如果您为组织内不同的产品或团队设置了多个 Jira 实例，可以指定希望 DefectDojo 在哪个 Jira 空间中创建问题。请从下拉菜单中选择一个项目。

如果此菜单没有列出任何 Jira 实例，请确认这些项目已在 DefectDojo 的全局 Jira 配置中连接——yourcompany.defectdojo.com/jira。

#### 项目键

这是您希望在 DefectDojo 中使用的空间的键。给定项目的空间键可以在 URL 中找到，也可以在空间设置中的「Space key」下找到。

![图片](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### 问题模板

您可以在此处确定要向 Jira 发送多少 DefectDojo 元数据。请选择以下两个选项之一：

* **jira\_full**：问题将跟踪来自 DefectDojo 的所有参数——完整的描述、CVE、严重程度等。如果您需要在 Jira 中获取完整的发现项上下文（例如处理该问题的人员无法访问 DefectDojo），这个选项会很有用。

以下是 **jira\_full** 问题的示例：
​
![图片](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited：** 问题只会跟踪 DefectDojo 链接、产品/测试活动/测试链接，以及报告人和环境字段。其他所有字段仅在 DefectDojo 中跟踪。如果您不需要在 Jira 中获取完整的发现项上下文（例如处理该问题的人员主要在 DefectDojo 中工作，不需要在 JIRA 中也掌握完整情况），这个选项会很有用。

​以下是 **jira\_limited** 问题的示例：​

![图片](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### 组件

如果您使用组件来管理 Jira 空间，可以在此处为 DefectDojo 指定合适的组件。如需指定多个组件，请输入以逗号分隔的列表（例如 `Security, DevSecOps`）；每个值都会作为单独的组件发送到 Jira。

**自定义字段**

如果您不需要在 DefectDojo 的问题中使用自定义字段，可以将此字段保留为 'null'。

但是，如果您的 Jira 空间设置**要求您**在新建问题时使用自定义字段，您就需要将这些映射硬编码。

**Jira Cloud 现在允许您直接在应用内创建默认的自定义字段值。有关如何配置此项的更多信息，请参阅 [Atlassian 关于自定义字段的文档](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/)。**

请注意，DefectDojo 无法将特定于某个问题的元数据作为自定义字段发送，只能发送默认值。只有当您的 Jira 空间**要求空间中的每个问题都必须存在这些自定义字段**时，才需要设置此部分。

请按照 **[本指南](#custom-fields-in-jira)** 开始使用自定义字段。

**Jira 标签**

选择您希望问题在 Jira 中创建时附带的相关标签，例如 **DefectDojo**、**YourProductName..**

![图片](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### 默认经办人

Jira 中默认经办人的名称。如果留空，DefectDojo 在创建问题时将遵循您 Jira 空间中的默认行为。

### 其他表单选项

#### 启用与 Jira 空间的连接

只有在没有创建任何相关问题的情况下，才能从您的实例中移除 Jira 集成。如果已经创建了问题，则无法从 DefectDojo 中彻底移除某个 Jira 实例。

不过，您可以在产品级别禁用 Jira 集成。这不会删除或更改 DefectDojo 已创建的任何现有 Jira 工单，但会禁止后续的所有更新。

#### 将漏洞 ID 添加为 Jira 标签

此选项可让您自动将漏洞 ID 数据添加为 Jira 标签。漏洞 ID 是由各个安全工具添加到发现项中的——可能是 Common Vulnerabilities and Exposures（CVE）编号，也可能是特定于报告该发现项的工具的其他格式。

#### 启用测试活动 Epic 映射（针对产品）

在 DefectDojo 中，测试活动代表一系列工作的集合。每个测试活动包含一个或多个测试，而每个测试又包含一个或多个需要缓解的发现项。Jira 中的 Epic 也以类似的方式运作，此复选框可让您将测试活动作为 Epic 推送到 Jira。

* DefectDojo 中的一个测试活动——请注意底部列出的三个发现项。
​
![图片](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* 同一个测试活动推送到 JIRA 后如何变成一个 Epic——该测试活动的发现项也会一并推送，并作为子问题存在于该 Epic 内部。

![图片](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### 推送所有问题

如果勾选，DefectDojo 会自动将所有活动且已验证的发现项作为问题推送到 Jira。如果不勾选，则所有发现项都需要手动推送到 Jira。

#### 推送备注

如果启用，Jira 评论会显示在 DefectDojo 中相关发现项的备注下（截图），反之亦然；发现项上的备注也会作为评论添加到相关的 Jira 问题中。

#### 以评论形式发送 SLA 通知

如果启用，任何违反 DefectDojo 服务级别协议规则的问题都会在对应的 Jira 问题上添加相应的提示评论。这些评论会每天发布一次，直到该问题得到解决为止。

服务级别协议可以在 DefectDojo 的 **配置 \> SLA 配置** 下进行设置，并分配给各个产品。

#### 以评论形式发送风险接受到期通知？

如果启用，当某个问题关联的 DefectDojo 风险接受到期时，会在该 Jira 问题上添加相应的提示评论。这些评论会每天发布一次，直到该问题得到解决为止。

### 测试活动级别的 Jira 设置

因此，同一产品内的不同测试活动可以拥有各自不同的底层 Jira 设置。默认情况下，测试活动会'**继承产品的 Jira 设置'**，即与其所属的产品共享相同的 Jira 设置。

不过，您可以将某个测试活动的 **产品键**、**问题模板、自定义字段、Jira 标签、默认经办人** 更改为与默认产品设置不同的值

您可以从 **编辑测试活动** 页面访问此页面：**your\-instance.defectdojo.com/engagement/\[id]/edit**。

编辑测试活动页面可以从测试活动页面中找到，方法是点击该测试活动描述旁边的 ☰ 菜单。

![图片](images/Creating_Issues_in_Jira_5.png)

## 第 4 步：配置双向同步：Jira Webhook

Jira 集成支持通过 webhook 实现双向同步。DefectDojo 会在一个唯一地址上接收 Jira 通知，根据您的配置，这既可以让发现项接收来自 Jira 的评论，也可以让发现项通过 Jira 得到解决。

### 查找您的 Jira Webhook URL

您的 Jira Webhook 由您的 DefectDojo URL 和您在[第 1 步](#step-1-enable-the-jira-integration-in-system-settings)中生成的 **Jira webhook 密钥** 组成。两者都会显示在 ⚙️ **配置 \> 系统设置** 页面上，位于 **Jira webhook 密钥** 字段旁边（参见第 1 步中的截图）。

在 DefectDojo 处理传入的 Jira 通知之前，您还需要在同一页面上勾选 **启用 JIRA web hook**。如果该复选框或 **启用 JIRA 集成** 中任意一个未被勾选，传入的 webhook 都会被忽略。

### 创建 Jira Webhook

1. 访问 `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. 点击「Create a Webhook」。
3. 在标有「URL」的字段中输入：`https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`。该 Webhook 密钥已在上文的 **Jira webhook 密钥** 字段旁列出。
4. 在「Comments」下启用「Created」。在 Issue 下启用「Updated」。
5. 请确保您的 JIRA 实例信任 DefectDojo 实例所使用的 SSL 证书。对于 JIRA Cloud，DefectDojo 必须使用[由全球受信任的证书颁发机构签发的有效 SSL/TLS 证书](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

请注意，使用此 webhook 并不需要在 Jira 内创建密钥。该密钥已内置在 DefectDojo 的 URL 中，因此只需将完整的 URL 添加到 Jira Webhook 表单即可。

传入的 webhook 请求是通过该 URL 中的密钥进行身份验证的，因此请将完整的 URL 当作凭据对待，并妥善保密。

#### 测试 Webhook

一旦您根据 DefectDojo 发现项创建了一个或多个问题，就可以通过在其中一个发现项上添加评论来测试该 Webhook。该评论应当会被 Jira webhook 作为备注接收。

如果这一操作没有正常生效，可能是您 Jira 实例上的防火墙问题阻挡了该 Webhook。

* DefectDojo 的防火墙规则中包含一个 **Jira Cloud** 复选框，必须启用该选项，DefectDojo 才能接收来自 Jira 的 Webhook 消息。

### 替代方案：使用 Jira Automation（发送 Web 请求）

某些 Jira 实例不允许使用 `/plugins/servlet/webhooks` 下的系统 webhook — 例如，当该管理区域受到限制、只允许使用 **Jira Automation** 规则时。在这种情况下，您可以使用 Automation 的 **发送 Web 请求** 操作来实现同样的双向同步，该操作会向相同的 DefectDojo webhook 端点发送请求。

DefectDojo 的 webhook 端点接受任何 HTTP `POST` 请求，只要其请求头包含 `Content-Type: application/json` 且 URL 路径中带有有效的密钥即可。它**并不**要求请求必须来自 Jira 的系统 webhook 机制，因此 Automation 的"发送 Web 请求"操作可以作为现成的替代方案使用。

#### 前提条件

系统 webhook 的前提条件同样适用：

* 在 ⚙️ **配置 \> 系统设置** 页面上，**启用 JIRA 集成** 和 **启用 JIRA web hook** 均已勾选。
* 该页面上已设置一个非空的 **Jira webhook 密钥**。该密钥只能包含 `A-Z`、`a-z`、`0-9`、`_` 和 `-` 这些字符。
* 该发现项（或发现项组）已关联到该 Jira 问题。如果该问题未关联任何 DefectDojo 发现项，请求仍会被接受（HTTP `200`），但不会执行任何操作。

#### DefectDojo 如何处理该请求

* DefectDojo 会根据顶层的 `webhookEvent` 字段进行分支处理。只会处理 `"jira:issue_updated"` 和 `"comment_created"` 这两个值；其他任何值都会被接受但忽略。Automation **不会**自行添加此字段，因此您必须在请求正文中自行包含该字段。
* 因此，请将请求的 **Body** 设置为 **Custom data**，并提供下面的 JSON。**Empty** 和 **Jira issue data** 这两个正文选项不包含必需的 `webhookEvent` 字段，因此 DefectDojo 会忽略它们。
* 无论是否成功应用了更新，该端点始终返回 HTTP `200`。成功或失败只能在响应正文和 DefectDojo 日志中查看 — Automation 审计日志中的 `200` 本身**并不能**确认该更新已经送达某个发现项。

#### 规则 1 — 问题已更新

创建一个具有以下设置的 Automation 规则：

* **Trigger：** *Issue transitioned*（或者其他在您要同步的字段发生变化时触发的条件，例如 Status 上的 *Field value changed*）。
* **Action：** *Send web request*
  * **Web request URL：** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method：** `POST`
  * **Web request body：** *Custom data*
  * **Headers：** `Content-Type: application/json`
  * **Custom data：**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

问题更新的约束条件：

* `issue.id` 必须是 **Jira 问题内部的数字 ID**（`{{issue.id}}`），而不是问题键（例如 `PROJ-123`）。DefectDojo 会根据这个数字 ID 将更新匹配到对应的发现项。
* `resolution` 和 `updated` 字段必须始终存在。`resolution` 可以为 `null`，但如果缺少其中任何一个字段，请求会被接受（`200`），但会被静默地不予处理。
* 状态同步和自动缓解由 `status.statusCategory.key` 驱动，其 Jira 取值为 `new`（待处理）、`indeterminate`（处理中）和 `done`（已完成）。只有当问题真正被关闭时，发现项才会被缓解，而不是仅仅因为出现了某个解决结果值。

#### 规则 2 — 问题已评论

创建第二个具有以下设置的 Automation 规则：

* **Trigger：** *Issue commented*
* **Action：** *Send web request* — 与规则 1 相同的 URL、方法、请求头及 *Custom data* 正文选项，正文内容如下：

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

评论的约束条件：

* `body` 和 `updateAuthor` 必须同时存在。
* DefectDojo 会从 `comment.self` URL 中推导出目标问题 — 具体来说，是 `<id>`，即 `.../issue/<id>/comment/...` 这一段中的对应部分 — 因此该处必须填入 `{{issue.id}}`（该数字 ID）。
* **循环预防：** 如果评论作者与 DefectDojo 用来发布自身评论的 Jira 账户相同，DefectDojo 会跳过该评论，以避免产生回声循环。如果您希望*所有*评论都被接收，请使用与 DefectDojo 的 Jira 实例中配置的账户**不同**的 Jira 用户来运行该 Automation 规则。

#### 关于智能值的说明

上面展示的智能值（`{{issue.id}}`、`{{issue.status.statusCategory.key}}`、`{{comment.author.accountId}}` 等）是 Jira Cloud 的标准名称，但在不同实例之间可能会有所差异。在正式上线前，请使用 Automation 的 payload 预览功能，确认每个智能值都能解析为您预期的结果。

## 测试 Jira 集成

#### 测试 1：发现项能否成功推送到 Jira？

为了测试 Jira 集成是否正常工作，您可以在 DefectDojo 中为与 Jira 关联的产品添加一个新的空白发现项。**产品 \> 发现项 \> 添加新发现项。**

填写您想要的标题、严重程度和描述，然后点击“完成”。该发现项应作为问题出现在 Jira 中，并带有所有相关元数据。

如果 Jira 问题未能正确创建，请检查您的通知中是否存在错误代码。

* 请确认与 DefectDojo 的 Jira 配置相关联的 Jira 用户，在该 Jira 空间中拥有创建和更新问题的权限。

#### 测试 2：Jira Webhook 发送到 DefectDojo

为了测试 Jira 的 Webhook，请为一个同时在 JIRA 中作为问题存在的发现项添加一条备注（例如上一节中的测试问题）。

如果 Webhook 配置正确，您应该会在 Jira 中看到该备注作为该问题下的一条评论出现。

如果此功能未能正常工作，可能是您的 Jira 实例上存在防火墙问题，阻止了该 Webhook。

* DefectDojo 的防火墙规则中包含一个 **Jira Cloud** 复选框，必须先启用该复选框，DefectDojo 才能接收来自 Jira 的 Webhook 消息。

## 断开与 Jira 的连接

只有在尚未创建任何相关问题的情况下，才能从您的实例中移除 Jira 集成。如果已经创建了问题，则无法从 DefectDojo 中完全移除某个 Jira 实例。

不过，您可以在产品级别禁用 Jira 集成：在**编辑产品**表单中，取消勾选“启用与 Jira 空间的连接”选项即可。这不会删除或更改任何已由 DefectDojo 创建的现有 Jira 工单，但会禁止后续的任何更新。

# 将发现项推送到 Jira

## 将发现项推送到 Jira
具有 JIRA 映射的产品可以将发现项作为问题推送到 Jira。这可以通过以下两种方式进行管理：

* 可以逐个发现项手动创建为问题。
* 如果在产品上启用了“**推送所有问题**”设置，发现项也可以自动推送。（这仅适用于**活动**且**已验证**的发现项。）

此外，您还可以选择将发现项组推送到 Jira，而不是推送单个发现项。这样会创建一个问题，其中包含多个相关的 DefectDojo 发现项。

### 手动推送发现项

1. 在 DefectDojo 的发现项页面中，导航到 **JIRA** 标题处。如果该发现项尚未作为问题存在于 JIRA 中，则 JIRA 标题处的值将显示为“**无**”。
​
2. 点击“**无**”值旁边的箭头，即可创建一个新的 Jira 问题。该问题创建时所处的状态，取决于您团队的工作流以及 DefectDojo 中的 Jira 配置。如果发现项没有出现，请刷新页面。
​
![图片](images/Creating_Issues_in_Jira.png)

3. 问题创建后，DefectDojo 会创建一个指向该问题的链接，该链接由 Jira 键和问题 ID 组成。链接旁边还会有一个红色垃圾桶图标，可用于从 Jira 中删除该问题。
​
![图片](images/Creating_Issues_in_Jira_2.png)

4. 再次点击该箭头，会将对该问题所做的所有更改推送到 Jira，并相应地更新该 Jira 问题。如果该发现项所属产品启用了“**推送所有问题**”设置，此过程将自动进行。

### Jira 评论

* 如果在某个 Jira 问题上添加了评论，同样的评论也会被添加到该发现项的**备注**部分下。
* 同样，如果为某个发现项添加了备注，该备注也会作为评论被添加到 Jira 问题中。

### Jira 状态变更

DefectDojo 上的 Jira 配置中包含两个 Jira 转换的设置项，它们会触发发现项的状态变更。

* 当在 Jira 上执行**“关闭”转换**时，相关联的发现项也会关闭，并在 DefectDojo 中被标记为**非活动**和**已缓解**。DefectDojo 会在发现项页面的**缓解方式**标题下记录此项变更。
​
![图片](images/Creating_Issues_in_Jira_3.png)

* 当在 Jira 问题上执行**“重新打开”转换**时，相关联的发现项会在 DefectDojo 中被设置为**活动**，并失去其**已缓解**状态。

### 将 Jira 解决方案映射到风险接受/误报

除了“关闭/重新打开”转换之外，Jira 配置中还包含一些可选字段，让您可以将 Jira 的**解决方案**映射到 DefectDojo 发现项的状态。这些字段是在**添加 Jira 配置（快速）**工作流的步骤 6 和步骤 7 中设置的，之后也可以在 Jira 配置中进行编辑：

* **风险已接受发现项映射解决方案** — 当某个 Jira 问题以此解决方案关闭时，与之关联的发现项在 DefectDojo 中会变为风险已接受状态。
* **误报发现项映射解决方案** — 当某个 Jira 问题以此解决方案关闭时，与之关联的发现项在 DefectDojo 中会变为误报状态。

#### 状态与解决方案：一个常见的混淆点

这些字段映射的是 Jira 的**解决方案**，而不是 Jira 的**状态**。状态和解决方案是两个相互独立的 Jira 概念：状态描述的是该问题在工作流中所处的位置（Open、In Progress、Done），而解决方案描述的是该问题是如何被解决的（Fixed、Won't Do、Duplicate、False Positive 等）。

一个常见的混淆点在于：Jira 的工作流转换可以将状态更改为“Done”，但*不*设置任何解决方案。发生这种情况时，DefectDojo 的解决方案映射将不会被触发——发现项会按照上文所述的标准**“关闭”转换**行为被标记为**已缓解**，而不是风险已接受或误报。

#### 前提条件：Jira 工作流转换上的“Set issue resolution”后置函数

Jira 的工作流引擎不会自动填充“解决方案”字段。每个需要以特定解决方案关闭问题的转换，都必须在该转换本身上配置一个**Set issue resolution**后置函数。如果没有配置该后置函数，问题会转移到新的状态，但解决方案字段会保持为空，DefectDojo 的映射也就没有可匹配的对象。

Jira 管理员可以通过**项目设置 → 工作流 →（编辑工作流）→（选择相应的关闭转换）→ 后置函数 → 添加后置函数 → Set issue resolution**这一路径添加该后置函数。

## 将发现项组作为 Jira 问题推送

如果您启用了发现项组功能，就可以将一组发现项作为单个问题推送到 Jira，而不是为每个发现项分别创建单独的问题。

不过，与发现项组相关联的 Jira 问题无法通过 DefectDojo 进行交互或删除，必须直接从 Jira 实例中删除。

### 自动创建并推送发现项组

在启用了“自动推送到 Jira”并且在导入时选择了分组依据选项的情况下：

只要发现项组被成功创建，自动推送到 Jira 并作为问题创建的就是该发现项组，而不是各个独立的发现项。

![图片](images/Creating_Issues_in_Jira_4.png)

## Jira 中的自定义字段
<span style="background: rgba(243, 122, 78,0.5">DefectDojo 目前不支持将任何特定于问题的信息传递到这些自定义字段中——这些字段在问题创建后，需要在 Jira 中手动更新。每个自定义字段通过 DefectDojo 创建时，都只会带有一个默认值。</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud 现在允许您直接在应用内创建自定义字段的默认值。有关如何配置此功能的更多信息，请参阅[Atlassian 关于自定义字段的文档](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/)。</span>

DefectDojo 内置的 Jira 问题类型（**Bug、Task、Story** 和 **Epic**）都已配置完毕，可以“开箱即用”。DefectDojo 中的数据字段会自动映射到 Jira 中的相应字段。默认情况下，DefectDojo 会为其创建的任何新问题分配优先级、标签和报告人。

某些 Jira 配置在创建问题之前，还需要处理额外的自定义字段。以下流程将帮助您在 DefectDojo \-\> Jira 集成中处理这些自定义字段，确保问题能够成功创建。这些自定义字段会被添加到从 DefectDojo 发送到关联 Jira 实例的所有 API 调用中。

如果您尚未在 Jira 中使用自定义字段，则无需遵循此流程。

1. 记录您在 Jira 中的自定义字段名称（**Jira UI**）
2. 确定新自定义字段的键值（Jira 字段规范端点）
3. 以键值为参照，找到每个自定义字段可接受的数据（Jira 问题端点）
4. 创建一个字段参考 JSON 代码块，用于记录所有自定义字段的键及其可接受的数据（Jira 问题端点）
5. 将该 JSON 代码块存储在关联的 DefectDojo 产品中，以便能够从 Jira 创建自定义字段（DefectDojo UI）
6. 测试您的配置，确保所有必需的数据都能从 Jira 正确传输

#### 步骤 1：记录您在 Jira 中的自定义字段名称

Jira 支持多种不同的上下文字段，包括日期选择器、自定义标签、单选按钮等。每个上下文字段都有各自不同的键值，可以在 Jira API 中找到。

请写下每个所需自定义字段的名称，因为在下一步中，您需要通过 Jira API 来查找它们。

**自定义字段列表示例（您的自定义字段名称会有所不同）：**

* DefectDojo 自定义 URL 字段
* 另一个自定义字段示例
* ...

#### 步骤 2：查找您的 Jira 自定义字段键值

首先，导航到您整个 Jira 实例的字段规范 URL。

下面是一个字段规范 URL 的示例：

`https://yourcompany-example.atlassian.net/rest/api/2/field`

该 API 会返回一长串 JSON 字符串，您应将其格式化为可读文本（可以使用代码编辑器、浏览器扩展程序，或访问 <https://jsonformatter.org/>）。

该 URL 返回的 JSON 会包含您所有的 Jira 自定义字段，其中大多数与 DefectDojo 无关，其值为 `"Null"`。此 API 响应中的每个对象对应 Jira 中的一个不同字段。您需要查找那些 `"name"` 属性与您在 Jira UI 中创建的每个自定义字段名称相匹配的对象，然后记下它们的 "key" 属性的值。

![图片](images/Using_Custom_Fields.png)

在 JSON 输出中找到匹配的对象后，您就可以确定该对象的 "key" 值——在本例中，它是 `customfield_10050`。

Jira 会为每个自定义字段生成不同的键值，但这些键值一旦创建就不会再更改。如果您以后创建另一个自定义字段，它将拥有一个新的键值。

**扩展我们的自定义字段列表：**

* "DefectDojo 自定义 URL 字段" \= customfield\_10050
* "另一个自定义字段示例" \= customfield\_12345
* ...

#### 步骤 3：在 Jira 问题上查找自定义字段

在 Jira 中找到一个包含您在步骤 2 中记录的自定义字段的问题。复制该问题标题对应的问题键（格式类似于 "`EXAMPLE-123`"），然后导航到以下 URL：

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

这将返回另一段 JSON 字符串。

和之前一样，API 输出中会包含大量值为 `null` 的 `customfield_##` 对象参数——这些是 Jira 默认添加的自定义字段，与该问题无关。输出中还会包含与您在上一步中找到的自定义字段键值相匹配的 `customfield_##` 值。与字段规范的输出不同，您在这里看不到任何标识这些自定义字段的名称，这也是为什么您需要在步骤 2 中记录键值的原因。

![图片](images/Using_Custom_Fields_2.png)

**示例：**
我们知道 `customfield_10050` 代表 DefectDojo 自定义 URL 字段，因为我们在步骤 2 中已经记录过它。现在我们可以看到，在 `EXAMPLE-123` 问题中，`customfield_10050` 的值为 `"https://google.com"`。

#### 步骤 4：根据每个 Jira 自定义字段键创建 JSON 字段参考

现在，您需要获取列表中每个自定义字段的值，并将它们存储在一个 JSON 对象中（用作参考）。您可以忽略任何不在您列表中的自定义字段。

这个 JSON 对象将包含新 Jira 问题所需的所有默认值。我们建议使用团队容易识别为“待更改”默认值的名称，例如：“`change-me.com`”、“`Change this paragraph.`”等。

**示例：**

根据步骤 3，我们现在知道 Jira 期望 "`customfield_10050`" 对应一个 URL 字符串。我们可以据此构建示例 JSON 对象。

假设我们还找到了一个与 DefectDojo 相关的短文本字段，并将其识别为 "`customfield_67890`"。我们会在第二次 API 输出中查看该字段，查看其关联的值，并同样将该存储值引用到我们的示例 JSON 对象中。
​
随着您添加更多自定义字段，您的 JSON 对象将逐渐变成如下所示的样子。

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

重复此过程，直到您已将 Jira 中所有与 DefectDojo 相关的自定义字段都添加到您的 JSON 字段参考中。

#### 数据类型与 Jira 语法

某些字段，例如日期字段，在 Jira 中可能对应多个自定义字段。如果是这种情况，您需要将这两个字段都添加到您的 JSON 字段参考中。

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

其他字段，例如标签字段，可能会以字符串列表的形式记录——请确保您的 JSON 字段参考所使用的格式，与 Jira 的 API 输出格式相匹配。

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

其他一些自定义字段可能包含额外的上下文信息，这些信息应当从字段参考中移除。例如，自定义多选字段在 API 输出中会包含一个额外的代码块，您需要将其移除，因为该代码块存储的是该字段当前的值。

* 您应当从该字段中移除多余的对象：

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* 您可以将其简化为以下内容，忽略第二部分：

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### 完整字段参考示例

下面是一个完整的 JSON 字段参考，其中的行内注释说明了每个自定义字段所对应的内容。这只是一个尽可能全面的示例。您实际的 JSON 会包含不同的键值和数据，具体取决于您希望在创建问题时使用的自定义值。

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### 步骤 5：将自定义字段添加到 DefectDojo 产品

现在，您可以在关联的 DefectDojo 产品中的自定义字段部分，添加这些自定义字段。具体操作如下：

* 导航到编辑产品页面 - defectdojo.com/product/ID/edit。
* 导航到自定义字段，将 JSON 字段参考以纯文本形式粘贴到自定义字段框中。
* 点击“提交”。

#### 步骤 6：通过新建发现项测试您的 Jira 自定义字段：

现在，当您在与 Jira 关联的产品中创建新的发现项时，Jira 会根据其中包含的 JSON 代码块，自动在 Jira 中创建所有这些自定义字段。这些自定义字段将带有默认值（例如 "change-me-please" 等）被创建。

在 DefectDojo 的产品中，导航到发现项 \> 添加新发现项页面。请确保该发现项同时处于活动和已验证状态，以确保它会被推送到 Jira，然后在 Jira 端确认这些自定义字段已成功创建，且没有任何不一致之处。
