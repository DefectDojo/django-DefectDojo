---
title: Jira（旧版）
description: 使用 Jira 集成
weight: 1
audience: pro
aliases:
- /zh-hans/issue_tracking/jira/pro__jira_guide/
- /zh-hans/en/share_your_findings/jira_guide
---

> **本页介绍的是旧版 Jira 集成。** 这里所述的按产品配置的 Jira 集成已被 **[Jira 下游连接器](/connectors/downstream/about/)** 取代；该连接器目前已在每个 DefectDojo Pro 实例上全面提供，是将发现项推送到 Jira 的推荐方式。因此，在 Pro 侧边栏中，**Connect > Jira** 带有 `LEGACY` 徽章——详见[菜单徽章](/navigation/pro__menu_badges/)。
>
> **如果您是第一次配置 Jira，请从 [下游连接器](/connectors/downstream/about/) 开始，而不是本指南。**
>
> **已经在使用旧版集成？** DefectDojo Pro 提供内置的迁移功能，可将您现有的经典 Jira 配置迁移到下游连接器，其中包括已经推送过的工单——详见下文的[迁移到 Jira 下游连接器](#migrating-to-the-jira-downstream-connector)。
>
> 旧版集成会继续正常运作，本指南的内容对其仍然准确适用。

DefectDojo 的 Jira 集成可用于将发现项数据推送到一个或多个 Jira Space。这样一来，您就可以将 DefectDojo 整合到标准的开发工作流程中。下面是几个具体的应用示例：

* AppSec 团队可以有选择地将发现项推送到开发人员使用的 Jira Space，从而使问题修复工作能够与日常开发工作一起得到合理的优先级排序。使用该看板的开发人员无需访问 DefectDojo——他们可以将所有工作都集中在一个地方进行。
* DefectDojo 可以将所有发现项推送到 AppSec 团队使用的双向同步 Jira Space，从而让团队能够分工进行问题验证。该看板会与 DefectDojo 保持同步，并支持复杂的修复工作流程。
* DefectDojo 可以有选择地将来自不同产品和/或测试活动的发现项推送到不同的 Jira Space，从而使每项内容都保持在恰当的上下文中。

## 迁移到 Jira 下游连接器

DefectDojo Pro 可以自动将您现有的经典 Jira 配置转换为下游连接器配置，无需您手动重新搭建。

**入口位置：** 前往 **Connect \> Downstream** 打开**下游连接器**页面，然后使用 **Classic Jira Migration** 卡片。点击 **Migrate from classic Jira**，然后确认。

只有在存在待迁移的经典 Jira 配置，或存在需要报告的历史运行记录时，该卡片才会出现——因此从未使用过经典 Jira 的实例不会看到它。全部迁移完成后，卡片仍会保留，但按钮会被禁用，因为已经没有可执行的操作。

运行迁移需要具备**全局 Maintainer 级别权限**（具体而言，是编辑集成的权限），并且必须在已登录的浏览器会话中执行——无法通过 API 令牌来驱动。

### 已推送的工单会发生什么变化

**您现有的 Jira 工单会被保留并重新关联——不会成为孤立工单，连接器也不会重复创建。** 每一个此前已由经典 Jira 推送过的发现项都会保留其原有工单，此后由连接器接管，就地更新同一张工单。发现项组上的关联链接也会以同样的方式延续下来。

唯一的例外是**测试活动 Epic**。下游连接器没有 Epic 的概念，因此 Epic 工单会在迁移的警告信息中列出，并保持不变。

### 迁移的内容

* 您的 Jira**实例**连接——包括 URL 和凭据——会成为一个下游连接器集成实例，并保留其原有名称。
* **严重程度映射**和**状态映射**（即您的打开与关闭转换键）都会被迁移过去。
* 每个 **Jira Project** 配置都会成为一个工单跟踪器映射，保留其项目密钥和问题类型，并仍然分配给原来的产品或测试活动。
* **Push All Issues** 设置会被保留：原先启用该设置的项目会继续自动推送。
* **自定义字段**、**关闭/重新打开转换字段**、**组件**、**默认经办人**以及**标签**都会被转换为字段映射。如果您此前使用过 *Add Vulnerability Id as a Jira label*，它也会被转换为一个标签映射。
* **自定义 Issue 模板**目录会成为一个工单模板。标准模板不会被复制，因为连接器本身已经内置了相应的等效模板。

### 不会被迁移的内容

这些内容会在迁移运行时以警告形式报告——但不会中止迁移。请在结果中查找*"连接器无法迁移的内容"*列表。

* **Jira → DefectDojo 反向同步。** 这是最重要的一点。下游连接器不会将 Jira 中的更改*反向*同步回来，因此那些根据 Jira 的解决方案（resolution）将发现项状态设置为风险接受或误报的解决方案映射不会被迁移。**如果您依赖反向同步功能，请保留经典 Jira 实例的现有配置**——迁移不会将其移除。
* **测试活动 Epic 映射**——连接器没有 Epic 的概念。
* **推送备注**、**SLA 通知评论**以及**风险接受到期评论**——连接器不会将这些内容发布到 Jira。
* 名为 `summary`、`description`、`project`、`issuetype` 或 `status` 的自定义字段——这些名称已被连接器保留，使用其中任何一个的字段映射都会被跳过。
* 超过 512 个字符的自定义字段值——会被跳过，而不是截断。
* 未关联任何产品或测试活动的 Jira Project 不会产生任何分配。

### 迁移后经典集成会发生什么

**不会出现重复推送。** 对于每一个被迁移的 project，迁移过程都会关闭该经典 Jira project，此后只有连接器会继续推送。您无需手动禁用任何内容。

您的经典配置会**被保留，而不是删除**——实例、project 和 issue 记录都会完整保留，只是推送设置会被关闭。这是有意为之的设计：正是这一点使得该变更可以撤销，也正是这一点让反向同步在您依赖它时能够继续正常工作。

**如需回滚**，请重新启用经典 Jira project 设置，并移除迁移过程创建的连接器配置。目前没有一键撤销功能。

**重复运行是安全的。** 迁移过程会记录已经转换过的内容，并在第二次运行时跳过这些内容，因此不会产生重复项。如果某个 project 或实例迁移失败，其余部分仍会继续完成迁移——迁移失败的 project 会继续在经典集成上运行，而不会被关闭，因此在您排查问题期间，它仍能正常工作。

### 运行期间

迁移过程会在后台运行，并随时报告进度。完成后，您会收到一份汇总信息——包括创建了多少个连接器、映射、分配、模板和工单链接，关闭了多少个经典 project，以及跳过了哪些内容——同时附带上文所述的各类警告。同一时间只能运行一个迁移任务。

# 配置 Jira

配置 Jira 需要完成以下步骤：
1. 在 System Settings 中启用 Jira 集成。在启用之前，DefectDojo 中其余的 Jira 相关设置都会处于隐藏状态。
2. 使用用户名/密码或 API 令牌连接一个 Jira 实例。可以关联多个实例。
3. 将该 Jira 实例添加到 DefectDojo 内的一个或多个产品或测试活动。
4. 如果您希望使用双向同步，请创建一个 Jira Webhook，用于向 DefectDojo 发送更新。

## 步骤 1：在 System Settings 中启用 Jira 集成

Jira 集成默认处于关闭状态，在关闭期间，DefectDojo 会隐藏界面中所有其他 Jira 相关控件。这是需要配置的第一项内容：在启用之前，下面的所有步骤都无法使用。

在集成被禁用期间，侧边栏中不会出现 **Jira Instances** 条目，因此也就没有地方可以添加 Jira 实例：

![image](images/jira-menu-hidden-pro.png)

### 启用集成

1. 从 DefectDojo 侧边栏进入 **Settings \> System \> System Settings**。在仍使用先前菜单布局的实例上，该项位于以您的许可证套餐命名的分组下——**Pro Settings** 或 **Enterprise Settings**。参见[设置菜单](/navigation/pro__settings_menu/)。
​
2. 在 **Jira Integration Settings** 部分，勾选 **Enable Jira Integration**。
​
3. 点击 **Submit**。**Jira Instances** 会立即出现在侧边栏中，无需重新加载页面：

![image](images/jira-enable-system-settings-pro.png)

### 该设置会控制哪些内容

启用 **Enable Jira Integration** 之后，才会显示其余的 Jira 相关界面。启用后，您将获得：

* **Jira Instances** 菜单，用于添加和编辑 Jira 实例
* 资产 ⚙️ 菜单上的 **Jira Project Settings** 页面，以及测试活动上的 Jira 相关设置
* 发现项和发现项组上的 **Push to Jira** 操作、发现项表单与批量编辑表单中的 Jira 相关字段，以及资产、测试活动、发现项和发现项组列表（包括 CSV 导出）中的 Jira 相关列

该设置同样会在界面之外控制集成的启用状态：在关闭期间，DefectDojo 不会将发现项推送到 Jira（包括通过 API 发送的 `push_to_jira` 请求），传入的 Jira Webhook 也会被忽略。

**Jira Integration Settings** 中其余的 Jira 相关字段（**Add Vulnerability ID as Jira Label**、**Enable Jira Web Hook**、**Disable Jira Web Hook Secret**、**Jira Web Hook Secret**、**Jira Minimum Severity**）无论集成是开启还是关闭都会保持可见，但在集成启用之前不会产生任何效果。

## 步骤 2：连接 Jira 实例

启用集成后，连接 Jira 实例是配置 DefectDojo 的 Jira 集成的下一步。请注意，目前尚不支持 Jira Service Management。

#### 需要从 Jira 获取的信息

Atlassian 在 Jira Cloud 和 Jira Data Center 之间使用不同的身份验证方式。

对于 **Jira Cloud**，您需要准备：
* 一个 Jira URL，例如 https://yourcompany.atlassian.net/
* 一个在您的 Jira 实例中拥有创建和更新 Issue 权限的账户。可以是以下形式之一：
    * 标准的**用户名/密码**组合
    * **用户名/API Token** 组合

对于 **Jira Data Center（或 Server）**，您需要准备：
* 一个 Jira URL，例如 https://jira.yourcompany.com
* 一个在您的 Jira 实例中拥有创建和更新 Issue 权限的账户。可以是以下形式之一：
    * 标准的**用户名/密码**组合
    * **邮箱地址/Personal Access Token** 组合

此外，您还可以选择映射：
* 用于触发发现项重新打开和关闭的 Jira Transitions
* 可为发现项应用风险接受和误报状态的 Jira Resolutions（可选）

只要 DefectDojo 使用的 Jira 账户/令牌拥有在相应 Jira Space 中创建 Issue 的权限，一个 Jira Instance 连接就可以处理多个 Jira Space。

### 添加 Jira 实例

1. 请确认已按照[步骤 1](#step-1-enable-the-jira-integration-in-system-settings)所述，在 System Settings 中勾选了 **Enable Jira Integration**。在勾选之前，侧边栏不会出现 **Jira Instances** 菜单。

2. 从 DefectDojo 侧边栏进入 **Enterprise Settings \> Jira Instances \> + New Jira Instance** 页面。

![image](images/jira-instance-beta.png)

3. 为此 Jira Instance 选择一个 **Configuration Name**，供 DefectDojo 使用。这个名称只是 DefectDojo 中该实例连接的一个标签，不需要与任何 Jira 数据相关联。

4. 选择您公司 Jira 实例的 URL——如果您使用的是 Jira Cloud，通常会类似于 `https://**yourcompany**.atlassian.net`。

5. 在 Jira 的 Username / Password 字段中填入合适的身份验证方式：
    * 若使用标准的**用户名/密码 Jira 身份验证**，请在这些字段中填入 Jira 用户名和对应的密码。
    * 若使用**用户 API token（Jira Cloud）**进行身份验证，请在用户名字段填入用户名，并在密码字段填入对应的 **API token**。
    * 若使用 Jira 的**Personal Access Token（简称 PAT，仅适用于 Jira Data Center 和 Jira Server）**进行身份验证，请在密码字段中填入该 PAT。使用 Jira PAT 进行身份验证时不会用到用户名，但该表单中此字段仍为必填项，因此您可以在此填入一个占位值，用于标识您的 PAT。

请注意，与此连接关联的用户必须拥有在您的 Jira 实例中创建 Issue 及访问数据的权限。

6. 您需要提供 Epic Name ID、Re-open Transition ID 和 Close Transition ID 的值。这些值之后可以修改。登录 Jira 后，您可以通过以下 URL 获取这些值：
- **Epic Name ID**：访问 `https://<YOUR JIRA URL>/rest/api/2/field` 并搜索 Epic Name。将 `number` 中的数字复制出来并粘贴到这里。如果您的 Jira Space 没有关联 Epic Name ID（例如因为使用的是 Team-Managed Space），请在此字段中填入 0。
- **Re-open Transition ID**：访问 `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` 来查找您 Jira 实例对应的 ID。将其粘贴到 Reopen Transition ID 字段中。
- **Close Transition ID**：访问 `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` 来查找您 Jira 实例对应的 ID。将其粘贴到 Close Transition ID 字段中。

7. 选择您希望在 Jira 中创建 Issue 时所使用的 Default issue type。可选项包括标准 Jira issue type 中的**Bug、Task、Story** 和 **Epic**，以及自定义 issue type 中的 **Spike** 和 **Security**。如果您希望使用其他 Issue Type，请联系 [support@defectdojo.com](mailto:support@defectdojo.com) 寻求协助。

8. 选择您的 Issue Template，它将决定在 Jira 中创建 Issue 时的 Issue Description。

共有两种类型：
- **Jira\_full**，会在 Jira Issue 中包含全部发现项信息
- **Jira\_limited**，只会包含少量发现项信息和元数据

如果将此字段留空，将默认使用 **Jira\_full。** 如果您需要其他类型的模板，请联系 [support@defectdojo.com](mailto:support@defectdojo.com)。

9. 如果需要，可以填写一个 Jira Resolution 的名称，当该 Resolution 在 Issue 上被触发时，会将发现项的状态更改为风险已接受或误报。

此时即可提交表单。如果需要，您还可以在 Optional Fields 下进一步自定义您的 Jira 集成。点击该按钮后，您可以为 Jira Issue 添加通用文本，或更改 Jira Severity Mappings 的映射方式。

## 步骤 3：将产品或测试活动连接到 Jira

DefectDojo 中的每个产品或测试活动都拥有各自的设置，用于控制发现项如何转换为 JIRA Issue。您可以在此决定关联的 Jira Space，并设置创建 Issue、Epic、Label 及其他 JIRA 元数据时的默认行为。

### 为产品添加 Jira

点击产品上的齿轮菜单 ⚙️，即可打开 **Jira Project Settings** 页面。

![image](images/jira-project-settings.png)

#### Jira Instance(Jira 实例)

如果您为组织内不同的产品或团队配置了多个 Jira 实例，可以在此指定您希望 DefectDojo 在哪个 Jira Space 中创建 Issue。请从下拉菜单中选择一个 Space。

如果此菜单没有列出任何 Jira 实例，请确认这些 Space 已在 DefectDojo 的全局 Jira Configuration 中完成连接——yourcompany.defectdojo.com/jira。

#### Project key(项目密钥)

这是您希望与 DefectDojo 搭配使用的 Space 的密钥。给定 Space 的 Space Key 可以在 URL 中找到。（此前这被称为 **Jira Project Key**，但自 2025 年 9 月起，Jira 中已将其改称为 **Space Key**。）

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Epic Issue Type Name(Epic Issue 类型名称)

Jira 中 Epic issue type 的名称。默认值为 "Epic"，如果您的 Jira 实例使用了不同的名称，可以进行修改。

#### Issue template(Issue 模板)

在这里，您可以决定希望向 Jira 发送多少 DefectDojo 元数据。请从以下两个选项中选择一个：

* **jira\_full**：Issue 会记录来自 DefectDojo 的全部参数——完整的 Description、CVE、Severity 等。如果您需要在 Jira 中呈现完整的发现项上下文（例如处理该 Issue 的人员没有 DefectDojo 访问权限），这个选项会很有用。

以下是一个 **jira\_full** Issue 的示例：
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited：** Issue 只会记录 DefectDojo 链接、产品/测试活动/测试链接，以及 Reporter 和 Environment 字段。其余所有字段仅在 DefectDojo 中记录。如果您不需要在 Jira 中呈现完整的发现项上下文（例如处理该 Issue 的人员主要在 DefectDojo 中工作，不需要在 JIRA 中也看到完整信息），这个选项会很有用。

​以下是一个 **jira\_limited** Issue 的示例：

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component(组件)

如果您使用 Component 来管理 Jira Space，可以在此为 DefectDojo 指定合适的 Component。如需指定多个 Component，请输入以逗号分隔的列表（例如 `Security, DevSecOps`）；每个值都会作为一个独立的 component 发送到 Jira。

#### Custom fields(自定义字段)

如果您不需要在 DefectDojo 的 issue 中使用 Custom Fields，可以将此字段保留为 'null'。

但是，如果您的 Jira Space Settings **要求您**在新建 Issue 时使用 Custom Fields，则需要对这些映射进行硬编码。

请注意，DefectDojo 无法将任何特定于某个 Issue 的元数据作为 Custom Fields 发送，只能发送一个默认值。只有当您的 Jira Space **要求这些 Custom Fields 必须存在**于该 Space 内的每个 Issue 中时，才需要设置此部分。

请参照**[本指南](#custom-fields-in-jira)**开始使用 Custom Fields。

#### Close / Reopen Transition fields(关闭/重新打开转换字段)

有些 Jira workflow **要求**在执行 transition 时必须设置某些字段——例如，某些 workflow 会拒绝关闭 Issue，除非在关闭界面提供了 Resolution 和 Justification 字段。上面的 Custom fields 设置只在 Issue *创建*时生效，因此无法满足这类 workflow 的要求。

如果没有这些设置，DefectDojo 发送的 close / reopen transition 将不带任何字段。要求必须提供字段的 workflow 会拒绝该 transition，导致发现项和 Jira Issue 失去同步：该发现项在 DefectDojo 中显示为已缓解，而对应的 Issue 在 Jira 中仍保持打开状态。

**Close Transition fields** 和 **Reopen Transition fields** 设置接受一个 JSON 对象，该对象会作为 close / reopen transition 调用的 `fields` 载荷发送。例如，要以 *Won't Fix* 的 Resolution 外加一个 justification 值来关闭 Issue：

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

如果您的 Jira workflow 在 transition 时不需要任何字段，请将这些设置保留为 'null'。

**您需要哪些字段？**

* 请向您的 Jira 管理员确认，close / reopen 的**transition 界面**上有哪些字段，其中哪些是由 validator 强制要求的。所配置的 JSON 必须满足**每一个**必填字段：只要载荷中缺少任意一个必填字段，Jira 就会拒绝整个 transition，不会设置任何内容——只提供部分必填字段并无帮助。
* 反过来，字段必须**出现在该 transition 界面上**才能被发送：对于尝试设置该 transition 界面上不存在的字段的 transition，Jira 会予以拒绝。
* 对于使用 Jira Cloud 当前 workflow 编辑器构建的 workflow，当 Issue 进入 done 类别的状态时，Jira 会自动填入站点默认的 Resolution。因此，仅仅要求填写 Resolution 并不会阻止这里的普通 transition，此时在该载荷中使用 `"resolution"` 的实际作用，是选择一个*有意义*的值（例如 *False Positive*），而不是使用站点默认值。使用经典编辑器或 marketplace validator 应用构建的 workflow，仍可能会硬性要求填写 Resolution。
* Reopen transition 通常会通过 workflow 本身清除 Resolution，因此 **Reopen Transition fields** 通常只需要填写您的 workflow 所要求的自定义字段即可。

**说明：**

* 对于某个产品或测试活动，*每一次* close（或 reopen）transition 发送的都是同一份 JSON——这些值是固定的，不会因发现项而异。如果您需要针对不同的处理结果使用不同的字段（例如，误报的发现项和已修复的发现项需要使用不同的 Resolution），请使用支持按状态配置 transition 字段映射的 DefectDojo Pro Jira Integrator。
* 值的格式与 Jira REST API 所使用的格式相同：文本字段使用字符串，resolution 使用 `{"name": ...}`，多选字段使用 `[{"name": ...}]`，依此类推。
* 如果此前因为这些设置缺失或不完整而导致 transition 被拒绝，只要修正这些设置，就能修复由此产生的偏差：该发现项下一次状态推送时，会使用配置好的字段重新尝试该 transition。
* 这两项设置在 `/api/v2/jira_projects/` REST 接口（`close_transition_fields` / `reopen_transition_fields`）中同样可用，因此也可以通过 API 进行管理。
* 当 DefectDojo 因为某个发现项被**删除**而关闭对应的 Issue 时，同样会应用这些字段——这些值会在关闭操作被加入队列的那一刻被捕获。

#### Jira labels(Jira 标签)

选择您希望在 Jira 中创建 Issue 时附带的相关 label，例如 **DefectDojo**、**YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee(默认经办人)

在 Jira 中默认经办人的名称。如果留空，DefectDojo 在创建 Issue 时将遵循您 Jira Space 中的默认行为。

### Jira Project Settings

#### Enabled(启用)

此开关用于控制 DefectDojo 是否为该产品将发现项推送到 Jira。关闭此开关不会删除或更改 DefectDojo 已创建的任何现有 Jira 工单，但会阻止后续的更新以及新 Issue 的创建。

只有在没有创建任何相关 Issue 的情况下，才能从您的实例中移除 Jira 集成。如果已经创建了 Issue，则无法从 DefectDojo 中完全移除某个 Jira Instance。

#### Add Vulnerability Id as a Jira label(将漏洞 ID 添加为 Jira 标签)

此选项可让您自动将漏洞 ID 数据添加为 Jira Label。漏洞 ID 是由各安全工具添加到发现项上的——它们可能是 Common Vulnerabilities and Exposures（CVE）ID，也可能是特定于报告该发现项的工具的其他格式。

#### Push All Issues(推送所有问题)

勾选后，DefectDojo 会自动将所有活动且已验证的发现项作为 Issue 推送到 Jira。如果不勾选，则所有发现项都需要手动推送到 Jira（可逐个推送，也可批量推送）。

启用此设置后，即使发现项的状态发生变化，Jira Issue 也会持续与 DefectDojo 保持同步。

#### Enable Engagement Epic Mapping(启用测试活动 Epic 映射)

在 DefectDojo 中，测试活动代表一组工作。每个测试活动包含一个或多个测试，每个测试又包含一个或多个需要缓解的发现项。Jira 中的 Epic 与此类似，此复选框可让您将测试活动作为 Epic 推送到 Jira。

* DefectDojo 中的一个测试活动——请注意底部列出的三个发现项。
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* 同一个测试活动推送到 JIRA 后如何变为一个 Epic——该测试活动的发现项也会一并推送，并作为 Child Issue 存在于该测试活动内部。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push Notes(推送备注)

启用后，Jira 上的 comment 会填充到 DefectDojo 中对应发现项的备注下；反之亦然——发现项上的备注也会作为 comment 添加到对应的 Jira Issue 上。

#### Send SLA Notifications As Comments(以评论形式发送 SLA 通知)

启用后，任何违反 DefectDojo Service Level Agreement 规则的 Issue，都会在对应的 Jira issue 上添加相应的 comment 予以说明。这些 comment 会每天发布一次，直到该 Issue 被解决为止。

Service Level Agreement 可以在 DefectDojo 的 **Configuration \> SLA Configuration** 下进行配置，并分配给每个产品。

#### Send Risk Acceptance Expiration Notifications As Comment(以评论形式发送风险接受到期通知)

启用后，只要某个 Issue 关联的 DefectDojo 风险接受到期，就会在对应的 Jira issue 上添加一条 comment 予以说明。这些 comment 会每天发布一次，直到该 Issue 被解决为止。

### 测试活动级别的 Jira 设置

默认情况下，测试活动会**从其所属产品继承 Jira 设置**。不过，您也可以针对单个测试活动覆盖这些 Jira 设置。

如需访问测试活动级别的 Jira 设置，请点击某个测试活动上的齿轮菜单 ⚙️，打开 **Jira Project Settings** 页面。

在此，您可以取消勾选 **Inherit from Product**，并为以下设置提供该测试活动专属的值：**Project Key**、**Issue Template, Custom Fields, Jira Labels, Default Assignee** 等。

请注意，一旦某个测试活动被分配了自己的 Jira project，它就无法再从产品继承设置。

![image](images/Creating_Issues_in_Jira_5.png)

## 步骤 4:配置双向同步:Jira Webhook

Jira 集成支持通过 Webhook 进行双向同步。DefectDojo 会在一个唯一的地址接收 Jira 通知,根据您的配置,这既可以让 Jira 中的评论同步到发现项,也可以让发现项通过 Jira 得到解决。

### 查找您的 Jira Webhook URL

您的 Jira Webhook 位于系统设置表单中的 **Jira 集成设置**下:即侧边栏中的 **企业设置 \> 系统设置**。

在 DefectDojo 处理传入的 Jira 通知之前,您还需要在同一页面上勾选 **启用 Jira Webhook**。  如果该复选框或 **启用 Jira 集成**(参见[步骤 1](#step-1-enable-the-jira-integration-in-system-settings))未勾选,传入的 Webhook 都会被忽略。

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### 创建 Jira Webhook

1. 访问 `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. 点击 'Create a Webhook'。
3. 对于标记为 'URL' 的字段,请输入:`https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`。Web Hook 密钥已在上文所述的 Jira 集成设置中列出。
4. 在 'Comments' 下启用 'Created'。在 Issue 下启用 'Updated'。
5. 请确保您的 JIRA 实例信任 DefectDojo 实例所使用的 SSL 证书。对于 JIRA Cloud,DefectDojo 必须使用[由全球可信证书颁发机构签发的有效 SSL/TLS 证书](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

请注意,您无需在 Jira 中创建密钥即可使用此 Webhook。该密钥已内置于 DefectDojo 的 URL 中,因此只需将完整的 URL 添加到 Jira Webhook 表单中即可。

传入的 Webhook 请求通过该 URL 中的密钥进行身份验证,因此请将完整 URL 视为凭据并妥善保密。

#### 测试 Webhook

在您根据 DefectDojo 发现项创建了一个或多个 Issue 后,您可以通过向其中一个发现项添加评论来测试该 Webhook。此评论应会被 Jira Webhook 作为备注接收。

如果此操作无法正常工作,可能是您的 Jira 实例上存在防火墙问题,阻止了该 Webhook。

* DefectDojo 的防火墙规则中包含一个 **Jira Cloud** 复选框,必须先启用该复选框,DefectDojo 才能接收来自 Jira 的 Webhook 消息。

### 备选方案:使用 Jira Automation(Send web request)

某些 Jira 实例不允许在 `/plugins/servlet/webhooks` 下使用系统 Webhook —— 例如该管理区域受限,只允许使用 **Jira Automation** 规则时。在这种情况下,您可以使用 Automation 的 **Send web request** 操作来实现相同的双向同步,该操作会向同一个 DefectDojo Webhook 端点发送请求。

DefectDojo 的 Webhook 端点接受任何带有 `Content-Type: application/json` 的 HTTP `POST` 请求,只要 URL 路径中包含有效的密钥即可。它**并不**要求请求必须源自 Jira 的系统 Webhook 机制,因此 Automation 的 "Send web request" 操作可以作为替代方案直接使用。

#### 前提条件

与系统 Webhook 相同的前提条件同样适用:

* 在 ⚙️ **配置 \> 系统设置** 页面上,**启用 JIRA 集成** 和 **启用 JIRA Webhook** 均已勾选。
* 该页面上已设置了非空的 **Jira webhook 密钥**。该密钥只能包含字符 `A-Z`、`a-z`、`0-9`、`_` 和 `-`。
* 该发现项(或发现项组)已经关联到对应的 Jira issue。如果该 issue 未关联到任何 DefectDojo 发现项,请求仍会被接受(HTTP `200`),但不会执行任何操作。

#### DefectDojo 如何处理该请求

* DefectDojo 会根据顶层的 `webhookEvent` 字段进行分支处理。只有 `"jira:issue_updated"` 和 `"comment_created"` 会被处理;其他任何值都会被接受但忽略。Automation **不**会自动添加此字段,因此您必须自行将其包含在请求正文中。
* 正因如此,请将请求的 **Body** 设置为 **Custom data**,并提供下方的 JSON。**Empty** 和 **Jira issue data** 这两个正文选项不包含所需的 `webhookEvent` 字段,因此 DefectDojo 会忽略它们。
* 该端点始终返回 HTTP `200`,无论更新是否实际生效。成功或失败只能在响应正文和 DefectDojo 日志中查看——Automation 审计日志中的 `200` 本身并**不**能确认更新已到达某个发现项。

#### 规则 1 —— Issue 已更新

创建一条 Automation 规则,内容如下:

* **Trigger:** *Issue transitioned*(或其他会在您同步的字段发生变化时触发的触发器,例如 Status 上的 *Field value changed*)。
* **Action:** *Send web request*
  * **Web request URL:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method:** `POST`
  * **Web request body:** *Custom data*
  * **Headers:** `Content-Type: application/json`
  * **Custom data:**

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

Issue 更新的约束条件:

* `issue.id` 必须是 **Jira issue 的数字内部 ID**(`{{issue.id}}`),而不是 issue key(例如 `PROJ-123`)。DefectDojo 会通过这个数字 ID 将更新与某个发现项进行匹配。
* `resolution` 和 `updated` 字段必须始终存在。`resolution` 可以为 `null`,但只要有任一字段缺失,请求就会被接受(`200`)但被静默忽略,不会被处理。
* 状态同步和自动缓解由 `status.statusCategory.key` 驱动,其 Jira 取值为 `new`(To Do)、`indeterminate`(In Progress)和 `done`(Done)。只有当 issue 被真正关闭时,发现项才会被标记为已缓解,而不仅仅是因为存在某个 resolution 值。

#### 规则 2 —— Issue 已评论

再创建第二条 Automation 规则,内容如下:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* —— URL、方法、请求头以及 *Custom data* 正文选项均与规则 1 相同,正文如下:

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

评论的约束条件:

* `body` 和 `updateAuthor` 必须都存在。
* DefectDojo 会从 `comment.self` URL 中推导出目标 issue —— 具体来说是 `.../issue/<id>/comment/...` 部分中的 `<id>`—— 因此 `{{issue.id}}`(数字 ID)必须出现在其中。
* **循环预防:** 如果评论作者与 DefectDojo 用于发布自身评论的 Jira 账户相同,DefectDojo 会跳过该评论,以避免出现回音循环。如果您希望**所有**评论都被摄取,请使用与 DefectDojo 的 Jira 实例中配置的账户不同的 Jira 用户来运行该 Automation 规则。

#### 关于智能值的说明

上面展示的智能值(`{{issue.id}}`、`{{issue.status.statusCategory.key}}`、`{{comment.author.accountId}}` 等)是 Jira Cloud 的标准名称,但在不同实例之间可能会有所差异。在正式上线前,请使用 Automation 的负载预览功能,确认每个智能值都能解析为您期望的结果。

## 测试 Jira 集成

#### 测试 1:发现项能否成功推送到 Jira?

为了测试 Jira 集成是否正常工作,您可以在 DefectDojo 中向与 Jira 关联的产品添加一个新的空白发现项。**产品 \> 发现项 \> 新增发现项。**

填写您想要的标题、严重程度和描述,然后点击 "Finished"。该发现项应会作为一个 Issue 出现在 Jira 中,并带有所有相关的元数据。

如果 Jira Issue 没有被正确创建,请检查您的通知中是否存在错误代码。

* 请确认与 DefectDojo 的 Jira 配置相关联的 Jira 用户,拥有在该 Jira Space 上创建和更新 issue 的权限。

#### 测试 2:Jira Webhook 发送到 DefectDojo

为了测试 Jira Webhook,请向一个在 JIRA 中也以 Issue 形式存在的发现项添加一条备注(例如上文测试中创建的那个 issue)。

如果 Webhook 配置正确,您应该会在 Jira 中看到该备注作为该 issue 的一条评论出现。

如果此操作无法正常工作,可能是您的 Jira 实例上存在防火墙问题,阻止了该 Webhook。

* DefectDojo 的防火墙规则中包含一个 **Jira Cloud** 复选框,必须先启用该复选框,DefectDojo 才能接收来自 Jira 的 Webhook 消息。

## 断开与 Jira 的连接

只有在没有创建任何相关 Issue 的情况下,才能从您的实例中移除 Jira 集成。  如果已经创建了 Issue,则无法将某个 Jira 实例从 DefectDojo 中完全移除。

不过,您可以通过在产品级别禁用 Jira 集成来关闭它。  在 **Jira 项目设置**页面(可通过产品上的 ⚙️ 齿轮菜单访问)中,取消勾选 **已启用**开关。这不会删除或更改 DefectDojo 已创建的任何现有 Jira 工单,但会停止后续的所有更新。

# 将发现项推送到 Jira

具有 JIRA 映射的产品可以通过多种方式将发现项作为 Issue 推送到 Jira。您可以逐条、批量、以发现项组的方式,或自动地推送发现项。

## 推送单个发现项

1. 打开您要推送的发现项。
2. 点击 **☰ 发现项菜单**,然后选择 **推送到 Jira**。
3. 在提示时确认推送。DefectDojo 将创建一个 Jira Issue 并将其关联到该发现项。

Issue 创建后,DefectDojo 会在发现项页面上显示指向该 Jira Issue 的链接。

![image](images/Creating_Issues_in_Jira_2.png)

您也可以在通过 **编辑发现项** 表单编辑某个发现项时,勾选 **推送到 Jira** 复选框。保存该发现项时,它将被推送到 Jira。

### 更新已关联的 Jira Issue

如果某个发现项已经关联了一个 Jira Issue,再次选择 **推送到 Jira** 会用 DefectDojo 中所做的任何更改来更新现有的 Jira Issue。如果产品上启用了 **推送所有 Issue**,这种同步会自动发生。

### 取消发现项与 Jira 的关联

要移除某个发现项与其 Jira Issue 之间的关联,请点击 **☰ 发现项菜单**,然后选择 **取消与 Jira 的关联**。此操作会移除 DefectDojo 中的关联,但不会删除 Jira Issue 本身。

## 批量推送发现项

您可以使用批量更新表单一次性将多个发现项推送到 Jira:

1. 在发现项列表中,使用复选框选择您要推送的发现项。
2. 打开 **批量更新** 表单。
3. 在 **Jira 设置** 下,勾选 **推送到 Jira** 复选框。
4. 点击 **提交**。

所选的发现项将被加入 Jira 推送队列。DefectDojo 会显示一条确认消息,说明有多少个发现项已被加入队列。

## 将测试活动推送为 Epic

如果您的 Jira 项目设置中开启了 **启用测试活动 Epic 映射**,您就可以将某个测试活动作为 Epic 推送到 Jira。该测试活动的发现项将作为该 Epic 下的子 Issue 被推送。

要将某个测试活动推送为 Epic:

1. 打开您要推送的测试活动。
2. 点击 **☰ 测试活动菜单**,然后选择 **推送到 Jira**。
3. 您可以选择性地提供一个 **Epic 名称**(留空则默认使用测试活动名称)和一个 **Epic 优先级**。
4. 勾选 **推送到 Jira(创建 Epic)** 并提交表单。

## 将发现项组推送为 Jira Issue

如果您启用了发现项组功能,就可以将一组发现项作为单个 Issue(而不是为每个发现项分别创建 Issue)推送到 Jira。

要推送一个发现项组:

1. 打开该发现项组。
2. 点击 **☰ 发现项组菜单**,然后选择 **推送到 Jira**,或者在编辑该发现项组时勾选 **推送到 Jira** 复选框。

如果需要移除某个发现项组关联的 Jira Issue,必须直接在 Jira 实例中删除。

### 自动创建并推送发现项组

在产品上启用 **推送所有 Issue**,并在导入时选择了 **分组依据** 选项后:

只要发现项组被成功创建,自动推送到 Jira 的将是该发现项组本身(作为一个 Issue),而不是各个单独的发现项。

![image](images/Creating_Issues_in_Jira_4.png)

## 自动推送行为

DefectDojo 可以在多种场景下自动将发现项和更新推送到 Jira:

### 推送所有 Issue

当产品的 Jira 项目设置中启用了 **推送所有 Issue** 时,DefectDojo 会自动为所有活动且已验证的发现项创建 Jira Issue,其中也包括通过扫描导入创建的发现项。Jira Issue 一经创建,即使该发现项的状态发生变化,它也会持续与 DefectDojo 保持同步。

### 状态变化时的自动同步

当启用了 **推送所有 Issue** 或系统级别的 **发现项 Jira 同步** 设置后,DefectDojo 会在对发现项执行某些操作时,自动更新已关联的 Jira Issue:

* **请求审查** \- 系统会在已关联的 Jira Issue 上添加一条评论(如果该发现项属于某个发现项组,则添加到该发现项组的 Jira Issue 上)。
* **清除审查** \- 系统会在已关联的 Jira Issue 上添加一条评论。
* **关闭发现项** \- 已关联的 Jira Issue 会被更新以反映该关闭状态。如果启用了 **推送备注**,系统还会添加一条评论。

## Jira 评论与备注

启用 Jira 项目设置中的 **推送备注** 后:

* 如果在某个 Jira Issue 上添加了一条评论,同样的评论会被添加到该发现项的 **备注** 部分下。
* 反过来,如果在某个发现项上添加了一条备注,该备注也会作为评论被添加到对应的 Jira issue 上。

## Jira 状态变化

Jira 实例配置中包含两个 Jira 转换(Transition)条目,它们会触发发现项的状态变化。

* 当在 Jira 上执行 **'Close' 转换** 时,相关联的发现项也会随之关闭,并在 DefectDojo 上被标记为 **非活动** 和 **已缓解**。DefectDojo 会在发现项页面的 **缓解方式** 标题下记录此变化。
​
![image](images/Creating_Issues_in_Jira_3.png)

* 当在该 Jira Issue 上执行 **'Reopen' 转换** 时,相关联的发现项会在 DefectDojo 上被设置为 **活动**,并失去其 **已缓解** 状态。

## 将 Jira 解决方案映射到风险接受/误报

Jira 实例配置包含两个可选字段,可让您将某个 Jira **解决方案(Resolution)** 映射到某个 DefectDojo 发现项状态:

* **风险已接受发现项映射解决方案** —— 当某个 Jira issue 以此解决方案关闭时,关联的发现项会在 DefectDojo 中变为风险已接受。
* **误报发现项映射解决方案** —— 当某个 Jira issue 以此解决方案关闭时,关联的发现项会在 DefectDojo 中变为误报。

### 状态与解决方案:一个常见的混淆点

这些字段映射的是 Jira 的 **解决方案(Resolution)**,而不是 Jira 的 **状态(Status)**。状态和解决方案是两个相互独立的 Jira 概念:状态描述的是该 issue 在工作流中所处的位置(Open、In Progress、Done),而解决方案描述的是它是如何被解决的(Fixed、Won't Do、Duplicate、False Positive 等)。

### 前提条件:Jira 工作流转换上的 "Set issue resolution" 后置功能

Jira 的工作流引擎不会自动填充 Resolution 字段。  每一个应当以特定解决方案关闭 issue 的转换,都需要在该转换本身上配置一个 **Set issue resolution** 后置功能。如果没有这个后置功能,issue 会转移到新的状态,但 Resolution 会保持为空,DefectDojo 的映射也就没有可匹配的内容。

Jira 管理员可以通过 **Project Settings → Workflows →(编辑工作流)→(选择要关闭的转换)→ Post Functions → Add post function → Set issue resolution** 来添加此后置功能。

# Jira 中的自定义字段

<span style="background: rgba(243, 122, 78,0.5">DefectDojo 目前尚不支持将任何 Issue 特定信息传递到这些自定义字段中 \- 这些字段需要在 issue 创建后于 Jira 中手动更新。每个自定义字段在从 DefectDojo 创建时都只会带有一个默认值。</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud 现已支持直接在应用内创建自定义字段的默认值。有关如何配置此功能的更多信息,请参阅[Atlassian 关于自定义字段的文档](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/)。</span>

DefectDojo 内置的 Jira Issue 类型(**Bug、Task、Story** 和 **Epic)** 都已配置为可以'开箱即用'。DefectDojo 中的数据字段会自动映射到 Jira 中对应的字段。默认情况下,DefectDojo 会为其创建的任何新 Issue 分配 Priority、Labels 和 Reporter。

某些 Jira 配置在创建 issue 之前需要先处理额外的自定义字段。以下流程可让您在 DefectDojo \-\> Jira 集成中处理这些自定义字段,确保 issue 能够成功创建。这些自定义字段会被添加到 DefectDojo 发送给已关联 Jira 实例的所有 API 调用中。

如果您尚未在 Jira 中使用自定义字段,则无需遵循此流程。

1. 记录您在 Jira 中的自定义字段名称(**Jira UI**)
2. 确定新自定义字段的键值(Jira 字段规范端点)
3. 参照键值,定位每个自定义字段可接受的数据(Jira Issue 端点)
4. 创建一个字段参考 JSON 块,以记录所有自定义字段的键及其可接受的数据(Jira Issue 端点)
5. 将该 JSON 块存储到关联的 DefectDojo 产品中,以便从 Jira 创建自定义字段(DefectDojo UI)
6. 测试您的成果,确保所有必需的数据都能从 Jira 正确地流转过来

#### 步骤 1:记录您在 Jira 中的自定义字段名称

Jira 支持多种不同的上下文字段,包括日期选择器、自定义标签、单选按钮。每一种上下文字段在 Jira API 中都会有不同的键值。

请记下每个所需自定义字段的名称,因为您将需要在下一步中通过 Jira API 搜索它们。

**自定义字段列表示例(您的自定义字段名称会有所不同):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### 步骤 2:查找您的 Jira 自定义字段键值

首先,请导航到您整个 Jira 实例的字段规范 URL。

以下是字段规范 URL 的一个示例:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

该 API 会返回一长串 JSON,您应将其格式化为可读文本(可使用代码编辑器、浏览器扩展,或 <https://jsonformatter.org/>)。

该 URL 返回的 JSON 会包含您所有的 Jira 自定义字段,其中大多数与 DefectDojo 无关,其值为 `"Null"`。此 API 响应中的每个对象都对应 Jira 中的一个不同字段。您需要查找那些 `"name"` 属性与您在 Jira UI 中创建的每个自定义字段名称相匹配的对象,然后记下它们的 "key" 属性的值。

![image](images/Using_Custom_Fields.png)

在 JSON 输出中找到匹配的对象后,您就可以确定其 "key" 值 \- 在本例中为 `customfield_10050`。

Jira 会为每个自定义字段生成不同的键值,但这些键值一旦创建就不会更改。如果您以后再创建另一个自定义字段,它将拥有一个新的键值。

**扩展我们的自定义字段列表:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Another example of a Custom Field" \= customfield\_12345
* ...

#### 步骤 3 \- 在 Jira Issue 上查找自定义字段

在 Jira 中找到一个包含您在步骤 2 中记录的自定义字段的 issue。复制作为标题的 Issue Key(应类似于 "`EXAMPLE-123`"),然后导航到以下 URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

这将返回另一段 JSON。

和之前一样,该 API 输出会包含许多值为 `null` 的 `customfield_##` 对象参数 \- 这些是 Jira 默认添加的自定义字段,与该 issue 无关。它也会包含与您在上一步中找到的自定义字段键值相匹配的 `customfield_##` 值。与字段规范的输出不同的是,您在这里不会看到用于标识这些自定义字段的名称,这也是为什么您需要在步骤 2 中记录键值的原因。

![image](images/Using_Custom_Fields_2.png)

**示例:**
我们在步骤 2 中已经记录过,知道 `customfield_10050` 代表 DefectDojo Custom URL Field。现在我们可以看到,在 `EXAMPLE-123` 这个 issue 中,`customfield_10050` 的值为 `"https://google.com"`。

#### 步骤 4 \- 根据每个 Jira 自定义字段键创建 JSON 字段参考

接下来,您需要获取列表中每个自定义字段的值,并将它们存储在一个 JSON 对象中(用作参考)。您可以忽略任何不在您列表中的自定义字段。

这个 JSON 对象将包含新建 Jira Issue 所需的全部默认值。我们建议使用便于团队识别的名称,将其标记为需要更改的'默认'值,例如:'`change-me.com`'、'`Change this paragraph.`' 等。

**示例:**

根据步骤 3,我们现在知道 Jira 期望 "`customfield_10050`" 是一个 URL 字符串。我们可以据此构建示例 JSON 对象。

假设我们还找到了一个与 DefectDojo 相关的短文本字段,并将其识别为 "`customfield_67890`"。我们会在第二次的 API 输出中查看该字段,查看其对应的值,并同样将该存储值引用到我们的示例 JSON 对象中。
​
随着您不断添加自定义字段,您的 JSON 对象将逐渐变成下面这样。

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

重复此过程,直到已将 Jira 中所有与 DefectDojo 相关的自定义字段都添加到您的 JSON 字段参考中。

#### 数据类型与 Jira 语法

某些字段(例如日期字段)可能对应 Jira 中的多个自定义字段。如果是这种情况,您需要将这两个字段都添加到您的 JSON 字段参考中。

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

其他字段(例如 Label 字段)可能以字符串列表的形式被跟踪 \- 请确保您的 JSON 字段参考所使用的格式与 Jira 的 API 输出格式相匹配。

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

其他自定义字段可能包含应从字段参考中移除的额外上下文信息。例如,自定义多选字段在 API 输出中包含一个额外的代码块,您需要将其移除,因为该代码块存储的是该字段的当前值。

* 您应从该字段中移除这个额外的对象:

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
* 您可以将其简化为以下内容,并忽略第二部分:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### 已完成字段参考示例

以下是一份完整的 JSON 字段参考,并附有行内注释说明每个自定义字段所对应的内容。这只是一个综合性的示例。您的 JSON 会包含不同的键值和数据,具体取决于您希望在创建 issue 时使用的自定义值。

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

#### 步骤 5 \- 将自定义字段添加到 DefectDojo 产品

现在,您可以在 Jira 项目设置页面(可通过产品上的 ⚙️ 齿轮菜单访问)中,将这些自定义字段添加到关联的 DefectDojo 产品。请将 JSON 字段参考以纯文本形式粘贴到 **自定义字段** 框中并保存。

#### 步骤 6 \- 通过新建发现项测试您的 Jira 自定义字段:

现在,当您在与 Jira 关联的产品中创建一个新的发现项时,Jira 会根据其中包含的 JSON 块自动创建所有这些自定义字段。这些自定义字段将以默认值("change\-me\-please" 等)被创建。

在 DefectDojo 的该产品中,导航到 发现项 \> 新增发现项 页面。请确保该发现项同时处于活动和已验证状态,以确保它会被推送到 Jira,然后在 Jira 一侧确认这些自定义字段已成功创建且没有任何不一致之处。
