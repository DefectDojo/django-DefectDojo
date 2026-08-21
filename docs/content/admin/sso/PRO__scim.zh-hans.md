---
title: SCIM 预配
description: 通过身份提供程序为 DefectDojo Pro 用户进行预配和取消预配
weight: 19
audience: pro
---

DefectDojo Pro 支持 SCIM 2.0，可让您的身份提供程序直接创建、更新和停用 DefectDojo 用户。如果没有 SCIM，DefectDojo 只有在用户登录时才能获知该用户的存在，因此从身份提供程序中移除某人只会阻止其后续登录，但其 DefectDojo 账户仍会保持活动状态。

SCIM 与单点登录相互独立又互为补充。SSO 决定谁可以登录；SCIM 则使账户列表本身与您的目录保持同步。大多数客户会同时配置两者：使用 SAML 或 OIDC 进行身份验证，使用 SCIM 进行预配。

SCIM 配置只能由**超级用户**执行。

## SCIM 在 DefectDojo 中的作用

当您通过 SCIM 连接身份提供程序后，它可以：

* 在有人被分配该应用程序时创建 DefectDojo 用户
* 在目录中的姓名和电子邮件地址发生变化时进行更新
* 在用户被取消分配或离开组织时将其停用
* 创建组，并添加或移除组成员

通过 SCIM 停用用户会同时完成两件事：账户被标记为不活动，用户将无法再登录，同时该用户的 DefectDojo API 令牌也会被删除。因此，离职处理可以一步同时关闭这两扇门，这也是相较于仅依赖身份提供程序而言，使用 SCIM 的主要原因。

用户记录本身会被保留。发现项、备注和历史记录都会引用创建它们的人员，因此 DefectDojo 会停用账户而不是删除它。如果同一个人后来回归，通过身份提供程序重新激活即可恢复访问权限，而不会影响这些历史记录。

## 设置

1. 打开 **Connect > Authorization** 并选择 **SCIM Provisioning**。SCIM 与您的登录提供程序列在一起，因为它连接到同一个身份提供程序，并被标记为 **Provisioning**，以便与那些会在登录页面上添加按钮的提供程序区分开来。

2. 勾选 **Enable SCIM Provisioning** 并提交。在此选项关闭期间，SCIM 端点表现得如同不存在一样，因此来自您身份提供程序的连接测试会报告该地址未找到。

3. 复制页面上显示的 **Tenant URL**，格式如下：

   ```
   https://<your-instance>.cloud.defectdojo.com/scim/v2
   ```

4. 在 **SCIM Tokens** 面板中，为令牌起一个能说明其用途的名称，例如 "Okta production"，然后选择 **Generate Token**。

5. 从对话框中复制该令牌，并粘贴到您的身份提供程序中。DefectDojo 只存储该令牌的哈希值，因此无法再次显示。如果丢失，请生成新令牌并撤销旧令牌。

您可以同时保留多个有效令牌。若要轮换令牌，请先生成新令牌、更新您的身份提供程序，然后再撤销旧令牌。这样就不会出现预配功能中断的窗口期。

令牌面板会记录每个令牌最后一次被使用的时间，这是确认您的身份提供程序是否确实在访问 DefectDojo 的快捷方法。

## Okta

1. 在 Okta 管理控制台中，进入 **Applications > Browse App Catalog**，添加 **SCIM 2.0 Test App (Header Auth)**。如果您已经为 DefectDojo 配置了 SAML 应用程序，也可以直接在该应用程序上启用预配功能。

2. 打开 **Provisioning** 选项卡，选择 **Configure API Integration**。

3. 将 **SCIM 2.0 Base Url** 设置为上文复制的 Tenant URL。

4. 将 **API Token** 设置为 `Bearer <your token>`，包括单词 `Bearer` 和一个空格。此应用类型会将该值原样作为 Authorization 头发送。

5. 选择 **Test API Credentials**，然后保存。

6. 在 **Provisioning > To App** 下，启用 **Create Users**、**Update User Attributes** 和 **Deactivate Users**。

7. 将人员或组分配给该应用程序。Okta 会先按用户名在 DefectDojo 中查找每个人，只有在找不到时才会创建账户，因此已拥有 DefectDojo 账户的用户会被关联，而不会被重复创建。

若要同时推送组，请打开 **Push Groups** 选项卡，添加您希望 DefectDojo 镜像的组。有关 DefectDojo 如何处理这些组，请参见下文的[组](#groups)。

## Microsoft Entra ID

1. 在 Entra 管理中心，进入 **Enterprise applications > New application > Create your own application**，选择非目录（non-gallery）选项。如果您已经为 DefectDojo 配置了应用程序，直接使用该应用程序即可。

2. 打开 **Provisioning**，将 **Provisioning Mode** 设置为 **Automatic**。

3. 将 **Tenant URL** 设置为上文复制的 Tenant URL。

4. 将 **Secret Token** 设置为您的 SCIM 令牌。Entra 会将其作为 bearer 令牌发送，因此这里不要添加单词 `Bearer`。

5. 选择 **Test Connection**，然后保存。

6. 在 **Users and groups** 下分配用户和组，并启动预配。

Entra 的预配周期约为 40 分钟。在配置过程中，**Provision on demand** 可以立即应用单个用户或组，这能让您更快地确认配置是否生效。

## DefectDojo 存储的内容

DefectDojo 只映射一小部分 SCIM 属性，其余的会被忽略。

| SCIM attribute | DefectDojo field |
|---|---|
| `userName` | 用户名 |
| `name.givenName` | 名 |
| `name.familyName` | 姓 |
| `emails` | 电子邮件地址 |
| `active` | 账户是否启用 |
| `externalId` | 保留下来，供您的身份提供程序日后匹配该记录 |

DefectDojo 未建模的属性，包括电话号码、职位名称以及 SCIM 企业扩展，会被接受并忽略，而不是被拒绝。在您的身份提供程序中映射额外的属性是无害的。

有两个属性值得特别关注：

**用户名（Username）。** DefectDojo 的用户名只允许包含字母、数字以及字符 `@ . + - _`。如果您的身份提供程序发送的用户名包含其他字符，DefectDojo 会拒绝该用户，并给出说明问题的错误信息，而不是悄悄存储一个不同的用户名。存储被更改后的用户名会导致您的提供程序之后无法找到该账户。

**电子邮件地址（Email address）。** SCIM 并不要求提供电子邮件地址，DefectDojo 也会在没有它的情况下创建用户。但请注意，对于没有电子邮件地址的用户，DefectDojo 的通知（包括计划报告和告警）将无处可发。除非有特殊原因，否则请映射 `emails` 属性。

SCIM 从不设置密码，也从不授予超级用户或职员（staff）身份。如果您的身份提供程序配置为发送密码，DefectDojo 会忽略它们。以这种方式预配的用户通过 SSO 登录。

## 组

SCIM 只管理由它创建的组。您在 DefectDojo 界面中创建的组，或通过 SAML 或 Azure AD 组映射生成的组，对 SCIM 而言是不可见的，您的身份提供程序无法重命名、清空或删除这些组。

这一点很重要，因为组推送本质上是一次完整替换。如果身份提供程序可以"接管"一个已有的组，那么它下一次同步时就会用目录中的内容替换掉该组原本精心维护的成员关系。因此，推送一个名称已被占用的组会失败，并显示说明冲突的消息。若要将某个现有组交给您的身份提供程序管理，请将两者之一重命名，或者删除 DefectDojo 中的组，让提供程序重新创建它。

在一个由 SCIM 管理的组内，成员关系归属于您的身份提供程序，而角色归属于 DefectDojo：

* 新添加的成员会被赋予 **Reader** 角色。
* 如果您在 DefectDojo 中将某人提升为更高的角色，后续的同步不会改动该角色。
* 任何被手动添加到 SCIM 管理组中的人，都会在下一次同步时被移除，因为身份提供程序才是"谁属于该组"的权威来源。

通过 SCIM 删除一个组会移除该组及其成员关系，但绝不会删除组内的人员本身。

## 保护管理员账户的访问权限

默认情况下，SCIM 不会停用超级用户账户。任何预配方案中最常见的故障，都是身份提供程序的授权范围超出预期，而超级用户正是在出现问题时用来重新进入 DefectDojo 的手段。

如果您希望身份提供程序也能管理超级用户，请在 SCIM 设置页面启用 **Allow SCIM to deactivate superusers**。即便启用该选项，DefectDojo 仍会拒绝停用最后一个仍处于活动状态的超级用户，因此预配操作不可能让实例失去管理员。

## 限制

* 每个 DefectDojo 实例仅支持一个身份提供程序。
* 过滤功能支持基于 `userName`、`displayName`、`externalId` 和 `id` 的单一相等比较，这涵盖了 Okta 和 Entra 在匹配记录时发送的内容。更复杂的过滤条件会被拒绝，并返回相应的错误信息。
* 未实现批量操作、排序以及 `/Me` 端点。
* 组成员关系通过 Groups 端点进行管理。在用户记录上发送组成员信息不会产生任何效果，这与两家提供程序的实际行为一致。

## 故障排查

**连接测试报告"未找到"。** SCIM 已关闭，或该实例未获得相应许可。请检查 **Enable SCIM Provisioning** 是否已开启，以及您的订阅是否包含 SSO。在两者都满足之前，整个 SCIM 地址都会表现得如同不存在一样。

**连接测试报告身份验证失败。** 令牌错误，或已被撤销。请生成新令牌并更新您的身份提供程序。在 Okta 中，请检查该值是否以 `Bearer ` 及一个空格开头；在 Entra 中，请检查它是否不包含该前缀。

**某用户预配失败，并报告与用户名相关的错误。** 用户名中包含 DefectDojo 不允许的字符。请更改您的身份提供程序映射到 `userName` 的属性，最常见的做法是改用该用户的电子邮件地址或用户主体名称。

**某个组推送失败，报告已存在同名的组。** 说明该名称的 DefectDojo 组是在别处创建的。请参见上文的[组](#groups)。

**某个组成员预配失败。** 说明该人员尚未被预配到 DefectDojo。请将其分配给该应用程序，其成员关系会在下一个周期成功建立。

**从 Diagnostics 开始排查。** 被拒绝的 SCIM 请求会记录在 **Connect > Diagnostics** 下，包含端点、状态以及 DefectDojo 返回的消息。这通常比查看您的身份提供程序日志更快，也是唯一能同时看到交互双方情况的位置。成功的预配不会记录在此处；用户和组的变更会显示在审计历史中。

**一切都显示成功，但 DefectDojo 中却什么都没出现。** 请检查 Tenant URL 是否以 `/scim/v2` 结尾且没有多余的斜杠，并确认您的身份提供程序确实能够访问您的实例。SCIM Tokens 面板中的 **Last Used** 列会显示是否已收到任何请求。

**DefectDojo Pro 用户：** 如果您的实例按 IP 地址限制访问，请在配置 SCIM 之前，将您身份提供程序的地址添加到防火墙白名单中。参见[防火墙规则](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings)。
