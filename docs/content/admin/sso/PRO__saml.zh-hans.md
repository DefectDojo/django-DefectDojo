---
title: SAML 配置
description: 在 DefectDojo Pro 中配置 SAML
weight: 1
audience: pro
---

DefectDojo Pro 支持通过 **Enterprise Settings** 界面进行 SAML 身份验证。开源版 DefectDojo 不包含单点登录（SSO）功能——有关开源版的访问控制，请参阅[已授权用户](/admin/user_management/os__authorized_users/)。

## ACS URL (Assertion Consumer Service)

您的身份提供程序需要知道在用户完成身份验证后应将 SAML 响应 POST 到哪里。DefectDojo 的 ACS URL 为：

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

关于此端点，有几点需要了解：

- **该端点仅接受 `POST` 请求。** 直接在浏览器中打开 ACS URL 会发出 GET 请求，并返回 **HTTP 405 Method Not Allowed**。这是预期行为——并不代表 SAML 配置有误或出现故障。该端点被设计为由您的 IdP 在 SAML 重定向流程中调用，而不是由浏览器直接输入网址访问。
- **ACS URL 始终在您的 DefectDojo Cloud 实例上可用**——您无需先在 DefectDojo 中启用 SAML 才能将 IdP 指向它。您可以按任意顺序配置 IdP 端和 DefectDojo 端。

## 设置

1. 打开 **Enterprise Settings > SAML Settings**。

   ![image](images/sso_betaui_1.png)

2. 设置 **Entity ID**——即您的 SAML 身份提供程序用来识别 DefectDojo 的标签或 URL。此字段为必填项。

3. 可选设置 **Login Button Text**——用户点击以开始 SAML 登录的按钮上显示的文字。

4. 可选设置 **Logout URL**，用于在用户从 DefectDojo 注销后将其重定向到该地址。

5. 选择一种 **Name ID Format**：
   - **Persistent** —— 用户在各个会话中始终由相同的 SAML 标识来识别。
   - **Transient** —— 用户每次登录都会获得不同的 SAML ID。
   - **Entity** —— 所有用户共用同一个 SAML NameID。
   - **Encrypted** —— 每个用户的 NameID 均经过加密。

6. **Required Attributes** —— 指定 DefectDojo 要求 SAML 响应中必须包含的属性。

7. **Attribute Mapping** —— 将您的 IdP 发送的属性映射到它们应填充的 DefectDojo 用户字段。每一行将一个 **SAML Attribute** 与一个 **DefectDojo Field** 配对；使用 **Add Attribute Mapping** 添加更多行，使用垃圾桶图标删除某一行。

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** 为自由文本，必须与您的 IdP 实际发出的属性名称完全一致。部分 IdP（例如 Entra ID / Azure AD）发送的是完整限定的声明 URI，例如 `http://schemas.microsoft.com/identity/claims/emailaddress`，而不是易读的名称。如果不确定您的 IdP 发送的是什么，请启用 **Enable SAML Debugging**（参见[故障排查](#troubleshooting)），并在日志中查看断言内容。
   - **DefectDojo Field** 从一个列表中选择：**Username**、**First Name**、**Last Name** 和 **Email**。
   - 至少应映射对应 **Username** 的属性。DefectDojo 在将 SAML 登录与现有账户匹配时是按用户名查找用户的。
   - 强烈建议将某个属性映射到 **Email**：DefectDojo 会使用电子邮件地址发送通知，并用它来将传入的登录与现有账户按邮箱匹配。
   - 同一个属性可以填充多个字段——例如同一个电子邮件声明可以同时用于 **Email** 和 **Username**。但反过来不允许：每个 DefectDojo 字段只能由一个属性映射得到。
   - 只填写了一半的行在保存时会被拒绝，出错的单元格会被高亮显示。您添加但从未填写的行会被直接丢弃，而不会被当作错误处理。

8. **Remote SAML Metadata** —— 托管您的 SAML 身份提供程序元数据的 URL。

9. 勾选表单底部的 **Enable SAML** 以启用 SAML 登录。DefectDojo 登录页面上会出现一个 **Login With SAML** 按钮。

   ![image](images/sso_saml_login.png)。

## 附加选项

* **Create Unknown User** —— 如果在 SAML 响应中找不到某用户，自动创建一个新的 DefectDojo 用户。
* **Allow Unknown Attributes** —— 允许拥有未在 Attribute Mapping 中列出的属性的用户登录。
* **Sign Assertions/Responses** —— 要求所有传入的 SAML 响应均已签名。
* **Sign Logout Requests** —— 对 DefectDojo 发送的所有注销请求进行签名。
* **Force Authentication** —— 无论是否存在现有会话，都要求用户在每次登录时都向身份提供程序进行身份验证。
* **Enable SAML Debugging** —— 记录详细的 SAML 输出以供故障排查。有关日志输出位置，请参见[故障排查 → SAML Debugging output](#saml-debugging-output)。

## SAML 组映射

DefectDojo 可以使用 SAML 断言自动将用户分配到[用户组](../../user_management/create_user_group/)。DefectDojo 中的组会为其所有成员分配权限，因此组映射使您能够批量管理权限。这是通过 SAML 设置权限的唯一方式。

**组映射是可选的。** 尽管 **Group Name Attribute** 和 **Group Limiter Regex Expression** 字段在界面中带有必填星号（`*`），但即使不填写这两项，SAML 表单也可以提交，SAML 登录也能正常工作，无需组映射。您无需在启用 SAML 之前先在 IdP 中预先建好组或角色（例如 Azure AD 应用角色）——只有当您确实希望 DefectDojo 从断言中读取组成员信息时，才需要配置这些字段。如果不配置组映射，新创建的 SSO 用户默认将没有任何权限；请参见下文的 [SSO 生成用户的默认访问权限](#default-access-for-sso-provisioned-users)。

**Group Name Attribute** 字段用于指定 SAML 断言中哪个属性包含用户的组成员信息。用户登录时，DefectDojo 会读取该属性，并将用户分配到任何匹配的组。若要限制断言中哪些组会被纳入考虑，可使用 **Group Limiter Regex Expression** 字段——这是一个应用于断言中组名称的正则表达式，用于筛选 DefectDojo 应处理哪些组。

该值必须与您的身份提供程序在断言中实际发出的属性名称完全一致，包括任何命名空间前缀。像 `groups` 这样简短易读的名称，只有在您的 IdP 被配置为确实发出这个字面属性名时才有效——许多 IdP 实际使用的是完整限定的声明 URI。

### 按身份提供程序划分的 Group Name Attribute

| Identity Provider | Default attribute name to use |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups`（您在 SAML 应用的 Group Attribute Statement 中配置的属性名） |
| **Keycloak** | `groups`（或您在 Group List 映射器上设置的 “SAML Attribute Name”） |
| **PingFederate / generic** | 您在 IdP 端配置的值——请检查您 IdP 的断言，不要想当然地认为是 `groups` |

如果组映射看起来没有任何效果——用户能成功登录，但没有创建或分配任何组——请参见下文的[故障排查 → SAML 组映射没有效果](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned)。

如果不存在名称匹配的组，DefectDojo 会自动创建一个，并为其成员分配 **Reader** 角色。请注意，此 Reader 角色控制的是成员*对该组本身*的访问权限——它并不会授予对底层产品、产品类型或其他组织资产的任何访问权限。这些权限需要单独配置，新自动创建的组在超级用户为其分配相关产品或产品类型上的角色之前，不具备任何这类权限。

要启用组映射，请勾选表单底部的 **Enable Group Mapping** 复选框。

## SSO 生成用户的默认访问权限

当通过 SAML（或任何社交身份验证提供程序）创建新用户，且该用户未通过 SAML 组映射被添加到任何组时，该用户登录 DefectDojo 实例后将**没有任何权限**。他们登录后会看到零个产品类型、零个产品、零个测试活动——仪表板将显示为空。

要为每个新生成的 SSO 用户提供合理的基础权限，请在系统设置页面配置 **Default group** 和 **Default group role**：

1. 打开 **⚙️ Configuration → System Settings**（仅超级用户可见）。
2. 将 **Default group** 设置为新创建用户应加入的[用户组](../../user_management/create_user_group/)。
3. 将 **Default group role** 设置为他们在该组中应持有的角色（例如 **Reader**）。
4. 可选地将 **Default group email pattern** 设置为一个正则表达式（例如 `.*@yourcompany\.com$`），使默认组仅应用于邮箱匹配的用户。
5. 保存。

**Default group** 和 **Default group role** 必须同时设置——如果其中任意一项为空，默认组将不会被应用。

此设置适用于**每个新创建的用户**，包括通过 SAML、OAuth 及其他社交身份验证提供程序创建的用户，因为它运行在 Django 的用户创建信号上，而不是在某个特定的身份验证后端内部。

> **现有用户不受影响。** 默认组仅在用户首次创建时应用。即使您之后更改此设置，现有的 DefectDojo 用户仍将保留其当前的组成员关系。

## Cloud 与 On-Premise 版本的差异

DefectDojo Cloud 的 SAML 自定义程度不如 DefectDojo On-Prem。唯一可设置的变量都是通过界面进行的。以下是一些主要区别：

| Capability | Cloud | On-Premise |
|---|---|---|
| **Username matching** | 仅 NameID | 仅 NameID（`SAML_USE_NAME_ID_AS_USERNAME` 环境变量仅适用于开源版，不适用于 Pro 版） |
| **SAML assertion encryption** | 目前不支持 | 目前不支持 |
| **SAML login logs** | 界面中不可用。请联系支持团队请求日志。 | 可通过应用容器日志获取（`docker logs dojo`） |
| **Configuration method** | 仅限 Enterprise Settings 界面 | Enterprise Settings 界面、Django Admin 或 Django Shell |
| **Environment variables** | 客户无法直接设置。如需更改，请联系支持团队。 | 可通过 `dojo-compose-cli environment add` 设置 |

如果您需要按 NameID 以外的属性（例如 `uid` 或 `email`）匹配用户，请将您的身份提供程序配置为将所需的值作为 NameID 发送，而不是调整 DefectDojo 的设置。

## 故障排查

### SAML 调试输出

当勾选[附加选项](#additional-options)中的 **Enable SAML Debugging** 后，DefectDojo 会将详细的 SAML 处理输出——包括从 IdP 收到的原始属性——以 `DEBUG` 级别写入 `saml2` 日志记录器下的应用日志。

| Where you're running | Where to read the debug output |
|---|---|
| **DefectDojo Cloud** | SAML 调试日志不会在界面中显示。请联系 DefectDojo 支持团队请求特定时间段的日志。 |
| **On-Premise (single container)** | `docker logs dojo`（或您的 Helm/K8s 日志聚合系统） |
| **On-Premise (Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi`（或您集群的日志聚合系统） |

完成故障排查后，请**关闭**此选项——SAML 调试日志内容详细，可能包含来自您 IdP 的敏感属性值。

### 用户在 IdP 登录成功后收到 "User not found" 或 "Permission denied" 错误

如果 SAML 断言解析成功（没有 XML 或签名错误），但 DefectDojo 拒绝了登录，最常见的原因是 IdP 与 DefectDojo 之间的**用户名不匹配**。

DefectDojo 在将 SAML 登录与现有账户匹配时是**按用户名**查找用户的。如果您的 IdP 作为 `username` 属性发送的值与某个现有 DefectDojo 用户的用户名不一致，即使断言的其余部分均有效，查找也会失败。

有两种解决方法，请根据您的环境选择其一：

- **从 Attribute Mapping 中移除 `username`**，让 DefectDojo 改为使用 SAML 的 `NameID` 作为用户名。如果您 DefectDojo 中的用户名已经与 IdP 发出的 NameID 格式一致，这种方式是合适的。
- **统一用户名。** 确保 DefectDojo 中的用户名与您的 IdP 在 `username` 声明中发送的值完全一致。对大多数组织而言，最简单的约定是让 DefectDojo 用户名等于用户的电子邮件地址，并让 IdP 将邮箱作为 `username` 声明发送。

如果不确定 IdP 实际发送的内容，请启用上文的 **Enable SAML Debugging**，并在日志中查看解析后的属性。

### SAML 组映射没有效果——用户可以登录，但没有分配任何组

最常见的原因是 **Group Name Attribute** 字段与您的 IdP 实际发送的属性名称不匹配。请参见上文的[按身份提供程序划分的 Group Name Attribute](#group-name-attribute-by-identity-provider) 表格，并启用 **Enable SAML Debugging** 以查看 IdP 返回的原始属性。
