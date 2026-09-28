---
title: Azure Active Directory
description: 在 DefectDojo Pro 中配置 Azure AD 单点登录和组映射
weight: 5
audience: pro
---

DefectDojo Pro 支持通过 Azure Active Directory(Azure AD)登录,包括自动的用户组同步。开源版 DefectDojo 不包含 SSO——开源版的访问控制请参见[已授权用户](/admin/user_management/os__authorized_users/)。

## 前提条件

在配置 DefectDojo 之前,请先在 Azure 门户中完成以下步骤:

1. 在 Azure Active Directory 中[注册一个新应用](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)。

2. 记录已注册应用中的以下值:
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - 在 **Certificates & Secrets** 下,创建一个新的 **Client Secret** 并记录其值
   - **Application ID URI**

3. 在 **Authentication > Redirect URIs** 下,添加一个 **Web** 类型的 URI:
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## 配置

在 DefectDojo 中,前往**企业设置 > OAuth 设置**,选择 **Azure AD**,然后填写表单:

- **Azure AD OAuth Key**——输入您的 **Application (client) ID**
- **Azure AD OAuth Secret**——输入您的 **Client Secret**
- **Azure AD Resource**——默认值为 `https://graph.microsoft.com/`。这是 DefectDojo 用来从 [Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri) 读取附加信息(例如组名称)的 URI。仅当您的组名称存储在不同的 API 资源上时才需要更改此项。
- **Azure AD Tenant ID**——输入您的 **Directory (tenant) ID**
- **Azure AD Groups Filter**——可选,输入一个正则表达式字符串以限制导入哪些用户组(见下方[组映射](#group-mapping))

勾选**启用 Azure AD OAuth**并提交表单。登录页面上会出现一个**使用 Azure AD 登录**按钮。

## 组映射

组映射允许 DefectDojo 从 Azure AD 导入[用户组](../../user_management/create_user_group/)成员关系。DefectDojo 中的用户组通过 [RBAC](../../user_management/set_user_permissions/) 管理产品和产品类型的访问权限。

勾选**启用 Azure AD OAuth 分组**以激活此功能。登录时,DefectDojo 会将用户的 Azure AD 组与 DefectDojo 中已有的组进行匹配。任何在 DefectDojo 中不存在的组都会被自动创建。

如需仅导入部分组,请在 **Azure AD Groups Filter** 字段中输入正则表达式。例如:
- `^team-.*`——匹配任何以 `team-` 开头的组
- `teamA|teamB|groupC`——匹配特定的指定组

### 配置 Azure AD 以发送组信息

Azure AD 令牌必须配置为包含组 ID,否则令牌中不会出现任何组信息。

配置方法如下:
1. 在 Azure AD 令牌配置中添加一个[组声明(Group Claim)](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims)。如果不确定选择哪种组类型,请选择 **All Groups**。
2. **不要**启用 **Emit groups as role claims**。
3. 更新应用的 API 权限,加入 `GroupMember.Read.All` 或 `Group.Read.All`。建议使用 `GroupMember.Read.All`,因为它授予的权限更少。

### 组清理

如果启用了**启用 Azure AD OAuth 组清理**,通过 Azure AD 同步创建的 DefectDojo 组在没有任何剩余成员时会被自动移除。当某个用户在 Azure AD 中被移出某个组时,该用户也会从 DefectDojo 中对应的组中被移除。
