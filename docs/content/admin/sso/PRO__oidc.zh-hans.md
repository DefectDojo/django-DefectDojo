---
title: OIDC
description: 在 DefectDojo Pro 中配置 OpenID Connect (OIDC) 单点登录
weight: 17
audience: pro
---

DefectDojo Pro 支持通过通用 OpenID Connect (OIDC) 提供程序登录。开源版 DefectDojo 不包含单点登录（SSO）功能——有关开源版的访问控制，请参阅[已授权用户](/admin/user_management/os__authorized_users/)。

## 配置

在 DefectDojo 中，进入 **Enterprise Settings > OIDC Settings**。

![image](images/oidc_pro.png)

填写表单：

1. **Endpoint** —— 您的 OIDC 提供程序的基础 URL。请勿包含 `/.well-known/openid-configuration`。
2. **Client ID** —— 您的 OIDC 客户端 ID。
3. **Client Secret** —— 您的 OIDC 客户端密钥。
4. 可选配置 **Claim Mapping** 和 **Group Mapping** —— 参见下文。
5. 勾选 **Enable OIDC**。

提交表单后，DefectDojo 登录页面上会出现一个 **Log In With OIDC** 按钮。

您可以随时使用 **Validate Config** 在不保存设置的情况下检查配置。它会获取发现文档、验证签名密钥和颁发者、回显应在您的提供程序处注册的确切重定向 URI，并将您的声明与组映射与提供程序公布的声明进行交叉核对。

## 声明映射

每一行将一个 **OIDC Claim** 映射到它应填充的 **DefectDojo Field**。使用 **Add Claim Mapping** 添加更多行，使用垃圾桶图标删除某一行。

![image](images/sso_oidc_claim_mapping.png)

没有对应行的字段将保留其标准声明，因此只有在您的提供程序使用不同命名时才需要此部分。标准声明如下：

| DefectDojo Field | Standard claim |
| --- | --- |
| Username | `preferred_username` |
| Email | `email` |
| First Name | `given_name` |
| Last Name | `family_name` |

说明：

- 未配置的实例默认已填好这四行，因此您可以在做任何更改之前先看到 OIDC 的默认行为。
- 同一个声明可以填充多个字段。但每个 DefectDojo 字段只能由一个声明映射。
- 声明会同时从 ID 令牌和 userinfo 响应中读取，因此即使您的提供程序只在其中一处发布某个声明，映射仍然有效。
- 如果某个用户缺少已映射的声明或该声明为空，该字段将保留其标准值，而不会被清空。

## 组映射

DefectDojo 可以在每次登录时，将您的提供程序报告的组镜像为 DefectDojo 中的组。勾选 **Enable Group Mapping** 以显示相关设置。

![image](images/sso_oidc_group_mapping.png)

- **Group Claim Name** —— 包含用户组信息的声明。**大多数提供程序默认不会发出此声明**，需要显式配置映射器；例如在 Keycloak 中，需要为客户端添加一个 *Group Membership* 映射器。请注意，*User Realm Role* 映射器发送的是领域（realm）**角色**，而不是组。
- **Group Limiter Regex Expression** —— 只有匹配此表达式的组才会被镜像。使用 `.*` 可允许所有组。
- **Remove Stale Group Memberships** —— 启用后，提供程序在下一次登录时不再报告的 OIDC 生成组的成员关系将被移除。此操作仅影响由 OIDC 创建的组；您手动分配的组，以及由其他提供程序（如 SAML）生成的组，均不受影响。

组会在首次使用时创建，并按提供程序报告的名称精确命名。如果您的提供程序发送完整的组路径（例如启用了 **Full group path** 选项的 Keycloak *Group Membership* 映射器就会这样做），DefectDojo 中的组名将是 `/Group A` 而不是 `Group A`。如果您希望名称与来自其他提供程序的组保持一致，请关闭该选项，否则最终会为同一个逻辑组生成两个不同的 DefectDojo 组。

如果组映射看起来没有任何效果，请运行 **Validate Config**：它会报告您指定的声明是否是提供程序实际公布的声明之一。
