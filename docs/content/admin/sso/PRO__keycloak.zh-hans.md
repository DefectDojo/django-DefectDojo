---
title: KeyCloak
description: 在 DefectDojo Pro 中配置 KeyCloak 单点登录
weight: 13
audience: pro
---

DefectDojo Pro 支持通过 KeyCloak 登录。开源版 DefectDojo 不包含 SSO——开源版的访问控制请参见[已授权用户](/admin/user_management/os__authorized_users/)。

本指南假定您已经配置好了一个 KeyCloak Realm。如果尚未配置,请参见 [KeyCloak 文档](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html)。

## 前提条件

在配置 DefectDojo 之前,请先在您的 KeyCloak realm 中完成以下步骤:

1. 添加一个类型为 `openid-connect` 的新客户端。记录该客户端 ID。

2. 在客户端设置中:
   - 将 **Access Type** 设置为 `confidential`
   - 在 **Valid Redirect URIs** 下,添加您的 DefectDojo URL,例如 `https://yourorganization.cloud.defectdojo.com` 或 `https://your-dojo-host/*`
   - 在 **Web Origins** 下,添加相同的 URL(或 `+`)
   - 在 **Fine Grained OpenID Connect Configuration** 下:
     - 将 **User Info Signed Response Algorithm** 设置为 `RS256`
     - 将 **Request Object Signature Algorithm** 设置为 `RS256`
   - 保存设置。

3. 在 **Scope** 下,将 **Full Scope Allowed** 设置为 `off`。

4. 在 **Mappers** 下,添加一个自定义映射器:
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** 选择您的客户端 ID
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. 在 **Credentials** 下,复制 **Secret**。

6. 在 **Realm Settings > Keys** 中,复制 **Public Key**(签名密钥)。

7. 在 **Realm Settings > General > Endpoints** 中,打开 OpenID 端点配置并复制 **Authorization** 和 **Token** 端点 URL。

## 配置

在 DefectDojo 中,前往**企业设置 > OAuth 设置**,选择 **KeyCloak**,然后填写表单:

- **KeyCloak OAuth Key**——输入您的客户端名称(来自步骤 1)
- **KeyCloak OAuth Secret**——输入您的客户端凭据密钥(来自步骤 5)
- **KeyCloak Public Key**——输入来自您 realm 设置的 Public Key(来自步骤 6)
- **KeyCloak Resource**——输入 Authorization Endpoint URL(来自步骤 7)
- **KeyCloak Group Limiter**——输入 Token Endpoint URL(来自步骤 7)
- **KeyCloak OAuth Login Button Text**——为 DefectDojo 登录按钮选择显示文字

勾选**启用 KeyCloak OAuth**并提交表单。登录页面上会出现一个带有您所配置文字的登录按钮。
