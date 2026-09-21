---
title: Auth0
description: 在 DefectDojo Pro 中配置 Auth0 单点登录
weight: 3
audience: pro
---

DefectDojo Pro 支持通过 Auth0 登录。开源版 DefectDojo 不包含 SSO——开源版的访问控制请参见[已授权用户](/admin/user_management/os__authorized_users/)。

## 前提条件

在配置 DefectDojo 之前,请先在您的 Auth0 控制台中完成以下步骤:

1. 创建新应用:**Applications > Create Application > Single Page Web Application**。

2. 配置应用:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. 记录以下值——您在 DefectDojo 中会用到它们:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## 配置

在 DefectDojo 中,前往**企业设置 > OAuth 设置**,选择 **Auth0**,然后填写表单:

- **Auth0 OAuth Key**——输入您的 **Client ID**
- **Auth0 OAuth Secret**——输入您的 **Client Secret**
- **Auth0 Domain**——输入您的 **Domain**

勾选**启用 Auth0 OAuth**,即可在 DefectDojo 登录页面添加一个**使用 Auth0 登录**按钮。
