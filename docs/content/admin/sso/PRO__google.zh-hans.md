---
title: Google 身份验证
description: 在 DefectDojo Pro 中配置 Google OAuth
weight: 11
audience: pro
---

DefectDojo Pro 支持通过 Google 账户登录。首次登录时,如果新用户尚不存在,会自动创建。现有的 DefectDojo 用户会通过用户名(即 Google 邮箱中 `@` 之前的部分)与 Google 账户进行匹配。开源版 DefectDojo 不包含 SSO——开源版的访问控制请参见[已授权用户](/admin/user_management/os__authorized_users/)。

## 前提条件

在配置 DefectDojo 之前,请先在 Google Cloud Console 中完成以下步骤:

1. 登录 [Google Developers Console](https://console.developers.google.com)。

2. 前往**凭据 > 创建凭据 > OAuth 客户端 ID**。

   ![image](images/google_1.png)

3. 选择 **Web Application**,并为其设置一个描述性名称(例如 `DefectDojo`)。

4. 在**授权重定向 URI**下,添加:
   `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/`

5. 记录 **Client ID** 和 **Client Secret Key**。

## 配置

在 DefectDojo 中,前往**企业设置 > OAuth 设置**,选择 **Google**,然后填写表单:

- **Google OAuth Key**——输入您的 **Client ID**
- **Google OAuth Secret**——输入您的 **Client Secret Key**
- **Whitelisted Domains**——输入您组织的域名(例如 `yourcompany.com`),以允许该域下的任何用户登录
- **Whitelisted E-mail Addresses**——或者,输入允许登录的特定邮箱地址(例如 `user1@yourcompany.com, user2@yourcompany.com`)

您必须至少设置一个白名单域名或邮箱地址,否则将没有任何用户能够通过 Google 登录。

勾选**启用 Google OAuth**并提交表单。登录页面上会出现一个**使用 Google 登录**按钮。
