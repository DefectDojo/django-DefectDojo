---
title: Okta
description: 在 DefectDojo Pro 中配置 Okta 单点登录
weight: 15
audience: pro
---

DefectDojo Pro 支持通过 Okta 登录。开源版 DefectDojo 不包含单点登录（SSO）功能——有关开源版的访问控制，请参阅[已授权用户](/admin/user_management/os__authorized_users/)。

## 前提条件

在配置 DefectDojo 之前，请先在 Okta 中完成以下步骤：

1. 前往 [Okta](https://www.okta.com/developer/signup/) 登录或创建账户。

2. 进入 **Applications**，点击 **Add Application**。

   ![image](images/okta_1.png)

3. 选择 **Web Applications**。

   ![image](images/okta_2.png)

4. 在 **Login Redirect URLs** 下，添加您的 DefectDojo 回调 URL。同时勾选 **Implicit** 复选框。

   ![image](images/okta_3.png)

5. 点击 **Done**。

6. 在 **Dashboard** 中，记下 **Org-URL**。

   ![image](images/okta_4.png)

7. 打开新创建的应用程序，记下 **Client ID** 和 **Client Secret**。

   ![image](images/okta_5.png)

## 配置

在 DefectDojo 中，进入 **Enterprise Settings > OAuth Settings**，选择 **Okta**，然后填写表单：

- **Okta OAuth Key** —— 输入您的 **Client ID**
- **Okta OAuth Secret** —— 输入您的 **Client Secret**
- **Okta Tenant ID** —— 按照 `https://your-org-url/oauth2` 的格式输入您的 Org-URL

勾选 **Enable Okta OAuth** 并提交表单。登录页面上将出现一个 **Login With Okta** 按钮。
