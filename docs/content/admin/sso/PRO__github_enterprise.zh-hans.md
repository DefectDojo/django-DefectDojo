---
title: GitHub Enterprise
description: 在 DefectDojo Pro 中配置 GitHub Enterprise 单点登录
weight: 7
audience: pro
---

DefectDojo Pro 支持通过 GitHub Enterprise 登录。开源版 DefectDojo 不包含 SSO——开源版的访问控制请参见[已授权用户](/admin/user_management/os__authorized_users/)。

## 前提条件

在配置 DefectDojo 之前,请先在 GitHub Enterprise 中完成以下步骤:

1. 在您的 GitHub Enterprise Server 中[创建一个新的 OAuth 应用](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app)。

2. 为该应用选择一个名称,例如 `DefectDojo`。

3. 设置 **Redirect URI**:
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. 记录该应用的 **Client ID** 和 **Client Secret**。

## 配置

在 DefectDojo 中,前往**企业设置 > OAuth 设置**,选择 **GitHub Enterprise**,然后填写表单:

- **GitHub Enterprise OAuth Key**——输入您的 **Client ID**
- **GitHub Enterprise OAuth Secret**——输入您的 **Client Secret**
- **GitHub Enterprise URL**——输入您组织的 GitHub URL,例如 `https://github.yourcompany.com/`
- **GitHub Enterprise API URL**——输入您组织的 GitHub API URL,例如 `https://github.yourcompany.com/api/v3/`

勾选**启用 GitHub Enterprise OAuth**并提交表单。登录页面上会出现一个**使用 GitHub 登录**按钮。
