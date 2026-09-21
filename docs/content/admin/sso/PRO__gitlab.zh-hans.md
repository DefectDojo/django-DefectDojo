---
title: GitLab
description: 在 DefectDojo Pro 中配置 GitLab 单点登录
weight: 9
audience: pro
---

DefectDojo Pro 支持通过 GitLab 登录。开源版 DefectDojo 不包含 SSO——开源版的访问控制请参见[已授权用户](/admin/user_management/os__authorized_users/)。

## 前提条件

在配置 DefectDojo 之前,请先在 GitLab 中完成以下步骤:

1. 前往您 GitLab 个人资料的应用页面:
   - GitLab.com:`https://gitlab.com/profile/applications`
   - 自托管:`https://your-gitlab-host/profile/applications`

2. 创建一个新应用:
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. 记录该应用的 **Application ID** 和 **Secret**。

## 配置

在 DefectDojo 中,前往**企业设置 > OAuth 设置**,选择 **GitLab**,然后填写表单:

- **GitLab OAuth Key**——输入您的 **Application ID**
- **GitLab OAuth Secret**——输入您的 **Secret**
- **GitLab API URL**——输入您 GitLab 实例的基础 URL,例如 `https://gitlab.com`

勾选**启用 GitLab OAuth**并提交表单。登录页面上会出现一个**使用 GitLab 登录**按钮。
