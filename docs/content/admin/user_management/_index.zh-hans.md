---
title: 用户管理
description: 管理 DefectDojo 中的用户、访问控制和身份验证
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

DefectDojo 的用户管理界面在各版本中有所不同。请选择与您的安装版本相匹配的部分。

## DefectDojo 开源版

开源版 DefectDojo 使用**已授权用户**模型:通过将用户添加到某条记录的已授权用户列表,即可授予该用户访问对应产品或产品类型的权限。超级用户和职员可以查看所有内容。

* [已授权用户](./os__authorized_users/)——如何授予对产品和产品类型的访问权限

开源版 DefectDojo 的身份验证方式为本地用户名/密码,加上密码重置流程。

## DefectDojo Pro

DefectDojo Pro 使用基于角色的系统,包括成员、组和全局角色。用户还可以通过 SAML 或受支持的某个 OAuth 提供商获得 SSO 访问权限。

* [DefectDojo 中的权限](./about_perms_and_roles/)——角色、成员身份、全局角色和配置权限概述
* [设置用户权限](./set_user_permissions/)——分配角色、全局角色和配置权限
* [共享权限:用户组](./create_user_group/)——一次性为多个用户分配权限
* [在 Pro 中设置权限](./pro_permissions_overhaul/)——用于管理成员和权限的 Pro 专属界面
* [批量重置用户凭据](./pro__resetting_user_credentials/)——一次性为多个用户轮换 API 令牌并强制重置密码
* [操作权限图表](./user_permission_chart/)——每个内置角色所拥有的每项权限的完整参考
* [自定义 RBAC 角色](./pro__custom_rbac_roles/)——通过选择单项权限构建您自己的角色
* [单点登录](/admin/sso/)——Pro 版的 SAML 和 OAuth 配置

## 版本间迁移

如果您正在从开源版的已授权用户模型迁移到 Pro 版的 RBAC,或者正在从使用 RBAC 的 3.0 之前的开源版本升级到当前的已授权用户模型,请参阅 [3.0 升级说明](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization)。现有的访问权限将自动保留。
