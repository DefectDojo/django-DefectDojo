---
title: 单点登录
description: DefectDojo Pro 支持通过 SAML 和多种 OAuth 提供程序实现单点登录
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2026-04-30 00:00:00+00:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
pro-feature: true
aliases:
- /zh-hans/admin/user_management/configure_sso/
- /zh-hans/admin/sso/os__saml/
- /zh-hans/admin/sso/os__auth0/
- /zh-hans/admin/sso/os__azure_ad/
- /zh-hans/admin/sso/os__github_enterprise/
- /zh-hans/admin/sso/os__gitlab/
- /zh-hans/admin/sso/os__google/
- /zh-hans/admin/sso/os__keycloak/
- /zh-hans/admin/sso/os__oidc/
- /zh-hans/admin/sso/os__okta/
- /zh-hans/admin/sso/os__remote_user/
---

单点登录是 **DefectDojo Pro** 的功能。从 DefectDojo 3.0 起，SSO 相关能力——SAML、OIDC 以及内置的 OAuth 提供程序——仅在 DefectDojo Pro 中提供。开源版 DefectDojo 使用本地用户名/密码登录及密码重置流程。

如果您正在运行开源版 DefectDojo 并希望使用 SSO，需要切换到 [DefectDojo Pro](https://defectdojo.com)；迁移方法请参见 [3.0 升级说明](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only)。升级后，现有的用户账户和组成员关系都会被保留。有关开源版 DefectDojo 的访问控制，请参见[已授权用户](/admin/user_management/os__authorized_users/)页面。

## 查看当前配置

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** 会在一个页面中列出所有受支持的提供程序——哪些已配置、哪些已启用、各自使用什么协议——并可直接跳转到其中任意一个的设置表单。如果您想了解此实例的当前状态，而不是配置某个特定的提供程序，可以从这里开始。

## 受支持的 SSO 提供程序（DefectDojo Pro）

DefectDojo Pro 支持 SAML 以及以下 OAuth 提供程序。每份指南都会介绍提供程序端的设置步骤，以及在 Pro 版 **Enterprise Settings** 界面中对应的配置方式。

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**
* **[LDAP](/admin/sso/pro__ldap/)**

## 通过目录预配用户（DefectDojo Pro）

上述提供程序决定谁可以登录。**[SCIM Provisioning](/admin/sso/pro__scim/)** 则使账户列表本身与您的目录保持同步，因此用户在加入时会被创建，在信息变更时会被更新，在离开时会被停用（同时其 API 令牌也会被删除）。

DefectDojo Pro 中的 SSO 配置只能由**超级用户**执行。

**DefectDojo Pro 用户：** 在设置 SSO 之前，请先将您的 SAML 或 SSO 服务的 IP 地址添加到防火墙白名单中。更多信息请参见[防火墙规则](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings)。

## 禁用用户名/密码登录

在 DefectDojo Pro 中配置好 SSO 后，您可能希望禁用传统的用户名/密码登录表单。在 **Enterprise Settings > Login Settings** 下取消勾选 **Allow Login via Username and Password**。

![image](images/pro_login_settings.png)

### 登录回退方式

如果您的 SSO 集成出现故障，您始终可以通过在 DefectDojo URL 后追加以下内容，返回标准登录表单：

`/login?force_login_form`

我们建议至少保留一个配置了用户名和密码的管理员账户，作为回退方案。
