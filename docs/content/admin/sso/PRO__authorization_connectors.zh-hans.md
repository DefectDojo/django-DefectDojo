---
title: 授权连接器
description: 在一个页面中查看所有身份提供商:哪些已配置、哪些已启用,以及各自使用的协议
weight: 1
audience: pro
---

授权连接器(Authorization Connectors)是一个页面,列出了 DefectDojo Pro 支持的每一个身份提供商、各自当前所处的状态,以及所使用的协议。在该页面出现之前,每个提供商都有各自独立的设置表单,无法在不逐一打开的情况下回答“这个实例上都配置了什么”这个问题。

授权连接器是 **DefectDojo Pro** 功能。可在**连接 > 授权**下找到该页面。只有**超级用户**才能查看或更改身份提供商配置。

![Authorization Connectors](images/authorization_connectors.png)

## 页面结构

提供商被分为两个部分,每个部分按字母顺序列出,标题旁标有数量:

* **已配置的提供商**——已在本实例上设置好的提供商,无论其当前是否处于开启状态。
* **可用的提供商**——受支持但尚未配置的提供商。

这里刻意按“是否已配置”而非“是否已启用”来划分。一个曾被配置、随后又被关闭的提供商仍会留在“已配置的提供商”中,因为设置它的人会在那里查找它。其状态则显示在卡片上。

每张卡片显示:

| | |
| --- | --- |
| **图标和名称** | 提供商名称,不含协议 |
| **协议标签** | `SAML 2.0`、`OAuth 2.0`、`OpenID Connect` 或 `LDAP` |
| **状态标签** | `Enabled`、`Disabled` 或 `Not configured` |
| **`BETA` 标签** | 出现在仍处于测试阶段的提供商上 |
| **操作** | 已配置的提供商显示**管理配置**,可用的提供商显示**配置** |

两个部分都设有搜索框,可按提供商名称和协议匹配,因此搜索 `oauth` 会将页面缩小到仅显示 OAuth 类提供商。

![Available providers](images/authorization_available.png)

## 每个提供商仅有一份配置

身份提供商的设置在每个实例上、每个提供商只有一组值——一个 Okta 应用、一个 SAML 身份提供商、一个 LDAP 目录。卡片上也是这样体现的,没有“新增一个”的选项:要更改某个提供商的设置方式,您需要编辑已经存在的那份配置。

这正是授权连接器与[连接器库](/connectors/upstream/about/)的不同之处,在连接器库中,一个工具可以并列拥有多份配置。

## 三种状态及其含义

| 状态 | 含义 | 下一步操作 |
| --- | --- | --- |
| **Enabled** | 已配置且正在接受登录 | 无需操作 |
| **Disabled** | 已配置,但已关闭——其按钮不会出现在登录页面上 | 如需重新启用,请在其配置中重新开启 |
| **Not configured** | 受支持,但尚未填写任何内容 | 点击**配置**进行设置 |

选择某个提供商会直接打开该提供商自身的设置表单,中间没有额外的提供商选择步骤。

## 受支持的提供商

| 提供商 | 协议 | 设置指南 |
| --- | --- | --- |
| Auth0 | OAuth 2.0 | [Auth0](/admin/sso/pro__auth0/) |
| GitHub Enterprise | OAuth 2.0 | [GitHub Enterprise](/admin/sso/pro__github_enterprise/) |
| GitLab | OAuth 2.0 | [GitLab](/admin/sso/pro__gitlab/) |
| Google | OAuth 2.0 | [Google](/admin/sso/pro__google/) |
| Keycloak | OAuth 2.0 | [KeyCloak](/admin/sso/pro__keycloak/) |
| LDAP | LDAP | [LDAP](/admin/sso/pro__ldap/) |
| Microsoft Entra ID | OAuth 2.0 | [Azure Active Directory](/admin/sso/pro__azure_ad/) |
| Okta | OAuth 2.0 | [Okta](/admin/sso/pro__okta/) |
| OpenID Connect | OpenID Connect | [OIDC](/admin/sso/pro__oidc/) |
| SAML | SAML 2.0 | [SAML](/admin/sso/pro__saml/) |

该页面报告的是提供商配置的*状态*。它绝不会返回配置中的机密信息——客户端密钥、绑定密码和证书都不属于该页面背后的数据,也无法从中读取出来。

## 当某个提供商无法连接时

授权连接器告诉您已配置了什么,但不会显示登录失败的记录。这些记录保存在[诊断](/admin/diagnostics/pro__diagnostics/)中,SSO、SAML 和 LDAP 各自会报告自己的尝试记录以及被拒绝的原因——错误的断言签名、被拒绝的绑定、不匹配的属性等。这些记录属于实例级别,因此仅超级用户可见。

请始终保留至少一个使用用户名和密码登录的超级用户账户作为后备,并记住 `/login?force_login_form` 会在身份提供商出现故障时返回标准登录表单。两者都参见[单点登录](/admin/sso/)。

## 相关内容

* [单点登录](/admin/sso/)——各提供商的设置指南和登录设置
* [诊断](/admin/diagnostics/pro__diagnostics/)——登录尝试失败的原因
* [连接器](/connectors/upstream/about/)——本页面所参照的上游库
