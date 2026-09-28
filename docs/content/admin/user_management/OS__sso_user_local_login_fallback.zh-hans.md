---
title: 为 SSO 用户重新启用登录（开源版）
description: 在迁移到开源版（SSO 仅为 Pro 版功能）之后，为通过 SSO 创建的用户设置本地密码
audience: opensource
weight: 2
---

## 适用场景

SSO（SAML、OIDC、OAuth）是 [DefectDojo Pro](https://defectdojo.com) 的功能。如果你升级到开源版 DefectDojo 3.x（或以其他方式脱离 Pro 版），SSO 登录选项会被移除，此前通过 SSO 创建的用户将无法再登录。他们的账户从未被设置过本地密码，而 UI 和 API 也不允许你为其设置密码：DefectDojo 会将它们识别为 SSO 账户并阻止这一更改。

你**不需要**删除并重新创建这些用户（那样会丢失他们的历史记录、权限和对象归属）。相反，只需在后端为每个账户设置一个本地密码，并强制其在下次登录时重置密码。

关于 SSO 仅限 Pro 版这一背景，请参阅 [SSO 章节](/admin/sso/) 和 [3.0 升级说明](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only)。

## 为什么会出现这种情况

开源版 DefectDojo 只针对 Django 的本地用户数据库进行身份验证。它判断某个账户是否为"SSO 用户"，唯一依据就是该账户是否拥有一个可用的密码。通过 SSO 创建的账户在创建时被设置了一个*不可用*的密码，因此：

* 本地登录会失败（没有可供校验的密码），并且
* UI 和 API 中的**强制密码重置（Force password reset）**控件会被阻止，并提示该用户是通过 SSO 进行身份验证的。

设置一个真实的密码可以同时清除这两个限制：账户可以进行本地登录，并且强制重置标志也变得可以设置。

## 变通方法

在 `uwsgi` 容器内的 Django shell 中执行以下步骤：

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### 单个用户示例

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

## 用户接下来要做什么

通过带外方式（电子邮件、团队聊天工具，或你们平时共享敏感信息的其他方式）将临时密码发送给每位用户。在他们下次登录时，DefectDojo 会将其重定向到**修改密码（Change Password）**页面，并且在他们设置好自己的密码之前，不允许前往任何其他页面。一旦完成设置，强制重置标志会自动清除。

如果你的实例启用了"忘记密码"流程（`DD_FORGOT_PASSWORD`，默认开启）并配置了电子邮件，那么在账户拥有可用密码之后，用户也可以改用登录页面上的 **I forgot my password（忘记密码）**链接，无需使用临时密码即可设置新密码。

## 说明

* **Kubernetes：** 改为在 Django pod 中运行该 shell，例如 `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell`（请根据你的发布版本调整部署和容器名称）。
* 请选择一个强度足够的一次性密码。由于设置了 `force_password_reset = True`，用户无法保留这个密码，因此它只需要能撑过一次登录即可。
* 请至少保留一个可用的本地管理员账户，以确保你不会被锁在外面。
