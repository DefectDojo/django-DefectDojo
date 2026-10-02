---
title: 速率限制
description: 在登录页面配置速率限制以缓解暴力破解攻击
weight: 4
audience: opensource
aliases:
- /zh-hans/en/open_source/rate_limiting
---

DefectDojo 内置了登录页面速率限制功能，以防范暴力破解攻击，该功能由 [Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html) 提供支持。

## Configuration

速率限制通过以下设置进行配置（有关如何应用这些设置，请参阅[配置](/get_started/open_source/configuration/)）：

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Rate Limit (`DD_RATE_LIMITER_RATE`)

设置限制请求频率的方式。支持的单位有：

- 秒：`1s`
- 分钟：`5m`
- 小时：`100h`
- 天：`2400d`

有关更多配置选项，请参阅 [Django Ratelimit rates 文档](https://django-ratelimit.readthedocs.io/en/stable/rates.html)。

### Block Requests (`DD_RATE_LIMITER_BLOCK`)

默认情况下，速率限制只会记录违规行为，而不会阻止请求。将 `DD_RATE_LIMITER_BLOCK` 设置为 `True` 后，一旦超过所配置的速率，就会主动阻止所有传入请求。

### Account Lockout (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

启用后，若某个用户的登录尝试触发了速率限制，该用户必须重置密码才能再次登录。这可以降低在暴力破解攻击期间凭据被攻破的风险。

## Multi-Process Behaviour

在运行多个 `uwsgi` 进程时，该速率限制软件包使用的是每个进程本地的基于内存的缓存。在此默认配置下，速率限制计数器不会跨进程共享。
