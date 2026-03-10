---
title: "Rate Limiting"
description: "Configure rate limiting on the login page to mitigate brute force attacks"
weight: 4
audience: opensource
aliases:
  - /en/open_source/rate_limiting
---

DefectDojo includes login-page rate limiting to protect against brute force attacks, powered by [Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html).

## Configuration

Rate limiting is configured via the following settings (see [Configuration](../../get_started/open_source/configuration) for how to apply these):

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Rate Limit (`DD_RATE_LIMITER_RATE`)

Sets how frequently requests will be limited. Supported units:

- Seconds: `1s`
- Minutes: `5m`
- Hours: `100h`
- Days: `2400d`

See the [Django Ratelimit rates docs](https://django-ratelimit.readthedocs.io/en/stable/rates.html) for extended configuration options.

### Block Requests (`DD_RATE_LIMITER_BLOCK`)

By default, rate limiting records offenses but does not block requests. Setting `DD_RATE_LIMITER_BLOCK` to `True` will actively block all incoming requests once the configured rate is exceeded.

### Account Lockout (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

When enabled, a user whose login attempts trigger the rate limit will be required to reset their password before they can log in again. This reduces the risk of credential compromise during a brute force attack.

## Multi-Process Behaviour

When running with multiple `uwsgi` processes, the rate limiting package uses a memory-based cache that is local to each process. Rate limit counters are not shared across processes in this default configuration.
