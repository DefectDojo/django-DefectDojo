---
title: Limitación de tasa
description: Configure la limitación de tasa en la página de inicio de sesión para
  mitigar ataques de fuerza bruta
weight: 4
audience: opensource
aliases:
- /es/en/open_source/rate_limiting
---

DefectDojo incluye limitación de tasa en la página de inicio de sesión para proteger contra ataques de fuerza bruta, mediante [Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html).

## Configuration

La limitación de tasa se configura mediante los siguientes ajustes (consulte [Configuración](/get_started/open_source/configuration/) para saber cómo aplicarlos):

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Rate Limit (`DD_RATE_LIMITER_RATE`)

Establece con qué frecuencia se limitarán las solicitudes. Unidades admitidas:

- Segundos: `1s`
- Minutos: `5m`
- Horas: `100h`
- Días: `2400d`

Consulte la [documentación de tasas de Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/rates.html) para ver opciones de configuración extendidas.

### Block Requests (`DD_RATE_LIMITER_BLOCK`)

De forma predeterminada, la limitación de tasa registra las infracciones pero no bloquea las solicitudes. Configurar `DD_RATE_LIMITER_BLOCK` en `True` bloqueará activamente todas las solicitudes entrantes una vez que se supere la tasa configurada.

### Account Lockout (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

Cuando está habilitado, un usuario cuyos intentos de inicio de sesión activen el límite de tasa deberá restablecer su contraseña antes de poder volver a iniciar sesión. Esto reduce el riesgo de compromiso de credenciales durante un ataque de fuerza bruta.

## Multi-Process Behaviour

Al ejecutarse con varios procesos de `uwsgi`, el paquete de limitación de tasa usa una caché basada en memoria que es local a cada proceso. En esta configuración predeterminada, los contadores del límite de tasa no se comparten entre procesos.
