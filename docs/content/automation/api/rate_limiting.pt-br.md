---
title: Limitação de taxa
description: Configure a limitação de taxa na página de login para mitigar ataques
  de força bruta
weight: 4
audience: opensource
aliases:
- /pt-br/en/open_source/rate_limiting
---

O DefectDojo inclui limitação de taxa (rate limiting) na página de login para proteger contra ataques de força bruta, com tecnologia do [Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html).

## Configuração

A limitação de taxa é configurada por meio das seguintes definições (veja [Configuration](/get_started/open_source/configuration/) para saber como aplicá-las):

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Rate Limit (`DD_RATE_LIMITER_RATE`)

Define a frequência com que as requisições serão limitadas. Unidades suportadas:

- Segundos: `1s`
- Minutos: `5m`
- Horas: `100h`
- Dias: `2400d`

Consulte a [documentação de taxas do Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/rates.html) para opções de configuração estendidas.

### Block Requests (`DD_RATE_LIMITER_BLOCK`)

Por padrão, a limitação de taxa registra as ocorrências, mas não bloqueia as requisições. Definir `DD_RATE_LIMITER_BLOCK` como `True` bloqueará ativamente todas as requisições recebidas assim que a taxa configurada for excedida.

### Account Lockout (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

Quando habilitado, um usuário cujas tentativas de login acionarem o limite de taxa precisará redefinir sua senha antes de conseguir fazer login novamente. Isso reduz o risco de comprometimento de credenciais durante um ataque de força bruta.

## Comportamento com múltiplos processos

Ao executar com múltiplos processos `uwsgi`, o pacote de limitação de taxa usa um cache baseado em memória, local a cada processo. Os contadores de limite de taxa não são compartilhados entre processos nessa configuração padrão.
