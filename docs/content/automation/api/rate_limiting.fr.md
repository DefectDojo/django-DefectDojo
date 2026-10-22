---
title: Limitation de débit
description: Configurer la limitation de débit sur la page de connexion pour atténuer
  les attaques par force brute
weight: 4
audience: opensource
aliases:
- /fr/en/open_source/rate_limiting
---

DefectDojo intègre une limitation de débit sur la page de connexion pour se protéger contre les attaques par force brute, basée sur [Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html).

## Configuration

La limitation de débit se configure via les paramètres suivants (voir [Configuration](/get_started/open_source/configuration/) pour savoir comment les appliquer) :

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Rate Limit (`DD_RATE_LIMITER_RATE`)

Définit la fréquence à laquelle les requêtes sont limitées. Unités prises en charge :

- Secondes : `1s`
- Minutes : `5m`
- Heures : `100h`
- Jours : `2400d`

Consultez la [documentation Django Ratelimit sur les taux](https://django-ratelimit.readthedocs.io/en/stable/rates.html) pour des options de configuration avancées.

### Block Requests (`DD_RATE_LIMITER_BLOCK`)

Par défaut, la limitation de débit enregistre les infractions mais ne bloque pas les requêtes. Définir `DD_RATE_LIMITER_BLOCK` sur `True` bloque activement toutes les requêtes entrantes une fois le débit configuré dépassé.

### Account Lockout (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

Lorsque cette option est activée, un utilisateur dont les tentatives de connexion déclenchent la limite de débit doit réinitialiser son mot de passe avant de pouvoir se reconnecter. Cela réduit le risque de compromission des identifiants lors d'une attaque par force brute.

## Multi-Process Behaviour

Lors de l'exécution avec plusieurs processus `uwsgi`, le package de limitation de débit utilise un cache en mémoire local à chaque processus. Dans cette configuration par défaut, les compteurs de limitation de débit ne sont pas partagés entre les processus.
