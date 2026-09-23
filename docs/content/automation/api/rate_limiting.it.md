---
title: Limitazione della frequenza
description: Configura la limitazione della frequenza nella pagina di accesso per
  mitigare gli attacchi di forza bruta
weight: 4
audience: opensource
aliases:
- /it/en/open_source/rate_limiting
---

DefectDojo include la limitazione della frequenza nella pagina di accesso per proteggere dagli attacchi di forza bruta, basata su [Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html).

## Configurazione

La limitazione della frequenza viene configurata tramite le seguenti impostazioni (vedi [Configurazione](/get_started/open_source/configuration/) per come applicarle):

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Frequenza limite (`DD_RATE_LIMITER_RATE`)

Imposta la frequenza con cui le richieste verranno limitate. Unità supportate:

- Secondi: `1s`
- Minuti: `5m`
- Ore: `100h`
- Giorni: `2400d`

Consulta la [documentazione di Django Ratelimit sulle frequenze](https://django-ratelimit.readthedocs.io/en/stable/rates.html) per opzioni di configurazione estese.

### Blocco delle richieste (`DD_RATE_LIMITER_BLOCK`)

Per impostazione predefinita, la limitazione della frequenza registra le violazioni ma non blocca le richieste. Impostando `DD_RATE_LIMITER_BLOCK` su `True` verranno bloccate attivamente tutte le richieste in arrivo una volta superata la frequenza configurata.

### Blocco account (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

Se abilitato, un utente i cui tentativi di accesso attivano il limite di frequenza dovrà reimpostare la propria password prima di poter accedere di nuovo. Questo riduce il rischio di compromissione delle credenziali durante un attacco di forza bruta.

## Comportamento multi-processo

Quando si esegue con più processi `uwsgi`, il pacchetto di limitazione della frequenza utilizza una cache basata sulla memoria locale a ciascun processo. I contatori del limite di frequenza non sono condivisi tra i processi in questa configurazione predefinita.
