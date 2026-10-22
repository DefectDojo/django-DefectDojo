---
title: Configurazione
description: DefectDojo è altamente configurabile.
draft: false
weight: 2
audience: opensource
aliases:
- /it/en/open_source/installation/configuration
---

## dojo/settings/settings.dist.py

Le impostazioni principali sono memorizzate in [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py). È utile usare questo file come riferimento per capire cosa può essere configurato, ma non dovrebbe essere modificato direttamente, perché le modifiche verrebbero sovrascritte durante l'aggiornamento di DefectDojo. Esistono diversi metodi per modificare le impostazioni predefinite:

### Variabili d'ambiente

La maggior parte dei parametri può essere impostata tramite variabili d'ambiente. 

Quando distribuisci DefectDojo tramite **Docker Compose**, puoi impostare le variabili d'ambiente in [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml). Tieni presente che devi impostare le variabili per tre servizi: `uwsgi`, `celerybeat` e `celeryworker`.

Quando distribuisci DefectDojo in un cluster **Kubernetes**, puoi impostare le variabili d'ambiente come `extraConfigs` ed `extraSecrets` in [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml).

### File di ambiente (non con Docker Compose o Kubernetes)

`settings.dist.py` legge le variabili d'ambiente da un file il cui nome è specificato nella variabile d'ambiente `DD_ENV_PATH`. Se questa variabile non è impostata, viene utilizzato il valore predefinito `.env.prod`. Il file deve trovarsi nella directory `dojo/settings`.

Un esempio è disponibile in [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

### local_settings.py

`local_settings.py` può contenere personalizzazioni più complesse, come l'aggiunta di voci MIDDLEWARE o INSTALLED_APP.
Questo file viene elaborato *dopo* settings.dist.py, quindi puoi modificare le impostazioni fornite da DefectDojo così come sono.
 Il file deve trovarsi nella directory `dojo/settings`. Le variabili d'ambiente in questo file non devono avere il prefisso `DD_`.
Se il file non è presente, sentiti libero di crearlo. Non modificare direttamente `settings.dist.py`.

Un esempio è disponibile in [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

In modalità release di Docker Compose, i file in `docker/extra_settings/` (relativo al file `docker-compose.yml`) verranno copiati in `dojo/settings/` all'interno del container docker all'avvio.

`local_settings.py` può essere usato anche in Kubernetes. La variabile `localsettingspy` verrà memorizzata come ConfigMap e montata nella posizione appropriata dei container.

## Configurazione nella UI

Gli utenti con stato di superuser possono configurare ulteriori opzioni tramite la UI in `Configuration` / `System Settings`. 
