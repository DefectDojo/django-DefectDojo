---
title: Esecuzione in produzione
description: Per l'uso in ambienti di produzione, si consigliano aggiustamenti delle
  prestazioni e backup.
draft: false
weight: 4
audience: opensource
aliases:
- /it/en/open_source/installation/running-in-production
---

## Utilizzo in produzione (con Docker compose)

Il file docker-compose.yml in questo repository è pienamente funzionale per valutare DefectDojo nel tuo ambiente locale.

Sebbene Docker Compose sia uno dei metodi di installazione supportati per distribuire un DefectDojo containerizzato in un ambiente di produzione, il file docker-compose.yml non è pensato per l'uso in produzione senza prima personalizzarlo in base alla tua situazione specifica.

Consulta [Esecuzione con Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) per maggiori informazioni su come eseguire DefectDojo con Docker Compose.

### Requisiti di sistema

Si consiglia di utilizzare un server di database dedicato e non il database PostgreSQL preconfigurato. Questo migliorerà significativamente le prestazioni di DefectDojo.

#### Dimensione dell'istanza

Con un database separato, i requisiti minimi consigliati per eseguire DefectDojo sono:

-   2 vCPU
-   8 GB di RAM
-   10 GB di spazio su disco (ricorda, il tuo database non è qui \-- quindi
     ciò che hai per il tuo S/O dovrebbe bastare). Potresti allocare
    un disco diverso da quello del tuo SO per potenziali miglioramenti
    delle prestazioni.

### Sicurezza
Verifica la configurazione di `nginx` e altri aspetti di runtime, come gli header di sicurezza, per rispettare i tuoi requisiti di conformità.
Modifica la chiave di crittografia AES256 `&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw` in `docker-compose.yml` con un valore univoco per la tua istanza.
Questa chiave di crittografia viene utilizzata per crittografare le chiavi API e altre credenziali memorizzate in Defect Dojo per connettersi a strumenti esterni come SonarQube. Una chiave può essere generata in vari modi, ad esempio utilizzando un password manager o `openssl`:

```
     openssl rand -base64 32
```
```
      DD_CREDENTIAL_AES_256_KEY: "${DD_CREDENTIAL_AES_256_KEY:-<PUT THE GENERATED KEY HERE>o}"
```

## Backup dei file

In entrambi i casi (DB dedicato o containerizzato), se stai facendo self-hosting, si consiglia di implementare e creare backup periodici dei tuoi dati.

### File multimediali

I file multimediali per i file caricati, inclusi i modelli di minaccia e le accettazioni del rischio, sono memorizzati in un volume docker. Questo volume deve essere sottoposto a backup regolarmente.

## Regolazioni delle prestazioni

### uWSGI

Per impostazione predefinita (tranne in modalità `ptvsd` per scopi di debug), uWSGI
gestirà 16 connessioni simultanee.

In base alle tue impostazioni di risorse, puoi regolare:

-   `DD_UWSGI_NUM_OF_PROCESSES` per il numero di processi generati.
    (predefinito 4)
-   `DD_UWSGI_NUM_OF_THREADS` per il numero di thread in questi
    processi. (predefinito 4)

Ad esempio, potresti avere 4 processi con 6 thread ciascuno, ottenendo 24
connessioni simultanee.

### Celery worker

Per impostazione predefinita, viene generato un singolo celery worker mono-processo. Quando si memorizzano grandi quantità di riscontri o si eseguono importazioni di grandi dimensioni, può essere utile regolare questi parametri per evitare la carenza di risorse.

Le seguenti variabili possono essere modificate per aumentare le prestazioni del worker, mantenendo un singolo container celery.

-   `DD_CELERY_WORKER_POOL_TYPE` ti permette di passare a `prefork`.
    (predefinito `solo`)

Quando abiliti `prefork`, è necessario utilizzare
le variabili seguenti. Consulta il
file Dockerfile.django-* per i riferimenti al suo interno.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` ha come valore predefinito 2.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` ha come valore predefinito 8.
-   `DD_CELERY_WORKER_CONCURRENCY` ha come valore predefinito 8.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` ha come valore predefinito 128.

Puoi eseguire il seguente comando per visualizzare la configurazione:

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
e verificare cosa è effettivamente in vigore.

### Importazione asincrona: deprecata
Questa funzionalità è stata rimossa nella versione 2.47.0
