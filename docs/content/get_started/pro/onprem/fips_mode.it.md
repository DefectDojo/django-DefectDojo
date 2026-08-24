---
title: Modalità FIPS 140-3
date: 2026-07-27 00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro può essere distribuito con crittografia convalidata FIPS 140-3, per ambienti soggetti al controllo FedRAMP **SC-13** o requisiti simili.

La modalità FIPS viene fornita come **un set separato di immagini container**, identificate da un suffisso di tag `-fips`. Le immagini standard restano invariate: abilitare FIPS è una scelta esplicita, mai un'impostazione predefinita silenziosa.

Per accedere alle immagini FIPS, contattaci all'indirizzo [hello@defectdojo.com](mailto:hello@defectdojo.com).

## Cosa forniscono le immagini FIPS

Tutte le operazioni crittografiche vengono eseguite dal **OpenSSL FIPS Provider 3.1.2**, che detiene il certificato NIST CMVP **[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)** ai sensi del FIPS 140-3. I servizi Go utilizzano il **Go Cryptographic Module v1.0.0**, certificato CMVP **[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**.

Poiché l'applicazione avviene **all'interno del container**, la modalità FIPS non richiede che l'host esegua un kernel abilitato FIPS. Questo è ciò che la rende praticabile su runtime container gestiti come **Amazon ECS con il tipo di avvio Fargate**, dove il sistema operativo host non è sotto il tuo controllo.

> **FIPS 140-3, non 140-2.** Il FIPS 140-3 sostituisce il 140-2 e soddisfa un requisito scritto in riferimento a quest'ultimo. Tutti i certificati FIPS 140-2 passeranno alla CMVP Historical List il **21 settembre 2026** e da quella data non supporteranno più nuove distribuzioni, quindi i nuovi sistemi dovrebbero essere convalidati rispetto a un modulo 140-3.

### Copertura

| Componente | Coperto | Modulo |
|---|:---:|---|
| Applicazione Django (`dojo`) | sì | OpenSSL FIPS Provider 3.1.2 |
| Importazione asincrona (`dojo-import-scan`) | sì | OpenSSL FIPS Provider 3.1.2 |
| Celery worker e beat | sì | OpenSSL FIPS Provider 3.1.2 |
| Initializer (`init`) | sì | OpenSSL FIPS Provider 3.1.2 |
| Worker di orchestrazione (`ddorch-workers`) | sì | OpenSSL FIPS Provider 3.1.2 |
| nginx | sì | OpenSSL FIPS Provider 3.1.2 |
| Motore di advisory PSIRT | sì | OpenSSL FIPS Provider 3.1.2 |
| Connectors, Integrators, ddorch, server MCP | sì | Go Cryptographic Module v1.0.0 |
| **Sensei** | **parziale** | binari del servizio: Go Cryptographic Module v1.0.0. Toolchain di scanner in bundle: **non coperta** |
| **PostgreSQL / Redis (incorporati)** | **no** | utilizzare servizi esterni conformi a FIPS |

**Sensei è un caso parziale che vale la pena comprendere.** I suoi binari sono compilati rispetto al modulo Go convalidato, quindi il TLS e i token della job API sono coperti. L'immagine include inoltre una toolchain di scanner di terze parti poliglotta — Node (che include il proprio OpenSSL), Rust (rustls), Python, Ruby e binari Go di terze parti che non compiliamo — e diversi di questi recuperano i database degli advisory tramite TLS utilizzando la propria crittografia. Questa toolchain non può essere ricondotta a un unico modulo convalidato, quindi non è coperta e non dovrebbe essere presentata come tale a un valutatore.

PostgreSQL/Redis incorporati non hanno alcuna variante FIPS. In Kubernetes, la chart rifiuta il rendering se abiliti FIPS insieme a Sensei o ai datastore incorporati, quindi il compromesso è una decisione esplicita e non un'assunzione (vedi [Barriere di sicurezza](#guard-rails)).

## Abilitare la modalità FIPS — Docker Compose

Due modifiche: usare le immagini `-fips` e impostare `DD_FIPS_MODE`.

**1. Punta i tag delle immagini alle varianti FIPS.** Nel tuo `.env` o override di compose:

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. Imposta `DD_FIPS_MODE` negli anchor di ambiente condivisi.** Il file compose definisce blocchi condivisi che ogni servizio rilevante unisce, quindi si tratta di tre modifiche anziché una per servizio:

```yaml
x-dojo-vars: &dojoenv
  DD_FIPS_MODE: "1"        # dojo, dojo-import-scan, celerybeat, celeryworker, init, ddorch-workers
  # ... existing settings

x-nginx-vars: &nginxenv
  DD_FIPS_MODE: "1"        # nginx
  # ... existing settings

x-psirt-vars: &psirtenv
  DD_FIPS_MODE: "1"        # psirt
  # ... existing settings
```

Quindi ricrea lo stack:

```bash
docker compose up -d --force-recreate
```

## Abilitare la modalità FIPS — Kubernetes (Helm)

Imposta un solo valore. La chart seleziona le varianti `-fips` delle immagini e imposta `DD_FIPS_MODE` per ogni pod:

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

Poiché i datastore incorporati non hanno una variante FIPS e Sensei è coperto solo parzialmente, un'installazione FIPS dovrebbe utilizzare PostgreSQL e Redis esterni e lasciare Sensei disabilitato, a meno che tu non accetti l'avvertenza sopra riportata:

```yaml
fips:
  enabled: true
sensei:
  enabled: false          # partial coverage — see the table above
postgresql:
  enabled: false          # use an external FIPS-compliant database
redis:
  enabled: false          # use an external FIPS-compliant cache
```

Se hai bisogno di Sensei in un ambiente FIPS, abilitalo deliberatamente con
`fips.validate: false` e documenta la toolchain di scanner in bundle come
non convalidata nel tuo system security plan.

### Barriere di sicurezza

Se `fips.enabled` è true mentre è abilitato anche un componente privo di variante FIPS, **la chart rifiuta il rendering** e indica i responsabili:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

Questo è intenzionale. Una distribuzione in cui la maggior parte dei servizi utilizza crittografia convalidata mentre uno o due non lo fanno silenziosamente è peggiore di un errore evidente: sembra conforme, supera un controllo superficiale ed emerge solo durante una valutazione. Se hai accettato per iscritto questo rischio, sovrascrivilo con `fips.validate: false`.

## Abilitare la modalità FIPS — Amazon ECS / Fargate

Fargate è un tipo di avvio per ECS, non un servizio separato: si registrano le task
definition ECS con `requiresCompatibilities: ["FARGATE"]` e `networkMode: awsvpc`.

Se esegui già DefectDojo Pro su ECS, cambiano solo due cose:

**1. I tag delle immagini** acquisiscono il suffisso `-fips`:

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2. `DD_FIPS_MODE=1`** nel blocco `environment` di ogni container che esegue
codice applicativo — uwsgi, celery worker, celery beat, l'initializer, i
worker di orchestrazione, nginx e psirt.

Il resto di questa sezione descrive una distribuzione ECS completa con FIPS abilitato, pensata
per chi parte da zero.

### Cosa predisporre per primo

| Risorsa | Note |
|---|---|
| VPC con due subnet | Subnet private più un NAT gateway, oppure subnet pubbliche con `assignPublicIp: ENABLED` |
| RDS per PostgreSQL | Utilizza un endpoint compatibile con FIPS e documentalo come componente ereditato |
| ElastiCache per Redis | Vengono utilizzati due database logici: `/0` per il broker Celery, `/1` per la cache |
| File system EFS | Due directory: una per `/app/media`, una contenente i certificati TLS di nginx |
| Voci di Secrets Manager | URL del database, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY` e la tua licenza Pro |
| Application Load Balancer | Listener HTTPS, che inoltra a un target group **HTTPS** sulla porta **8443** |
| Repository ECR | Contenenti le due immagini `-fips` |
| Ruoli IAM | Un execution role in grado di effettuare il pull da ECR, scrivere log e leggere quei secret, più un task role |
| Log group CloudWatch | Referenziato dalla configurazione `awslogs` di ogni container |

Colloca il certificato e la chiave TLS su EFS come `dojo.crt` / `dojo.key`, oltre a
`nginx_int.crt` / `nginx_int.key`. Entrambe le coppie devono esistere — vedi
[Tre cose di cui ECS ha bisogno](#three-things-ecs-needs-that-compose-provides-for-free)
più avanti per il motivo.

### 1. Il task dell'initializer (eseguito una volta per ogni upgrade)

Applica le migrazioni e inizializza i dati del primo avvio, poi termina. È un task, non un
servizio.

```json
{
  "family": "defectdojo-pro-init",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "init",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-initializer.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_INITIALIZE", "value": "true" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" },
        { "name": "DD_ADMIN_USER", "value": "admin" },
        { "name": "DD_ADMIN_MAIL", "value": "admin@example.com" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_ADMIN_PASSWORD", "valueFrom": "<SECRET_ARN_ADMIN_PASSWORD>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "init"
        }
      }
    }
  ]
}
```

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-init.json
aws ecs run-task --cluster <CLUSTER> --launch-type FARGATE \
  --task-definition defectdojo-pro-init \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}"
```

Attendi che raggiunga lo stato `STOPPED` con codice di uscita 0 prima di avviare i servizi.

### 2. Il servizio web (nginx + uwsgi)

Entrambi i container risiedono in un unico task, così nginx raggiunge uwsgi su `127.0.0.1`.

```json
{
  "family": "defectdojo-pro-web",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "volumes": [
    {
      "name": "media",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/media"
      }
    },
    {
      "name": "certs",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/nginx-certs"
      }
    }
  ],
  "containerDefinitions": [
    {
      "name": "uwsgi",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_UWSGI_ENDPOINT", "value": "0.0.0.0:3031" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "mountPoints": [{ "sourceVolume": "media", "containerPath": "/app/media" }],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "uwsgi"
        }
      }
    },
    {
      "name": "nginx",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips",
      "essential": true,
      "dependsOn": [{ "containerName": "uwsgi", "condition": "START" }],
      "portMappings": [{ "containerPort": 8443, "protocol": "tcp" }],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "USE_TLS", "value": "false" },
        { "name": "GENERATE_TLS_CERTIFICATE", "value": "false" },
        { "name": "DD_UWSGI_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_PORT", "value": "3031" },
        { "name": "DD_UWSGI_IMPORT_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_IMPORT_PORT", "value": "3031" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
        { "name": "DD_MCP_PORT", "value": "9142" },
        { "name": "PSIRT_ENABLED", "value": "false" },
        { "name": "NGINX_METRICS_ENABLED", "value": "false" }
      ],
      "mountPoints": [
        { "sourceVolume": "certs", "containerPath": "/etc/nginx/certs", "readOnly": true }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "nginx"
        }
      }
    }
  ]
}
```

`USE_TLS=false` seleziona la configurazione on-prem, che termina il TLS autonomamente sulla
porta 8443 utilizzando i certificati montati. Registrala e crea un servizio collegato
al load balancer:

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. Il servizio worker (Celery worker e beat)

Stessa immagine e stessi secret di uwsgi; l'entry point seleziona il processo. Esegui
esattamente **una** replica beat.

```json
{
  "family": "defectdojo-pro-worker",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "celeryworker",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-worker.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celeryworker"
        }
      }
    },
    {
      "name": "celerybeat",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-beat.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celerybeat"
        }
      }
    }
  ]
}
```

### 4. Conferma che la distribuzione utilizzi crittografia convalidata

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

Ogni container dovrebbe segnalare il modulo prima di servire qualsiasi richiesta:

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

Se un container manca da quell'output, significa che non è mai partito, perché il controllo
fallisce in modalità chiusa (fail-closed) — controlla il suo log stream per scoprirne il motivo.

### Tre cose di cui ECS ha bisogno e che Compose fornisce gratuitamente

Docker Compose offre un filesystem host da cui effettuare bind-mount e la risoluzione DNS per
i nomi dei container. Fargate non fornisce nessuna delle due cose, e ciascuna lacuna impedisce
l'avvio di nginx invece di degradare silenziosamente.

**1. I certificati TLS devono esistere prima dell'avvio di nginx.** nginx convalida ogni
`ssl_certificate` al caricamento della configurazione, e la configurazione on-prem non ha
un percorso privo di certificato: la porta 8080 emette solo un `301` verso HTTPS, quindi il
listener TLS 8443 è quello funzionante. Monta un volume **EFS** su `/etc/nginx/certs`
contenente `dojo.crt` / `dojo.key` e `nginx_int.crt` / `nginx_int.key`. Entrambe
le coppie devono essere presenti anche se usi un solo listener.

In alternativa imposta `USE_TLS=true`, che serve il file `nginx_TLS.conf` upstream e
consente a `GENERATE_TLS_CERTIFICATE=true` di far generare all'entrypoint un proprio
certificato. Questa configurazione instrada ogni percorso verso Django e non serve
l'interfaccia Vue da `/ui`, quindi è adatta a una distribuzione solo API o rigorosamente dietro ALB.

**2. `DD_MCP_HOST` deve essere risolvibile.** nginx risolve i nomi host di `proxy_pass` al
caricamento della configurazione. Il valore predefinito `mcp-server` viene risolto sotto Compose
(nome del container) e Helm (nome del Service), ma `awsvpc` non assegna ai container nomi DNS
propri e rifiuta sia `extraHosts` sia `dnsSearchDomains`:

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

Puntarlo al loopback quando il server MCP non è distribuito fa sì che `/mcp` risponda
`502` invece di impedire l'avvio dell'intero livello web.

**3. I file di configurazione di nginx provengono dall'immagine.** L'immagine nginx `-fips`
include già incorporato il set di configurazione on-prem, quindi non sono necessari mount.
Compose sovrappone i propri bind mount, quindi il comportamento di Compose resta invariato.

### Altre specificità di Fargate

- **L'archiviazione persistente deve essere EFS.** Fargate non può collegare EBS, quindi la
  directory media (`/app/media`) necessita di un volume EFS se conservi i file di scansione caricati.
- **Non sono richiesti container privilegiati né host networking.** Le immagini vengono eseguite
  come utente non root, e `awsvpc` assegna a ogni task una propria interfaccia di rete.
- **nginx → uwsgi.** I container nello *stesso* task condividono un namespace di rete, quindi
  collocare nginx insieme a uwsgi permette a nginx di raggiungerlo su `127.0.0.1` — l'opzione
  corretta più semplice. Se li separi in servizi ECS distinti, punta
  `DD_UWSGI_HOST` verso un nome di service discovery Cloud Map e apri il security
  group sulla porta di uwsgi.
- **Non sovrascrivere l'entrypoint di uwsgi.** Imposta
  `DD_UWSGI_ENDPOINT=0.0.0.0:3031` e lascia invariato l'ENTRYPOINT dell'immagine;
  uwsgi parla il protocollo uwsgi, che è ciò che nginx si aspetta. Sostituire
  l'entrypoint con `uwsgi --http` elimina insieme ad esso anche il controllo di avvio FIPS.
- **L'initializer è un task one-shot**, non un servizio. Eseguilo con
  `aws ecs run-task` (o come passaggio pre-deploy) e lascialo terminare; non assegnargli
  un desired count.
- **`healthCheck.retries` non può superare 10.** Valori più alti vengono rifiutati quando
  la task definition viene registrata.
- **Punta il load balancer verso la porta 8443** con un target group HTTPS. Il listener 8080
  della configurazione on-prem effettua solo un redirect verso HTTPS, quindi puntare a 8080
  crea un loop. Un certificato autofirmato sul target è accettabile per un ALB.
- **Terminazione TLS.** Se l'ALB termina il TLS per i client, documenta separatamente nel tuo
  SSP la postura FIPS del load balancer stesso.
- **I secret** vanno collocati in Secrets Manager o SSM Parameter Store tramite il
  blocco `secrets`, mai in `environment`. Questo include `DD_LICENSE`.

### Recuperare le evidenze su ECS

Il blocco di evidenza di avvio finisce nel log group indicato dalla configurazione
`awslogs` del container:

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

Su richiesta, all'interno di un task in esecuzione (richiede `enableExecuteCommand` sul servizio):

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## Avvio fail-closed

Con `DD_FIPS_MODE` impostato, ogni container verifica all'avvio che il provider convalidato sia caricato e che gli algoritmi non approvati vengano effettivamente rifiutati. **Se questo controllo fallisce, il container termina invece di avviarsi.**

Stessa logica della barriera della chart: un container che tornasse silenziosamente a crittografia non convalidata continuerebbe a servire traffico compromettendo la tua postura di conformità, e te ne accorgeresti solo durante una valutazione.

## Verificare la modalità FIPS

Ogni container stampa un blocco di evidenza all'avvio, che di solito è la forma più comoda per un valutatore. Sui runtime gestiti finisce nel tuo log aggregator:

```
================================================================
[FIPS] DefectDojo Pro FIPS mode verification
Providers:
  fips
    name: OpenSSL FIPS Provider
    version: 3.1.2
    status: active
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
================================================================
```

Recuperalo con:

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

Puoi anche verificare su richiesta all'interno di un container in esecuzione:

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

Per i servizi Go, la modalità FIPS è compilata staticamente e viene segnalata dal runtime Go:

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## Differenze di comportamento in modalità FIPS

Alcuni algoritmi non approvati non sono disponibili, quindi alcuni comportamenti cambiano. Ecco quelli per cui vale la pena pianificare.

### Hashing delle password

Le build FIPS utilizzano **PBKDF2-SHA256** come hasher di password predefinito. Argon2, bcrypt e scrypt non sono funzioni di derivazione delle chiavi approvate da FIPS e sono disabilitate.

Gli utenti esistenti non vengono bloccati. Django ricalcola l'hash di ogni password in PBKDF2 al successivo accesso riuscito dell'utente, e gli hash PBKDF2-SHA1 restano verificabili durante la transizione. Se preferisci un passaggio netto, forza un reset della password invece di affidarti alla migrazione graduale.

### Suite di cifratura TLS

ChaCha20-Poly1305 non è approvato da FIPS e viene rimosso da ogni configurazione nginx che termina il TLS, e TLS 1.3 viene fissato su `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`. TLS 1.2 e TLS 1.3 restano disponibili tramite le suite AES-GCM. I client che supportano solo ChaCha20 non riusciranno a connettersi.

Il modulo convalidato rifiuterebbe comunque ChaCha20; rimuoverlo dalla configurazione fa sì che il server non annunci mai una suite che non può completare, il che rende la configurazione distribuita autoesplicativa per un valutatore.

### Autenticazione di base delle metriche

Quando l'autenticazione delle metriche di nginx è abilitata, l'hash della password utilizza SHA-256 crypt anziché il formato MD5 di Apache (`apr1`), che il modulo convalidato rifiuta. Questo è trasparente a meno che tu non generi tu stesso le voci `.htpasswd`, nel qual caso usa `openssl passwd -5`.

### Parser di scansione

Alcuni parser utilizzano MD5 per costruire le chiavi di deduplicazione. Si tratta di un uso non legato alla sicurezza ed è esplicitamente annotato come tale, quindi quei parser continuano a funzionare normalmente in FIPS. Nessuna funzionalità dei parser viene persa.

## Note sulla distribuzione

- **Terminazione TLS.** Se il TLS termina su un load balancer davanti a DefectDojo, quel dispositivo è responsabile della propria postura FIPS e dovrebbe essere documentato separatamente nel tuo system security plan. L'immagine nginx `-fips` copre il TLS terminato da DefectDojo stesso.
- **Database e cache.** PostgreSQL e Redis sono prodotti separati. In un ambiente FIPS, utilizza istanze conformi a FIPS — ad esempio un database gestito che offra un endpoint FIPS — e documentale come componenti ereditati.
- **Ambito di conformità.** DefectDojo non è di per sé un modulo crittografico e non detiene alcun certificato proprio. Ciò che queste immagini forniscono è crittografia convalidata, eseguita da moduli che tale certificazione la possiedono, in esecuzione in modalità approvata FIPS. Il tuo valutatore vorrà i nomi dei moduli e i numeri di certificato, che compaiono nell'output di evidenza sopra.
