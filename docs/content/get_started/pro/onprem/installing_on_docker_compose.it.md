---
title: Installazione su Docker Compose
description: Installa DefectDojo Pro self-hosted su un singolo host utilizzando dojo-compose-cli,
  con PostgreSQL su un server separato
draft: false
weight: 15
audience: pro
---

Questa pagina descrive l'installazione di DefectDojo Pro su Docker Compose, che è il più semplice dei due modelli self-hosted ed è la scelta giusta se non si utilizza già Kubernetes.

Il risultato è costituito da due host. Uno esegue l'applicazione e i suoi servizi di supporto sotto Docker Compose, e l'altro esegue PostgreSQL. È possibile puntare a un database gestito anziché eseguirne uno proprio, e per la valutazione è possibile eseguire il database in un container sull'host dell'applicazione, anche se questo non è consigliato per i dati di produzione.

Quasi tutto il lavoro viene svolto da `dojo-compose-cli`, fornito da DefectDojo insieme alla licenza. Il suo comando `first-install` è una procedura guidata interattiva che configura l'implementazione, scarica le immagini, avvia tutto e registra un servizio systemd.

## Prima di iniziare

Dimensionare prima l'implementazione. Le indicazioni sul dimensionamento dell'hardware in questa sezione coprono cosa provisionare sia per l'host dell'applicazione sia per il database.

Ubuntu 24.04 LTS è il sistema operativo supportato per questa installazione. Aggiornarlo completamente prima di iniziare. L'installazione esegue comandi come root, quindi è necessario `sudo` o una shell root su entrambi gli host.

Saranno necessari due file da DefectDojo, forniti insieme all'abbonamento: l'archivio `dojo-compose-cli` e il file di licenza, solitamente denominato `dojopro.lic`. Contattare il proprio referente commerciale o [support@defectdojo.com](mailto:support@defectdojo.com) se non si dispone di questi file.

## Configurare il database

DefectDojo Pro richiede PostgreSQL 16 o versioni successive.

### Utilizzo di un database gestito

Se si utilizza un servizio PostgreSQL gestito, seguire la documentazione del provider per creare l'istanza, quindi creare quanto segue:

- Un database denominato `dojodb`
- Un utente del database denominato `dojodbusr`, con tutti i privilegi su `dojodb`, impostato come proprietario

Annotare l'hostname, la porta se non è quella predefinita 5432, e le credenziali. Serviranno durante l'installazione.

### Eseguire PostgreSQL autonomamente

Su Ubuntu 24.04, PostgreSQL 16 è presente nei repository predefiniti:

```bash
apt update
apt -y install postgresql postgresql-contrib
```

Creare i database e l'utente dell'applicazione. DefectDojo utilizza un secondo database per il proprio servizio di orchestrazione, quindi crearli entrambi:

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

Utilizzare una password alfanumerica. I caratteri speciali devono essere codificati come URL più avanti, quando la password viene inserita in una stringa di connessione, ed è un passaggio facile da sbagliare.

Quindi consentire al database di accettare connessioni dall'host dell'applicazione. In `/etc/postgresql/16/main/postgresql.conf`, impostare `listen_addresses` sull'indirizzo del server del database stesso, oppure su `*` se si preferisce non fissarlo:

```bash
listen_addresses = '<db-server-address>'
```

E in `/etc/postgresql/16/main/pg_hba.conf`, aggiungere tre righe che autorizzano l'host dell'applicazione. Limitare l'accesso all'indirizzo dell'host dell'applicazione è preferibile ad aprirlo a tutto:

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

Riavviare affinché entrambe le modifiche abbiano effetto:

```bash
systemctl restart postgresql
```

## Preparare l'host dell'applicazione

### Connettività in uscita

In una rete con restrizioni, l'host dell'applicazione necessita di accesso in uscita verso quanto segue. Tutti utilizzano HTTPS sulla porta 443, salvo indicazione contraria.

| Destinazione | Scopo | Richiesto |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | Il registro dei container di DefectDojo Pro | Sì |
| Il proprio host del database, solitamente porta 5432 | Applicazione verso database | Sì |
| I repository dei pacchetti della propria distribuzione | Dipendenze del sistema operativo durante la configurazione | Sì |
| `download.docker.com` | Pacchetti di Docker Engine durante la configurazione | Sì |
| `api.first.org` | Punteggi di previsione degli exploit EPSS | Facoltativo |
| `www.cisa.gov` | Il catalogo KEV delle vulnerabilità sfruttate note | Facoltativo |

Creare l'allowlist per hostname anziché per indirizzo. Il registro si trova dietro una rete di distribuzione dei contenuti, quindi i suoi indirizzi variano a seconda della località e cambiano nel tempo.

Se l'host raggiunge Internet tramite un proxy in uscita, vedere [Running DefectDojo Behind a Forward HTTPS Proxy](/onprem_deployment/forward_proxy/). Se non ha alcun accesso a Internet, seguire invece la procedura di installazione air-gapped in questa sezione.

### Verificare che il database sia raggiungibile

Installare gli strumenti client e connettersi prima di proseguire. Un problema del database è molto più facile da diagnosticare ora che nel bel mezzo dell'installazione:

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### Installare Docker Engine

Seguire le [istruzioni di installazione di Docker Engine per Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Utilizzare la documentazione ufficiale di Docker anziché una copia, poiché i passaggi cambiano nel tempo. Installare il pacchetto `docker-compose-plugin` insieme al motore, incluso per impostazione predefinita in tali istruzioni.

Quindi aggiungere il proprio utente al gruppo `docker` e applicare la nuova appartenenza:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## Installare DefectDojo

Copiare l'archivio della CLI e il file di licenza sull'host dell'applicazione, nella stessa directory, ed estrarre la CLI:

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

Quindi eseguire il programma di installazione da quella directory:

```bash
sudo ./dojo-compose-cli first-install
```

La procedura guidata richiede quanto segue.

| Richiesta | Cosa rappresenta |
| --- | --- |
| `DOJO_CLI_KEY` | Una chiave di cifratura per la configurazione che la CLI memorizza su disco. Sceglierla ora e conservarla, poiché i comandi successivi la richiedono. |
| DefectDojo Version | La versione da installare. |
| Deploy Version | I file di distribuzione da utilizzare. Impostarla sullo stesso valore della versione. |
| Deploy Type | `separate-db` per un database su un host separato, oppure `containerized-db` per eseguire PostgreSQL in un container. |
| Database Connection Type | Scegliere Single Line e fornire l'intera stringa di connessione. |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`. Deve iniziare con `postgres://` anziché `postgresql://`. |
| `DD_ALLOWED_HOSTS` | Gli header host a cui l'applicazione risponderà. |
| `DD_SITE_URL` | L'URL completo su cui gli utenti raggiungono DefectDojo, ad esempio `https://defectdojo.internal.example.com`. |

Due cose utili da sapere durante le richieste. Fornire la connessione al database come riga unica anziché valore per valore, poiché il percorso per singolo valore al momento non richiede il nome utente. E se la password contiene caratteri come `!`, `@` o `#`, codificarli come URL nella stringa di connessione.

Il programma di installazione scarica quindi le immagini, avvia lo stack, crea un servizio systemd e stampa le credenziali di amministratore generate. **Salvare queste credenziali prima di chiudere il terminale. Non verranno mostrate di nuovo.**

Al termine, DefectDojo è disponibile all'URL del sito fornito.

## Cosa ha creato l'installazione

| Elemento | Posizione |
| --- | --- |
| File binario della CLI | `/usr/bin/dojo-compose-cli` |
| File dell'applicazione, file compose, configurazione nginx, media | `/opt/dojo/` |
| File di licenza | `/etc/defectdojo/dojopro.lic` |
| Configurazione cifrata della CLI | `/etc/defectdojo/compose.config` |
| Certificati TLS | `/opt/dojo/certs/` |
| Personalizzazioni | `/opt/dojo/customizations/` |
| Servizio systemd | `/etc/systemd/system/defectdojo-compose.service` |

Crea inoltre un utente e un gruppo `dojosrv`, proprietari dei file dell'applicazione.

Lo stack in esecuzione comprende l'applicazione Django, un container separato che gestisce le importazioni delle scansioni, nginx, un worker e uno scheduler Celery, Valkey per la cache e le code, il servizio dei connettori e il server MCP. `docker ps` li elenca.

Nell'uso quotidiano, questi sono i comandi necessari:

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

Utilizzare `app restart` dopo aver modificato qualsiasi configurazione, poiché ricrea i container in modo che i nuovi valori vengano applicati.

## Sostituire il certificato TLS

L'installazione include un certificato autofirmato in modo che il sito funzioni immediatamente. Sostituirlo con il proprio sovrascrivendo due file, mantenendo i nomi esattamente come sono:

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

Quindi eseguire `dojo-compose-cli app restart` per applicarli.

## Reimpostare la password di amministratore

Se si perde la password generata, reimpostarla dall'host dell'applicazione. DefectDojo deve essere in esecuzione:

```bash
dojo-compose-cli app change-password
```

## Aggiornamento

Eseguire prima il backup del database, e leggere le note di rilascio per ogni versione tra quella attuale e quella di destinazione, non solo per quella di destinazione. Vedere le [note di aggiornamento](/releases/os_upgrading/upgrading_guide/).

La CLI può eseguire l'intero aggiornamento, chiedendo la versione:

```bash
dojo-compose-cli app upgrade
```

Se si preferisce procedere per passaggi, arrestare l'applicazione, impostare la nuova versione, scaricare i file di distribuzione corrispondenti, quindi riavviare:

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

Il passaggio di download confronta il `docker-compose.yml`, la configurazione nginx e il `local_settings.py` in arrivo con quelli già presenti, e segnala quando differiscono in modo da poter riconciliare le proprie modifiche. Aggiungere `--overwrite` accetta le nuove versioni di tali file e scarta le modifiche locali apportate, quindi utilizzarlo con consapevolezza.

Conservare le proprie impostazioni in `/opt/dojo/customizations/local_settings.py`. Quel file è proprio e sopravvive agli aggiornamenti.

## Riferimento dei comandi

`dojo-compose-cli --help` elenca tutto, e ogni sottocomando accetta anch'esso `--help`. I comandi più probabilmente necessari:

| Comando | Cosa fa |
| --- | --- |
| `first-install` | Installazione iniziale interattiva |
| `app start`, `app stop`, `app restart` | Controlla lo stack |
| `app upgrade` | Aggiorna a una versione più recente |
| `app pull-images`, `app purge-images` | Recupera o rimuove le immagini configurate |
| `app change-password` | Reimposta la password di amministratore, con l'app in esecuzione |
| `config print` | Mostra la configurazione attuale |
| `config set` | Imposta la versione, la versione di distribuzione, il tipo di distribuzione o la modalità air-gapped |
| `config rotate-secret` | Ruota la chiave che cifra la configurazione memorizzata |
| `environment print`, `environment add`, `environment remove` | Gestisce le variabili d'ambiente |
| `deploy download` | Recupera i file di distribuzione per la versione configurata |
| `license print`, `license status`, `license update` | Controlla e aggiorna la licenza |
| `validate db-connection` | Verifica la stringa di connessione al database |
| `validate deploy-version` | Verifica che i file di distribuzione corrispondano alla versione configurata |
| `diagnostics collect` | Raccoglie un pacchetto diagnostico per una richiesta di supporto |
| `register` | Autentica al registro dei container |
| `update-binary` | Aggiorna la CLI stessa |

La maggior parte dei comandi richiede `DOJO_CLI_KEY`, poiché la configurazione è cifrata a riposo. Esportarla per la propria sessione, oppure passarla tramite `sudo` con `sudo -E`:

```bash
export DOJO_CLI_KEY="your-key"
```

## Domande o supporto

Se un'installazione non si completa, `dojo-compose-cli diagnostics collect` raccoglie un pacchetto di report che è il modo più rapido per farci aiutare. Inviarlo, insieme a cosa si stava eseguendo quando si è verificato l'errore, a [support@defectdojo.com](mailto:support@defectdojo.com).
