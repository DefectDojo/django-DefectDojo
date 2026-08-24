---
title: Installazione di DefectDojo Pro in un ambiente air-gapped
description: Prepara gli artifact di installazione di DefectDojo Pro su un host con
  accesso a Internet, quindi spostali in una rete air-gapped
draft: false
weight: 8
audience: pro
---

This page is a supplement to the installation instructions supplied with your DefectDojo Pro license. It covers only what changes when the target host has no route to the internet. Everything else, including the host prerequisites and the PostgreSQL setup, follows the standard instructions.

The approach uses two hosts. A staging host with normal internet access downloads the deployment artifacts and container images. You then move those artifacts into the air-gapped network by whatever transfer process your environment allows, and complete the install on the target host with no network access to DefectDojo.

Plan for the staging host to be reachable again later. Upgrades repeat the same transfer, so it is worth keeping.

## Cosa ti serve

Sull'host di staging: un host Linux con accesso a Internet, Docker installato e spazio libero su disco sufficiente per la directory di deployment più le immagini dei container compresse. Le immagini rappresentano la parte più consistente e arrivano a diverse centinaia di megabyte ciascuna.

Sull'host air-gapped: Docker installato e funzionante, e un server PostgreSQL già predisposto e raggiungibile, entrambi secondo le istruzioni di installazione standard.

Su entrambi: una copia dell'archivio `dojo-compose-cli` e il tuo file di licenza, come fornito da DefectDojo. Usa la versione 2.1.0 o successiva della CLI. Le versioni precedenti non dispongono della modalità air-gapped, e senza di essa la CLI tenta di raggiungere il registry dei container a ogni comando, fallendo con errori di risoluzione dei nomi invece di indicare chiaramente il problema.

## Prepara gli artifact

Esegui questi passaggi sull'host di staging.

### 1. Registra la CLI

Installa prima Docker, se non è già presente. Consulta la [documentazione di installazione di Docker](https://docs.docker.com/engine/install/) per le istruzioni specifiche della tua distribuzione.

Estrai l'archivio della CLI, quindi registrala:

```bash
sudo ./dojo-compose-cli register
```

La registrazione installa la CLI in `/usr/bin`, crea il gruppo `dojosrv`, aggiunge il tuo utente ai gruppi `dojosrv` e `docker`, convalida la licenza e autentica Docker rispetto al registry dei container di DefectDojo.

Ti verrà richiesta una `DOJO_CLI_KEY`, che cifra la configurazione della CLI memorizzata su disco. Impostala nell'ambiente per evitare che ti venga richiesta a ogni comando:

```bash
export DOJO_CLI_KEY="your-key"
```

L'appartenenza ai nuovi gruppi non si applica alla shell corrente. Apri una nuova sessione, oppure applica i gruppi nella sessione esistente:

```bash
newgrp docker
```

Verifica con `id` che siano elencati sia `docker` che `dojosrv`. Una volta che il tuo utente fa parte del gruppo `docker`, i comandi restanti non richiedono `sudo`.

Se l'host di staging raggiunge Internet tramite un proxy HTTPS in uscita, configura le variabili del proxy prima di scaricare qualsiasi elemento. Consulta [Eseguire DefectDojo dietro un proxy HTTPS forward](/onprem_deployment/forward_proxy/).

### 2. Imposta la versione

Imposta sia la versione di deployment sia la versione dell'applicazione sulla release che intendi installare, sostituendo `x.y.z`:

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

Usa la stessa versione in entrambi i comandi e mantienila coerente per il resto di questa procedura. Mescolare versioni diverse tra gli artifact di deployment e le immagini produce uno stack che non si avvia oppure si avvia con le immagini sbagliate.

### 3. Scarica gli artifact di deployment e le immagini

Scarica la directory di deployment:

```bash
dojo-compose-cli deploy download
```

Questo popola `/opt/dojo` con il file compose, la configurazione di nginx, i template dell'issue tracker, la directory delle personalizzazioni e una sottodirectory con versione per la release selezionata.

Quindi scarica le immagini dei container:

```bash
dojo-compose-cli app pull-images
```

Verifica cosa è arrivato:

```bash
docker image ls
```

Prendi nota del prefisso di repository condiviso dalle immagini DefectDojo in quell'output. Ti servirà nel passaggio successivo, e l'insieme delle immagini varia tra le release, quindi leggilo dal tuo output effettivo invece di dare per scontato un elenco.

### 4. Registra la configurazione generata

L'installazione standard genera diversi valori di configurazione al primo avvio. In un'installazione air-gapped li imposti manualmente sull'host di destinazione, quindi acquisiscili ora:

```bash
dojo-compose-cli environment print | head -n 9
```

Conserva la chiave di cifratura delle credenziali e la secret key. Entrambe sono stringhe casuali generate di 64 caratteri, e la chiave delle credenziali in particolare deve corrispondere a quella usata al momento della cifratura delle credenziali, quindi registrala con precisione e conservala come segreto. I valori di uwsgi e celery nello stesso output sono utili come punto di partenza per l'host di destinazione.

Tratta questo output come sensibile. Contiene le chiavi che proteggono le credenziali memorizzate per il tuo deployment.

### 5. Impacchetta tutto

Crea una directory per il trasferimento, usando la versione nel nome in modo che il contenuto sia inequivocabile in seguito:

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

Archivia la directory di deployment, preservando i permessi:

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

Salva le immagini dei container. Questo script prende il prefisso di repository annotato al passaggio 3, salva ogni immagine corrispondente e la comprime:

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

Rendilo eseguibile ed eseguilo con il tuo prefisso:

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

Verifica che ogni immagine del passaggio 3 abbia prodotto un file, quindi impacchetta la directory:

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

Sposta `artifacts-x.y.z.tar.gz` nella rete air-gapped usando il tuo normale processo di trasferimento, insieme all'archivio della CLI e al file di licenza se non sono già presenti.

## Installa sull'host air-gapped

### 6. Installa la CLI e abilita la modalità air-gapped

Estrai l'archivio della CLI, quindi posiziona la licenza dove la CLI se l'aspetta:

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

Attiva la modalità air-gapped. Questo è il primo comando della CLI che esegui su questo host, e installa la CLI in `/usr/bin`, convalida la licenza dal file e cifra la configurazione memorizzata durante il processo:

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

Verifica che sia stato applicato:

```bash
dojo-compose-cli config print
```

L'output include `Air Gapped Deploy` impostato su true. Imposta anche qui `DOJO_CLI_KEY` nell'ambiente, in modo che i comandi successivi non la richiedano.

Non eseguire `register` su questo host. La registrazione serve ad autenticarsi rispetto al registry dei container, che per definizione non è raggiungibile, e in modalità air-gapped la CLI la rifiuta invece di tentarla. Lo stesso vale per gli altri comandi che raggiungono il registry:

| Comando | Comportamento in modalità air-gapped |
| --- | --- |
| `register` | Rifiutato. L'autenticazione al registry non è disponibile. |
| `deploy download` | Rifiutato. Eseguilo invece sull'host di staging. |
| `app pull-images` | Rifiutato. Eseguilo invece sull'host di staging. |
| `app upgrade` | Rifiutato. Consulta la sezione sull'aggiornamento più avanti. |
| `app start`, `app stop`, `app restart` | Disponibile. Questi comandi non contattano il registry. |

Ogni comando rifiutato termina con un messaggio che indica la modalità air-gapped, quindi un rifiuto in questo contesto è la CLI che funziona come previsto, non un problema da diagnosticare.

Applica l'appartenenza ai nuovi gruppi prima di continuare:

```bash
newgrp docker
```

### 7. Ripristina la directory di deployment

Estrai il bundle di trasferimento, quindi sposta l'archivio di deployment al suo posto:

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

La configurazione della CLI potrebbe aver creato una `/opt/dojo` quasi vuota contenente solo la licenza. Se è presente, rimuovila prima, in modo che l'archivio non si fonda con essa:

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

Estrai la vera directory di deployment, quindi correggi la proprietà e i permessi della cartella media:

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. Imposta la configurazione manualmente

Un'installazione air-gapped non utilizza la prima installazione interattiva, quindi devi impostare i valori che altrimenti verrebbero generati automaticamente. Usa le chiavi acquisite al passaggio 4:

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

Imposta la versione in modo che corrisponda agli artifact che hai spostato:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

Imposta l'URL del sito e gli host consentiti. L'URL del sito deve essere l'indirizzo che risolve verso questo host all'interno della tua rete:

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

Imposta la connessione al database, usando il server PostgreSQL predisposto in precedenza:

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. Carica le immagini dei container

Questo script carica ogni file immagine presente nella directory delle immagini:

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

Eseguilo dall'interno della directory degli artifact estratta:

```bash
chmod u+x load-images.bash
./load-images.bash
```

Quindi verifica con `docker image ls` che tutte le immagini siano state caricate, alla versione prevista.

### 10. Avvia lo stack

Avvia lo stack con la CLI. Questo funziona in modalità air-gapped, poiché legge la configurazione che hai impostato e pilota il file compose locale senza contattare il registry:

```bash
dojo-compose-cli app start
```

`app stop` e `app restart` sono disponibili allo stesso modo. Usa `app restart` dopo aver modificato un qualsiasi valore d'ambiente, perché ricrea i container in modo che i nuovi valori vengano applicati.

Due cose da verificare se lo stack non si avvia. Il comando richiede che la directory di deployment sia al suo posto, quindi verifica che `/opt/dojo/docker-compose.yml` esista, come da passaggio 7. Inoltre la versione configurata seleziona i tag delle immagini, quindi deve corrispondere alle immagini caricate al passaggio 9.

DefectDojo sarà quindi disponibile all'indirizzo impostato come URL del sito.

## Aggiornare un deployment air-gapped

`app upgrade` scarica dal registry dei container, quindi è uno dei comandi rifiutati dalla modalità air-gapped. Gli aggiornamenti seguono lo stesso percorso dell'installazione, invece di essere gestiti da un singolo comando.

Sull'host di staging, imposta la nuova versione e ripeti per essa i passaggi da 3 a 5. Trasferisci il nuovo bundle, carica le nuove immagini, quindi sull'host air-gapped imposta la versione su quella nuova e riavvia:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

Due aspetti traggono spesso in inganno. Riavviare senza modificare la versione configurata riporta lo stack alle immagini che avevi già, perché è la versione a selezionare i tag delle immagini. Inoltre l'insieme delle immagini può cambiare tra le release, quindi confronta ciò che hai caricato con quanto prodotto dal pull della nuova versione, invece di dare per scontato che l'elenco precedente sia ancora valido.

La tua directory di deployment esistente non recepisce automaticamente il file compose o la configurazione di nginx della nuova versione, quindi ripristina il nuovo contenuto di `/opt/dojo` come hai fatto al passaggio 7, mantenendo le tue personalizzazioni, i certificati e i media.

Esegui il backup del database prima di ogni aggiornamento e consulta le [note di aggiornamento](/releases/os_upgrading/upgrading_guide/) per ogni versione compresa tra quella attuale e quella di destinazione. Se sei rimasto indietro di diverse release, contatta il supporto prima di iniziare.

## Funzionalità che richiedono accesso in uscita

Un deployment air-gapped funziona senza alcuna connettività in uscita, ma le funzionalità che raggiungono servizi esterni non possono operare mentre è disconnesso. Questo vale per i connector e gli integrator che effettuano il pull da strumenti ospitati nel cloud, per le integrazioni con issue tracker come Jira, per le notifiche in uscita verso servizi come Slack e Microsoft Teams, e per i dati di arricchimento delle vulnerabilità normalmente recuperati secondo una pianificazione.

Questi elementi vengono configurati per singolo deployment invece di essere attivi per impostazione predefinita, quindi la loro assenza non compromette un'installazione air-gapped. Se ne abiliti uno, aspettati che fallisca con errori di risoluzione dei nomi o di connessione finché il deployment non avrà un percorso verso quel servizio. Se il percorso in uscita esiste ma passa attraverso un proxy, consulta [Eseguire DefectDojo dietro un proxy HTTPS forward](/onprem_deployment/forward_proxy/).

### Dati EPSS e KEV da un mirror interno

L'arricchimento EPSS e KEV è un'eccezione che vale la pena configurare, perché non richiede un percorso verso Internet pubblico. Entrambi si configurano nel Tuner, in Finding Enrichment, e ciascuno dispone di un proprio interruttore di attivazione e di un proprio URL di lookup. I campi URL vengono forniti puntando alle fonti pubbliche, e puoi reindirizzarli verso una copia ospitata all'interno della tua rete.

Il mirror deve servire gli stessi file nello stesso formato delle fonti pubbliche. I lookup recuperano un file specifico dall'URL fornito, invece di individuare automaticamente ciò che è presente, quindi un mirror che riimpacchetta o riorganizza i dati non funzionerà. Aggiorna le tue copie secondo una pianificazione che preferisci, poiché il deployment legge solo ciò che il tuo mirror fornisce.

## Domande o supporto

Per assistenza con un'installazione o un aggiornamento air-gapped, contatta il tuo referente commerciale o [support@defectdojo.com](mailto:support@defectdojo.com).
