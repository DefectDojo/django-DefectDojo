---
title: Migrazione da Open Source a DefectDojo Pro self-hosted
description: Sposta il database e i file multimediali di DefectDojo open source in
  un deployment self-hosted di DefectDojo Pro
draft: false
weight: 6
audience: pro
---

Questa pagina descrive come spostare i dati da un'istanza DefectDojo open source in un deployment self-hosted di DefectDojo Pro.

Gli esempi utilizzano Amazon Web Services, con Docker Compose su EC2 oppure Kubernetes su EKS, e il database su Amazon RDS per PostgreSQL. Questa è la combinazione rispetto alla quale questa procedura è stata convalidata. La stessa sequenza si applica ad altri provider che offrono PostgreSQL gestito e risorse di calcolo equivalenti, nonché a hardware on-premise, adattando i comandi specifici del provider.

Poiché sei tu a ospitare il deployment, i tuoi dati rimangono all'interno del tuo ambiente per l'intera durata della migrazione. Sei tu a eseguire l'esportazione e il ripristino, e il supporto DefectDojo può assisterti in qualsiasi fase. Se la tua istanza di DefectDojo Pro è ospitata nel cloud da DefectDojo anziché essere self-hosted, contatta invece [support@defectdojo.com](mailto:support@defectdojo.com), perché in quel caso è il team DefectDojo a eseguire il ripristino per te.

In sintesi, esporti il database e i file multimediali dall'istanza open source, li ripristini nel database e nello storage utilizzati dal tuo deployment Pro, punti Pro verso il database ripristinato e infine convalidi il risultato.

## Prima di iniziare

Prima di esportare qualsiasi cosa, verifica quanto segue.

Il motore del database. DefectDojo supporta PostgreSQL. Il supporto a MySQL è stato deprecato e successivamente [rimosso nella 2.37.0](/releases/os_upgrading/2.37/), quindi un'istanza meno recente ancora basata su MySQL deve essere convertita a PostgreSQL prima di poter essere migrata. Contatta il supporto se questo è il tuo caso.

Dove viene eseguito il database. Può trattarsi di un container dell'installazione predefinita con Docker Compose, oppure di un servizio separato sullo stesso host, su un'altra VM, o su un servizio gestito come Amazon RDS o Cloud SQL. Il comando di esportazione varia a seconda del caso.

La tua versione open source. La trovi nel footer dell'interfaccia utente, oppure dai tag di deployment e dalle versioni delle immagini. Tutte le release 2.x possono essere migrate con questa procedura. Se stai eseguendo la 3.0.0, 3.0.1, 3.0.2 o 3.0.100, esegui l'aggiornamento alla [3.0.200](/releases/os_upgrading/3.0.200/) o successiva prima di iniziare. Consulta le [note di aggiornamento](/releases/os_upgrading/upgrading_guide/) per ogni versione compresa tra quella attuale e quella a cui esegui l'aggiornamento.

Allineamento delle versioni. La tua versione open source dovrebbe corrispondere, o essere il più possibile vicina, alla versione di DefectDojo Pro verso cui stai migrando. Al primo avvio, Pro esegue le migrazioni del database che portano lo schema alla propria versione, quindi un divario di versione ampio aumenta il rischio di una migrazione lunga o non riuscita. Allinea le versioni prima di eseguire il dump.

Il database di destinazione. Effettua il provisioning di una versione principale di PostgreSQL attualmente supportata, la 16 o successiva, e mai più vecchia della versione eseguita dalla tua istanza open source, perché un dump non può essere ripristinato in una versione principale precedente. Su AWS, posiziona l'istanza RDS nello stesso VPC delle risorse di calcolo Pro e consenti il traffico in ingresso sulla porta 5432 dall'host da cui esegui il ripristino.

L'host di ripristino. Ti serve una macchina nella stessa rete del database, con gli strumenti client PostgreSQL `pg_restore` e `psql` installati. Su AWS, utilizza un'istanza EC2 nello stesso VPC, idealmente nella stessa Availability Zone dell'istanza RDS.

Spazio libero su disco. Il server di origine deve disporre di spazio sufficiente per il dump del database e per l'archivio multimediale compresso, prima di spostarli.

## Fase 1: esporta il database

La configurazione predefinita di Docker Compose utilizza `defectdojo` sia come nome utente che come nome del database. Questi valori possono essere sovrascritti, quindi controlla il valore di `DD_DATABASE_URL` nel tuo file `docker-compose.yml` o `.env`. La stringa di connessione predefinita è:

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

Nei comandi seguenti, sostituisci `<db_username>`, `<database_name>` e `<postgres_container_name>` con i tuoi valori. Trova il nome del container con `docker ps`.

Si consiglia un dump compresso in formato custom. `pg_restore` può caricarlo direttamente, evitando la maggior parte dei problemi di proprietà e di ruolo che si presentano durante un ripristino in un database gestito.

Per un PostgreSQL containerizzato, che è la configurazione predefinita di Docker Compose:

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Se il database richiede una password, passala tramite l'ambiente:

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Per un PostgreSQL esterno o remoto, ad esempio una VM separata, Amazon RDS o Cloud SQL:

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Funziona anche un dump SQL in testo semplice, ottenuto omettendo `-Fc`. Tende a includere istruzioni `CREATE ROLE`, `ALTER ROLE` e `CREATE DATABASE` che un database gestito rifiuterà, quindi consulta la nota nella Fase 4 se ne utilizzi uno.

## Fase 2: esporta i file multimediali

DefectDojo memorizza gli artefatti caricati, come screenshot, modelli di minaccia e documenti di accettazione del rischio, in una directory multimediale. I file di scansione utilizzati per l'importazione e la reimportazione non vengono conservati su disco da DefectDojo open source, poiché vengono eliminati una volta analizzati, quindi la directory multimediale contiene solo gli artefatti caricati dagli utenti.

La posizione della directory dipende dalla modalità di deployment utilizzata:

| Metodo di deployment | Percorso multimediale tipico |
| --- | --- |
| Docker Compose | Volume denominato `defectdojo_media`, montato in `/app/media` |
| Bare metal | `/opt/dojo/media`, oppure il percorso impostato in `DD_MEDIA_ROOT` |
| Kubernetes | Volume persistente montato in `/app/media` |

Comprimi la directory in un unico archivio. Da un volume denominato:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

Da un percorso su disco:

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## Fase 3: assegna un nome ai file

Inserisci la tua versione open source in entrambi i nomi dei file, in modo che la versione in gioco sia inequivocabile durante il ripristino. Per un'istanza che esegue la 2.38.1:

| File | Rinominato in |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

Sposta entrambi i file sul tuo host di ripristino. Puoi copiarli direttamente con uno strumento come `scp`, oppure caricarli in uno storage a oggetti privato nel tuo account e scaricarli sull'host di ripristino. Su AWS ciò significa un bucket S3 privato e `aws s3 cp`. In entrambi i casi, i dati rimangono all'interno del tuo ambiente.

## Fase 4: ripristina il database

Esegui il ripristino dal tuo host di ripristino, puntando all'endpoint del database. I servizi PostgreSQL gestiti differiscono per ciò che supportano in questo ambito. Amazon RDS non offre un'importazione in un solo passaggio di un file dump da un bucket, quindi il percorso supportato è un `pg_restore` lato client.

1. Crea il database e il ruolo dell'applicazione. Connettiti come utente master e crea il database di destinazione e il ruolo previsto dal dump. I valori predefiniti sono `defectdojo` per entrambi, quindi utilizza i tuoi valori se li hai sovrascritti.

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. Ripristina il dump. Per un dump in formato custom, utilizza `--no-owner` e `--no-privileges` in modo che il ripristino non tenti di riassegnare la proprietà a ruoli che non esistono nella destinazione. Un database gestito non concede un vero superuser, quindi un ripristino che tenta di farlo fallirà.

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

Per un dump SQL in testo semplice, prima commenta o rimuovi eventuali istruzioni `CREATE ROLE`, `ALTER ROLE`, `CREATE DATABASE` e `ALTER DATABASE ... OWNER`, quindi caricalo:

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

Se il ripristino segnala errori, salva l'output e contatta il supporto prima di rimuovere ulteriori elementi dal dump. Rimuoverne troppi può lasciare il database in uno stato incoerente, più difficile da diagnosticare rispetto all'errore originale.

## Fase 5: ripristina i file multimediali

Colloca il contenuto dell'archivio multimediale nel punto da cui il tuo deployment Pro legge i file caricati. L'applicazione li cerca in `/app/media`, che nel tuo deployment è supportato da un bind mount o da un volume persistente. Consulta la documentazione di installazione fornita con la tua licenza per conoscere il percorso host o il volume utilizzato dal tuo deployment.

Per un deployment Docker Compose supportato da un volume denominato:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

Per un deployment Kubernetes, estrai l'archivio localmente e copialo nel pod Django, che scrive nella persistent volume claim montata in `/app/media`:

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## Fase 6: punta DefectDojo Pro verso il database ripristinato

Aggiorna la connessione al database in modo che Pro utilizzi il database appena ripristinato, quindi avvia l'applicazione. Al primo avvio, Pro esegue le migrazioni del database che aggiornano lo schema dalla tua versione open source alla versione Pro. A seconda delle dimensioni del database e dell'ampiezza del divario di versione, l'operazione può richiedere del tempo, e l'applicazione non è disponibile finché non termina.

Per i deployment Docker Compose, imposta l'URL del database nella configurazione del deployment e riavvia lo stack. La chiave di configurazione e il comando esatti dipendono dalla versione di `dojo-compose-cli` che ti è stata fornita, quindi segui la documentazione di installazione allegata alla tua licenza. La stringa di connessione ha questa forma:

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Per i deployment Kubernetes, imposta l'URL del database nei tuoi valori Helm ed esegui nuovamente il deployment:

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Le funzionalità Pro disponibili per il tuo deployment dipendono dalla tua licenza e dalla modalità di deployment, poiché alcune di esse non sono applicabili a un'installazione self-hosted. DefectDojo conferma l'insieme applicabile al tuo caso durante la migrazione.

## Fase 7: convalida i dati

Una volta che l'applicazione è in esecuzione sul database ripristinato:

1. Accedi al tuo deployment DefectDojo Pro.
2. Verifica che i tuoi Asset, Organizzazioni, Engagement, Test e Riscontri siano presenti. Nella versione open source, Asset e Organizzazioni erano chiamati Prodotti e Tipi di prodotto.
3. Scarica dall'interfaccia utente un file caricato rappresentativo, ad esempio un allegato su un Riscontro, un Test o un Engagement, per confermare che il ripristino multimediale abbia funzionato.
4. Verifica che gli account utente e i gruppi siano integri. Le impostazioni SSO e le altre impostazioni di autenticazione di solito devono essere riconfigurate per il nuovo deployment.
5. Segnala eventuali discrepanze al tuo referente DefectDojo.

## Pianificazione del passaggio

Il dump è un'istantanea puntuale, quindi tutto ciò che viene creato nell'istanza open source dopo averlo eseguito non sarà presente nel deployment Pro. Per evitare di perdere dati, blocca l'istanza open source per il dump finale e il passaggio, oppure esegui la migrazione durante un periodo di bassa attività.

Vale la pena dedicare tempo a una prova a vuoto. Migra prima una copia recente, convalidala, quindi ripeti il processo per il passaggio effettivo. La seconda esecuzione è più rapida e ti indica quanto tempo richiederà la migrazione dello schema descritta nella Fase 6.

## Checklist di migrazione

- Motore del database, posizione del database e versione open source identificati
- Versione open source allineata con la versione Pro di destinazione
- PostgreSQL di destinazione provisionato e raggiungibile da un host di ripristino dotato degli strumenti client PostgreSQL
- Database esportato, possibilmente con un dump in formato custom
- Directory multimediale individuata e compressa
- Entrambi i file rinominati con la versione open source
- Database e ruolo dell'applicazione creati nella destinazione
- Dump ripristinato, con l'output del ripristino controllato per individuare eventuali errori
- File multimediali ripristinati nel percorso o nel volume utilizzato dal tuo deployment
- Pro puntato verso il database ripristinato e avviato, con le migrazioni dello schema completate
- Dati convalidati nel nuovo deployment

## Domande o supporto

DefectDojo supporta questa migrazione dall'inizio alla fine. Per assistenza in qualsiasi fase, contatta il tuo referente commerciale o [support@defectdojo.com](mailto:support@defectdojo.com).
