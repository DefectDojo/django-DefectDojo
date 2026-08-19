---
title: Eseguire il backup di un deployment self-hosted
description: Le quattro cose da acquisire, dove si trova ciascuna nei deployment Compose
  e Kubernetes, e come verificare che un backup possa essere effettivamente ripristinato
draft: false
weight: 12
audience: pro
---

A deployment is more than its database. A backup that captures only the database restores into a system that runs but is missing uploaded files and cannot decrypt the credentials it holds for your other tools. This page covers what to capture, where each piece lives, and how to confirm the result is restorable.

## Le quattro cose da acquisire

Il database contiene le tue organizzazioni, gli asset, gli engagement, i test, i riscontri, gli utenti e la configurazione.

I file caricati risiedono al di fuori del database. Screenshot, modelli di minaccia, documenti di accettazione del rischio e allegati simili si trovano su un filesystem, e il database contiene solo i percorsi che vi puntano.

La configurazione del deployment è ciò che permette all'applicazione di tornare operativa esattamente come prima, incluse le tue personalizzazioni e i certificati TLS.

Le chiavi di cifratura sono l'elemento più spesso trascurato. La chiave di cifratura delle credenziali è ciò che rende leggibili le credenziali memorizzate per i tuoi strumenti connessi. Se ripristini un database senza di essa, quelle credenziali restano intatte ma non decifrabili, il che significa che ogni integrazione dovrà essere reinserita manualmente.

## Il database

La maggior parte dei deployment self-hosted punta a un servizio PostgreSQL gestito, che è l'impostazione predefinita della chart e la configurazione consigliata. In tal caso, usa i backup automatici e il point-in-time recovery forniti dal provider stesso, invece di crearne di propri. Ci sono due aspetti che vale la pena verificare piuttosto che dare per scontati: che i backup automatici siano effettivamente abilitati sull'istanza, dato che un database gestito con i backup disattivati non ne ha alcuno, e che la finestra di retention corrisponda a quanto richiesto dalla tua organizzazione.

Se gestisci PostgreSQL autonomamente, esegui un dump compresso in formato custom:

```bash
pg_dump -h <db_host> -U <db_user> -Fc <db_name> > defectdojo-$(date +%F).dump
```

Ripristinalo con `pg_restore`, usando `--no-owner` e `--no-privileges` se la destinazione ha ruoli diversi rispetto all'origine:

```bash
pg_restore -v --no-owner --no-privileges -h <db_host> -U <db_user> -d <db_name> defectdojo-<date>.dump
```

Esegui il dump secondo una pianificazione, conservalo al di fuori della macchina che lo ha prodotto, e mantieni un numero di generazioni sufficiente a sopravvivere a un problema che non noti immediatamente.

## File caricati

In un deployment Docker Compose, i file caricati si trovano nella directory `media` all'interno della directory di deployment sull'host. Includi questo percorso nel tuo normale backup del filesystem. Se lo hai spostato su uno storage separato, esegui il backup di quel filesystem invece che del punto di mount.

Su Kubernetes, il volume media viene predisposto in base al backend di storage configurato, e il luogo fisico in cui risiedono i dati determina come proteggerli:

| Backend di storage | Dove risiedono i dati | Come proteggerli |
| --- | --- | --- |
| `efs` | Un filesystem Amazon EFS | AWS Backup |
| `filestore` | Un'istanza Google Filestore | Backup di Filestore |
| `gcsfuse` | Un bucket Cloud Storage | Versioning del bucket, oppure una copia pianificata verso un altro bucket |
| `nfs` | Il tuo server NFS | Qualsiasi meccanismo protegga quel server |
| `pvc` | Un volume della tua storage class | Uno snapshot del volume CSI, se il tuo driver lo supporta |

La chart predispone il volume, ma non ne protegge il contenuto. Non è integrata alcuna pianificazione di snapshot, quindi il backup deve provenire dalla piattaforma o dai tuoi strumenti.

## Configurazione e chiavi

Su Compose, acquisisci la directory `customizations`, la directory `certs` e la configurazione e i valori d'ambiente memorizzati dalla CLI. `config print` e `environment print` mostrano ciò che è impostato.

Su Kubernetes, acquisisci i tuoi file values e il contenuto dei secret a cui fa riferimento la tua release.

In entrambi i casi, conserva la chiave di cifratura delle credenziali e la secret key in un luogo duraturo e separato, in un secret manager piuttosto che insieme al backup. Chiunque possieda sia il database sia la chiave delle credenziali può leggere le credenziali di ogni strumento connesso, quindi non dovrebbero viaggiare insieme.

## Cosa non è un backup

La chart annota le proprie persistent volume claim in modo che sopravvivano a `helm uninstall`, comportamento attivo per impostazione predefinita. Si tratta di una protezione contro una disinstallazione accidentale, non di un backup. Non serve a nulla in caso di corruzione, di un'eliminazione all'interno dell'applicazione o di un aggiornamento andato male, perché in ognuno di questi casi il volume sopravvive e il danno è già presente su di esso.

Anche gli snapshot conservati solo nello stesso account o progetto del deployment sono più deboli di quanto sembrino. Qualsiasi cosa possa eliminare il deployment può di norma eliminare anche quelli.

## Verificare che un backup sia ripristinabile

Un backup che nessuno ha mai ripristinato è solo un'ipotesi. Testalo in un ambiente usa e getta anziché sopra l'ambiente di produzione, e verifica quanto segue:

1. Accedi e verifica che le tue organizzazioni, gli asset, gli engagement, i test e i riscontri siano presenti nei numeri attesi.
2. Apri un riscontro con un allegato e scaricalo. Questo dimostra che il ripristino dei media ha funzionato, poiché il solo database mostrerebbe l'allegato elencato ma non riuscirebbe a servirlo.
3. Apri una connessione a uno strumento configurato e verifica che le sue credenziali siano intatte. Questo dimostra che hai ripristinato correttamente la chiave di cifratura delle credenziali, ed è il controllo più probabile a rivelare una lacuna.
4. Verifica che utenti e gruppi siano stati trasferiti correttamente. Le impostazioni di autenticazione come SSO in genere richiedono una riconfigurazione per un ambiente diverso, quindi considera le differenze in quest'area come previste e non come un ripristino fallito.

Esegui questa prova secondo una pianificazione, non solo quando ne hai bisogno. Effettuare un ripristino per la prima volta durante un incidente è il punto in cui i piani di backup solitamente falliscono.

## Domande o supporto

Per assistenza nella pianificazione dei backup del tuo deployment, o se un ripristino non funziona come previsto, contatta [support@defectdojo.com](mailto:support@defectdojo.com).
