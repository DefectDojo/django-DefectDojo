---
title: Distribuire DefectDojo Pro su OpenShift
description: 'Cosa è specifico di OpenShift nel deployment self-hosted di DefectDojo
  Pro: security context constraints, Route e storage ReadWriteMany'
draft: false
weight: 8
audience: pro
---

DefectDojo Pro è eseguibile su OpenShift 4.x, incluse OpenShift Container Platform, ROSA e OKD.

Questa pagina integra la guida di installazione fornita con la tua licenza DefectDojo Pro. Quella guida contiene la procedura completa, inclusa una sezione dedicata a OpenShift. Questa pagina illustra ciò che è diverso su OpenShift, in modo che tu sappia cosa avere pronto prima di iniziare e cosa aspettarti dalle impostazioni specifiche della piattaforma.

Uno script di bootstrap per OpenShift viene fornito con i materiali della tua licenza. Si installa su un cluster esistente e gestisce gran parte di quanto descritto in questa pagina, inclusi lo storage, il valore di `fsGroup`, la Route e l'installazione stessa. È idempotente, quindi rieseguirlo riutilizza ciò che ha già creato, e supporta una modalità dry run che stampa ciò che farebbe senza modificare nulla. Il resto di questa pagina si applica sia che tu utilizzi quello script sia che tu esegua l'installazione manualmente.

## Security context constraints

DefectDojo Pro viene eseguito sotto la SCC predefinita `restricted-v2`. Non è necessario concedere `anyuid`, `privileged` o qualsiasi altra SCC con privilegi elevati all'account di servizio.

Se configurato per OpenShift, DefectDojo Pro viene eseguito interamente con security context non privilegiati. I container vengono eseguiti senza privilegi, non possono elevarli e rilasciano tutte le capability. L'ID utente viene lasciato assegnare a OpenShift dall'intervallo allocato al tuo namespace, anziché essere fissato a un UID predefinito che la SCC rifiuterebbe.

Se i pod vengono rifiutati per il mancato superamento della convalida SCC, la causa abituale è che il deployment non è stato configurato per OpenShift, non che sia necessario concedere un constraint.

## Lo storage deve essere ReadWriteMany

I pod Django e Celery worker leggono e scrivono gli stessi file multimediali, ovvero le scansioni caricate, gli screenshot e i report generati. Necessitano di un volume condiviso, quindi lo storage ReadWriteOnce non è sufficiente per un deployment multi-nodo.

Su OpenShift, l'impostazione predefinita è una PersistentVolumeClaim a fronte della StorageClass predefinita del cluster. Questo funziona quando la classe predefinita esegue il provisioning di ReadWriteMany, cosa tipica sui cluster basati su OpenShift Data Foundation o NFS. Per i deployment multi-nodo in cui la classe predefinita è ReadWriteOnce, configura invece uno storage basato su NFS.

### fsGroup su storage basato su NFS

OpenShift limita `fsGroup` all'intervallo allocato al namespace. Quando utilizzi storage NFS o EFS, devi fornire un valore compreso in quell'intervallo, altrimenti il montaggio del volume fallisce con un errore di permessi.

Leggi l'inizio dell'intervallo dall'annotazione del namespace e usalo come tuo `fsGroup`:

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

L'annotazione contiene un intervallo espresso come valore iniziale e lunghezza. Usa il valore iniziale. Questo è necessario solo per lo storage NFS ed EFS, non per il percorso predefinito basato su PersistentVolumeClaim.

## Route, TLS e cookie

Su OpenShift, DefectDojo Pro viene esposto tramite una Route anziché un Ingress, con terminazione TLS edge e un reindirizzamento da HTTP.

Su ROSA, gli hostname delle Route vengono generati come `<release-name>-<namespace>.apps.<cluster-domain>`, quindi una release `dojopro` nel namespace `dojopro` ottiene `dojopro-dojopro.apps.<cluster-domain>`. Ottieni il dominio apps del cluster con:

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

Un hostname sotto il dominio apps del cluster è coperto dal certificato wildcard predefinito e non richiede alcuna configurazione del certificato. Per qualsiasi altro hostname, fornisci un tuo certificato e aggiungi un CNAME verso l'hostname della Route.

Imposta `dojo.secureCookies` su `false` su OpenShift. Con una Route a terminazione edge, il TLS termina al router e la connessione dal router al pod è in HTTP semplice, quindi i cookie contrassegnati come secure non vengono mai rinviati e l'accesso fallisce. Questo è obbligatorio, non opzionale, ogniqualvolta la Route termina il TLS all'edge.

## Profili di risorse

Sono disponibili tre profili di risorse e ne selezioni uno al momento dell'installazione. `minimal` è per sviluppo, CI e testing. `standard` è per la produzione con carico moderato. `performance` è per la produzione ad alto carico e abilita l'autoscaling.

Imposta il dimensionamento tramite il profilo anziché sovrascrivendo i singoli valori, in modo che il tuo file di configurazione non entri in conflitto con esso.

## Prima di iniziare

Un cluster OpenShift 4.x a cui hai eseguito l'accesso, con `oc`, `helm`, `openssl` e `jq` disponibili in locale.

Un namespace, e il valore della sua annotazione supplemental-groups se utilizzi storage NFS o EFS.

Una StorageClass predefinita che esegue il provisioning di ReadWriteMany, oppure i dettagli di un server NFS.

PostgreSQL 16 per qualsiasi utilizzo oltre alla valutazione. Un PostgreSQL integrato è disponibile per lo sviluppo, ma passa a un database gestito esterno prima di passare in produzione.

Il tuo file di licenza DefectDojo Pro.

L'hostname della Route previsto.

## Accesso di rete in uscita

In un cluster con restrizioni in uscita, consenti il traffico HTTPS in uscita sulla porta 443 verso il container registry che ospita le immagini di DefectDojo Pro. L'hostname del registry si trova nella guida di installazione fornita con la tua licenza. Gli endpoint del registry si trovano dietro load balancer e i loro indirizzi cambiano, quindi consenti l'hostname anziché un indirizzo fisso.

Il cluster deve inoltre poter raggiungere il tuo database sulla porta PostgreSQL.

L'arricchimento sulla exploitability è opzionale e richiede altre due destinazioni via HTTPS sulla porta 443. I punteggi EPSS provengono da `api.first.org`, mentre i dati CISA KEV provengono da `www.cisa.gov`. Entrambi vengono serviti da content delivery network i cui indirizzi cambiano, quindi consenti gli hostname. Senza di essi, DefectDojo funziona normalmente e i riscontri non vengono arricchiti con dati EPSS o KEV.

Se il traffico in uscita passa attraverso un proxy anziché essere diretto, consulta [Eseguire DefectDojo dietro un proxy HTTPS forward](/onprem_deployment/forward_proxy/).

## Il job di inizializzazione deve completarsi per primo

L'installazione esegue un job Kubernetes che applica le migrazioni, crea l'utente admin e carica i dati iniziali. Richiede circa quindici minuti. Finché non si completa, l'utente admin non esiste e non puoi accedere, anche se la Route risponde già.

Osservalo:

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

Il job è completato quando `oc get job` riporta `1/1` completamenti.

Gli altri pod attendono l'initializer tramite un init container. Una volta inizializzato il database, puoi impostare `dojo.skipInitContainer` su `true` per saltare quell'attesa negli aggiornamenti successivi.

## Verifica

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

Quindi apri l'hostname della Route ed esegui l'accesso.

## Risoluzione dei problemi

### Pod rifiutati dai security context constraints

Molto probabilmente il deployment non è stato configurato per OpenShift, quindi è ricaduto sui valori predefiniti che fissano un ID utente che la SCC non consente. Concedere `anyuid` o `privileged` non è la soluzione e non è necessario.

### L'accesso reindirizza di nuovo alla pagina di login

`dojo.secureCookies` è impostato su `true` dietro una Route a terminazione edge. Impostalo su `false` ed esegui l'aggiornamento.

### Errori di permessi nel montaggio del volume su NFS

Il `fsGroup` è al di fuori dell'intervallo consentito per il namespace. Leggi l'annotazione supplemental-groups e usa l'inizio dell'intervallo.

### Errori Multi-Attach, o pod bloccati in ContainerCreating

Il volume è ReadWriteOnce e più di un pod sta tentando di montarlo. Controlla la claim e la classe sottostante:

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

Passa a una classe ReadWriteMany, oppure a uno storage basato su NFS.

### Avvisi relativi al certificato nel browser

Il TLS predefinito della Route utilizza il certificato wildcard del cluster, che copre solo i nomi sotto il dominio apps del cluster. Per qualsiasi altro hostname, fornisci un tuo certificato.

### Lettura dei log

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

Per un output più dettagliato, sia `config.logLevel` che `celery.logLevel` accettano `DEBUG`.

## Aggiornamento

Gli aggiornamenti seguono la procedura standard. Consulta [Aggiornamento di DefectDojo Pro (On-Premise)](/get_started/pro/onprem/upgrading/).

## Domande o supporto

Per assistenza con un deployment su OpenShift, contatta il tuo referente commerciale o [support@defectdojo.com](mailto:support@defectdojo.com).
