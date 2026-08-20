---
title: Self-hosting di DefectDojo Pro
date: 2021-02-02 20:46:29+01:00
weight: 5
audience: pro
---

DefectDojo Pro può essere ospitato interamente in autonomia (self-hosted) nel proprio ambiente, offrendo il controllo completo su infrastruttura, dati e postura di sicurezza. È adatto a organizzazioni con requisiti di conformità, residenza dei dati o sicurezza interna che escludono una distribuzione ospitata nel cloud, e offre le stesse funzionalità del prodotto ospitato nel cloud.

Questa pagina descrive i modelli di distribuzione disponibili, cosa è necessario prima di iniziare e come si colloca il resto di questa sezione.

## Due modelli di distribuzione

**Docker Compose su un singolo host** è il più semplice dei due. L'applicazione, i worker asincroni e la cache vengono eseguiti tutti su una sola macchina, gestita da uno strumento a riga di comando fornito da noi. Poiché nulla in questa configurazione scala orizzontalmente, l'host deve essere dimensionato per il picco anziché per la media, e per la maggior parte delle implementazioni il picco si verifica quando arriva una grande importazione di scansione mentre le persone stanno lavorando nell'interfaccia utente.

**Kubernetes, tramite il nostro chart Helm**, esegue questi stessi componenti come workload separati. Questo consente di dimensionare per lo stato stazionario e aggiungere repliche quando arriva il carico, e permette di scalare la parte effettivamente occupata invece dell'intera macchina.

Entrambi i modelli utilizzano PostgreSQL. Per la produzione consigliamo un database gestito esterno, che è quanto il chart Helm presuppone per impostazione predefinita. Gli strumenti di Compose possono anche eseguire PostgreSQL in un container accanto all'applicazione, il che è comodo per la valutazione ma non è ciò che si desidera per i dati di produzione.

Se si utilizza già Kubernetes, conviene usarlo. Un singolo host funziona perfettamente bene, e molte implementazioni funzionano in questo modo, ma si finisce per acquistare un margine di manovra che non si può riallocare. Se non si utilizza Kubernetes e non lo si desidera, Compose è una scelta legittima e non un compromesso.

## Prima di iniziare

Dimensionare prima l'implementazione. Entrambi i modelli dipendono dalla conoscenza approssimativa del numero di riscontri che si prevede di conservare e del numero di persone che lavoreranno contemporaneamente nel prodotto, e questi due numeri determinano parti diverse dell'implementazione. Le indicazioni sul dimensionamento dell'hardware in questa sezione coprono entrambi gli aspetti.

Sarà necessario un file di licenza e gli strumenti di distribuzione per il modello scelto. DefectDojo fornisce entrambi all'inizio dell'abbonamento. Se non si dispone di questi elementi, o se è necessario farli riemettere, contattare il proprio referente commerciale o [support@defectdojo.com](mailto:support@defectdojo.com).

Sarà inoltre necessario un luogo in cui eseguirlo, un database PostgreSQL raggiungibile e un hostname che risolva verso l'implementazione. Le singole pagine di installazione trattano i dettagli specifici per ciascun modello.

## Cos'altro contiene questa sezione

Le pagine accanto a questa coprono il resto del ciclo di vita. Sono presenti indicazioni sul dimensionamento per la scelta dell'hardware, istruzioni per spostare un'istanza open source esistente in un'implementazione Pro self-hosted, e una procedura per l'installazione in ambienti in cui l'host di destinazione non ha accesso a Internet.

Per le implementazioni già in esecuzione, sono presenti pagine sull'aggiornamento, sul backup, sull'innalzamento dei limiti che rifiutano i caricamenti di scansioni di grandi dimensioni, e sull'espansione dello storage per i file caricati quando un host inizia a scarseggiare. Utilizzare la navigazione della sezione per sfogliarle.

## Domande

Se si sta valutando quale dei due modelli scegliere per il proprio ambiente, o se la propria situazione non corrisponde alle ipotesi qui descritte, preferiamo discuterne prima del provisioning piuttosto che dopo.

I clienti esistenti devono contattare il proprio referente commerciale o [support@defectdojo.com](mailto:support@defectdojo.com). Se si sta valutando DefectDojo Pro e si desidera discutere del self-hosting, contattarci all'indirizzo [hello@defectdojo.com](mailto:hello@defectdojo.com).
