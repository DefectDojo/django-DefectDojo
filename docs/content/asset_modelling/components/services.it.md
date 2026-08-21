---
title: Servizi
description: Monitoraggio dei Microservizi
weight: 1
---

## Cos'è un Servizio?

I Servizi (abbreviazione di Microservizi) sono una funzionalità opzionale all'interno degli Asset che fornisce un contesto aggiuntivo su dove hanno origine i Riscontri all'interno di un Asset. Aiutano a isolare i Riscontri a un particolare componente di un Asset, anziché all'intero Asset nel suo complesso, offrendo chiarezza e precisione di reporting in ambienti con architetture complesse.

I Servizi sono utili quando è necessario segmentare ulteriormente i risultati provenienti da un Test, oppure se si prevede di avere più istanze dello stesso Riscontro all'interno di una pipeline di Reimportazione che non si desidera deduplicare. Alcuni strumenti di scansione potrebbero creare Riscontri separati per ciascuna posizione di file e, se si preferisce mantenere queste istanze di un Riscontro come Riscontri separati, i servizi possono essere un modo utile per etichettare queste diverse posizioni.

## Servizi in Pro

I Servizi sono disponibili nella versione Pro, ma sono in gran parte superati dalla possibilità di stabilire relazioni padre-figlio tra gli Asset. I Servizi ottengono lo stesso risultato e possono comunque essere utili quando ristrutturare gli Asset non è fattibile, oppure quando è necessario un ambito di deduplicazione a livello di scansione senza alterare la gerarchia degli Asset, ma eliminano il contesto. Ad esempio, la criticità di business, il fatturato e il personale possono essere attribuiti agli Asset ma non ai Servizi. Per questo motivo, i Servizi sono utili principalmente nel contesto di DefectDojo OS.

## Come specifico un Servizio?

L'opzione per specificare un Servizio è disponibile nei moduli di importazione o reimportazione della scansione, all'interno del menu a tendina dei Campi opzionali. Da quel momento, la deduplicazione viene applicata ai Test che condividono lo stesso valore di Servizio.

È importante notare che i Servizi distinguono tra maiuscole e minuscole. Se il Servizio dell'importazione iniziale è stato identificato come “Service 1” (S maiuscola) e si reimporta una scansione che ha risolto tutti i problemi precedenti ma si identifica il Servizio come “service 1” (s minuscola), la deduplicazione non verrà applicata al Servizio previsto.

## Come funzionano i Servizi?

I Servizi funzionano consentendo di specificare a quali Test precedenti si applicheranno le regole di deduplicazione al momento della Reimportazione.

Se, ad esempio, si importa una scansione e si imposta il Servizio come “Service 1,” per poi reimportare una seconda scansione impostando il Servizio come “Service 2,” la deduplicazione non verrà applicata tra queste due scansioni perché il Servizio è diverso.

Eventuali reimportazioni successive dedupleranno i risultati precedenti della prima scansione solo se il Servizio è stato impostato come “Service 1,” e dedupleranno i risultati precedenti della seconda scansione solo se il Servizio è stato impostato come “Service 2.” In sostanza, se il Servizio è diverso tra due versioni di una scansione reimportata, queste verranno trattate come Riscontri diversi, anche se le scansioni stesse sono identiche.

In questo esempio, se, al momento della reimportazione, il Servizio non viene impostato né come Service 1 né come Service 2, e viene invece lasciato vuoto, la deduplicazione non verrà applicata né alla prima né alla seconda scansione, e verranno chiusi solo i Riscontri privi di Servizio.

## Come dovrebbero essere utilizzati i Servizi?

In pratica, i Servizi sono più utili quando:

* Un singolo Asset contiene più componenti distribuiti in modo indipendente.
* Team diversi possiedono parti diverse dello stesso Asset.
* I test di sicurezza vengono eseguiti su singoli servizi (ad esempio, la scansione di una API o di un microservizio specifico).
