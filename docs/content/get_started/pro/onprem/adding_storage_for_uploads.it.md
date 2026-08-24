---
title: Aggiungere spazio di archiviazione per i file caricati
description: Espandi lo spazio di archiviazione disponibile per i file caricati in
  un deployment Docker Compose senza modificare il deployment stesso
draft: false
weight: 11
audience: pro
---

I file caricati risiedono nella directory media sull'host, e in un deployment Docker Compose lo spazio disponibile per essi corrisponde a quanto rimane sul disco della VM. Caricamenti di grandi dimensioni come gli SBOM possono riempire quel disco. Questa pagina illustra come espandere lo spazio senza modificare il deployment stesso.

## Perché questo funziona a livello di sistema operativo

Il deployment Docker Compose monta in bind la directory media dell'host nei container che ne hanno bisogno, sia i container dell'applicazione sia l'nginx che restituisce agli utenti i file caricati. I container leggono e scrivono su un percorso dell'host, quindi qualunque filesystem sia montato su quel percorso è ciò che utilizzano. Montare lì maggiore capacità è trasparente per l'applicazione.

Ecco perché l'approccio qui descritto è una modifica a livello di sistema operativo piuttosto che una modifica al deployment. Mantenere invariato il file Compose fornito con la tua release mantiene la tua installazione coerente con gli altri deployment on-premise, ed evita di perdere la modifica quando un aggiornamento sostituisce quel file.

## Storage a blocchi, l'opzione più semplice

Montare un dispositivo a blocchi aggiuntivo è il modo consueto di gestire un disco pieno su Linux, ed è l'opzione da considerare per prima. Funziona un volume NAS o SAN, così come lo storage a blocchi di un cloud provider, come un volume Amazon EBS.

Separare lo storage dell'applicazione dal disco del sistema operativo è in generale una buona pratica, quindi hai due scelte ragionevoli. Monta il dispositivo sulla directory media per dare ai caricamenti una propria capacità, oppure montalo un livello più in alto, sulla directory di deployment, in modo che tutti i dati dell'applicazione risiedano su un filesystem separato dalla VM.

## Storage a oggetti, con alcune avvertenze

Utilizzare uno storage a oggetti come Amazon S3 per i caricamenti è fattibile e rimuove del tutto il limite di capacità, ma è una soluzione meno naturale rispetto a un dispositivo a blocchi. Prima di sceglierlo, considera quanto segue.

Lo storage a oggetti non è un filesystem. S3 non supporta scritture casuali, l'aggiunta di dati a un file esistente o il blocco dei file (file locking). Un livello FUSE copre queste lacune, ma emula semantiche che lo storage sottostante non possiede.

La latenza è superiore rispetto a un dispositivo a blocchi. Questo influisce sui caricamenti e, poiché nginx serve i file caricati dalla stessa directory, influisce anche sui download.

Aggiunge dipendenze di rete. A seconda della posizione della VM nella tua rete, raggiungere il bucket potrebbe richiedere un ulteriore attraversamento della rete, e quel percorso deve ora essere disponibile affinché i caricamenti funzionino.

I riavvii richiedono attenzione. Il bucket deve essere montato all'avvio, il che introduce una relazione temporale tra il completamento del mount e l'avvio di DefectDojo. A seconda della latenza, questo può causare un riavvio bloccato o un avvio con il mount non ancora pronto.

I permessi devono essere allineati. I permessi IAM del bucket devono conciliarsi con i permessi del filesystem di cui l'applicazione ha bisogno per scrivere i caricamenti.

### Strumenti per montare lo storage a oggetti

Tre strumenti sono comunemente utilizzati per montare S3 come filesystem su Linux.

`rclone mount` è stabile, attivamente mantenuto, e offre modalità di caching del filesystem virtuale che gestiscono bene il buffering in lettura e scrittura. Dei tre, è quello che consiglieremmo se scegli questa strada.

`goofys` è ottimizzato per la velocità. Ci riesce eseguendo la creazione e la scrittura dei file in modo asincrono e ignorando le operazioni che S3 non supporta nativamente, come le scritture casuali e il blocco dei file.

`s3fs-fuse` è il più compatibile con POSIX dei tre, supportando funzionalità come la modifica di proprietario e permessi, ma imitare un filesystem reale lo rende notevolmente più lento di goofys.

## Spostare la directory media su un nuovo filesystem

Questo richiede un periodo di inattività, poiché l'applicazione non deve scrivere caricamenti mentre questi vengono copiati.

1. Interrompi DefectDojo con `dojo-compose-cli app stop`, in modo che nulla cambi sotto di te durante lo spostamento.
2. Rinomina la directory media esistente per conservarla come punto di rollback, ad esempio spostando `media` in `old-media` all'interno della tua directory di deployment.
3. Crea una directory vuota nel percorso media originale, che fungerà da punto di mount.
4. Collega il nuovo filesystem. I dettagli dipendono da cosa hai scelto sopra, ma si riducono a tre cose: rendere lo storage disponibile a Linux, il che per lo storage a oggetti significa creare il bucket e i relativi permessi; montarlo nel percorso media; e fare in modo che il mount sopravviva a un riavvio, di solito con una voce in `/etc/fstab` o l'equivalente per il tuo strumento.
5. Copia i contenuti precedenti, preservando proprietario e permessi. `rsync -Pav` dalla vecchia directory alla nuova fa questo e riporta l'avanzamento, il che è utile quando c'è molto da spostare.
6. Conferma che i file siano arrivati. Per lo storage a oggetti, controllare il bucket nella console del tuo provider è il modo più rapido per essere sicuri che il mount stia effettivamente scrivendo dove pensi.
7. Avvia DefectDojo con `dojo-compose-cli app start` e carica un file di prova. Se il caricamento fallisce, i log del container indicheranno il motivo, e i permessi sono la causa più comune.

Conserva la vecchia directory finché il caricamento di prova non ha successo e non hai confermato che i file migrati da essa sono leggibili nell'interfaccia utente. È la tua via di ritorno nel caso in cui il nuovo filesystem non si comporti correttamente.

## Ambito del supporto

Queste sono raccomandazioni generali. Aggiungere spazio di archiviazione a una VM è un compito che riguarda il sistema operativo, e i dettagli specifici del metodo scelto, in particolare uno storage a oggetti montato tramite FUSE, esulano dall'ambito del supporto on-premise. L'approccio è deliberatamente impostato per mantenere il tuo deployment coerente con ogni altra installazione on-premise, lasciando invariato il file Compose che forniamo e risolvendo il problema di capacità al livello del sistema operativo, dove appartiene.

Se stai valutando le opzioni per il tuo ambiente, contatta [support@defectdojo.com](mailto:support@defectdojo.com) e potremo discutere insieme i compromessi prima che tu ti impegni con una scelta.
