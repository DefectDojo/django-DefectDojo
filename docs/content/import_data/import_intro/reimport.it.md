---
title: Reimport
description: Scopri come importare i dati manualmente, tramite API o tramite un connettore
weight: 2
aliases:
- /it/en/connecting_your_tools/import_scan_files/using_reimport
---

Quando un Test viene creato in DefectDojo (sia in anticipo, sia importando un file di scansione), il Test può essere esteso con nuovi dati di Riscontro.

Ad esempio, supponiamo che tu abbia una pipeline CI/CD progettata per inviare un nuovo report a DefectDojo ogni giorno. Invece di creare un nuovo Test o Engagement per ogni 'esecuzione' della pipeline, potresti far confluire ogni report nello stesso Test utilizzando **Reimport**.

## Reimport: riepilogo del processo

Il Reimport dei dati non sostituisce alcun dato precedente nel Test; al contrario, confronta il file di scansione in arrivo con i dati di scansione esistenti in un test per prendere decisioni informate:

* In base all'ultimo file, quali vulnerabilità sono ancora presenti?
* Quali vulnerabilità non sono più presenti?
* Quali vulnerabilità erano state precedentemente risolte, ma sono state reintrodotte?

Il Test tiene traccia e separa ogni versione di scansione tramite la **Cronologia di importazione**, in modo da poter verificare nel tempo le variazioni dei Riscontri nel tuo Test.

![image](images/using_reimport.png)

## Logica del Reimport: crea, ignora, chiudi o riapri

Quando si utilizza Reimport, DefectDojo confronterà i dati di scansione in arrivo con quelli esistenti, per poi applicare le modifiche ai Riscontri contenuti nel tuo Test come segue:

### Creazione dei Riscontri

Qualsiasi vulnerabilità non contenuta nell'importazione precedente verrà aggiunta automaticamente al Test come nuovo Riscontro.

### Ignora i Riscontri esistenti

Se un Riscontro in arrivo corrisponde a un Riscontro già esistente, il Riscontro in arrivo verrà scartato anziché essere registrato come Duplicato. Questi Riscontri sono già stati registrati - non è necessario aggiungere un nuovo oggetto Riscontro. La pagina del Test mostrerà questi Riscontri come **Left Untouched** (non modificati).

### Campi fix_available e fix_version

Se un Riscontro in arrivo corrisponde a un Riscontro già esistente, il Riscontro in arrivo viene controllato per verificare se i campi `fix_available` e `fix_version` differiscono, e vengono aggiornati in caso affermativo. Questi Riscontri sono già stati registrati - non è necessario aggiungere un nuovo oggetto Riscontro. La pagina del Test mostrerà questi Riscontri come **Left Untouched** (non modificati).

### Chiusura dei Riscontri

Se esistono Riscontri già presenti nel Test ma non presenti nel report in arrivo, puoi scegliere di impostare automaticamente quei Riscontri su Inattivo e Mitigato (partendo dal presupposto che quelle vulnerabilità siano state risolte dopo l'importazione precedente). La pagina del Test mostrerà questi Riscontri come **Closed** (chiusi).

Se **non** vuoi che i vecchi Riscontri vengano chiusi, puoi disabilitare questo comportamento su Reimport:

* Deseleziona la casella **Close Old Findings** se utilizzi l'interfaccia utente
* Imposta `close_old_findings` su `False` se utilizzi l'API (su questo endpoint, `close_old_findings` è `True` per impostazione predefinita)

**Nota sull'ambito:** a differenza di Import, Reimport non può mai considerare altri Test all'interno dell'Engagement quando valuta i Riscontri da chiudere. L'ambito di chiusura dei Riscontri è sempre limitato al Test di destinazione.

La funzionalità `close_old_findings` rispetterà anche il campo `service`: solo i Riscontri con un valore `service` identico (o nessun valore `service`, se non ne è stato specificato uno) verranno presi in considerazione per la chiusura.

### Riapertura dei Riscontri

* Se un Riscontro Chiuso ricompare in un Reimport, verrà automaticamente riaperto. Si presume che quella vulnerabilità si sia ripresentata, nonostante la mitigazione precedente. La pagina del Test terrà traccia di questi Riscontri come **Reactivated** (riattivati).

Se stai utilizzando uno scanner senza triage, o se comunque non vuoi che i Riscontri Chiusi vengano riattivati, puoi disabilitare questo comportamento su Reimport:

* Imposta **do_not_reactivate** su **True** se utilizzi l'API
* Seleziona la casella **Do Not Reactivate** se utilizzi l'interfaccia utente

### Comportamento di Force Active e Force Verified

Impostare `active=true` (interfaccia utente: **Force Active**) o `verified=true` (interfaccia utente: **Force Verified**) su un Reimport imposterà lo stato corrispondente su ogni Riscontro corrispondente, **inclusi i Riscontri che altrimenti sarebbero Inattivi perché Mitigati**. Si tratta dello stesso comportamento di riattivazione descritto sopra, reso semplicemente esplicito su ogni Riscontro in arrivo.

Force Active e Force Verified **non** sovrascrivono gli stati che rappresentano una decisione esplicita dell'utente o del sistema sul motivo per cui un Riscontro non dovrebbe essere Attivo:

| Status | Does Force Active reactivate it? | Why |
|---|---|---|
| Mitigato / Chiuso | Sì | Stesso comportamento di riattivazione predefinito |
| Rischio accettato | No | Il Riscontro è Inattivo perché un utente ha esplicitamente accettato il rischio; il reimport non deve revocare silenziosamente questa decisione |
| Duplicato | No | Il Riscontro è Inattivo perché la deduplicazione lo ha contrassegnato come duplicato di un altro Riscontro; è il Riscontro originale (non il duplicato) a dover essere attivo |
| Falso positivo | No | Stessa motivazione di Rischio accettato — una decisione di triage esplicita |
| Fuori ambito | No | Stessa motivazione di Rischio accettato — una decisione di triage esplicita |

Se vuoi che un Riscontro con Rischio accettato o Duplicato torni Attivo, devi prima rimuovere l'Accettazione del rischio o il contrassegno di Duplicato. Force Active da solo non lo farà.

## Apertura del modulo di Reimport

Il modulo **Re-Import Findings** è accessibile da qualsiasi pagina Test, nel menu a discesa **⚙️Gear**.

![image](images/using_reimport_2.png)

Il **Modulo** **Re-import Findings** **non** ti permetterà di importare un tipo di scansione diverso, né di cambiare la destinazione dei Riscontri che stai cercando di caricare. Se vuoi fare una di queste cose, dovrai usare il **modulo Import Scan**.

## Utilizzo della Cronologia di importazione

La Cronologia di importazione per un dato test è elencata sotto l'intestazione **Test Overview** nella pagina del **Test**.

Questa tabella mostra ogni Import o Reimport come una singola riga con un **Timestamp**, insieme alle colonne **Branch Tag, Build ID, Commit Hash** e **Version**, se questi sono stati specificati.

![image](images/using_reimport_3.png)

### Azioni

Questa intestazione indica le azioni intraprese da un Import/Reimport.

* **\# created indica il numero di nuovi Riscontri creati al momento dell'Import/Reimport**
* **\# closed mostra il numero di Riscontri che sono stati chiusi da un Reimport (perché non presenti nel report in arrivo).**
* **\# left untouched mostra il conteggio dei Riscontri Aperti che non sono stati modificati da un Reimport (perché presenti anche nel report in arrivo).**
* **\#** **reactivated** mostra tutti i Riscontri Chiusi che sono stati riaperti da un Reimport in arrivo.

## Deduplicazione del Reimport

Reimport decide se un elemento in arrivo corrisponde a un Riscontro esistente utilizzando le impostazioni di **[Deduplicazione del Reimport](/triage_findings/finding_deduplication/about_deduplication/)**. Questo è separato dalla "Deduplicazione dello stesso strumento" e dalla "Deduplicazione tra strumenti diversi", che operano dopo che i Riscontri esistono già.

Se noti che Reimport chiude vecchi Riscontri e ne crea di nuovi quando cambia solo un attributo minore (ad esempio, uno spostamento del numero di riga), ottimizza la **Deduplicazione del Reimport** per quello strumento in modo da usare identificatori stabili che ignorino tali attributi (come Unique ID From Tool).

**DefectDojo Pro** può risolvere questo problema direttamente per gli strumenti privi di ID univoci affidabili: abilitando **[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/)**, Reimport riconosce un Riscontro la cui posizione è cambiata — uno spostamento di riga, una rinomina di file, uno spostamento di URL o un aggiornamento della versione di una dipendenza — come lo *stesso* Riscontro, aggiornandolo sul posto e preservandone la cronologia delle posizioni.

## Reimport tramite API - nota speciale

Nota che l'endpoint API /reimport può sia **estendere un Test esistente** (applicando il metodo descritto in questo articolo), sia **creare un nuovo Test** con nuovi dati - non è necessaria una chiamata iniziale a `/import`, né la creazione preventiva di un Test.

Per saperne di più sulla creazione di una pipeline CI/CD automatizzata utilizzando DefectDojo, consulta la nostra guida [qui](/automation/api/api-v2-docs/).
