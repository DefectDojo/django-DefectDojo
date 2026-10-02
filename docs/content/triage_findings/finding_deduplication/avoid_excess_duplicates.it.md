---
title: Evitare duplicati eccessivi
description: ''
weight: 4
aliases:
- /it/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport
---

Uno dei punti di forza di DefectDojo è che il modello dati può adattarsi a molti casi d'uso e applicazioni diversi. È probabile che l'approccio cambi man mano che si padroneggia il software e si scoprono modi per ottimizzare il proprio flusso di lavoro.

Per impostazione predefinita, DefectDojo non elimina alcun Riscontro duplicato creato. Ogni Riscontro è considerato un'istanza separata di una vulnerabilità. In questo caso, quindi, i **Riscontri duplicati** possono essere un indicatore che è necessario modificare il flusso di lavoro.

## Quando sono accettabili i Riscontri duplicati?

I Riscontri duplicati non sono sempre indicativi di un problema. Ci sono molti casi in cui mantenere i duplicati è l'approccio preferibile. Ad esempio:

* Se il team utilizza e produce report su Engagement interattivi. Se si vuole creare un report distinto su un singolo Test specifico, è utile sapere se esiste un'occorrenza di un Riscontro già individuato in precedenza.
* Se si dispone di Engagement separati per contesto (ad esempio perché riguardano repository diverse), è utile poter segnalare i Riscontri che si presentano in entrambi i luoghi.

## Verifica delle importazioni ridondanti

## Passaggio 1: ripulire i duplicati in eccesso

Fortunatamente, le impostazioni di Deduplicazione di DefectDojo consentono di eliminare in massa i duplicati una volta superata una determinata soglia. Questa funzionalità semplifica il processo di pulizia. Per saperne di più su questo processo, vedere il nostro articolo su **Finding Deduplication** \<\-il link verrà inserito qui.

### Passaggio 2: valutare gli Engagement alla ricerca di ridondanze

Una volta ripuliti i Riscontri duplicati, è buona norma esaminare il Prodotto che li conteneva per verificare se esiste una causa evidente. Si potrebbe scoprire che al suo interno sono presenti Engagement con un contesto ridondante.

#### Engagement duplicati o riutilizzati

Gli Engagement archiviano uno o più Test per un determinato contesto di test. In definitiva, spetta a chi utilizza DefectDojo definire tale contesto, ma se all'interno del Prodotto sono presenti alcuni Engagement che dovrebbero condividere lo stesso contesto, valutare la possibilità di unirli in un unico engagement.
​
### Domande da porsi quando si definisce il contesto di un Engagement:

* Se volessi produrre un report su questo lavoro, l'Engagement conterrebbe tutte le informazioni rilevanti di cui ho bisogno?
* Stiamo creando gli Engagement in anticipo in modo proattivo, oppure vengono creati 'ad\-hoc' dal processo di importazione?
* Stiamo utilizzando il tipo corretto di Engagement \- **Interactive** o **CI/CD**?
* Quale sezione della codebase viene interessata dai test: ogni repository rappresenta un contesto separato, oppure più repository possono costituire un contesto condiviso per i test?
* Chi sono gli stakeholder coinvolti nel Prodotto, e come verranno condivisi i risultati con loro?

### Passaggio 3: verificare la presenza di Test ridondanti

Se si scopre che sono stati creati Test separati che catturano lo stesso contesto di test, questo può essere un indicatore che tali test possono essere consolidati in un'unica Reimportazione.

DefectDojo dispone di due metodi per importare i dati di test e creare Riscontri: **Import** e **Reimport**. Questi due metodi sono molto simili, ma la differenza fondamentale è che **Import** crea sempre un nuovo Test, mentre **Reimport** può aggiungere nuovi dati a un Test esistente. Vale anche la pena notare che **Reimport** non crea Riscontri duplicati all'interno di quel Test.

Ogni volta che si importano nuovi report di vulnerabilità in DefectDojo, tali report vengono archiviati in un oggetto Test. Un oggetto Test può essere creato in anticipo da un utente per contenere un futuro **Import**. Se un utente desidera importare dati senza specificare una destinazione Test, verrà creato un nuovo Test per archiviare il report in arrivo.

I Test sono oggetti flessibili e, sebbene possano contenere un solo *tipo* di report, possono gestire più istanze dello stesso report tramite il metodo **Reimport**. Per saperne di più su Reimport, vedere il nostro **[articolo](/import_data/import_intro/reimport/)** su questo argomento.


## Utilizzare Reimport per Test continuativi

Se si dispone di una pipeline CI/CD, di un processo di scansione giornaliero o di qualsiasi altro tipo di report ricorrente in arrivo, impostare in anticipo un processo di Reimport è fondamentale per evitare duplicati eccessivi. Reimport riunisce il contesto e i Riscontri associati a un test ricorrente in un'unica pagina Test, dove è possibile consultare la cronologia delle importazioni e monitorare le variazioni delle vulnerabilità tra le varie scansioni.

1. Creare un Engagement per archiviare i risultati CI/CD relativi all'oggetto su cui viene eseguito il CI/CD. Potrebbe trattarsi di un repository di codice su cui sono configurate azioni CI/CD. In generale, è preferibile impostare un Engagement separato per ogni pipeline, in modo da poter capire rapidamente da dove provengono i risultati dei Riscontri.
​
2. Ogni azione CI/CD importerà i dati in DefectDojo in un passaggio separato, quindi ciascuna di esse dovrebbe essere mappata su un Test separato. Ad esempio, se ogni esecuzione della pipeline avvia un NPM\-audit oltre a una scansione delle dipendenze, ogni risultato di scansione dovrà confluire in un Test (annidato sotto l'Engagement).
​
3. Non è necessario creare un nuovo Test ogni volta che viene eseguita l'azione CI/CD. È invece possibile **Reimportare** i dati nella stessa posizione di test.

### Reimport in azione

DefectDojo confronterà i dati di scansione in arrivo con quelli già esistenti, quindi applicherà le modifiche ai Riscontri contenuti nel Test nel modo seguente:
​
#### Creazione dei Riscontri

Tutte le vulnerabilità non presenti nell'importazione precedente verranno aggiunte automaticamente al Test come nuovi Riscontri.
​
#### Ignorare i Riscontri esistenti

Se i Riscontri in arrivo corrispondono a Riscontri già esistenti, quelli in arrivo verranno scartati anziché essere registrati come Duplicati. Questi Riscontri sono già stati registrati \- non è necessario aggiungere un nuovo oggetto Riscontro. La pagina del Test mostrerà questi Riscontri come **Left Untouched**.
​
#### Chiusura dei Riscontri

Se nel Test sono già presenti Riscontri che non compaiono nel report in arrivo, è possibile scegliere di impostare automaticamente tali Riscontri su Inattivo e Mitigato (nel presupposto che quelle vulnerabilità siano state risolte dopo l'importazione precedente). La pagina del Test mostrerà questi Riscontri come **Closed**.

Se non si desidera che alcun Riscontro venga chiuso, è possibile disabilitare questo comportamento su Reimport:

* Deselezionare la casella **Close Old Findings** se si utilizza l'interfaccia utente
* Impostare **close\_old\_findings** su **False** se si utilizza l'API  ​

#### Riapertura dei Riscontri

* Se sono presenti Riscontri chiusi che ricompaiono in una Reimportazione, verranno automaticamente Riaperti. Il presupposto è che tali vulnerabilità si siano ripresentate, nonostante la mitigazione precedente. La pagina del Test terrà traccia di questi Riscontri come **Reactivated**.

Se si utilizza uno scanner privo di triage, o comunque non si desidera che i Riscontri chiusi vengano riattivati, è possibile disabilitare questo comportamento su Reimport:

* Impostare **do\_not\_reactivate** su **True** se si utilizza l'API
* Selezionare la casella **Do Not Reactivate** se si utilizza l'interfaccia utente

### Utilizzare la Import History

La Import History di un determinato test è elencata sotto l'intestazione **Test Overview** nella pagina **Test**.

Questa tabella mostra ogni Import o Reimport come una singola riga con un **Timestamp**, insieme alle colonne **Branch Tag, Build ID, Commit Hash** e **Version**, se specificate.

![image](images/Avoiding_Duplicates_Reimport_Recurring_Tests.png)

### Actions

Questa intestazione indica le azioni eseguite da un Import/Reimport.

* **\# created indica il numero di nuovi Riscontri creati al momento dell'Import/Reimport**
* **\# closed mostra il numero di Riscontri chiusi da una Reimportazione (perché non presenti nel report in arrivo).**
* **\# left untouched mostra il numero di Riscontri aperti rimasti invariati da una Reimportazione (perché presenti anche nel report in arrivo).**
* **\#** **reactivated** mostra eventuali Riscontri chiusi che sono stati riaperti da una Reimportazione in arrivo.

### Perché non usare semplicemente Import?

Sebbene entrambi i metodi siano possibili, Import dovrebbe essere riservato alle **nuove occorrenze** di Riscontri e dati, mentre Reimport dovrebbe essere utilizzato per **ulteriori iterazioni** degli stessi dati.

Se la pipeline CI/CD esegue un Import e crea un nuovo oggetto Test ogni volta, ogni Import produrrà una raccolta di Riscontri distinti che dovranno poi essere gestiti come oggetti separati. Utilizzare Reimport risolve questo problema ed elimina la quantità di 'pulizia' necessaria quando una vulnerabilità viene risolta.

Utilizzare Reimport consente di archiviare ogni report ricorrente sulla stessa pagina, mantenendo una continuità ogni volta che vengono aggiunti nuovi dati al Test.

Tuttavia, se si utilizza lo stesso strumento di scansione in più posizioni o contesti, potrebbe essere più opportuno creare un Test separato per ciascuna posizione o contesto. Questo dipende dal metodo di organizzazione preferito.
