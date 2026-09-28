---
title: Deduplication Tuning
description: Configura il modo in cui DefectDojo identifica e gestisce i riscontri
  duplicati
weight: 4
audience: pro
aliases:
- /it/en/working_with_findings/finding_deduplication/tune_deduplication
---

Deduplication Tuning è una funzionalità di DefectDojo Pro che offre un controllo granulare su come vengono deduplicati i riscontri, consentendo di ottimizzare il rilevamento dei duplicati per il proprio specifico flusso di lavoro di test di sicurezza.

## Deduplication Settings

In DefectDojo Pro, è possibile accedere a Deduplication Tuning tramite:
**Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** nelle istanze che utilizzano ancora il layout di menu precedente)

![immagine](images/deduplication_tuning.png)

La pagina Deduplication Settings offre tre aree di configurazione principali:
- Same Tool Deduplication
- Cross Tool Deduplication
- Reimport Deduplication

## Same Tool Deduplication

Same Tool Deduplication è abilitata per impostazione predefinita per tutti i parser degli strumenti di sicurezza. Questo garantisce che i riscontri provenienti da scansioni consecutive con lo stesso strumento vengano deduplicati correttamente.

Per modificare Same Tool Deduplication:

1. Selezionare uno **Security Tool** specifico dal menu a tendina
2. Scegliere un **Deduplication Algorithm** tra le opzioni disponibili

![immagine](images/same_tool_deduplication.png)

### Algoritmi di deduplicazione disponibili

DefectDojo Pro offre i seguenti metodi di deduplicazione per la deduplicazione all'interno dello stesso strumento:

#### Hash Code
Utilizza una combinazione di campi selezionati per generare un hash univoco. Quando selezionato, comparirà un terzo menu a tendina che mostra i campi utilizzati per calcolare l'hash.

##### Content Fingerprint

**Content Fingerprint** è un campo hash selezionabile (disponibile in tutte e tre le aree di configurazione) che fornisce un'identità *invariante rispetto alla posizione* per i riscontri di analisi statica. Viene derivato dallo snippet di codice vulnerabile che uno strumento include nel riscontro, normalizzato in modo che differenze di indentazione, annotazioni sui numeri di riga e formattazione non lo modifichino. Due riscontri relativi allo stesso codice vulnerabile generano lo stesso hash anche se il codice si è spostato su una riga o un file diverso.

Content Fingerprint viene calcolato per gli strumenti che includono uno snippet di codice nella descrizione del riscontro, tra cui **Bandit**, **Gosec**, **Brakeman**, **Checkmarx One** e qualsiasi strumento la cui descrizione contenga un blocco di codice o uno snippet SARIF.

> **Prima di selezionare Content Fingerprint come campo hash**, popolare i fingerprint per i riscontri esistenti eseguendo `./manage.py backfill_fingerprints`. I riscontri importati dopo l'introduzione della funzionalità ottengono i fingerprint automaticamente, ma i riscontri preesistenti non ne hanno alcuno: selezionare il campo senza eseguire il backfill fa sì che i riscontri esistenti e quelli in arrivo generino hash diversi, interrompendo ogni corrispondenza finché il backfill non viene eseguito.

Content Fingerprint si abbina bene a **CWE** per gli strumenti che incorporano percorsi di file o numeri di riga nei titoli, dove gli altri campi identificativi cambiano ogni volta che il codice si sposta. Vedere [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools).

#### Unique ID From Tool
Sfrutta l'identificatore interno dello strumento di sicurezza per i riscontri, garantendo una deduplicazione perfetta quando lo scanner fornisce ID univoci affidabili.

Questo algoritmo può essere utile quando si lavora con scanner SAST, o in situazioni in cui un riscontro può "spostarsi" nel codice sorgente man mano che lo sviluppo procede.

#### Unique ID From Tool or Hash Code
Tenta innanzitutto di utilizzare l'ID univoco dello strumento, quindi ricorre all'hash code se non è disponibile alcun ID univoco. Questa è l'opzione di deduplicazione più flessibile.

#### Global Component
Fa corrispondere i riscontri in base al nome e alla versione del componente in **tutti i Prodotti** dell'istanza, anziché all'interno di un singolo Prodotto o Engagement. Pensato per gli strumenti SCA in cui la stessa dipendenza vulnerabile compare in molti Prodotti. Questo algoritmo è disattivato per impostazione predefinita e deve essere abilitato dal supporto DefectDojo. Per maggiori dettagli, vedere [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/).

#### Global Vulnerability ID
Fa corrispondere i riscontri in base ai relativi **vulnerability ID** (CVE, GHSA, …) in **tutti i Prodotti** dell'istanza, anziché all'interno di un singolo Prodotto o Engagement. Pensato per gli strumenti che segnalano lo stesso CVE in molti Prodotti. Disattivato per impostazione predefinita e abilitato dal supporto DefectDojo.

> **Due strumenti che utilizzano lo stesso algoritmo a livello di istanza diventano candidati reciproci alla deduplicazione.** Quando due strumenti *diversi* sono entrambi configurati con un algoritmo a livello di istanza (Global Component o Global Vulnerability ID), i loro riscontri condividono un hash di raggruppamento costante, per cui un riscontro proveniente da uno dei due strumenti viene considerato per la deduplicazione rispetto all'altro su quella dimensione condivisa (componente o vulnerability ID). Questo è il comportamento cross-tool previsto: abilitarlo solo quando si desidera che quegli strumenti vengano deduplicati insieme.

### Campi Hash Code basati su insiemi (Vulnerability ID e CWE)

Due attributi dei riscontri contengono un *insieme* di valori anziché un valore singolo: i vulnerability ID (CVE, GHSA, …) e i CWE. Quando si utilizza l'algoritmo **Hash Code** (Same Tool o Cross Tool), è possibile aggiungere i seguenti campi a **Hash Code Fields** per controllare il modo in cui questi insiemi vengono confrontati:

| Field | I riscontri sono duplicati quando… |
|-------|-------------------------------|
| `vulnerability_ids` | hanno **esattamente lo stesso insieme** di vulnerability ID |
| `vulnerability_ids_partial` | condividono **almeno un** vulnerability ID |
| `vulnerability_ids_subset` | i vulnerability ID di un riscontro sono un **sottoinsieme** di quelli dell'altro |
| `cwes` | hanno **esattamente lo stesso insieme** di CWE |
| `cwes_partial` | condividono **almeno un** CWE |
| `cwes_subset` | i CWE di un riscontro sono un **sottoinsieme** di quelli dell'altro |

I campi `_partial` e `_subset` vengono confrontati per ogni coppia di riscontri anziché essere incorporati nell'hash: gli altri Hash Code Fields raggruppano i riscontri candidati, e il confronto tra insiemi restringe poi quel gruppo. (La corrispondenza esatta — `vulnerability_ids` e `cwes` — viene invece incorporata direttamente nell'hash.)

**Valori vuoti.** Se un riscontro non ha vulnerability ID (o CWE) per il matcher configurato:

- Se Hash Code Fields include anche un campo ordinario (ad esempio `title`), è quel campo a fornire l'identità: il matcher per insiemi viene saltato per la coppia e i riscontri possono comunque corrispondere sul resto dell'hash.
- Se un matcher per insiemi è l'**unico** campo, un riscontro senza valori non corrisponde a nulla: non avendo altro elemento identificativo, un insieme vuoto non viene considerato corrispondente a ogni altro riscontro.

**Regole di configurazione** (applicate al salvataggio delle impostazioni):

- Un campo relativo ai vulnerability ID (`vulnerability_ids`, `vulnerability_ids_partial` o `vulnerability_ids_subset`) può essere utilizzato da solo: un CVE o un GHSA identifica un'istanza specifica di vulnerabilità.
- I campi CWE (`cwes`, `cwes_partial`, `cwes_subset`) **non** possono essere l'unico criterio. Un CWE è una *classe* di debolezza, non un'istanza specifica, quindi la corrispondenza basata solo sul CWE unirebbe riscontri non correlati. Abbinare un matcher CWE a un campo identificativo come `title` o `file_path`.

## Cross Tool Deduplication

Cross Tool Deduplication è disattivata per impostazione predefinita, poiché la deduplicazione tra strumenti di sicurezza diversi richiede una configurazione attenta a causa delle variazioni nel modo in cui gli strumenti segnalano le stesse vulnerabilità.

![immagine](images/cross_tool_deduplication.png)

Per abilitare Cross Tool Deduplication:

1. Selezionare uno **Security Tool** dal menu a tendina
2. Cambiare il **Deduplication Algorithm** da "Disabled" a "Hash Code"
3. Selezionare quali campi utilizzare per generare l'hash nel menu a tendina **Hash Code Fields**

Cross Tool Deduplication supporta l'algoritmo Hash Code, adatto alla maggior parte dei flussi di lavoro, poiché strumenti diversi raramente condividono identificatori univoci compatibili. Per gli strumenti SCA che segnalano le stesse dipendenze, è disponibile anche [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/) come opzione cross-tool (disattivata per impostazione predefinita).

Da notare che anche Cross Tool Deduplication è limitata ai singoli Asset.

## Reimport Deduplication

**⚠️ I processi di reimport possono scartare completamente i riscontri prima che vengano registrati. Questo può causare perdita di dati se configurato in modo errato, pertanto le impostazioni di Reimport Deduplication devono essere modificate con cautela.**

Le impostazioni di Reimport Deduplication possono essere utilizzate per impostare un algoritmo per gli Universal Parser o per un Generic Findings Import Parser.

Per impostazione predefinita, Reimport Deduplication non può essere modificata per altri strumenti. Gli utenti che desiderano modificare l'algoritmo di Reimport Deduplication per altri strumenti nella propria istanza dovrebbero contattare il [supporto DefectDojo](mailto:support@defectdojo.com) per assistenza.

![immagine](images/reimport_deduplication.png)

Quando si configura Reimport Deduplication:

1. Selezionare lo **Security Tool** (Universal o Generic Parser)
2. Scegliere il **Deduplication Algorithm** appropriato

Le seguenti opzioni di algoritmo sono disponibili per Reimport Deduplication:
- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Il reimport può scartare completamente i riscontri prima che vengano registrati, pertanto le impostazioni di Reimport Deduplication devono essere modificate con cautela.

### Track Findings as Locations Change

Quando l'algoritmo di Reimport Deduplication di uno strumento è **Hash Code**, compare un ulteriore interruttore: **Track findings as locations change**. Se abilitato, un riscontro la cui posizione è cambiata tra un reimport e l'altro — uno spostamento di riga o una rinomina di file, uno spostamento di URL o un aggiornamento della versione di una dipendenza — viene trattato come lo *stesso* riscontro, anche se lo strumento ne ha ricalcolato la gravità. Un unico riscontro viene mantenuto nella sua posizione e la sua cronologia delle posizioni viene conservata, invece di chiudere il vecchio riscontro e crearne uno nuovo identico.

L'interruttore è disattivato per impostazione predefinita e si applica solo all'algoritmo di reimport Hash Code (gli strumenti con un Unique ID From Tool affidabile tracciano già gli spostamenti tramite i propri ID stabili). Abilitandolo, i riscontri esistenti dello strumento vengono automaticamente ri-sottoposti a hash in background, in modo che i dati storici partecipino immediatamente.

Vedere [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) per informazioni su come funziona la corrispondenza, cosa viene conservato e indicazioni per abilitarla su istanze di grandi dimensioni.

## Esecuzione retroattiva della deduplicazione sui dati esistenti

Una situazione comune quando si attiva per la prima volta Deduplication Tuning è avere un ampio arretrato di riscontri importati *prima* della modifica della configurazione di deduplicazione. In DefectDojo Pro non è necessario eseguire un comando separato per deduplicare questi dati storici: **la modifica delle Deduplication Settings di uno strumento avvia automaticamente un ri-hashing in background di tutti i riscontri esistenti associati a quel tipo di test**.

Cosa significa in pratica:

- Quando si modifica il **Deduplication Algorithm** o gli **Hash Code Fields** di uno strumento, DefectDojo accoda un job in background per ricalcolare gli hash di ogni riscontro di quello strumento già presente nell'istanza.
- Il job viene eseguito in modo asincrono. Su istanze di grandi dimensioni (milioni di riscontri), il completamento può richiedere del tempo e non si vedranno modifiche immediate nella tabella dei riscontri.
- Gli hash appena calcolati si applicano alle decisioni di deduplicazione successive su tutto l'arretrato.

Se si effettuano più modifiche alla configurazione in rapida successione, ognuna accoda il proprio job di ri-hashing. Attendere che il job precedente sia terminato prima di valutare i risultati, specialmente quando si confronta il numero di riscontri prima e dopo la modifica.

> **Nota per Pro self-hosted:** il job in background viene eseguito nel pool di worker Celery. Se i worker sono sotto carico o in coda, il ri-hashing può richiedere più tempo del previsto: controllare lo stato dei worker se i risultati non compaiono entro i tempi attesi per le dimensioni della propria istanza.

> **I feature flag non condizionano una configurazione già esistente.** Le Deduplication Settings salvate per uno strumento restano in vigore finché configurate; disattivare un feature flag correlato **non** riporta retroattivamente quello strumento alla deduplicazione predefinita. Per modificare o interrompere il comportamento di deduplicazione di uno strumento, aggiornare direttamente le sue Deduplication Settings (operazione che accoda anche il ri-hashing in background descritto sopra).

## Best practice per la deduplicazione

Per ottenere risultati ottimali con Deduplication Tuning:

- **Partire dalle impostazioni predefinite**: le impostazioni di deduplicazione preconfigurate funzionano bene nella maggior parte degli scenari
- **Testare le modifiche con attenzione**: dopo aver modificato le impostazioni di deduplicazione, monitorare alcuni import per verificare il comportamento corretto.
- **Pianificare i ri-hashing retroattivi**: la modifica delle impostazioni di deduplicazione ri-sottopone ad hash in background ogni riscontro esistente di quello strumento. Vedere [Esecuzione retroattiva della deduplicazione sui dati esistenti](#running-deduplication-retroactively-on-existing-data) sopra.
- **Usare Hash Code per la deduplicazione cross-tool**: quando si abilita la deduplicazione cross-tool, selezionare campi che identifichino in modo affidabile lo stesso riscontro tra strumenti diversi (come nome della vulnerabilità, posizione e gravità). **IMPORTANTE** Ogni strumento abilitato per la deduplicazione cross-tool **DEVE** avere gli stessi campi selezionati.
- **Mantenere le fonti cross-tool nello stesso Asset**: Cross Tool Deduplication è limitata all'Asset. I riscontri suddivisi tra Asset separati non verranno deduplicati anche con campi hash corrispondenti. Vedere [Cross Tool Deduplication](#cross-tool-deduplication) sopra.
- **Evitare una deduplicazione troppo ampia**: la deduplicazione cross-tool con troppo pochi campi hash può generare falsi duplicati
- **Eseguire il backfill prima di selezionare Content Fingerprint**: eseguire prima `./manage.py backfill_fingerprints`, quindi selezionare il campo, in modo che il ri-hashing avviato abbia già i fingerprint su cui lavorare. Vedere [Content Fingerprint](#content-fingerprint) sopra.
- **Abilitare il tracciamento della posizione tra le scansioni**: il ri-hashing automatico dell'interruttore copre l'intero arretrato dello strumento; su istanze di grandi dimensioni, attendere che finisca prima del prossimo reimport pianificato. Vedere [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades).

Ottimizzando le impostazioni di deduplicazione in base ai propri strumenti specifici, è possibile ridurre significativamente il rumore causato dai duplicati.

## Riscontri bloccati

Ogni volta che le Deduplication Settings vengono modificate per un determinato strumento, gli hash di deduplicazione vengono ricalcolati per quello strumento in tutta l'istanza DefectDojo.
