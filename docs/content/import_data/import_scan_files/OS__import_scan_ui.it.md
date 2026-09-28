---
title: Modulo Import Scan
description: ''
weight: 1
audience: opensource
---

Una volta impostata la vostra Gerarchia dei Prodotti con almeno un Tipo di Prodotto, un Prodotto, un Test e un Engagement, potete importare un file di scansione in DefectDojo e creare i Riscontri.

È facile riorganizzare la vostra Gerarchia dei Prodotti in DefectDojo, quindi va bene se non siete ancora sicuri di come impostare le cose. 

Per ora, è utile sapere che gli **Engagement** possono contenere dati provenienti da più strumenti, il che può essere utile se state eseguendo più strumenti contemporaneamente come parte di un'unica attività di test.

## Accesso al modulo Import Scan (UI classica / Open Source)

In DefectDojo OS, potete accedere a questo modulo da due posizioni:

* La sezione Test di un Engagement:
    ![image](images/import_scan_os.png)
* La sezione Riscontri della barra di navigazione su un Prodotto:
    ![image](images/import_scan_os_2.png)

## Compilazione del modulo Import Scan

![image](images/import_scan_ui.png)
Il modulo Import Scan creerà un nuovo Test annidato all'interno di un Engagement, che conterrà un Riscontro unico per ogni vulnerabilità contenuta nel vostro file di scansione.

Il Test verrà creato con un nome corrispondente allo Scan Type: ad esempio, una scansione Tenable si chiamerà ‘Tenable Scan’.

### Opzioni del modulo

* **Scan File:** facendo clic sul pulsante Choose, potete selezionare un file dal vostro computer da caricare.
* **Scan Date (opzionale):** se volete selezionare una singola Data di scansione da applicare a tutti i Riscontri risultanti da questa importazione, potete selezionare la data in questo campo.   
Se non selezionate una Data di scansione, i Riscontri creati da questo report utilizzeranno la data specificata dallo strumento. Gli SLA di ciascun Riscontro verranno calcolati in base alla loro data.
* **Scan Type:** selezionate lo strumento utilizzato per creare questi dati.
* **Environment:** selezionate un Environment corrispondente ai dati che state caricando.
* **Tags:** se volete usare i tag per organizzare ulteriormente i dati del Test, potete aggiungere Tag utilizzando questo modulo. Digitate il nome del tag che volete creare e premete Invio sulla tastiera per aggiungerlo all'elenco dei tag.

### Campi opzionali

* **Minimum Severity**: se volete creare Riscontri solo per un particolare livello di Gravità e superiori, potete selezionare qui il livello minimo di Gravità. Tutte le vulnerabilità con una gravità inferiore a questo campo verranno ignorate.
* **Active**: se volete impostare tutti i Riscontri in arrivo come Attivi o Inattivi, potete specificarlo qui. In caso contrario, DefectDojo utilizzerà i dati sulla vulnerabilità dello strumento per determinare se il Riscontro è Attivo o Inattivo. Questa opzione è rilevante se il vostro team deve eseguire manualmente il triage e la verifica dei Riscontri provenienti da un determinato strumento.
* **Verified**: come per Active, potete impostare il nuovo gruppo di Riscontri come Verificati o Non verificati per impostazione predefinita. Questo dipende dalle preferenze del vostro flusso di lavoro. Ad esempio, se il vostro team preferisce presumere che i Riscontri siano verificati salvo prova contraria, potete impostare questo campo su True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** possono tutti essere specificati se volete includere questi dettagli nel Test.
* **Source Code Management URI** può essere specificato anche questo. Questa opzione del modulo deve essere un URI valido.
* **Group By:** se volete creare Gruppi di Riscontri a partire da questo File, potete specificare qui il metodo di raggruppamento.

### Scanner senza triage: il campo Do Not Reactivate

Alcuni scanner potrebbero non includere informazioni di triage nei loro report (ad es. tfsec). Si limitano a scansionare codice o dipendenze, segnalare problemi e restituire tutto, indipendentemente dal fatto che una vulnerabilità sia già stata sottoposta a triage o meno.

Per gestire questo caso, DefectDojo include anche una casella di controllo "Do not reactivate" nel caricamento dei report (anche nell'API di reimportazione), in modo da poter usare DefectDojo come fonte di verità per il triage, invece di riattivare i vostri Riscontri sottoposti a triage a ogni importazione / reimportazione.

### Uso del campo Scan Completion Date (API: `scan_date`)

DefectDojo offre una moltitudine di report di scanner supportati, ma non tutti contengono le
informazioni più importanti per un utente. Il campo `scan_date` è una funzionalità intelligente e flessibile che
consente agli utenti di impostare la data di completamento di un dato report di scansione, e di farla propagare
a tutti i riscontri importati. Questo campo **non** è obbligatorio, ma il valore predefinito per
questo campo è la data di importazione (nel momento in cui la richiesta viene elaborata e viene restituita una risposta positiva).

Ecco i seguenti casi d'uso per l'utilizzo di questo campo:

1. Il report **non** imposta la data, e `scan_date` **non** viene impostato all'importazione
    - La data del Riscontro sarà il valore predefinito di `scan_date`
2. Il report **imposta** la data, e `scan_date` **non** viene impostato all'importazione
    - La data del Riscontro sarà quella impostata dal report
3. Il report **non** imposta la data, e `scan_date` **viene impostato** all'importazione
    - La data del Riscontro sarà quella impostata dall'utente per `scan_date`
4. Il report **imposta** la data, e `scan_date` **viene impostato** all'importazione
    - La data del Riscontro sarà quella impostata dall'utente per `scan_date`
