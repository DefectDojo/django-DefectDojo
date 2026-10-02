---
title: Utilizzo del generatore di report
description: Creare, eseguire e recuperare un report personalizzato in DefectDojo
  open source
draft: false
audience: opensource
weight: 24
slug: using-the-report-builder
aliases:
- /it/en/share_your_findings/pro_reports/working_with_generated_reports
- /it/metrics_reports/reports/working_with_generated_reports
---

Il generatore di report di DefectDojo consente di assemblare un report personalizzato a partire da un insieme di widget di contenuto, di eseguirlo e di esportarne il risultato (ad esempio stampandolo in PDF). I report personalizzati possono riepilogare i Riscontri o gli Endpoint che si desidera condividere con un pubblico esterno e possono includere elementi di branding e testo standard.

> **Nota:** in DefectDojo open source, si crea un report, lo si esegue e se ne recupera l'output come attività da svolgere una tantum. I layout dei report (i template) e l'output del report generato **non vengono salvati** nella versione open source. Per riutilizzare un layout, è necessario ricrearlo nel generatore di report. Per salvare Temi, Blocchi e Template riutilizzabili e per mantenere una cronologia persistente dei report generati, vedere il [Generatore di report](../report-builder/) di DefectDojo Pro.

## Apertura del generatore di report

Il generatore di report può essere aperto dalla pagina **📄 Reports** nella barra laterale.

![immagine](images/Using_the_Report_Builder.png)

La pagina del generatore di report è organizzata in due colonne. Nella colonna sinistra **Report Format** si progetta il report, utilizzando i widget della colonna destra **Available Widgets**.

![immagine](images/Using_the_Report_Builder_2.png)

## Passaggio 1: configurare le opzioni del report

![immagine](images/Using_the_Report_Builder_3.png)

Nella sezione Report Options è possibile eseguire le seguenti azioni:

* Impostare un **Report Name** per il report
* Includere nel report le **Finding Notes** create dagli utenti
* Includere nel report le **Finding Images**
* Caricare un'**Image** di intestazione per il report

### Selezionare un'immagine di intestazione per il report

Per aggiungere un'immagine nella parte superiore del report, fare clic sul pulsante **Choose File** e caricare un'immagine in DefectDojo.

L'immagine verrà ridimensionata automaticamente per adattarsi al documento e verrà visualizzata direttamente sopra il **Report Name**.

![immagine](images/Using_the_Report_Builder_4.png)

## Passaggio 2: aggiungere contenuti con i widget

Una volta impostate le opzioni del report, è possibile iniziare a progettarlo utilizzando i widget di DefectDojo.

I widget sono elementi di contenuto di un report che si aggiungono trascinandoli e rilasciandoli nella colonna **Report Format**. Il report finale viene generato in base alla posizione di ciascun widget, con il **Report Name** e l'**Header Image** visualizzati in alto.

* Gli elementi del report possono essere riordinati trascinando e rilasciando i widget in un nuovo ordine.
* Per rimuovere un widget da un report, fare clic e trascinarlo nuovamente nella colonna di destra.
* I widget possono anche essere compressi facendo clic sull'intestazione grigia, per semplificare la navigazione nel generatore di report.
* Il widget Findings, il widget WYSIWYG e il widget Endpoints possono essere utilizzati ciascuno più di una volta.

Per maggiori informazioni sui widget dei report, vedere l'[indice dei widget di report](./#report-widget-index).

## Passaggio 3: eseguire e visualizzare il report

Una volta completata la creazione del report, è possibile generarlo facendo clic sul pulsante verde **Run** in fondo alla sezione **Report Format**.

DefectDojo genera il report a partire dai widget assemblati. Al termine della generazione, è possibile visualizzare il report HTML risultante nel browser.

![immagine](images/Using_the_Report_Builder_14.png)

Un report generato è un'istantanea puntuale: riflette i dati presenti in DefectDojo nel momento in cui è stato eseguito e non si aggiorna automaticamente al variare dei dati.

## Passaggio 4: esportare il report

I report sono predisposti per essere esportati o stampati facilmente.

Il metodo più semplice è stampare in PDF. Con il report HTML aperto, aprire una finestra di dialogo di **Print** nel browser e impostare **Save to PDF** come **Print Destination**.

![immagine](images/Using_the_Report_Builder_15.png)

## Suggerimenti per la formattazione del report

* Le sezioni WYSIWYG possono essere utilizzate per contestualizzare o riepilogare gli elenchi di riscontri. Si consiglia di utilizzare questo widget nel corso del report, tra i widget Findings o Vulnerable Endpoints.

## Indice dei widget di report

### Widget Cover Page

Il widget Cover Page consente di impostare un titolo, un sottotitolo e metadati aggiuntivi per il report. È possibile avere una sola Cover Page per un determinato report.

![immagine](images/Using_the_Report_Builder_5.png)

### Widget Executive Summary

Il widget Executive Summary ha lo scopo di riepilogare il report a colpo d'occhio. Contiene un titolo (il valore predefinito è Executive Summary) e una casella di testo che può contenere qualsiasi informazione si ritenga necessaria per riepilogare il report.

![immagine](images/Using_the_Report_Builder_6.png)

È inoltre possibile **Include SLAs** nell'executive summary. Per aggiungere immagini, formattazione o qualsiasi elemento oltre al semplice testo, si consiglia di aggiungere un **widget WYSIWYG Content** subito dopo l'executive summary.

* È possibile avere un solo Executive Summary per un determinato report.
* Se il report contiene più configurazioni SLA (ad esempio, se si dispone di riscontri provenienti da Prodotti distinti, ciascuno con i propri standard SLA), ogni configurazione SLA verrà elencata nell'Executive Summary come riga separata.

### Widget Severities

Poiché ogni organizzazione definisce in modo diverso i livelli di gravità, il widget Severities consente di definire i livelli di gravità utilizzati nel report per facilitarne la comprensione.

![immagine](images/Using_the_Report_Builder_7.png)

### Widget Table of Contents

Il widget Table of Contents crea un elenco di ciascun riscontro presente nel report, per un accesso più rapido a riscontri specifici. Il sommario crea un'intestazione separata per ciascuna gravità presente nel report. Ogni riscontro elencato nel sommario ha un collegamento di ancoraggio associato per passare rapidamente al riscontro corrispondente nel report.

![immagine](images/Using_the_Report_Builder_8.png)

* È possibile aggiungere una sezione di **Custom Content**, che inserirà del testo sotto l'intestazione.
* È possibile caricare un'immagine nel Table of Contents facendo clic sul pulsante **Choose File** accanto alla riga **Image**. L'immagine caricata verrà visualizzata direttamente sopra l'intestazione selezionata. Le immagini verranno ridimensionate per adattarsi al documento.

### Widget WYSIWYG Content

Il widget WYSIWYG (What You See Is What You Get) può essere utilizzato per aggiungere al report una sezione contenente testo e immagini. È possibile aggiungere più copie di questo widget per fornire contesto ad altre sezioni del report.

![immagine](images/Using_the_Report_Builder_9.png)

* Il contenuto WYSIWYG può includere un titolo facoltativo.
* È possibile aggiungere immagini a un widget WYSIWYG trascinandole e rilasciandole direttamente nella casella **Content**. Le immagini inserite nella casella Content verranno visualizzate alla loro risoluzione originale.
* È possibile aggiungere più widget WYSIWYG a un report.

### Widget Findings

Il widget Findings fornisce un elenco e un riepilogo di ciascun riscontro che si desidera includere nel report. È possibile definire l'ambito dei riscontri da includere tramite i filtri.

Il widget Findings è suddiviso in due sezioni. La sezione superiore contiene un elenco di filtri utilizzabili per determinare quali riscontri includere, mentre la sezione inferiore contiene l'elenco dei riscontri risultante dopo l'applicazione dei filtri.

Per applicare i filtri al widget Findings, impostare i parametri di filtro e fare clic sul pulsante **Apply Filter** in basso. È possibile visualizzare in anteprima i risultati del filtro controllando l'elenco dei riscontri situato sotto la sezione Filters.

![immagine](images/Using_the_Report_Builder_10.png)

* Come per i widget, la sezione Filters può essere espansa e compressa facendo clic sull'intestazione grigia Filters.
* È possibile aggiungere al report più widget Findings separati con parametri di filtro diversi, se si desidera che il report contenga più di un elenco di riscontri.
* Nei suddetti elenchi vengono inclusi solo i riscontri che si è autorizzati a visualizzare, in base al controllo degli accessi basato sui ruoli.

#### Esempio di elenco riscontri renderizzato

![immagine](images/Using_the_Report_Builder_11.png)

### Widget Vulnerable Endpoints

Il widget Vulnerable Endpoints è simile al widget Findings. È possibile utilizzare questo widget per elencare tutti i riscontri relativi a Endpoint specifici e ordinare l'elenco dei riscontri per Endpoint anziché per livello di gravità.

Il widget **Vulnerable Endpoints** elenca ciascun riscontro attivo per gli Endpoint selezionati. Anziché creare un unico elenco di riscontri non ordinati, questa funzionalità li suddivide in base al relativo contesto di Endpoint.

Come per il widget Findings, il widget Vulnerable Endpoints è suddiviso in una sezione Filter e in un elenco di Endpoint risultanti dai parametri di filtro.

![immagine](images/Using_the_Report_Builder_12.png)

Selezionare qui i parametri per gli Endpoint che si desidera includere e fare clic sul pulsante **Apply Findings** in basso. È possibile visualizzare in anteprima i risultati del filtro controllando l'elenco degli Endpoint situato sotto la sezione Filters.

* È possibile aggiungere al report più widget Vulnerable Endpoints separati con parametri di filtro diversi, se si desidera che il report contenga più di un elenco.
* Nei suddetti elenchi vengono inclusi solo i riscontri che si è autorizzati a visualizzare, in base al controllo degli accessi basato sui ruoli.

### Widget ---- (separatore)

Questo widget visualizza una linea orizzontale grigio chiaro per dividere le sezioni.

![immagine](images/Using_the_Report_Builder_13.png)
