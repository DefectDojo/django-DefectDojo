---
title: Scansioni infrastruttura / Smart Upload
description: Instrada automaticamente i Riscontri in arrivo al Prodotto corretto
weight: 3
audience: pro
aliases:
- /it/en/connecting_your_tools/import_scan_files/smart_upload
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Smart Upload è disponibile solo in DefectDojo Pro.</span>

Smart Upload è un importatore specializzato che acquisisce report da **strumenti di scansione dell'infrastruttura**, tra cui:

* Nexpose
* NMap
* OpenVas
* Qualys
* Tenable

Smart Upload è unico nel suo genere perché può suddividere i Riscontri di un file di scansione in Prodotti separati. Questo è rilevante in un contesto di scansione dell'infrastruttura, dove i Riscontri possono riguardare team diversi, avere SLA impliciti diversi, oppure dover essere inclusi in report separati in base al punto della vostra infrastruttura in cui sono stati individuati.

Smart Upload gestisce questo aspetto ordinando i riscontri in arrivo in base agli Endpoint individuati nella scansione. Inizialmente questi Riscontri dovranno essere assegnati manualmente, oppure indirizzati al Prodotto corretto da un elenco di Riscontri non assegnati. Tuttavia, una volta che un Riscontro è stato assegnato a un Prodotto, tutti i Riscontri successivi che condividono lo stesso Endpoint o Host verranno inviati allo stesso Prodotto.

## Opzioni del menu Smart Upload

Il menu Smart Upload si trova in una sezione comprimibile della barra laterale.

* **Add Findings consente di importare un nuovo file di scansione, in modo simile al metodo Import Scan di DefectDojo**
* **Unassigned Findings elenca tutti i Riscontri di Smart Upload che non sono ancora stati assegnati a un Prodotto.**

![image](images/smart_upload.png)

### Il modulo Smart Upload

Il modulo Smart Upload Import Scan è sostanzialmente identico al modulo Import Scan. Per maggiori dettagli, consultate le nostre note sul **modulo Import Scan**.

![image](images/smart_upload_2.png)

## Unassigned Findings

Una volta completato uno Smart Upload, tutti i Riscontri che non vengono assegnati automaticamente a un Prodotto (in base al loro Endpoint) vengono inseriti nell'elenco **Unassigned Findings**. Il primo Smart Upload per un determinato strumento non dispone ancora di alcun metodo per assegnare i Riscontri, quindi ogni Riscontro di questo file verrà inviato a questa pagina per essere smistato.

I Riscontri non assegnati non sono inclusi nella Gerarchia dei Prodotti e non compariranno in report, filtri o metriche finché non saranno stati assegnati.

### Lavorare con i Riscontri non assegnati

![image](images/smart_upload_3.png)

È possibile selezionare uno o più Riscontri non assegnati per lo smistamento tramite la casella di controllo ed eseguire una delle seguenti azioni:

* **Assign to New Product**, che crea un nuovo Prodotto
* **Assign to Existing Product**, che sposta il Riscontro in un Prodotto esistente
* **Disregard Selected Findings**, che rimuove il Riscontro dall'elenco

Ogni volta che un Riscontro viene assegnato a un Prodotto nuovo o esistente, viene inserito in un Engagement dedicato chiamato ‘Smart Upload’. Questo Engagement conterrà un Test denominato in base allo Scan Type (ad es. Tenable Scan). I Riscontri successivi caricati tramite Smart Upload che corrispondono a quegli Endpoint verranno inseriti in quell'Engagement \> Test.

### Riscontri ignorati

Se un Riscontro viene ignorato, verrà rimosso dall'elenco Unassigned Findings. Tuttavia, il Riscontro non verrà memorizzato, quindi i successivi caricamenti di scansioni potrebbero far sì che il Riscontro riappaia nuovamente nell'elenco Unassigned Findings.
