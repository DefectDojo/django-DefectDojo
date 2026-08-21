---
title: Allegare file
description: Carica screenshot, report o altri file di supporto su un Riscontro, un
  Engagement o un Test in DefectDojo Pro
audience: pro
weight: 3
---

È possibile allegare file a un **Riscontro**, a un **Engagement** o a un **Test** per fornire un contesto di supporto — ad esempio uno screenshot proof-of-concept, un report grezzo dello scanner, uno schema di rete o un foglio di calcolo a supporto di un risultato.

Ciascun oggetto mantiene il proprio insieme di file ed è possibile allegare **fino a 10 file** a un singolo oggetto.

## Tipi di file supportati

Per impostazione predefinita sono accettate le seguenti estensioni:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Gli amministratori possono modificare questo elenco tramite la variabile d'ambiente `DD_FILE_UPLOAD_TYPES`.
Il caricamento di un file la cui estensione non è presente nell'elenco viene rifiutato.

## Come allegare un file a un Riscontro

1. Aprire il Riscontro a cui si desidera allegare un file.
2. Fare clic sul **menu a ingranaggio (⚙)** in alto a destra del Riscontro e scegliere **Aggiungi file**.
3. Inserire un **Titolo** per il file e selezionare il file dal computer, quindi salvare.

   ![L'azione Aggiungi file nel menu a ingranaggio del Riscontro, con la scheda File sottostante](images/PRO_attach_files_menu.png)

Lo stesso menu a ingranaggio è disponibile nelle pagine di **Engagement** e **Test**, quindi i file possono essere allegati a ciascuno di questi oggetti allo stesso modo.

## Visualizzazione e download dei file

I file allegati sono elencati nella scheda **File** della **Panoramica del Riscontro** (e nella sezione equivalente su Engagement e Test). Fare clic sul titolo di un file per scaricarlo.

![La scheda File di un Riscontro con un file allegato elencato](images/PRO_finding_files_tab.png)

L'accesso è soggetto a verifica dei permessi: un utente deve disporre del permesso di **visualizzazione** sul Riscontro, Engagement o Test padre per poter scaricare i relativi file.

## Eliminazione dei file

Per rimuovere un file, aprire il menu della riga del file (l'icona **⋮**) nella scheda **File** e scegliere **Elimina file**. Lo stesso menu offre anche **Modifica nome file** per rinominare un allegato.
