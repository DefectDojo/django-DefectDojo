---
title: Allegare file
description: Carica screenshot, report o altri file di supporto su un Riscontro, un
  Engagement o un Test in DefectDojo OS
audience: opensource
weight: 3
aliases:
- /it/triage_findings/findings_workflows/add_files/
---

Puoi allegare file a un **Riscontro**, un **Engagement** o un **Test** per fornire un contesto di supporto — ad esempio uno screenshot di proof-of-concept, un report grezzo dello scanner, uno schema di rete o un foglio di calcolo a supporto di un risultato.

Ogni oggetto mantiene il proprio insieme di file, e puoi allegare **fino a 10 file** a un singolo oggetto.

## Tipi di file supportati

Per impostazione predefinita vengono accettate le seguenti estensioni:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Gli amministratori possono modificare questo elenco tramite la variabile d'ambiente `DD_FILE_UPLOAD_TYPES`.
Il caricamento di un file la cui estensione non è presente nell'elenco viene respinto dal modulo.

I file immagine (come `.png` e `.jpeg`) vengono visualizzati come anteprima in miniatura, mentre gli altri
tipi di file vengono mostrati con un'icona generica. In entrambi i casi, cliccando sul file lo si
scarica.

## Come allegare un file a un Riscontro

1. Apri il Riscontro a cui vuoi allegare un file.
2. Apri il menu delle azioni (il pulsante **☰** in alto a destra del Riscontro) e clicca su
   **Manage Files**.

   ![Manage Files nel menu delle azioni del Riscontro](images/OS_manage_files_menu.png)

3. Nella pagina **Add files**, inserisci un **Title** per il file e scegli il file dal tuo
   computer. Puoi aggiungere fino a tre file alla volta; salva e torna indietro per aggiungerne altri se necessario.

   ![Il modulo di caricamento Manage Files](images/OS_manage_files_form.png)

4. Clicca su **Save**.

Il file viene quindi elencato nel pannello **Files** del Riscontro. I file immagine vengono visualizzati come
miniatura:

![Pannello Files su un Riscontro che mostra uno screenshot allegato](images/OS_finding_files_panel.png)

## Allegare file a Engagement e Test

Engagement e Test utilizzano lo stesso workflow **Manage Files**:

- Nella pagina di dettaglio di un **Engagement** o **Test**, apri il pannello **Files** e clicca sul relativo
  pulsante di modifica (matita), quindi aggiungi i file esattamente come faresti per un Riscontro.

Come per i Riscontri, gli allegati immagine vengono visualizzati come miniatura e gli altri tipi di file mostrano
un'icona generica.

## Visualizzare e scaricare i file

I file allegati compaiono nel pannello **Files** nella pagina di dettaglio dell'oggetto. Clicca su un file per
scaricarlo. L'accesso è soggetto a verifica dei permessi: un utente deve disporre del permesso **view** sul
Riscontro, Engagement o Test padre per poter scaricare i relativi file.

## Eliminare i file

Per rimuovere un file, apri **Manage Files** per l'oggetto, seleziona la casella **Delete** sotto
il file che vuoi rimuovere, e clicca su **Save**.
