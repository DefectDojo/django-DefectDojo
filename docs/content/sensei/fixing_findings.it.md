---
title: Correggere i riscontri con Sensei
description: Scansiona, gestisci le candidate di correzione automatica e apri pull
  request di correzione
draft: false
audience: pro
weight: 3
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Sensei è una funzionalità esclusiva di DefectDojo Pro ed è attualmente in versione BETA.</span>

Una volta effettuato l'onboarding di un repository, Sensei compare direttamente sui tuoi riscontri e nell'hub di Sensei. Questa pagina illustra come scansionare un repository, gestire le candidate di correzione automatica e correggere i singoli riscontri. Per avviare una correzione è necessario un accesso almeno di livello **Writer** al Prodotto del riscontro.

## Scansionare un repository

Le scansioni importano i riscontri in un engagement con lo stesso nome del branch. Puoi avviare una scansione su richiesta dall'hub di Sensei: apri le azioni di riga di un repository e scegli **Scan now**.

![Finestra di dialogo Scan with Sensei](images/scan_dialog.png)

Seleziona il branch da scansionare (per impostazione predefinita è il branch predefinito del repository) e scegli **Start scan**. In modalità ospitata da DefectDojo, le scansioni vengono eseguite automaticamente anche quando viene aperta una pull request.

## La colonna Sensei sui riscontri

I repository sottoposti a onboarding aggiungono una colonna **Sensei** alla tabella dei riscontri. Ogni riscontro mostra un pulsante **Fix** (o il relativo stato di correzione corrente), così puoi correggere senza uscire dalla vista di triage.

![Colonna Sensei nella tabella dei riscontri](images/findings_sensei_column.png)

Il pulsante ha due stati:

- **Fix:** il Prodotto del riscontro è stato sottoposto a onboarding su Sensei. Facendo clic si avvia una correzione.
- **Configure Product:** il Prodotto del riscontro **non** è ancora stato sottoposto a onboarding. Facendo clic vieni indirizzato a Sensei per eseguire l'onboarding di un repository per quel Prodotto; una volta completato l'onboarding, il pulsante diventa **Fix**.

## Correggere un singolo riscontro

Facendo clic su **Fix** (nella tabella dei riscontri o nell'intestazione di dettaglio di un riscontro) si apre la finestra di dialogo **Fix with Sensei**. Scegli il branch di base a cui la pull request di correzione dovrà puntare, quindi fai clic su **Fix**.

![Finestra di dialogo Fix with Sensei](images/fix_with_sensei_dialog.png)

Sensei genera una correzione e apre una pull request. Lo stato di correzione del riscontro viene mostrato come badge che passa da *in corso* a *PR aperta* (oppure *non riuscita*). Una volta aperta la pull request, il badge rimanda direttamente ad essa.

![Dettaglio del riscontro con badge di stato della correzione](images/finding_detail_fix.png)

> **💡 Una correzione, una PR:** ogni correzione approvata consuma una correzione dalla tua quota e apre una pull request. Rivedi ed esegui il merge della PR in GitHub come faresti con qualsiasi altra.

## Gestione delle candidate di correzione automatica

Quando un repository ha le correzioni automatiche abilitate, ogni scansione mette in staging i riscontri corrispondenti come **candidate** nella scheda **Auto-fix Candidates** dell'hub di Sensei. Questo è il modello preview-first di Sensei: i riscontri vengono messi in staging, ma **non viene eseguito nulla (nessun costo LLM) finché non approvi**. L'approvazione apre le pull request di correzione e consuma correzioni.

![Gestione delle candidate di correzione automatica](images/auto_fix_candidates.png)

Ogni candidata mostra il riscontro, il relativo stato, la gravità, il rischio, la priorità, il repository di destinazione e il branch della PR. Per correggere:

- **Approvarne una:** fai clic su **Approve** su una riga per aprire il selettore del branch e avviare quella correzione.
- **Approvarne più di una:** seleziona più righe e utilizza l'azione di approvazione collettiva.

I riscontri approvati restano elencati come **In Progress** (o **Failed**) finché non viene collegata la relativa pull request, in modo che una correzione in corso o non riuscita non scompaia mai prima di produrre una PR.

> **🔎 Correzione automatica senza intervento:** se hai abilitato *Automatically remediate candidates* sul repository, un controllo in background apre automaticamente le PR di correzione per le candidate in staging, fino al raggiungimento della tua quota di correzioni, senza approvazione manuale.

## Monitorare scansioni e impatto

Due sezioni dell'hub di Sensei ti aiutano a seguire ciò che Sensei ha fatto:

- **Scan Activity:** un registro di ogni scansione ed esecuzione di correzione, con la relativa modalità (Branch Scan, PR Scan, Fix (Finding)), il trigger (Manual, Webhook, Auto Remediated), lo stato, il tempo di esecuzione e i link all'engagement o alla pull request prodotta.

  ![Registro Scan Activity](images/scan_activity.png)

- **Fix Impact:** un riepilogo delle correzioni applicate, con gli asset corretti più di frequente, nella parte superiore dell'hub.

  ![Pannello Fix Impact](images/fix_impact.png)

Utilizza le azioni di riga **Scan now**, **Scan history**, **Configure** e **Re-stage candidates** per gestire nel tempo ogni repository sottoposto a onboarding (vedi [Riferimento](/sensei/sensei_reference/#repository-row-actions)).
