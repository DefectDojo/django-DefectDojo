---
title: Dashboard principale di DefectDojo
description: Utilizzare la pagina principale di DefectDojo
weight: 1
audience: opensource
aliases:
- /it/en/customize_dojo/dashboards/Introduction_dashboard
- /it/en/customize_dojo/dashboards/pro_dashboards
---

La Dashboard è probabilmente la prima pagina che vedrai quando apri DefectDojo. Riassume le prestazioni del tuo team e fornisce strumenti di tracciamento per monitorare aree specifiche del tuo ambiente di gestione delle vulnerabilità.

<div class="version-opensource">

![immagine](images/dashboard.png)

</div>
<div class="version-pro">

> **💡 DefectDojo Pro:** In DefectDojo Pro, la home page è una **dashboard completamente personalizzabile** — la costruisci tu stesso a partire da widget e li disponi come preferisci, anziché utilizzare il layout fisso descritto di seguito. Consulta **[Dashboard personalizzabili](../custom-dashboards/)** per i concetti e una panoramica dell'interfaccia. Il resto di questa pagina descrive la Dashboard principale open source.

</div>

<div class="version-opensource">

## Componenti della Dashboard

La dashboard open source offre una panoramica di alto livello della tua postura di sicurezza con i seguenti componenti integrati:

### Schede di riepilogo

La riga superiore della dashboard mostra quattro schede di riepilogo che offrono una visione a colpo d'occhio dell'attività:

* **Engagement attivi** — numero totale di Engagement attualmente aperti in tutti i Prodotti.
* **Riscontri negli ultimi 7 giorni** — nuovi Riscontri creati nell'ultima settimana.
* **Chiusi negli ultimi 7 giorni** — Riscontri risolti di recente.
* **Accettati negli ultimi 7 giorni** — Riscontri per cui è stato accettato il rischio di recente.

Ogni scheda rimanda direttamente all'elenco filtrato pertinente, così puoi approfondire con un solo clic.

### Gravità storica dei Riscontri

Questo grafico a torta suddivide tutti i Riscontri mai creati in DefectDojo per Gravità (Critica, Alta, Media, Bassa, Informativa), offrendoti una rapida lettura della distribuzione complessiva delle vulnerabilità nel tuo ambiente.

### Gravità dei Riscontri segnalati per mese

Questo grafico a linee traccia il volume e la gravità dei Riscontri in arrivo mese per mese, aiutandoti a individuare tendenze come picchi successivi all'integrazione di un nuovo scanner o miglioramenti costanti dovuti alle attività di remediation.

### Configurazione della Dashboard

I Superuser possono attivare o disattivare i grafici visualizzati nella dashboard. Vai al menu a forma di ingranaggio nell'angolo in alto a destra e seleziona **Modifica configurazione dashboard** per mostrare o nascondere:

* **Mostra grafici** — controlla i grafici Gravità storica dei Riscontri e Gravità dei Riscontri segnalati.
* **Mostra sondaggi** — controlla la tabella dei Questionari Engagement risposti non assegnati.
* **Mostra tabelle dati** — controlla le tabelle dei 10 migliori/peggiori Prodotti per valutazione.

Seleziona **Ripristina configurazione dashboard** dallo stesso menu per ripristinare le impostazioni predefinite.

</div>
