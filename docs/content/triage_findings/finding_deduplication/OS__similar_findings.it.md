---
title: Riscontri simili
description: Trova Riscontri correlati nella pagina Visualizza Riscontro e collegali
  manualmente come duplicati
audience: opensource
weight: 3
---

Mentre la [Deduplicazione](../about_deduplication) viene eseguita automaticamente al momento dell'importazione, **Riscontri simili** è uno strumento manuale e interattivo presente nella pagina **Visualizza Riscontro**. Mostra altri Riscontri nello stesso Asset che assomigliano a quello che stai visualizzando e ti permette di collegarli manualmente in un cluster di duplicati.

Usalo quando la deduplicazione automatica non ha raggruppato Riscontri che ritieni debbano appartenere insieme, oppure quando vuoi esplorare cos'altro in un Asset assomiglia alla vulnerabilità attuale.

## Dove trovarlo

Apri un qualsiasi Riscontro per raggiungere la sua pagina Visualizza Riscontro. Scorri verso il basso fino al pannello **Riscontri simili**. Il numero nel titolo è il conteggio dei Riscontri nell'Asset che corrispondono ai valori del Riscontro attuale.

![Il titolo del pannello Riscontri simili nella pagina Visualizza Riscontro](images/similar_findings_panel.png)

Il pannello è chiuso per impostazione predefinita. Fai clic sul titolo del pannello (oppure sulla freccia / pulsante filtro a destra) per espanderlo ed eseguire la query.

## Come vengono associati i Riscontri

Quando apri il pannello, DefectDojo precompila un filtro con i valori del Riscontro attuale e cerca nello **stesso Asset** altri Riscontri corrispondenti. I campi utilizzati per avviare la corrispondenza sono:

- ID Vulnerabilità (ad esempio, identificatori CVE)
- CWE
- Percorso del file
- Numero di riga
- Unique ID from tool
- Tipo di Test
- Asset (e Tipo di Asset)

Il Riscontro attuale viene sempre escluso dai propri risultati. La corrispondenza è limitata all'Asset, quindi Riscontri simili non va mai oltre gli Asset. Se uno dei due Engagement ha la deduplicazione a livello di Engagement abilitata, le corrispondenze che superano il confine di un Engagement non possono essere collegate (vedi [Azioni](#actions) più sotto).

Questo è diverso dall'algoritmo di deduplicazione automatica, che confronta `hash_code` (o Unique ID from tool) per decidere le corrispondenze. Riscontri simili getta deliberatamente una rete più ampia in modo da poter scoprire Riscontri correlati che una corrispondenza rigorosa basata sull'hash non individuerebbe.

## Perfezionare la corrispondenza

I valori iniziali sono solo un punto di partenza. Il pannello dei filtri nella parte superiore della sezione ti permette di rendere la corrispondenza più rigorosa o più permissiva: rimuovi un campo per ampliare i risultati, oppure aggiungi criteri (gravità, stato, endpoint, date, EPSS e altro) per restringerli.

![Il pannello dei filtri di Riscontri simili](images/similar_findings_filters.png)

- **Cancella filtri** svuota ogni campo in modo da poter costruire una query da zero.
- **Riavvia** torna alla corrispondenza predefinita basata sui valori del Riscontro attuale.

## Leggere i risultati

Ogni Riscontro corrispondente è elencato in una tabella. La colonna **Relazione** indica come quel Riscontro si relaziona a quello che stai visualizzando:

- **Originale** – il Riscontro radice/originale del cluster di duplicati del Riscontro attuale
- **Duplicato** – un Riscontro già contrassegnato come duplicato di quello attuale
- **Simile** – una corrispondenza che non fa ancora parte del cluster del Riscontro attuale

![La tabella dei risultati di Riscontri simili](images/similar_findings_list.png)

La tabella mostra anche Gravità, Titolo, Data, Stato, Test, Engagement, CWE, ID Vulnerabilità, punteggio EPSS, File (con numero di riga) e JIRA (quando l'integrazione JIRA è abilitata). Ogni colonna è ordinabile e i risultati possono essere esportati (Copia, Excel, CSV, PDF).

## Azioni

Se disponi del permesso di modifica su un Riscontro, la colonna **Azione** offre un menu a tendina per gestire il cluster di duplicati direttamente da questa pagina:

![Il menu azioni di riga di Riscontri simili](images/similar_findings_actions.png)

- **Contrassegna come duplicato** – collega il Riscontro simile al cluster di duplicati del Riscontro attuale.
- **Imposta come originale** – promuove un Riscontro a originale (radice del cluster).
- **Ripristina lo stato di duplicato del riscontro** – rimuove un Riscontro dal suo cluster.

Un'azione potrebbe non essere disponibile (mostrata come **Nessuna**) quando non è valida, ad esempio quando il Riscontro simile si trova in un Engagement diverso e la deduplicazione a livello di Engagement è abilitata, oppure quando è già l'originale di un cluster diverso. Queste azioni modificano le stesse relazioni di duplicato utilizzate dalla deduplicazione automatica, quindi un Riscontro che contrassegni qui si comporta esattamente come un duplicato rilevato automaticamente.

## Abilitare e disabilitare Riscontri simili

Riscontri simili è controllato da un'impostazione di sistema globale. Vai su **Configurazione > Impostazioni di sistema** e attiva/disattiva **Abilita Riscontri simili**. È abilitato per impostazione predefinita.

![L'impostazione di sistema Abilita Riscontri simili](images/similar_findings_enable_setting.png)

Poiché la query analizza un intero Asset, può essere costosa su Asset di grandi dimensioni. Se noti pagine Visualizza Riscontro lente, puoi disabilitare la funzionalità qui, oppure limitare il numero di risultati restituiti con la variabile d'ambiente `DD_SIMILAR_FINDINGS_MAX_RESULTS` (predefinito `25`).
