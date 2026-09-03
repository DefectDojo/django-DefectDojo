---
title: Similar Findings
description: Trova i riscontri correlati nella pagina Visualizza riscontro e collegali
  manualmente come duplicati
audience: pro
weight: 3
---

Mentre la [Deduplicazione](../about_deduplication) viene eseguita automaticamente al momento dell'import, **Riscontri simili** è uno strumento manuale e interattivo nella pagina **Visualizza Riscontro**. Mostra altri Riscontri nello stesso Asset che assomigliano a quello che stai osservando e ti permette di collegarli manualmente in un cluster di duplicati.

Usalo quando la deduplicazione automatica non ha raggruppato Riscontri che ritieni debbano stare insieme, oppure quando vuoi esplorare cos'altro in un Asset assomiglia alla vulnerabilità corrente.

## Dove trovarlo

Apri un Riscontro qualsiasi e scorri fino alla scheda **Riscontri duplicati e simili**. Ha due schede:

- **Riscontri duplicati** – i Riscontri già collegati a questo come duplicati (il cluster automatico).
- **Riscontri simili** – altri Riscontri nell'Asset che corrispondono ai valori del Riscontro corrente ma non fanno ancora parte del suo cluster.

Seleziona la scheda **Riscontri simili** per eseguire la query.

![La scheda Riscontri duplicati e simili nella pagina Visualizza Riscontro](images/pro_similar_findings.png)

## Come vengono abbinati i Riscontri

DefectDojo cerca nello **stesso Asset** Riscontri che assomigliano a quello corrente, in base a valori come gli ID di vulnerabilità (ad esempio identificatori CVE), CWE, percorso del file, numero di riga e ID univoco dallo strumento. Il Riscontro corrente viene sempre escluso dai propri risultati, e la corrispondenza non attraversa mai i confini tra Asset.

Questo è diverso dall'algoritmo di deduplicazione automatica, che confronta `hash_code` (o l'ID univoco dallo strumento) per decidere le corrispondenze. Riscontri simili allarga deliberatamente la rete di ricerca in modo da poter scoprire Riscontri correlati che una corrispondenza rigida basata su hash non troverebbe.

## Lavorare con i risultati

La scheda Riscontri simili è una tabella dati completa con gli stessi controlli utilizzati altrove nell'interfaccia Pro:

- La **Ricerca per parole chiave** e i controlli di filtro per colonna (a imbuto) e ordinamento permettono di restringere l'elenco.
- Il menu a tendina delle **viste salvate** (**Predefinita**) e l'icona di salvataggio permettono di memorizzare un layout di filtri/colonne da riutilizzare.
- I pulsanti delle impostazioni delle colonne e del layout controllano quali colonne vengono mostrate.
- **Esporta** scarica i risultati correnti, e **Cancella filtri** azzera la tabella.

Ogni riga mostra l'ID del Riscontro corrispondente, Gravità, Priorità, Rischio, nome del Riscontro, CWE, punteggi CVSS, ID di vulnerabilità, dati EPSS, exploit intelligence (Known Exploited / Ransomware), stato, Asset e altro ancora. Fai clic sul nome di un Riscontro per aprirlo.

## Azioni

Apri il menu delle azioni (il pulsante **⋮** all'inizio di una riga) per gestire il cluster di duplicati direttamente da questa pagina:

![Il menu delle azioni di riga di Riscontri simili](images/pro_similar_findings_actions.png)

- **Imposta come Riscontro originale** – promuove un Riscontro a originale (radice del cluster).
- **Contrassegna come duplicato** – collega il Riscontro simile al cluster di duplicati del Riscontro corrente.

Queste azioni modificano le stesse relazioni di duplicato utilizzate dalla deduplicazione automatica, quindi un Riscontro collegato qui si comporta esattamente come un duplicato rilevato automaticamente. Ogni Riscontro contrassegnato come duplicato compare quindi nella scheda **Riscontri duplicati** di questa scheda.

Un'azione potrebbe non essere disponibile quando non è valida, ad esempio quando il Riscontro simile è già l'originale di un cluster diverso, oppure quando collegarlo attraverserebbe un confine di Engagement mentre la deduplicazione a livello di Engagement è abilitata.

## Abilitazione e disabilitazione di Riscontri simili

Riscontri simili è controllato dall'impostazione di sistema globale **Abilita Riscontri simili**, abilitata per impostazione predefinita. Poiché la query esamina un intero Asset, può risultare costosa su Asset di grandi dimensioni; se noti pagine Visualizza Riscontro lente, questa impostazione può essere disattivata.
