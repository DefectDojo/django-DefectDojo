---
title: Panoramica delle metriche Pro
description: Come sfruttare le metriche in DefectDojo Pro
audience: pro
weight: 2
---

L'interfaccia di DefectDojo Pro dispone di diverse dashboard di Metriche per aiutarti a visualizzare la tua attuale postura di sicurezza. Ogni dashboard consente agli stakeholder ai vari livelli dell'organizzazione di prendere decisioni informate senza dover interpretare dati grezzi o navigare tra i singoli Riscontri. Queste dashboard includono:
* [Executive Insights](/metrics_reports/pro_metrics/pro__executive_insights/#main-content)
* [Priority Insights](/metrics_reports/pro_metrics/pro__priority_insights/#main-content)
* [Program Insights](/metrics_reports/pro_metrics/pro__program_insights/#main-content)
* [Remediation Insights](/metrics_reports/pro_metrics/pro__remediation_insights/#main-content)
* [Tool Insights](/metrics_reports/pro_metrics/pro__tool_insights/#main-content)

![Panoramica delle metriche](images/metrics_image1.png)

## Funzionalità delle metriche

Prima di approfondire ciascuna dashboard specifica, vale la pena esaminare alcuni elementi comuni a tutte le dashboard.

### Filtri

Tutte le Metriche possono essere filtrate per intervallo di tempo, Organizzazione, Asset e Tag. Dopo aver impostato il filtro desiderato, è necessario fare clic su Applica filtro affinché il filtro abbia effetto. Se desideri esportare in PDF tutti i grafici, le tabelle e i diagrammi presenti nella dashboard con il filtro attualmente applicato, fai clic su Esporta come PDF. 

L'intervallo di filtro è limitato all'ultimo anno, ma può essere impostato per includere gli ultimi 7, 14, 30, 90 o 180 giorni.

Nota che i parametri di filtro vengono visualizzati nell'URL, quindi puoi salvare nei preferiti più pagine con diversi parametri di filtro. Questo può essere utile per un rapido riferimento o per generare in modo coerente un particolare tipo di report.

### Sottomenu 

Ogni grafico dispone di un menu kebab ⋮ nell'angolo in alto a destra di ciascuna vista, con le seguenti funzionalità:
* Aggiorna forzatamente — Aggiorna manualmente per includere eventuali nuovi aggiornamenti dei dati. 
* Espandi grafico — Apre lo stesso grafico in una finestra modale più grande.
* Scarica grafico come SVG — Scarica il grafico come file SVG.
* Visualizza come tabella — Mostra i dati del grafico in formato tabellare.
    * Ogni colonna della tabella può essere alternata per essere visualizzata in ordine crescente o decrescente al clic. È inoltre possibile scaricare ciascuna tabella.

![Contenuto del menu kebab](images/metrics_image2.png)

### Accesso

La sezione Metriche rappresenterà solo i dati delle Organizzazioni e degli Asset per cui ciascun Utente dispone delle autorizzazioni appropriate per la visualizzazione. Un Utente con accesso limitato a un singolo Asset potrà vedere le Metriche solo per quel particolare Asset, ma se non ha accesso agli altri Asset all'interno dell'Organizzazione principale, i dati di tali Asset non verranno rappresentati nelle Metriche. 

### Visualizzazione dei dati nei grafici

L'asse X dei grafici a linee rappresenterà sempre l'intervallo di tempo del filtro corrente. Passando il cursore su un grafico a linee, apparirà una finestra modale con il conteggio dei valori sull'asse Y in quel punto temporale. 

![Finestra modale del grafico](images/metrics_image3.png)

### Attivazione/disattivazione dei risultati

Gli Utenti possono rendere visibili o nascondere determinate categorie di Riscontri nel grafico facendo clic sul relativo colore/nome nella parte superiore di ciascun grafico. 

Ad esempio, nel grafico Riscontri attivi per gravità riportato di seguito, se volessi vedere solo i Riscontri con gravità Alta o Critica, dovresti fare clic su Media, Bassa e Info nella parte superiore per rimuovere quei risultati dal grafico. Facendo di nuovo clic su Media, Bassa e Info, quei risultati riappariranno. 

![GIF di attivazione/disattivazione dei risultati del grafico](images/metrics_image4.gif)
