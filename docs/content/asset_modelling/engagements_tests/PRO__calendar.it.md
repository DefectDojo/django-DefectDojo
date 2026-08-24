---
title: Calendario
description: Come utilizzare il Calendario in DefectDojo Pro
audience: pro
weight: 9
---

DefectDojo dispone di un Calendario integrato che consente di monitorare tutti gli Engagement e i Test precedenti e attivi all'interno della propria organizzazione. Ogni volta che un Utente crea un nuovo Engagement o Test e stabilisce le date di inizio e fine, una voce corrispondente viene aggiunta automaticamente al Calendario. 

### Pagina iniziale 

La pagina del Calendario include dei filtri nella parte superiore e un calendario mensile sottostante. I filtri consentono di regolare quali risultati vengono visualizzati nel calendario in base a:
- Engagement e/o Test 
- Data di inizio e di fine 
- Stato dell'Engagement (ad es. Completed, In Progress, On Hold, ecc.) 
- Responsabile dell'Engagement/Test (ovvero, a chi è assegnato l'Engagement/Test?) 
- Tipo di Engagement (ad es. Interactive o CI/CD)
- Tipo di Test (ad es. Pen Test, Acunetix Scan, Tenable Scan, ecc.) 

![image](images/calendar1.png)
 
Una volta filtrati, i risultati possono essere esportati e condivisi come file ICS. 

È importante notare che il Calendario mostrerà solo gli Engagement e i Test a cui l'Utente che visualizza il calendario ha accesso. Non verranno visualizzati gli Engagement e i Test che l'Utente non ha il permesso di vedere. 

## Funzionalità 

### Vista mensile

Il calendario mensile mostra un'anteprima di cinque voci per ogni giorno. Le voci aggiuntive che si verificano in quel giorno rimarranno nascoste a meno che non si faccia clic su **"+ [X] events"** all'interno della cella di una determinata data. Una volta cliccato, il calendario passerà dalla vista mensile a quella giornaliera.

Facendo clic su una voce relativa a un Test o Engagement si aprirà una finestra modale con informazioni aggiuntive su quella voce, tra cui: 
- Data di inizio e di fine 
- Tipo di Test o Engagement 
- Responsabile 
- Stato 
- Asset 
- Engagement 
- Test 

Da lì, è possibile accedere all'Asset, all'Engagement o al Test tramite collegamento ipertestuale.

### Vista giornaliera 

Nella vista giornaliera, tutti gli Engagement e i Test attualmente attivi vengono visualizzati in ordine cronologico decrescente (ovvero, un Engagement o Test appena creato si troverà in fondo alla voce di quel giorno). Gli Engagement appaiono in blu, mentre i Test appaiono in arancione.

Se impostato all'interno dell'Engagement/Test in questione, il titolo di ciascuna voce nel calendario giornaliero includerà quanto segue:
- Stato 
- Prodotto
- Engagement
- Test
- Assegnatario 

#### Frecce

Le frecce sul lato sinistro e destro di ciascuna voce indicano se quel particolare Test o Engagement è presente nel giorno precedente e/o successivo. 

Ad esempio, un Test creato nello stesso giorno in cui viene visualizzato non avrà frecce a sinistra, perché quel Test non esisteva il giorno precedente. Al contrario, un Test che termina nello stesso giorno in cui viene visualizzato non avrà frecce a destra, perché la voce non esisterà il giorno successivo.

Ad esempio, poiché l'ultimo Engagement nella schermata seguente (**In Progress** Example Product A ▶ **Sample Engagement** (Unassigned)) viene visualizzato nel giorno in cui è stato creato, e la Data di fine prevista era impostata per il giorno successivo, non sono presenti frecce né a sinistra né a destra.

![image](images/calendar2.png)
