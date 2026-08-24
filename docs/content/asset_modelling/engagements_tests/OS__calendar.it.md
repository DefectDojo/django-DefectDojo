---
title: Calendario
description: Come utilizzare il Calendario in DefectDojo Pro
audience: opensource
weight: 9
---

Il Calendario di DefectDojo fornisce una vista cronologica centralizzata di tutti gli Engagement e i Test con date di inizio e fine definite, permettendo agli Utenti di comprendere rapidamente l'attività di test tra i Prodotti, identificare sovrapposizioni di pianificazione e navigare direttamente verso gli oggetti correlati. 

Quando un Utente crea un Engagement o un Test e definisce le date di inizio e fine, una voce corrispondente viene aggiunta automaticamente al Calendario. Le voci compaiono in tutte le date comprese tra la data di inizio definita e la data di fine definita, inclusa. 

## Accesso al Calendario 

La pagina Calendario è accessibile tramite il pulsante Calendar nella barra laterale. 

![image](images/OSC_ss3.png)

## Visibilità e permessi 

### Visibilità 

La pagina Calendario include filtri nella parte superiore e una griglia mensile del Calendario sottostante. Usa i controlli di navigazione sopra il Calendario per spostarti tra i mesi. 

La vista mensile viene visualizzata come una griglia fissa di sei settimane, a partire dalla settimana che contiene il primo giorno del mese selezionato.

Le voci visibili nel Calendario possono essere filtrate in base al tipo di oggetto (Engagement o Test) e al Testing Lead, stabilito nelle impostazioni dell'Engagement o del Test. Dopo aver selezionato i criteri di filtro, fai clic su Apply per aggiornare la vista del Calendario.

Può essere visualizzato un solo tipo di oggetto alla volta. Il passaggio tra Engagement e Test aggiorna di conseguenza la vista del Calendario.

### Permessi 

Il Calendario rispetta i permessi a livello di oggetto di DefectDojo. Gli Utenti vedono solo gli Engagement e i Test a cui sono autorizzati ad accedere.

## Visualizzazione e interazione con le voci 

All'interno di ogni cella data, le voci sono ordinate alfabeticamente in base al nome dell'oggetto. Facendo clic su una voce si viene reindirizzati all'oggetto corrispondente.

Il numero di voci visualizzabili in ogni giorno è dinamico e varia in base alle dimensioni dello schermo e al livello di zoom del browser. Se il numero di voci supera lo spazio disponibile in una cella data, in fondo alla cella appare un link nel formato “+X more”.

![image](images/OSC_ss1.png)

Fai clic sul link “+X more” per aprire una finestra modale che mostra tutte le voci per quella data. 

![image](images/OSC_ss2.png)

È importante notare che il Calendario stesso è una vista di sola lettura. Le date devono essere modificate all'interno delle impostazioni dell'oggetto Engagement o Test stesso. 

### Logica di denominazione 

La denominazione delle voci nel Calendario varia leggermente a seconda del tipo di oggetto. 

Le voci Engagement includono: 
- Nome del Prodotto
- Nome dell'Engagement
- Testing Lead

Le voci Test includono:
- Nome del Prodotto
- Nome dell'Engagement
- Tipo di Test 
- Testing Lead
