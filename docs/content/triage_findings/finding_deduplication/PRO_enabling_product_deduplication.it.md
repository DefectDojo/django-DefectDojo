---
title: Enabling Deduplication
description: Come abilitare la deduplicazione a livello di Prodotto o di Engagement
weight: 2
audience: pro
aliases:
- /it/en/working_with_findings/finding_deduplication/enabling_product_deduplication
---

La deduplicazione può essere applicata a livello dell'intero Prodotto, oppure limitata a un singolo Engagement.

## Deduplicazione per i Prodotti

1. Vai alla pagina Impostazioni di sistema: **Impostazioni > Sistema > ⚙️ Impostazioni di sistema** nella barra laterale (**Impostazioni > Impostazioni Pro > Impostazioni di sistema** nelle istanze che utilizzano ancora il layout di menu precedente).

![image](images/enabling_product-level_deduplication.png)

2. La scheda **Impostazioni di deduplicazione e dei Riscontri** si trova nella parte superiore della pagina **Impostazioni di sistema**.

![image](images/enabling_product-level_deduplication_2.png)

### Abilita deduplicazione dei Riscontri

**Abilita deduplicazione dei Riscontri** attiva l'algoritmo di deduplicazione per tutti i Riscontri. Una volta abilitata, la deduplicazione viene eseguita a ogni import successivo — DefectDojo confronta i Riscontri importati con quelli già presenti nel Prodotto di destinazione e contrassegna i duplicati in base alla tua configurazione.

### Elimina Riscontri duplicati

**Elimina Riscontri duplicati**, combinato con il campo **Numero massimo di duplicati**, limita quanti Riscontri duplicati DefectDojo conserva. Se abilitato, un job in background elimina periodicamente i duplicati in eccesso in modo che ogni Riscontro originale non superi il numero configurato in **Numero massimo di duplicati**. I duplicati più vecchi vengono rimossi per primi.

## Deduplicazione per gli Engagement

Invece di deduplicare sull'intero Prodotto, puoi limitare la deduplicazione a un singolo Engagement.

### Apri il modulo dell'Engagement

* **Per un nuovo Engagement:** apri il sottomenu **📥 Engagement** nella barra laterale e fai clic su **+ Nuovo Engagement**.

![image](images/enabling_deduplication_within_an_engagement.png)

* **Per un Engagement esistente (dalla pagina Tutti gli Engagement):** apri il menu **⋮** dell'Engagement e seleziona **Modifica Engagement**.

![image](images/enabling_deduplication_within_an_engagement_2.png)

* **Per un Engagement esistente (dalla pagina dell'Engagement):** apri il menu **⚙️ Ingranaggio** nell'angolo in alto a destra della pagina e seleziona **Modifica Engagement**.

![image](images/enabling_deduplication_within_an_engagement_3.png)

### Completa il modulo dell'Engagement

1. Nel modulo dell'Engagement, individua la casella di controllo ☐ **Isola la deduplicazione dagli altri Engagement**. Compare sopra il pannello **Campi opzionali +**.
2. Seleziona la casella per limitare la deduplicazione a questo Engagement.
3. Invia il modulo.

Quando questa opzione è abilitata, i Riscontri di questo Engagement verranno deduplicati solo rispetto ad altri Riscontri all'interno dello stesso Engagement. I Riscontri negli altri Engagement dello stesso Prodotto vengono ignorati dall'algoritmo di deduplicazione.

![image](images/enabling_deduplication_within_an_engagement_4.png)
