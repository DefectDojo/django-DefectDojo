---
title: Aggiornamento di DefectDojo Pro (On-Premise)
description: Procedura di aggiornamento supportata per i deployment self-hosted di
  DefectDojo Pro che utilizzano il chart Helm
draft: false
weight: 7
audience: pro
---

Questa pagina descrive la procedura di aggiornamento supportata per i deployment self-hosted di DefectDojo Pro che utilizzano il chart Helm di DefectDojo Pro.

## Aggiorna tutto come un'unica unità

Ogni release di DefectDojo Pro è costituita da una versione del chart Helm, dalle versioni delle immagini container e dai file delle impostazioni Pro. Questi elementi vengono creati e testati insieme e devono essere aggiornati insieme come un'unica unità.

L'aggiornamento dei soli tag delle immagini non è supportato e comprometterà il tuo deployment.

## File di impostazioni e aggiornamenti

DefectDojo Pro distribuisce un file `pro_settings.py` con ogni release, e il file cambia praticamente a ogni versione. Non trasportare una copia di `pro_settings.py` da una versione all'altra negli aggiornamenti, e non modificare manualmente una copia precedente. L'applicazione deve sempre eseguire il `pro_settings.py` corrispondente alla propria versione.

Inserisci le tue personalizzazioni in `local_settings.py`, mai in `pro_settings.py`. Il tuo `local_settings.py` viene preservato attraverso gli aggiornamenti.

Il chart Helm distribuisce e monta automaticamente il `pro_settings.py` corrispondente e il tuo `local_settings.py`. Quando esegui l'aggiornamento tramite il chart, non c'è nulla da copiare o migrare manualmente.

## Procedura di aggiornamento supportata

1. Esamina le note di rilascio per ogni versione compresa tra quella attuale e quella di destinazione, non solo quest'ultima. Consulta il [Changelog di DefectDojo Pro](/releases/pro/changelog/) e le [note di aggiornamento](/releases/os_upgrading/upgrading_guide/) specifiche per ciascuna versione.
2. Esegui il backup del tuo database.
3. Esegui l'aggiornamento alla release del chart Helm corrispondente alla versione dell'applicazione di destinazione, riutilizzando i tuoi file values esistenti. Non modificare i tag delle immagini indipendentemente dalla versione del chart.

Se hai domande sull'aggiornamento del tuo deployment on-premise, contatta [support@defectdojo.com](mailto:support@defectdojo.com).
