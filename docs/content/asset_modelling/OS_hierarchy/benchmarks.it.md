---
title: Benchmark OWASP ASVS
description: Confronta un Prodotto con lo OWASP Application Security Verification
  Standard
weight: 6
audience: opensource
---

DefectDojo supporta il confronto dei Prodotti con lo [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/), che fornisce una base per testare i controlli di sicurezza tecnici delle applicazioni web.

I benchmark consentono di misurare quanto un Prodotto soddisfi i requisiti di sicurezza definiti dalla propria organizzazione e di pubblicare un punteggio nella pagina del Prodotto per garantirne la visibilità.

## Accedere ai Benchmark

I benchmark sono disponibili dalla pagina **Prodotto**. Per aprire la vista Benchmark, selezionare il menu a discesa nell'area in alto a destra della pagina Prodotto e scegliere **OWASP ASVS v.3.1** verso la fine del menu.

## Livelli di Benchmark

OWASP ASVS definisce tre livelli di copertura della verifica:

- **Livello 1** – Per tutto il software. Copre i requisiti di sicurezza più critici con il costo di verifica più basso. Questo è il livello predefinito in DefectDojo.
- **Livello 2** – Per le applicazioni che contengono dati sensibili. Appropriato per la maggior parte delle applicazioni.
- **Livello 3** – Per le applicazioni più critiche, come quelle che eseguono transazioni di alto valore o memorizzano dati sensibili medici, finanziari o di sicurezza.

È possibile passare da un livello all'altro utilizzando il menu a discesa in alto a destra della vista Benchmark.

## Punteggio del Benchmark

Il lato sinistro della vista Benchmark mostra il punteggio attuale del Prodotto al livello ASVS selezionato:

- Il **punteggio desiderato** che l'organizzazione ha impostato come obiettivo
- La **percentuale di benchmark superati** rispetto al raggiungimento di tale punteggio
- Il **numero totale di benchmark abilitati** per il livello selezionato

Abilitando la casella **Publish** il punteggio ASVS verrà visualizzato direttamente nella pagina del Prodotto.

## Gestire le voci di Benchmark

Le singole voci di benchmark possono essere contrassegnate come superate o non superate man mano che il team esamina i controlli ASVS. Ulteriori voci di benchmark, oltre all'insieme predefinito ASVS, possono essere aggiunte o aggiornate tramite il **sito di amministrazione Django**.
