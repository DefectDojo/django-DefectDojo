---
title: Global Component Deduplication
description: Deduplica i riscontri di Software Composition Analysis in base al nome
  e alla versione del componente in tutti i Prodotti
weight: 5
audience: pro
---

Global Component Deduplication è un algoritmo di DefectDojo Pro che identifica i riscontri duplicati in **tutti i Prodotti** in base al nome e alla versione del componente a cui fanno riferimento. È pensato per gli strumenti di Software Composition Analysis (SCA), dove la stessa dipendenza vulnerabile (ad esempio, `timespan@2.3.0`) può comparire in molti Prodotti, e si desidera che DefectDojo tratti queste occorrenze come duplicati di un unico riscontro originale.

A differenza degli altri algoritmi di deduplicazione, la corrispondenza di Global Component **non è limitata a un singolo Prodotto o Engagement**. Un riscontro importato nel Prodotto B può essere contrassegnato come duplicato di un riscontro più vecchio nel Prodotto A, anche se i due Prodotti non sono correlati.

> **Global Component rispetto a Global Locations:** Global Component effettua la corrispondenza solo in base al nome e alla versione del componente. Se la propria istanza utilizza il modello di dati Locations, [Global Locations Deduplication](/triage_findings/finding_deduplication/pro__global_locations_deduplication/) è il successore più preciso: identifica le dipendenze tramite il Package URL completo e deduplica inoltre i riscontri URL/DAST tra i Prodotti. Consultare la tabella di confronto in quella pagina per scegliere quale utilizzare.

## Abilitazione dell'algoritmo Global Component

Global Component Deduplication è controllata da un feature flag ed è **disattivata per impostazione predefinita**. Un superuser può attivarla da **Settings > Feature Flags** sia sulle istanze Cloud che On-Premise. Vedere [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una volta abilitata la funzionalità, **Global Component** diventerà disponibile come opzione nel menu a tendina **Deduplication Algorithm** sia per le impostazioni di Same Tool sia di Cross Tool Deduplication nel Tuner.

## Configurazione di Global Component Deduplication

Global Component può essere applicato a Same-Tool Deduplication, Cross-Tool Deduplication o a entrambe, e viene configurato per singolo strumento di sicurezza da **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** nelle istanze che utilizzano ancora il layout di menu precedente; vedere [The Settings Menu](/navigation/pro__settings_menu/)).

### Same-Tool

Utilizzare Same-Tool Deduplication con l'algoritmo Global Component quando si desidera deduplicare i riscontri di un singolo strumento SCA su più Prodotti.

1. Aprire la scheda **Same Tool Deduplication**.
2. Selezionare lo strumento SCA dal menu a tendina **Security Tool** (ad esempio, `Dependency Track Finding Packaging Format (FPF) Export`).
3. Impostare il **Deduplication Algorithm** su **Global Component**.
4. Inviare il modulo.

Gli Hash Code Fields non vengono utilizzati da questo algoritmo e sono nascosti quando viene selezionato.

### Cross-Tool

Utilizzare Cross-Tool Deduplication con l'algoritmo Global Component quando si desidera deduplicare i riscontri dello stesso componente tra strumenti SCA e Prodotti diversi.

La corrispondenza cross-tool richiede che Global Component sia configurato su **ogni** strumento che deve partecipare.

1. Aprire la scheda **Cross Tool Deduplication**.
2. Per ogni strumento da includere: selezionarlo dal menu a tendina **Security Tool**, impostare l'algoritmo su **Global Component** e inviare.

## Come funziona la corrispondenza

Un nuovo riscontro viene contrassegnato come duplicato di un riscontro esistente quando:

- il nome e la versione del componente corrispondono esattamente, **e**
- esiste un riscontro più vecchio con lo stesso nome e versione del componente in qualsiasi punto dell'istanza DefectDojo — in qualsiasi Prodotto o Engagement.

La corrispondenza della versione del componente è esatta. Un riscontro per `timespan@2.3.0` **non** verrà deduplicato rispetto a uno per `timespan@2.3.1`.

L'impostazione di deduplicazione a livello di Engagement viene ignorata per questo algoritmo; la corrispondenza è sempre globale.

## Esempio

Supponiamo che Global Component sia abilitato su `Dependency Track Finding Packaging Format (FPF) Export` (Same Tool) e su uno strumento Generic Findings Import (Cross Tool):

| Step | Import | Nel Prodotto | Risultato |
| --- | --- | --- | --- |
| 1 | Scansione Dependency Track per `timespan@2.3.0` | Application 0 | Creato 1 riscontro attivo |
| 2 | Stessa scansione Dependency Track | Application 1 | Creato 1 riscontro, contrassegnato come duplicato del riscontro di Application 0 |
| 3 | Generic Findings Import per `timespan@2.3.0` | Application 2 | Creato 1 riscontro, contrassegnato come duplicato del riscontro di Application 0 (corrispondenza cross-tool) |
| 4 | Scansione Dependency Track per `timespan@2.3.1` | Application 3 | Creato 1 riscontro attivo — versione diversa, nessuna corrispondenza |

Ogni riscontro duplicato mostra il proprio originale nella parte inferiore della pagina del riscontro, nella catena dei duplicati.

## Visibilità cross-prodotto

Poiché la corrispondenza di Global Component attraversa i confini tra Prodotti, il riscontro originale in una catena di duplicati potrebbe trovarsi in un Prodotto a cui l'utente che visualizza il duplicato non ha accesso.

In tal caso, il riscontro è visibile ed etichettato come duplicato, ma l'utente non potrà aprirlo né accedere all'originale. Tenerne conto prima di abilitare Global Component su strumenti i cui riscontri sono sensibili ai controlli di accesso a livello di Prodotto.

## Ripristino

Per smettere di utilizzare Global Component per un determinato strumento, aprire le sue Deduplication Settings e riportare l'algoritmo a una delle opzioni con ambito limitato.

Per **Same Tool** Deduplication:

- Hash Code
- Unique ID From Tool
- Unique ID From Tool or Hash Code

Per **Cross Tool** Deduplication:

- Hash Code
- Disabled

La modifica dell'algoritmo avvia un ricalcolo in background degli hash di deduplicazione per i riscontri esistenti dello strumento.
