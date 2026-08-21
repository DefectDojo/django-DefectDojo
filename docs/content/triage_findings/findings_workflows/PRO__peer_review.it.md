---
title: Revisione tra pari e presa in carico
description: Richiedi una revisione a persone specifiche, prendi in carico una revisione
  affinché gli altri sappiano che è già gestita, e controlla chi è idoneo a essere
  interpellato
audience: pro
weight: 4
---

La revisione tra pari consente di chiedere a qualcuno di esaminare un Riscontro prima che venga chiuso. Nell'interfaccia di DefectDojo Pro una revisione può anche essere **presa in carico**, in modo che, quando più persone sono idonee, tutti possano vedere chi se ne sta occupando.

## Richiedere una revisione

Aprire un Riscontro e scegliere **Richiedi revisione** dal menu del Riscontro, oppure selezionare più Riscontri in un elenco e utilizzare l'[editor in blocco](../pro__bulk_edit_findings/).

È possibile richiedere una revisione a utenti e gruppi specifici, oppure selezionare **Consenti revisori idonei** per interpellare chiunque sia idoneo su quell'asset.

Richiedere una revisione imposta il Riscontro su **In revisione** e notifica i revisori.

## Prendere in carico una revisione

Quando una revisione è stata richiesta a più persone, una qualsiasi di esse può prenderla in carico:

* Sul Riscontro, utilizzare **Prendi in carico revisione** nel menu del Riscontro, oppure il pulsante nel banner di revisione.
* Il Riscontro mostra quindi chi detiene la revisione: sul Riscontro stesso, come colonna **Preso in carico da** negli elenchi dei Riscontri, e nella coda [Il mio lavoro](/metrics_reports/dashboards/pro__my_work/) di quella persona.

Una volta presa in carico una revisione:

* Solo la persona che la detiene, chi l'ha richiesta, oppure un superuser può **Cancellare la revisione**. Agli altri revisori idonei viene invece indicato chi la detiene.
* Chi la detiene può restituirla con **Rilascia revisione**, che la riporta nel pool senza terminare la revisione.

Se due persone la prendono in carico nello stesso momento, una delle due riesce e all'altra viene indicato chi ha avuto la meglio — la revisione può sempre essere detenuta da una sola persona.

Le prese in carico si gestiscono da sole in alcune situazioni che altrimenti andrebbero risolte manualmente:

* La cancellazione della revisione contrassegna la presa in carico come **completata**.
* La rimozione del detentore dall'elenco dei revisori, oppure la chiusura o la riapertura del Riscontro, **rilascia** la presa in carico.
* Un job in background rilascia le prese in carico il cui detentore non è più un revisore richiesto.

Completata e rilasciata vengono registrate separatamente, in modo che una revisione abbandonata sia distinguibile da una conclusa.

La presa in carico è controllata dal [feature flag](/admin/feature_flags/pro__feature_flags/) **Review Claiming**, attivo per impostazione predefinita.

## Controllare chi può essere interpellato per la revisione

"Tutti i revisori idonei" indica chiunque disponga del permesso **Review Findings** su quell'asset — non chiunque possa modificare il Riscontro.

Ciò è importante quando si desidera un'ampia visibilità ma un pool ristretto di revisori. Poiché **Review Findings** è un permesso separato, è possibile:

1. Creare un ruolo — ad esempio "Security Reviewer" — che conceda **Review Findings**.
2. Concederlo alla ristretta cerchia di persone che dovrebbero effettivamente essere interpellate.
3. Rimuovere **Review Findings** dai ruoli più ampi, lasciando invariato il loro accesso ai Riscontri.

Vedere [Ruoli RBAC personalizzati](/admin/user_management/pro__custom_rbac_roles/) per informazioni su come creare un ruolo.

Durante l'aggiornamento, a ogni ruolo che poteva già modificare i Riscontri viene concesso anche **Review Findings**, quindi "tutti i revisori idonei" continua a significare esattamente ciò che significava prima, finché non lo si modifica deliberatamente.

## Assegnare un Riscontro a una persona

La revisione chiede a qualcuno di *guardare*. L'assegnazione rende qualcuno *responsabile* e non mette il Riscontro in revisione.

**Assegnatari** si trova accanto a **Proprietari** nel modulo di modifica del Riscontro. Proprietari è un gruppo — il team a cui appartiene questa coda — mentre gli Assegnatari sono singole persone.

* Assegnare dal modulo di modifica del Riscontro, oppure a molti Riscontri contemporaneamente dall'editor in blocco.
* Nell'editor in blocco, gli assegnatari vengono **aggiunti** a chi è già assegnato. Selezionare **Sostituisci assegnatari esistenti** per rendere la propria selezione l'elenco completo — il che rimuove chiunque non sia stato selezionato, incluse tutte le persone se non se ne seleziona nessuna.
* Gli elenchi dei Riscontri includono una colonna **Assegnatari** e un filtro per assegnatario, e i report possono includere una colonna **Assegnatari**.
* Le assegnazioni di ciascuna persona compaiono nella relativa coda [Il mio lavoro](/metrics_reports/dashboards/pro__my_work/).

È possibile assegnare un Riscontro solo a qualcuno che può già vederlo. L'assegnazione non concede l'accesso.

Il [Rules Engine](/automation/rules_engine/) può impostare gli assegnatari automaticamente: scegliere **Set Users** e il campo **assignees**.

L'assegnazione è controllata dal [feature flag](/admin/feature_flags/pro__feature_flags/) **Work Assignment**.
