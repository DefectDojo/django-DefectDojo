---
title: Componenti
description: Monitoraggio delle librerie di terze parti e dei componenti software
  in DefectDojo Pro
audience: pro
weight: 1
---

In DefectDojo, i Componenti rappresentano librerie di terze parti, componenti software e moduli che potenzialmente presentano vulnerabilità.


## Viste dei Componenti

DefectDojo Pro include una vista tabellare dedicata per i Componenti, disponibile nella barra laterale.  Questa vista mostra i Riscontri attivi, i Riscontri duplicati e i Riscontri totali per ciascun Componente.  Questi valori includono tutti gli Asset presenti sull'istanza DefectDojo.

I Componenti di un singolo Asset sono visibili nella vista dell'Asset.

## La tabella dei Componenti

La tabella dei Componenti mostra le seguenti colonne:

* **Componente** — il nome del componente, popolato a partire dai dati della scansione.
* **Versione** — la versione del componente, popolata a partire dai dati della scansione.
* **Riscontri attivi** — il numero di Riscontri attivi associati al componente.
* **Riscontri duplicati** — il numero di Riscontri duplicati associati al componente.
* **Riscontri totali** — il numero totale di Riscontri associati al componente.

Facendo clic sul nome del Componente o sui valori di Riscontri attivi, Riscontri duplicati o Riscontri totali si apre un elenco filtrato dei Riscontri relativo al rispettivo campo.

Nella tabella viene visualizzato un Componente **None**, che mostra tutti i Riscontri non associati ad alcun Componente.

I Componenti importati rimangono nella tabella anche se tutti i Riscontri associati sono Mitigati. Quando vengono importati Riscontri per un Componente specifico, la tabella dei Componenti viene aggiornata per riflettere accuratamente i nuovi totali dei Riscontri.


### Esempio

Un Componente importato da una scansione Dependency-Check eseguita su un'applicazione con una dipendenza `lodash` vulnerabile potrebbe apparire nella tabella come segue:

| Componente | Versione | Riscontri attivi | Riscontri duplicati | Riscontri totali |
| --- | --- | --- | --- | --- |
| npm:lodash | 4.17.15 | 3 | 1 | 5 |

Facendo clic su `npm:lodash` si apre l'elenco di tutti i Riscontri che fanno riferimento a questo Componente. Facendo clic su `3` si apre lo stesso elenco filtrato ai soli Riscontri attivi.

## Aggiunta di Componenti

I Componenti possono essere estratti da un'importazione di scansione oppure aggiunti modificando manualmente un Riscontro. Una volta che un Nome del Componente viene associato a un Riscontro, una voce corrispondente viene aggiunta automaticamente alla tabella dei Componenti. Se il Componente è già associato ad altri Riscontri in DefectDojo, i totali di Riscontri attivi, Riscontri duplicati e Riscontri totali vengono aggiornati di conseguenza.

### Come vengono estratti i Componenti dai dati di scansione

Quando una scansione viene importata, i parser popolano i campi **Nome del Componente** e **Versione del Componente** di ciascun Riscontro a partire dall'output della scansione. La tabella dei Componenti viene quindi costruita a partire da questi valori. Il livello di dettaglio e la convenzione di denominazione dipendono dallo strumento che ha prodotto la scansione:

* **Gli strumenti di Software Composition Analysis (SCA)** in genere riportano un nome di pacchetto e una versione esatta. Ad esempio, OWASP Dependency-Check deriva il Componente dal [Package URL](https://github.com/package-url/purl-spec) presente nel proprio identificativo — un purl `pkg:npm/lodash@4.17.15` diventa `Component Name: npm:lodash`, `Component Version: 4.17.15`.
* **Gli scanner di container e pacchetti del sistema operativo** come Trivy, Anchore Grype e Anchore Engine riportano il pacchetto del sistema operativo o del linguaggio interessato — ad esempio, `Component Name: curl`, `Component Version: 7.68.0`.
* **Gli scanner di dipendenze specifici per linguaggio** come npm Audit, pip-audit, bundler-audit, Retire.js, Govulncheck e OSV-Scanner popolano il pacchetto e la versione responsabili a partire dai rispettivi manifest dell'ecosistema.

Gli scanner incentrati su configurazione, infrastruttura o logica del codice sorgente (come gli strumenti SAST e IaC) generalmente non popolano i campi del Componente, e i relativi Riscontri compaiono sotto il Componente **None**.

Per aggiungere o modificare un Componente manualmente, modifica il Riscontro e imposta direttamente i campi **Nome del Componente** e **Versione del Componente**. La tabella dei Componenti si aggiorna non appena il Riscontro viene salvato.

## Aggiornamento dei Componenti

Per aggiornare il Nome o la Versione di un Componente, è necessario aggiornare il campo Nome del Componente o Versione del Componente su tutti i Riscontri associati al Componente.

## Rimozione dei Componenti

Per rimuovere un Componente dalla tabella dei Componenti, è necessario aggiornare tutti i Riscontri associati al Componente rimuovendo i campi Nome del Componente e Versione del Componente. I Componenti vengono rimossi anche se tutti i Riscontri associati vengono eliminati.

Se tutti i Riscontri di un Componente sono Mitigati, il Componente rimane nella tabella ma il suo valore di Riscontri attivi viene impostato a 0.
