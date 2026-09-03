---
title: Modifica in blocco dei Riscontri
description: Applica modifiche ai metadati, tag, note e revisioni a molti Riscontri
  contemporaneamente nell'interfaccia di DefectDojo Pro
audience: pro
weight: 3
---

Nell'interfaccia di DefectDojo Pro, i Riscontri possono essere modificati in blocco da qualsiasi elenco di Riscontri — la pagina **Tutti i Riscontri**, oppure l'elenco dei Riscontri all'interno di un Test.

## Selezione dei Riscontri per la modifica in blocco

In qualsiasi tabella di Riscontri, utilizzare le caselle di controllo accanto ai Riscontri per selezionarli. Selezionando uno o più Riscontri viene visualizzata una **barra delle azioni in blocco** con i seguenti controlli:

* **Modifica in blocco** — apre un unico modulo in cui applicare modifiche ai metadati, tag, note e richieste di revisione a tutti i Riscontri selezionati. È la superficie consolidata principale (descritta in dettaglio di seguito).
* **Accettazione del rischio** — aggiunge i Riscontri selezionati a un'**Accettazione del rischio completa** nuova o esistente.
* **Gruppo di Riscontri** — aggiunge i Riscontri selezionati a un **Gruppo di Riscontri** nuovo o esistente, oppure li rimuove dal loro gruppo.
* **Unisci** — unisce i Riscontri selezionati in un unico Riscontro.
* **Elimina** — elimina i Riscontri selezionati (con conferma).

Un controllo viene disabilitato quando l'azione non può essere applicata alla selezione corrente — vedere [Disponibilità e Riscontri saltati](#availability-and-skipped-findings).

## Modifica in blocco

Il pulsante **Modifica in blocco** apre un unico modulo contenente tutte le azioni in blocco a livello di campo. Impostare solo i campi che si desidera modificare e lasciare invariati gli altri, quindi fare clic su **Aggiorna Riscontri selezionati** per applicare le modifiche. Le azioni disponibili sono:

* **Gravità** — imposta la gravità (Critica, Alta, Media, Bassa o Info).
* **Stato** — applica uno tra Attivo, Verificato, Falso positivo, Fuori ambito, Mitigato o In revisione difetto.
* **Data** — imposta la data di rilevamento.
* **Data di correzione pianificata** e **Versione di correzione pianificata**.
* **Accettazione del rischio semplice** — Accetta rischio o Annulla accettazione rischio. Applicata solo ai Riscontri il cui Prodotto ha l'Accettazione del rischio semplice abilitata; gli altri vengono saltati.
* **Tag** — aggiunge tag ai Riscontri selezionati, oppure utilizza l'interruttore **Aggiungi / Sostituisci** per sovrascrivere l'intero insieme di tag di ciascun Riscontro (**Aggiungi** aggiunge i tag; **Sostituisci** sostituisce tutti i tag esistenti).
* **Sostituisci tag specifico** — scambia un tag specifico con un altro (vedere di seguito).
* **Nota** — aggiunge una nota, con un tipo di nota facoltativo, a ogni Riscontro selezionato.
* **Revisione** — richiede o cancella la revisione sui Riscontri selezionati (vedere di seguito).
* **Invia a Jira** — mette in coda i Riscontri selezionati per l'invio a Jira. Visibile solo quando l'integrazione con Jira è abilitata.
* **Invia al Connector** — inoltra i Riscontri selezionati al connector configurato. Visibile solo quando questa funzionalità è abilitata.

### Sostituisci tag specifico

**Sostituisci tag specifico** esegue uno scambio di tag mirato e non distruttivo. Inserire il tag da sostituire in **Tag esistente da sostituire** e il tag sostitutivo in **Nuovo tag**. Per ogni Riscontro selezionato che effettivamente possiede il vecchio tag, DefectDojo rimuove quel singolo tag e aggiunge quello nuovo — tutti gli altri tag vengono mantenuti, e i Riscontri privi del vecchio tag restano invariati.

Questo è diverso dal campo **Tag** descritto sopra: **Tag** può *aggiungere* tag (Aggiungi) oppure *sovrascrivere l'intero insieme di tag* (Sostituisci), mentre **Sostituisci tag specifico** modifica solo il tag specificato.

### Revisione

L'azione **Revisione** gestisce la revisione tra pari su tutti i Riscontri selezionati:

* **Richiedi revisione** — scegliere uno o più **Revisori** e inserire una **Nota di revisione** (obbligatoria). Ogni Riscontro selezionato viene impostato su *In revisione* (Attivo, non Verificato), i revisori scelti vengono assegnati, viene aggiunta una nota di richiesta di revisione e i revisori vengono notificati.
* **Cancella revisione** — inserire una **Nota di revisione** (obbligatoria) per far uscire i Riscontri selezionati dallo stato *In revisione* e rimuovere i revisori assegnati.

I revisori tra cui è possibile scegliere sono gli utenti con accesso in modifica ai Riscontri selezionati.

## Accettazione del rischio, Gruppo di Riscontri, Unione ed Eliminazione

I restanti pulsanti delle azioni in blocco aprono le rispettive finestre di dialogo:

* **Accettazione del rischio** — crea una nuova **Accettazione del rischio completa** per governare i Riscontri selezionati, oppure li aggiunge a una esistente.
* **Gruppo di Riscontri** — crea un nuovo **Gruppo di Riscontri**, aggiunge i Riscontri a un gruppo esistente, oppure li rimuove dal gruppo attuale. I Gruppi di Riscontri possono essere creati solo all'interno di un singolo **Test** — i Riscontri provenienti da Test, Engagement o Prodotti diversi non possono condividere un gruppo.
* **Unisci** — unisce più Riscontri selezionati (tutti provenienti dallo stesso Asset) in uno solo.
* **Elimina** — elimina i Riscontri selezionati dopo la conferma in un popup.

## Disponibilità e Riscontri saltati

Ciascuna azione in blocco è disponibile solo quando può essere applicata all'intera selezione:

* **Modifica in blocco**, tag e revisione richiedono che ogni Riscontro selezionato sia modificabile dall'utente.
* **Accettazione del rischio** non è disponibile se un Riscontro selezionato non è modificabile, ha già il Rischio accettato, oppure è un duplicato.
* La creazione di un **Gruppo di Riscontri** richiede che ogni Riscontro sia modificabile, non raggruppato e appartenente allo stesso Test.
* **Unisci** richiede più di un Riscontro, tutti modificabili e provenienti dallo stesso Asset.
* **Elimina** richiede che ogni Riscontro selezionato sia eliminabile dall'utente.

Quando un'azione viene eseguita ma alcuni Riscontri non possono essere aggiornati — ad esempio non sono modificabili dall'utente, sono già in revisione, oppure appartengono a un Prodotto senza l'Accettazione del rischio semplice abilitata — DefectDojo applica la modifica agli altri e mostra un avviso **"Uno o più Riscontri saltati"** che spiega il motivo per cui ciascuno è stato saltato.
