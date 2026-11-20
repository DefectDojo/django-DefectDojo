---
title: "Condivisione della telemetria dei sensori"
description: "Scegli di condividere con DefectDojo eventi anonimizzati dei rilevamenti dei sensori e vedi cosa hanno contribuito i tuoi sensori"
weight: 11
audience: pro
draft: false
---

> **Non ancora disponibile:** la condivisione della telemetria dei sensori non può ancora essere attivata, né su DefectDojo Cloud né su un'istanza self-hosted, qualunque sia la sua configurazione. Questa pagina descrive come funzionerà una volta rilasciata.

La condivisione della telemetria dei sensori consente a un'istanza di inviare **eventi di rilevamento dei sensori** anonimizzati al servizio di threat intelligence di DefectDojo. Un rilevamento è una singola rilevazione di un sensore sui tuoi host collegata a un CVE. I rilevamenti condivisi indicano al servizio di intelligence quali vulnerabilità vengono sfruttate in the wild, e questa evidenza raggiunge ogni istanza tramite il feed di Threat Intelligence.

La condivisione è una funzionalità di **DefectDojo Pro**. È **disattivata per impostazione predefinita** e non viene inviato nulla finché un superuser non la attiva.

## Cosa viene condiviso e cosa no

Ogni evento contiene quattro valori e nient'altro:

| Campo | Che cos'è |
| --- | --- |
| CVE | Il CVE con cui è etichettata la regola di rilevamento che ha trovato corrispondenza |
| Ora | L'ora in cui è stato visto il rilevamento, in UTC. Minuti e secondi non vengono inviati |
| Origine | Al massimo il paese e la rete (ASN) da cui proveniva il rilevamento. Spesso vuota |
| ID del contributore | Un identificatore casuale che cambia ogni mese di calendario |

Un evento non contiene mai un payload o il corpo di una richiesta, un nome host, un indirizzo IP, un nome utente, una riga di comando, il nome di un asset, il nome di un'azienda, il nome o l'identificatore della regola di rilevamento, né il nome o l'URL della tua istanza. L'origine viene compilata solo quando la tua istanza è configurata per cercarla, e solo per un indirizzo pubblico. DefectDojo determina allora il paese e la rete sulla tua istanza e scarta lì l'indirizzo, prima di inviare qualsiasi cosa.

Gli identificatori delle regole sono esclusi di proposito: una regola che hai scritto tu può avere qualsiasi nome, compreso quello della tua azienda, di un host o di una persona.

Gli eventi vengono consegnati a DefectDojo con la chiave di licenza della tua istanza, ed è così che il servizio di intelligence li accetta. La chiave viaggia con la consegna, non all'interno degli eventi.

L'ID del contributore consente al servizio di intelligence di contare quante istanze diverse hanno visto un CVE nell'arco di un mese. Viene generato in modo casuale, sostituito ogni mese da uno nuovo, e quello vecchio non può essere ricavato da quello nuovo.

Vengono inviati solo i rilevamenti successivi all'attivazione della condivisione e risalenti alle ultime 24 ore. Disattivare la condivisione elimina ogni evento ancora in attesa di invio e scarta l'ID del contributore, e lo stesso accade con una modifica della clausola contrattuale. Riattivare la condivisione riparte con un nuovo ID del contributore.

## Prima di poterla attivare

La condivisione è regolata da una clausola del tuo contratto con DefectDojo. La scheda indica la **versione della clausola contrattuale** che accetti attivando la condivisione, e la condivisione non può essere attivata finché quella versione non è disponibile sulla tua istanza.

La clausola contrattuale verrà pubblicata prima che la condivisione diventi disponibile.

Se in seguito DefectDojo pubblica una nuova versione della clausola, la condivisione va in pausa da sola. La scheda lo segnala, gli eventi in attesa con la versione precedente vengono eliminati e non viene inviato nulla finché un superuser non riattiva la condivisione con la nuova versione. Mentre la condivisione è in pausa la casella è inizialmente deselezionata, quindi la nuova versione viene accettata solo selezionandola di nuovo. La condivisione riparte quindi da zero, con un nuovo ID del contributore.

La condivisione non è mai disponibile su un'istanza air-gapped, nella demo pubblica o nella sandbox.

## Attivare o disattivare la condivisione

1. Accedi come superuser e apri **Settings > System Settings**.
2. Scorri fino alla scheda **Sensor Telemetry** in fondo alla pagina.
3. Leggi cosa viene condiviso e la versione della clausola contrattuale indicata dalla scheda. Quando la tua istanza conosce l'indirizzo della clausola, la scheda lo collega accanto alla versione (**Read the contract term**).
4. Seleziona **Share Sensor Hit Events**, quindi **Submit**. Per interrompere, deseleziona la casella e seleziona **Submit**.

Ogni modifica viene registrata nel log di audit insieme all'utente che l'ha effettuata.

## Cosa mostra la scheda

* **Sharing**: Off, On, Paused (la clausola contrattuale è cambiata), On, Not Sending (non è configurato un endpoint di intelligence o una chiave di licenza; la scheda indica quale manca) oppure Not Available.
* **Events Shared**, **Events Waiting** ed **Events Dropped**: quanti eventi sono stati consegnati, sono in coda o sono stati scartati. Un evento che non può essere consegnato viene ritentato per un giorno al massimo e poi scartato.
* **Last Shared**: quando sono stati consegnati eventi l'ultima volta.
* **L'elenco dei CVE**: i CVE osservati dai tuoi sensori, fino ai 200 visti più di recente, con il numero di rilevamenti, quanti sono stati condivisi e quando ciascuno è stato visto per la prima e l'ultima volta. Il titolo della scheda mostra quanti CVE sono stati osservati in totale. Questo elenco viene conservato sulla tua istanza, che la condivisione sia attiva o meno.
* **Seen Elsewhere**: se altre istanze che condividono hanno visto lo stesso CVE. Viene compilato solo mentre la condivisione è attiva e il servizio di intelligence risponde, e solo per i CVE che la tua istanza ha già condiviso: la richiesta nomina il CVE, quindi non viene mai chiesto di un CVE visto solo prima dell'attivazione della condivisione. Altrimenti la riga sotto la tabella spiega perché è vuoto, ad esempio perché sull'istanza non è configurato un endpoint di intelligence o una chiave di licenza.

La scheda compare quando la tua istanza ha sensori, ha osservato un CVE o è stata configurata per la condivisione.

## Configurazione self-hosted

Su un'istanza self-hosted l'operatore imposta queste variabili d'ambiente. Sono tutte vuote per impostazione predefinita, e vuoto significa disattivato.

| Variabile | Scopo |
| --- | --- |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_VERSION` | La versione della clausola contrattuale. Senza di essa la condivisione non può essere attivata |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_URL` | Facoltativa. L'indirizzo HTTPS in cui si può leggere la clausola contrattuale. La scheda lo collega accanto alla versione |
| `DD_SENSOR_TELEMETRY_ENDPOINT` | L'URL di base HTTPS del servizio di intelligence. Senza di essa non viene mai effettuata alcuna chiamata di rete |
| `DD_THREAT_INTEL_LICENSE_KEY` | La chiave di licenza inviata con ogni consegna. Senza di essa non viene effettuata alcuna chiamata di rete |
| `DD_SENSOR_TELEMETRY_SOURCE_RESOLVER` | Facoltativa. Il percorso Python puntato di una funzione che converte un indirizzo di origine pubblico in un paese e un ASN. DefectDojo non include alcun database di paesi o ASN, quindi senza di essa gli eventi non hanno un'origine |
