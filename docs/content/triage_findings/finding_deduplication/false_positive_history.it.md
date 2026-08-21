---
title: Cronologia dei falsi positivi
description: Contrassegna automaticamente i nuovi Riscontri come falsi positivi quando
  un Riscontro corrispondente era già stato classificato in tal modo
weight: 7
---

**False Positive History** evita al team di dover classificare più volte lo stesso falso positivo. Quando è abilitata e viene importato un Riscontro, DefectDojo cerca Riscontri esistenti nello stesso Prodotto che corrispondano a esso e, se uno di questi è già contrassegnato come **Falso positivo**, anche il Riscontro in arrivo viene contrassegnato come Falso positivo.

> **Questa funzionalità è contrassegnata come EXPERIMENTAL nel prodotto** e **non può essere utilizzata contemporaneamente alla Deduplicazione.** Leggere [Quando è possibile utilizzarla](#when-you-can-use-it) prima di attivarla.

## Cosa fa

Supponiamo che uno scanner segnali un riscontro che il team analizza e contrassegna come falso positivo. A ogni scansione successiva, lo stesso riscontro ricompare. Normalmente qualcuno deve ignorarlo ogni volta. Con False Positive History attivata, DefectDojo riconosce il riscontro che si ripresenta e lo contrassegna automaticamente come Falso positivo.

I Riscontri contrassegnati in questo modo vengono impostati anche su **inattivi** e **non verificati**, non solo su Falso positivo. Questo è intenzionale — il riscontro esce completamente dalla coda attiva — ma può sorprendere chi si aspetta che cambi solo il flag Falso positivo.

La regola che DefectDojo applica è: *all'interno di un Prodotto, se un Riscontro è un falso positivo, lo sono anche tutti i Riscontri corrispondenti.*

### Modalità retroattiva

**Retroactive False Positive History** applica la stessa regola a ritroso. Quando si contrassegna un Riscontro come falso positivo, anche ogni altro Riscontro **Attivo** corrispondente in quel Prodotto viene contrassegnato come Falso positivo.

Questo riscrive i dati esistenti. Non è prevista alcuna anteprima né alcuna richiesta di conferma: la modifica avviene semplicemente su tutto il Prodotto. Attivarla con consapevolezza.

## Quando è possibile utilizzarla

**False Positive History e Deduplicazione sono reciprocamente esclusive.** Le due funzionalità risolvono problemi sovrapposti, quindi DefectDojo non consente di utilizzarle entrambe: nelle System Settings, l'attivazione di una disabilita l'altra, e attivare la Deduplicazione azzera le impostazioni di False Positive History.

Questo è l'aspetto più importante da comprendere riguardo a questa funzionalità. La maggior parte delle istanze utilizza la Deduplicazione, e per queste False Positive History non è disponibile. È pensata per le istanze che hanno scelto deliberatamente di non deduplicare.

## Attivazione

Entrambe le impostazioni si trovano in **System Settings**, nel blocco relativo alla deduplicazione, e sono entrambe **disattivate per impostazione predefinita**:

| Impostazione | Cosa fa |
| --- | --- |
| **Enable False Positive History** | Attiva la funzionalità per l'istanza. |
| **Enable Retroactive False Positive History** | Applica la regola anche a ritroso, come descritto sopra. Richiede l'impostazione precedente. |

Queste impostazioni sono **a livello di istanza**. Non esiste un'opzione di override per singolo Prodotto o per singolo Tool: attivarla influisce su ogni Prodotto dell'istanza.

## Cosa costituisce una corrispondenza

False Positive History decide se due Riscontri sono "lo stesso" utilizzando **l'algoritmo di deduplicazione configurato per il tool che li ha segnalati** — anche se la funzionalità di Deduplicazione vera e propria deve essere disattivata.

| Algoritmo di deduplicazione del tool | I Riscontri corrispondono quando condividono |
| --- | --- |
| **Hash Code** | lo stesso codice hash, calcolato a partire dagli Hash Code Fields configurati per quel tool |
| **Unique ID From Tool** | lo stesso ID univoco proveniente dal tool |
| **Unique ID From Tool or Hash Code** | uno dei due |
| **Legacy** | lo stesso titolo (senza distinzione tra maiuscole e minuscole) e la stessa gravità |

Di conseguenza, l'accuratezza di questa funzionalità dipende interamente dalla qualità della configurazione della deduplicazione per quel tool. **Ottimizzare l'algoritmo e i campi hash del tool prima di attivare False Positive History** — vedere [Deduplication Tuning](/triage_findings/finding_deduplication/pro__deduplication_tuning/) (Pro) oppure [Deduplication Tuning](/triage_findings/finding_deduplication/os__deduplication_tuning/) (Open Source).

La corrispondenza è limitata **all'interno di un Prodotto**. Non si estende mai tra Prodotti diversi e non si applica mai a livello di istanza.

### Corrispondenza basata su insiemi (Pro)

In DefectDojo Pro, la corrispondenza rispetta anche gli **Hash Code Fields basati su insiemi** — i matcher per ID di vulnerabilità e CWE (`vulnerability_ids_partial`, `vulnerability_ids_subset`, `cwes_partial`, `cwes_subset`, e le rispettive forme a corrispondenza esatta), con lo stesso significato che hanno nella deduplicazione.

Questo rende la corrispondenza di Pro **più restrittiva** rispetto a quella di Open Source, ed è proprio questo il punto: senza di essa, False Positive History potrebbe propagare un falso positivo a Riscontri che la deduplicazione con lo stesso tool non avrebbe mai considerato duplicati. Questo affinamento può solo ridurre l'insieme dei Riscontri contrassegnati: abilitare Pro non causerà mai la marcatura automatica di *più* Riscontri.

In Open Source, la corrispondenza utilizza solo il codice hash, quindi è più ampia. Tenerne conto durante l'ottimizzazione.

## Rischi da comprendere prima di attivarla

Questa funzionalità contrassegna i Riscontri come falsi positivi senza che una persona li esamini. Il suo raggio d'azione è determinato dalla configurazione della deduplicazione, quindi una configurazione poco restrittiva è pericolosa.

* **Una chiave di corrispondenza poco restrittiva può ignorare silenziosamente Riscontri non correlati.** L'algoritmo **Legacy** effettua la corrispondenza solo su titolo e gravità — una singola classificazione come falso positivo potrebbe contrassegnare come falso positivo ogni Riscontro con lo stesso titolo e la stessa gravità nel Prodotto, inclusi quelli genuini. Lo stesso vale per un insieme troppo ampio di Hash Code Fields. Restringere prima l'algoritmo.
* **La modalità retroattiva riscrive i Riscontri esistenti** senza anteprima, senza richiesta di conferma e senza un riepilogo di ciò che è stato modificato.
* **I Riscontri vengono disattivati e resi non verificati**, non semplicemente contrassegnati.
* **L'aggiornamento in blocco bypassa la normale elaborazione al momento del salvataggio**, quindi l'automazione che reagisce agli aggiornamenti dei Riscontri potrebbe non attivarsi per i Riscontri modificati in questo modo.
* **È ancora etichettata come EXPERIMENTAL** in DefectDojo stesso.

Per la maggior parte dei team, un approccio più sicuro consiste nel mantenere attiva la Deduplicazione e lasciare che i duplicati ereditino lo stato dal loro Riscontro originale, anziché passare a False Positive History. Vedere [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/).
