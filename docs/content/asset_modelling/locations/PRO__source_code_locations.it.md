---
title: Location del codice sorgente
description: Le Code location rappresentano dove risiede nel codice sorgente un riscontro
  di analisi statica e ne registrano la cronologia degli spostamenti man mano che
  il codice evolve
weight: 6
audience: pro
---

**Le Location del codice sorgente** estendono il modello Location all'analisi statica: accanto a URL (DAST) e Dependency (SCA), una location di tipo **Code** descrive dove risiede nel sorgente un riscontro SAST, identificato dal suo **percorso file e numero di riga**.

> Le Location del codice sorgente richiedono la funzionalità Location (Beta). Per abilitare Location sulla propria istanza, contattare [support@defectdojo.com](mailto:support@defectdojo.com).

## Cosa rappresentano

Ogni riscontro statico che segnala un percorso file ottiene una Code location. Il valore canonico della location è `path/to/file.py:42` (o solo il percorso file quando lo strumento non riporta la riga). Come tutte le Location, le code location sono oggetti condivisi: due riscontri sullo stesso file e riga fanno riferimento alla stessa location, e la location porta con sé stati di riferimento per riscontro e per asset.

Le code location sono **gestite dalle scansioni**: vengono create e aggiornate dagli import e dai reimport, non manualmente. Non esiste un'azione "Nuova Location del codice sorgente": lo scanner è la fonte di verità su dove risiedono i riscontri nel codice.

## Dove trovarle

- **All Source Code** nella barra laterale elenca tutte le code location dell'istanza, con lo stesso filtraggio e tagging di URL e Dependency.
- **View Source Code** nel menu Location di un Asset limita l'elenco a un singolo asset.
- La pagina di un riscontro mostra la sua code location attuale e, quando il riscontro si è spostato, la sua **cronologia delle location**.

## Cronologia degli spostamenti

Il codice sorgente si sposta continuamente: i commit spostano i numeri di riga, i refactoring rinominano i file. Quando [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) è abilitato per uno strumento, un riscontro che si sposta mantiene la propria identità, e i suoi riferimenti alla code location ne registrano il percorso:

- Il riferimento del riscontro alla location **precedente** viene mitigato e contrassegnato con *dove si è spostato il riscontro* e *perché è stata effettuata la corrispondenza* (riga più vicina, dataflow, rinomina del file ...).
- Viene creato un riferimento alla **nuova** location, che rimane attivo.

Il risultato è una catena di sostituzioni consultabile — "questo riscontro si trovava in `auth.py:42`, poi in `auth.py:57`, poi in `session.py:31`" — visualizzata come una timeline nella pagina del riscontro. Lo stesso meccanismo di cronologia copre gli spostamenti di URL e gli aggiornamenti di versione delle dipendenze, quindi tutti e tre i tipi di location condividono un'unica interfaccia a timeline.

La cronologia viene registrata a partire dal momento in cui Location viene abilitata sull'istanza. I riscontri spostatisi prima di allora mantengono la loro location attuale; gli spostamenti passati sono stati applicati ma non registrati. Per le istanze con anni di cronologia precedenti alla funzionalità, il [comando di consolidamento del churn](/triage_findings/finding_deduplication/pro__location_drift_matching/#consolidating-historical-churn) può ricostruire i percorsi unendo le catene storiche di chiusura-e-ricreazione.

## Correttezza dello stato

Gli stati dei riferimenti alle code location vengono mantenuti veritieri dal reimport su **ogni** algoritmo di corrispondenza, indipendentemente dal fatto che il drift matching sia abilitato o meno:

- Il riferimento di codice attuale di un riscontro corrispondente viene sincronizzato a ogni reimport, così un riscontro spostato non lascia il proprio vecchio riferimento attivo per sempre.
- La stessa sincronizzazione indipendente dall'impostazione si applica ai riferimenti di dependency: quando la versione del pacchetto di un riscontro SCA viene aggiornata, il riferimento alla vecchia versione viene mitigato invece di rimanere attivo insieme al nuovo.

## Relazione con i campi del riscontro

I campi propri del riscontro `file_path` / `line` rimangono gli scalari autorevoli (sono ciò che filtri, hash e API espongono); la Code location è la vista condivisa e con conteggio dei riferimenti di quella stessa coordinata. Il reimport aggiorna gli scalari in base all'ultima scansione e il meccanismo delle location ne deriva le location: i due non possono disallinearsi.
