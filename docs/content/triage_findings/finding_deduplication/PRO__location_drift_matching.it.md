---
title: Location Drift Matching
description: 'Tieni traccia dei riscontri man mano che le loro posizioni cambiano
  tra un reimport e l''altro: spostamenti di riga, rinomine di file, spostamenti di
  URL e aggiornamenti di versione delle dipendenze non chiudono più i riscontri per
  poi ricrearli'
weight: 6
audience: pro
---

**Corrispondenza degli spostamenti di posizione** consente al reimport di riconoscere come lo **stesso riscontro** un riscontro la cui *posizione* è cambiata. Senza di essa, il reimport abbina i riscontri tramite un hash di identità esatto che include i campi di posizione — quindi ogni spostamento di posizione chiude il riscontro precedente e ne crea uno identico come nuovo:

- Un commit sposta il codice e il **numero di riga** del riscontro cambia.
- Un refactoring **rinomina o sposta il file**.
- L'**URL, la porta o l'host** di un'applicazione web cambia tra una scansione DAST e l'altra.
- Un **aggiornamento di versione** di una dipendenza cambia la versione del pacchetto vulnerabile segnalata da uno strumento SCA.

Ognuno di questi casi produceva in precedenza un riscontro chiuso più un riscontro "nuovo" — perdendo lo stato, le note, il timer SLA, l'accettazione del rischio e il collegamento JIRA sull'originale, e generando falsi allarmi di "nuovo riscontro critico". Con la Corrispondenza degli spostamenti di posizione abilitata, un unico riscontro viene mantenuto: la sua posizione viene aggiornata in base all'ultima scansione e la sua cronologia viene preservata.

> La Corrispondenza degli spostamenti di posizione è una funzionalità di DefectDojo Pro. È **disattivata per impostazione predefinita** e viene abilitata per singolo strumento di sicurezza.

## Abilitazione del tracciamento della posizione

Il tracciamento della posizione viene configurato per singolo strumento in:
**Impostazioni > Flusso di lavoro dei riscontri > Deduplicazione al reimport** (**Impostazioni > Impostazioni Pro > Impostazioni di deduplicazione > Deduplicazione al reimport** nelle istanze che utilizzano ancora il layout di menu precedente)

1. Seleziona lo **strumento di sicurezza**.
2. Imposta l'**algoritmo di deduplicazione** su **Hash Code**. Il tracciamento della posizione si applica solo all'algoritmo Hash Code — gli strumenti con un **ID univoco dallo strumento** affidabile tracciano già gli spostamenti tramite i propri ID stabili e non ne hanno bisogno.
3. Abilita **Traccia i riscontri quando le posizioni cambiano**.

Il salvataggio dell'impostazione avvia automaticamente un nuovo calcolo dell'hash in background per i riscontri esistenti dello strumento (vedi [Abilitazione su dati esistenti](#enabling-on-existing-data-upgrades) di seguito), in modo che i riscontri importati prima dell'attivazione dell'opzione partecipino immediatamente.

## Come funziona la corrispondenza

Con il tracciamento abilitato, la corrispondenza al reimport avviene in due fasi:

1. **Identità stabile.** L'hash di reimport viene calcolato *senza* i campi di posizione volatili (riga, percorso del file, descrizione, nome/versione del componente, endpoint) — quindi l'identità di un riscontro cattura *cos'è* il riscontro, non *dove* si trova attualmente. I riscontri che non si sono spostati continuano a corrispondere esattamente, per primi, e non vengono mai disturbati.
2. **Abbinamento tramite evidenze.** All'interno di ogni gruppo di riscontri che condividono un'identità stabile, un matcher di posizione abbina i riscontri in arrivo con quelli esistenti utilizzando le evidenze di posizione, in passaggi deterministici dal più forte al più debole. Ogni riscontro viene instradato verso un solo matcher in base ai dati di posizione che porta con sé.

### Riscontri di codice (SAST)

| Passaggio | Abbina quando | Note |
|------|-----------|-------|
| Esatto | Stesso file e stessa riga | Vince sempre; un vicino spostato non può mai "rubare" la corrispondenza di un riscontro non spostato |
| Dataflow | Stessi oggetti sorgente/destinazione (`sast_source_object` / `sast_sink_object`) | Per gli strumenti che riportano il dataflow; immune alla rinumerazione delle righe |
| Riga più vicina | Stesso file, numero di riga più vicino | Greedy, dal più vicino in poi; solo stesso file |
| Rinomina file | File diverso | Solo quando rimane esattamente **un** riscontro in arrivo e **uno** esistente — l'ambiguità fallisce in modo sicuro |

### Riscontri URL (DAST)

| Passaggio | Abbina quando |
|------|-----------|
| Esatto | Insieme di endpoint identico |
| Deriva dell'insieme di endpoint | Insiemi di endpoint sovrapposti (endpoint aggiunti/rimossi) |
| Spostamento di porta | Stesso host e percorso, porta diversa |
| Deriva del percorso | Stesso host, percorso simile (similarità reciproca migliore del segmento) |
| Spostamento di host | Host diverso — solo come abbinamento 1×1 non ambiguo, con una protezione per il DNS wildcard |

### Riscontri di dipendenza (SCA)

| Passaggio | Abbina quando |
|------|-----------|
| Esatto | Stesso pacchetto, versione e manifest |
| Aggiornamento di versione | Stesso pacchetto, versione diversa |
| Spostamento del manifest | Stesso pacchetto, percorso di lockfile/manifest diverso |

Quando lo stesso pacchetto vulnerabile compare in **più manifest**, il riscontro di ciascun manifest viene tracciato in modo indipendente — un aggiornamento di versione in un lockfile non inghiotte mai il riscontro proveniente da un altro.

### Rivalutazioni della gravità

Gli strumenti di sicurezza rivalutano la gravità man mano che i loro motori di regole evolvono. Con il tracciamento abilitato, una modifica della gravità segnalata dallo strumento **non** divide l'identità di un riscontro: il riscontro continua a corrispondere e la sua gravità viene aggiornata in base alla scansione — a meno che una persona non abbia ritriagato manualmente la gravità, nel qual caso il valore umano prevale sempre (vedi sotto).

## Cosa viene preservato, cosa viene aggiornato

Un riscontro abbinato tramite lo spostamento di posizione mantiene tutto ciò che conta per il suo ciclo di vita: stato, note, accettazione del rischio, date SLA, collegamento JIRA e il suo ID riscontro.

I suoi **campi di posizione** (percorso del file, riga, campi di dataflow, endpoint, versione del componente) vengono aggiornati in base alla scansione in arrivo.

I suoi **campi descrittivi** (titolo, descrizione, gravità, versione del componente) vengono aggiornati dalla scansione *solo quando la scansione ne è ancora proprietaria*: DefectDojo registra un digest di ciascun campo così come è stato scritto per ultimo da import/reimport. Se il valore attuale corrisponde ancora a quel digest, è stato lo strumento a scriverlo e la scansione può aggiornarlo; se una persona ha modificato il campo nel frattempo, il valore umano viene preservato in modo permanente. I riscontri creati prima di questa funzionalità non hanno digest e vengono trattati come di proprietà umana — il reimport non sovrascriverà mai i loro campi descrittivi. L'unica eccezione è la **versione del componente**, che è telemetria di scansione che le persone in pratica non modificano mai manualmente: viene aggiornata anche senza un digest, quindi i riscontri SCA migrati ricevono comunque gli aggiornamenti di versione.

### L'identità segue sempre il report dello strumento

Quando un riscontro abbinato viene aggiornato, i suoi hash di identità memorizzati vengono **adottati dai valori della scansione in arrivo** — mai ricalcolati dai campi attuali del riscontro. Questa distinzione è importante: dopo un aggiornamento, i campi del riscontro sono una *fusione* di valori della scansione e modifiche umane, e un hash calcolato da questa fusione conterrebbe valori che nessuna scansione riporterà mai più, interrompendo silenziosamente ogni futuro reimport per quel riscontro. L'adozione garantisce che una persona che rinomina un riscontro, ne ritriaga la gravità o ne modifica la descrizione non possa mai comprometterne la capacità di corrispondere alla scansione successiva.

## Cronologia delle posizioni

In **Posizioni** (Beta), ogni corrispondenza di spostamento registra dove viveva prima il riscontro: la posizione del codice sorgente sostituita, l'URL o la versione della dipendenza vengono conservati come riferimento sul riscontro, con l'indicazione di dove si sono spostati e perché. La cronologia temporale della posizione del riscontro — "questo riscontro si trovava in `auth.py:42`, poi in `auth.py:57`, poi in `session.py:31`" — è visibile nella pagina del riscontro. Vedi [Posizioni del codice sorgente](/asset_modelling/locations/pro__source_code_locations/).

La Corrispondenza degli spostamenti di posizione funziona di per sé **con o senza** la funzionalità Posizioni: la corrispondenza si basa sui campi e sugli endpoint propri del riscontro, quindi i riscontri sopravvivono allo spostamento in entrambi i casi. Posizioni aggiunge in più la cronologia registrata e visibile. La registrazione della cronologia inizia dal momento in cui Posizioni viene abilitata — gli spostamenti precedenti sono stati applicati ma non registrati.

## Abilitazione su dati esistenti (aggiornamenti)

La funzionalità è progettata per auto-migrarsi:

- **Nulla cambia finché non la attivi.** Con l'opzione disattivata, gli hash di reimport vengono calcolati esattamente come prima.
- **Il salvataggio dell'opzione ricalcola l'hash dei riscontri esistenti.** Il job in background ricalcola gli hash di reimport memorizzati dello strumento con la nuova identità (priva di posizione) e crea eventuali record di riscontro Pro mancanti per i dati migrati dall'open source. Una volta completato, i riscontri vecchi e nuovi parlano lo stesso linguaggio di identità — un riscontro importato mesi fa viene tracciato esattamente come uno importato ieri.
- **Attiva l'opzione tra un'esecuzione di scansione e l'altra sulle istanze di grandi dimensioni.** Il ricalcolo dell'hash è un job in background sull'intera popolazione di riscontri dello strumento. Un reimport che arriva mentre è ancora in corso può vedere un mix di hash vecchi e nuovi e rielaborare una volta la porzione non ancora processata. Attiva l'opzione in un momento di calma e lascia terminare il job prima del prossimo reimport pianificato.
- **Titoli modificati manualmente.** Il ricalcolo dell'hash su base opzionale utilizza i valori attuali del database. Ogni campo comunemente modificato è escluso dall'identità tracciata — le modifiche alla gravità vengono di fatto *sanate* dal ricalcolo — ma se una persona ha rinominato il **titolo** di un riscontro (e il titolo è un campo hash per quello strumento), quel singolo riscontro verrà rielaborato una volta al reimport successivo prima di stabilizzarsi.

## Scelta dei campi hash per gli strumenti tracciati

Il tracciamento della posizione rimuove automaticamente i campi di posizione volatili dall'hash di reimport — non è necessario rimuovere manualmente `line` o `file_path` dalla configurazione dell'hash di uno strumento. Due configurazioni meritano attenzione:

- **Configurazioni interamente volatili.** Se i campi hash di uno strumento sono *interamente* campi di posizione (ad esempio solo `file_path` + `line`), rimuoverli non lascia nulla, e l'hash ricade sull'identità legacy titolo+CWE. La corrispondenza continua a funzionare — i passaggi basati su evidenze mantengono la discriminazione — ma l'identità è molto più grezza. Preferisci configurazioni che mantengano almeno un campo di contenuto stabile.
- **Posizione incorporata in campi stabili.** Le esclusioni di campo non aiutano quando i dati di posizione si nascondono *dentro* un campo che deve rimanere nell'hash. Uno strumento che intitola i riscontri "SQL Injection in queries.py:42" cambia il titolo a ogni spostamento di riga — l'identità si divide e il tracciamento non riesce a vedere l'abbinamento. Per questi strumenti, scegli campi hash che evitino il campo che perde informazioni; **CWE + Content Fingerprint** è la combinazione più solida (vedi [Content Fingerprint](/triage_findings/finding_deduplication/pro__deduplication_tuning/#content-fingerprint)).

## Interazione con la deduplicazione

Il tracciamento della posizione è una funzionalità del **reimport**: la deduplicazione Same Tool e Cross Tool restano invariate — i loro hash vengono calcolati esattamente come prima e le esclusioni non si applicano mai a esse. Due integrazioni deliberate:

- **Gli aggiornamenti di versione non bloccano più la deduplicazione delle dipendenze.** La barriera di posizione della deduplicazione normalmente richiede che due riscontri SCA facciano riferimento alla *stessa identica* versione del pacchetto. Per gli strumenti con tracciamento abilitato, è sufficiente un'identità di pacchetto condivisa (ecosistema + nome del pacchetto, con il namespace confrontato ogni volta che entrambe le parti lo riportano) — coerentemente con il fatto che il reimport tratta un aggiornamento di versione come lo stesso riscontro. Questo si applica solo alla deduplicazione Same Tool sotto Posizioni.
- **Input di identità puliti.** Poiché i riscontri abbinati adottano gli hash riportati dalla scansione, i valori consumati dalla deduplicazione riflettono sempre ciò che lo strumento ha riportato per ultimo — le modifiche umane non possono più contaminarli.

## Consolidamento del churn storico

Le istanze rimaste in funzione per anni senza tracciamento accumulano catene di chiusura-e-ricreazione: lo stesso riscontro chiuso e riaperto come nuovo record ogni volta che si spostava. Un comando di gestione individua queste catene (collegate passo dopo passo dagli stessi matcher, con una protezione di sovrapposizione del ciclo di vita in modo che i riscontri realmente coesistiti non vengano mai uniti) e consolida ciascuna catena sul suo riscontro più recente, contrassegnando le copie più vecchie come duplicati del sopravvissuto:

```bash
# Dry run — reports what would be consolidated, changes nothing
./manage.py consolidate_location_churn --product <id>

# Apply, with a confirmation prompt
./manage.py consolidate_location_churn --product <id> --apply
```

Il comando è dry-run per impostazione predefinita, non viene mai eseguito automaticamente e può essere delimitato con `--test` o `--product`. In Posizioni, la cronologia della posizione del sopravvissuto viene ricostruita a partire dalla catena.

## Protezioni e limiti

- **Le corrispondenze esatte vincono sempre.** Un riscontro non spostato viene abbinato esattamente prima che venga eseguito qualsiasi passaggio approssimato; i riscontri spostati non possono mai rubargli la corrispondenza.
- **L'ambiguità fallisce in modo sicuro.** Le rinomine di file e gli spostamenti di host vengono abbinati solo quando rimane esattamente un candidato per ciascuna parte. Due riscontri scomparsi entrambi mentre ne compaiono due nuovi restano non abbinati anziché essere indovinati.
- **I gruppi molto grandi si degradano in modo controllato.** Se un singolo bucket di identità supera il limite di abbinamento (40.000 confronti), la corrispondenza si degrada al solo abbinamento esatto per quel bucket invece di consumare tempo illimitato.
- **Compromesso accettato:** i passaggi 1×1 di rinomina/spostamento host possono creare una falsa continuità quando un riscontro scompare e un riscontro non correlato con la stessa identità stabile compare nello stesso reimport. Questo è il prezzo deliberato del tracciamento delle rinomine; l'identità stabile (stesso strumento, titolo, CWE, gravità...) limita quanto possa essere sbagliato l'abbinamento.

## Aggiornamento della posizione senza l'opzione attiva

Indipendentemente dal tracciamento della posizione, il reimport mantiene aggiornata la posizione di ogni riscontro abbinato su **tutti** gli algoritmi: un riscontro abbinato tramite ID univoco dallo strumento (o qualsiasi altro algoritmo) aggiorna i propri `line`, `file_path`, campi di dataflow e `component_version` in base al report in arrivo, e gli endpoint riportati vengono collegati mentre quelli scomparsi vengono mitigati. I valori che una scansione omette non sovrascrivono mai i dati esistenti, e una versione del componente fissata manualmente viene preservata. Questo chiude la lacuna di lunga data per cui i riscontri SAST abbinati tramite uid mostravano per sempre il numero di riga del loro primo import. Può essere disabilitato a livello di istanza con `DD_REIMPORT_REFRESH_LOCATION_FIELDS=False`.
