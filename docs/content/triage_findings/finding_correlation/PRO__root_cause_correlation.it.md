---
title: Correlazione delle cause radice
description: Raggruppa i Riscontri che condividono una causa radice — lo stesso componente
  vulnerabile, la stessa CVE, la stessa risorsa infrastrutturale o la stessa debolezza
  a un URL — in modo che una singola correzione possa essere ricondotta a ogni Riscontro
  che risolve
weight: 1
audience: pro
---

Una libreria vulnerabile inclusa in quaranta servizi produce quaranta Riscontri. Ognuno è reale, ognuno
viene sottoposto a triage separatamente, ed ognuno viene risolto dallo stesso identico aggiornamento
di versione. La **Correlazione delle cause radice** rende esplicita questa relazione: DefectDojo Pro
raggruppa i Riscontri che condividono una causa radice in un elenco classificato di **Cause radice**,
così da poter vedere l'unica correzione e tutto ciò che essa risolve.

La correlazione è **additiva e non distruttiva**. Ogni Riscontro rimane visibile in modo indipendente,
mantiene il proprio stato ed è sottoposto a triage esattamente come prima. La correlazione si limita ad
aggiungere collegamenti tra i Riscontri, i nodi cluster in cui questi collegamenti confluiscono, e le
prove che hanno prodotto ciascun collegamento.

> **La correlazione non è deduplicazione.** La [Deduplicazione](/triage_findings/finding_deduplication/)
> stabilisce che due report descrivono lo *stesso* Riscontro e ne contrassegna uno come duplicato. La
> correlazione mette in relazione Riscontri *diversi* che condividono una causa, e non contrassegna mai
> nulla come duplicato. Le due funzionalità operano in modo indipendente e possono essere entrambe
> abilitate.

## Abilitare la Correlazione delle cause radice

La Correlazione delle cause radice è in **Beta**, è controllata da un feature flag ed è **disattivata
per impostazione predefinita**. Un superuser può attivarla da **Impostazioni > Feature Flags**, sia
sulle istanze Cloud che On-Premise. Vedere [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Quando il flag è disattivato, il motore non esegue alcuna operazione: non vengono creati cluster, non
vengono creati collegamenti e non viene avviato nulla dopo un import.

Dopo aver attivato il flag, i Riscontri esistenti **non** vengono correlati retroattivamente finché non
vengono reimportati o finché non si esegue un backfill (vedere
[Backfilling dei Riscontri esistenti](#backfilling-existing-findings)).

## Cosa viene correlato

La correlazione raggruppa in base a quattro segnali. Tre di essi sono **esatti** — un collegamento
viene creato solo quando due Riscontri indicano realmente la stessa cosa — e uno è un'euristica
etichettata come tale.

| Tipo di causa radice | I Riscontri vengono raggruppati quando... | Esempio | Corrispondenza |
|---|---|---|---|
| **Component** | fanno riferimento allo stesso componente software alla stessa versione | `log4j-core 2.14.1` | Esatta |
| **CVE** | fanno riferimento allo stesso identificativo CVE | `CVE-2021-44228` | Esatta |
| **Resource** | indicano lo stesso oggetto infrastrutturale | `aws_s3_bucket.logs` | Esatta |
| **Endpoint** | segnalano la stessa classe di debolezza allo stesso URL | `CWE-79 at example.com/search` | Euristica |

Un Riscontro entra a far parte di **ogni** cluster che gli si applica, non solo di uno. Un Riscontro SCA
per `log4j-core 2.14.1` che porta con sé tre CVE entra a far parte di quattro Cause radice: il suo
cluster di componente e un cluster per ciascuna CVE. È proprio questo che consente a un Riscontro di
un'immagine container che segnala solo una CVE di correlarsi con il Riscontro SCA che segnala il
componente.

### Corrispondenza dei componenti

Dove è in uso il modello dati Locations, i componenti vengono identificati tramite il **Package URL
(purl)**, privato di qualificatori e sottopercorsi, in modo che lo stesso pacchetto segnalato su
distribuzioni o architetture diverse formi un unico cluster anziché più cluster separati. I Riscontri
che riportano solo i campi legacy `component_name` / `component_version` vengono invece identificati
tramite questi ultimi.

I Riscontri privi di un componente utilizzabile vengono esclusi anziché raggruppati: una versione
mancante, o il segnaposto `unknown-package` emesso da alcuni formati SBOM, farebbe altrimenti confluire
ogni riga priva di componente in un unico cluster privo di significato.

### Corrispondenza delle CVE

Gli identificativi CVE vengono convertiti in maiuscolo e ripuliti, così `cve-2021-44228` e
`CVE-2021-44228` finiscono nello stesso cluster. Solo gli identificativi CVE vengono utilizzati per la
corrispondenza — GHSA, GO, RUSTSEC e altri prefissi di advisory sono riconosciuti come id di
vulnerabilità altrove in DefectDojo, ma non formano ancora Cause radice.

### Corrispondenza delle risorse

Gli strumenti di cloud posture (CSPM) e infrastructure-as-code (IaC) segnalano una **risorsa** anziché
un pacchetto: un bucket S3, un namespace Kubernetes, un blocco di risorsa Terraform. Questi Riscontri
riportano un nome ma nessuna versione, quindi non sono componenti software e non vengono confrontati
come tali.

La corrispondenza delle risorse le raggruppa in base all'identificativo della risorsa, normalizzato per
maiuscole/minuscole in modo che strumenti che lo scrivono in modo diverso concordino comunque. Si
tratta di una corrispondenza esatta, ed è ciò che consente a un Riscontro IaC relativo a
`aws_s3_bucket.logs` di trovarsi nella stessa Causa radice del Riscontro CSPM a runtime relativo al
bucket effettivamente distribuito.

Vengono confrontati solo gli identificativi qualificati — un nome di risorsa contiene un separatore di
tipo o di percorso (`.`, `/`, `:`). Una singola parola isolata viene ignorata, in modo che un Riscontro
il cui scanner ha semplicemente omesso la versione del componente non venga trascinato in un cluster di
risorse con cui non ha nulla a che fare.

### Corrispondenza degli endpoint

Due strumenti DAST che analizzano la stessa applicazione spesso segnalano entrambi la stessa debolezza
allo stesso URL. La corrispondenza degli endpoint li raggruppa: la Causa radice è una **classe di
debolezza in una posizione**, ad esempio `CWE-79 at example.com/search`.

Questo è l'unico segnale **euristico**, ed è etichettato come tale ovunque compaia. Un purl o una CVE
condivisi rappresentano un'identità; "stesso CWE, stesso URL" è invece una valutazione, e un revisore
deve poterla soppesare diversamente. Il dettaglio del cluster contrassegna ogni membro con il proprio
tipo di corrispondenza.

Il CWE è obbligatorio. Un URL da solo è un luogo, non una causa — raggruppare ogni Riscontro su
`/search` a prescindere da cosa non va produrrebbe cluster grandi e privi di significato.

Query string, frammenti e porte vengono ignorati nel confronto degli URL, quindi `/search?q=a` e
`/search?q=b` rappresentano lo stesso luogo, così come lo stesso servizio sulle porte 443 e 8443.

> **Questo non correla SAST con DAST.** I riscontri statici identificano un file sorgente mentre i
> riscontri dinamici identificano un URL; la mappatura tra i due richiede una mappa dei percorsi che
> DefectDojo non possiede. La corrispondenza degli endpoint mette in relazione i riscontri dinamici tra
> loro.

### Quando una CVE è già coperta da un componente

Un Riscontro entra a far parte sia della sua causa di tipo componente *sia* di ciascuna delle sue cause
di tipo CVE, quindi un Riscontro SCA per `log4j-core 2.14.1` che porta con sé due CVE produce tre Cause
radice. Lasciate a sé stanti, tutte e tre competerebbero per la cima dell'elenco classificato — ma solo
una di esse rappresenta un effettivo lavoro da svolgere. Aggiornare `log4j-core` a una versione
corretta risolve entrambe le CVE in un colpo solo; non esiste un'azione separata di "correggere
CVE-2021-44228".

Per questo motivo una Causa radice di tipo CVE viene contrassegnata come **coperta** quando *ogni*
Riscontro membro attivo è anche membro attivo di un'unica causa di tipo componente o risorsa. Le cause
coperte sono nascoste per impostazione predefinita dalla pagina delle Cause radice, mantenendo l'elenco
limitato a ciò su cui si può effettivamente agire.

Nel momento in cui **un** membro si trova al di fuori di quel componente, la CVE torna a essere
autonoma. È il caso del Riscontro di un'immagine container che segnala solo una CVE senza alcun
componente associato: nessuna correzione del componente la raggiunge, quindi la CVE rappresenta un
lavoro effettivamente separato. Questo è esattamente il caso trasversale che la correlazione esiste per
far emergere, e non viene mai nascosto.

Attivare **Mostra CVE coperte** sopra la tabella per visualizzarle. Ciascuna è etichettata con la causa
che la copre, così è chiaro quale correzione la risolve. Le cause coperte sono nascoste solo
dall'elenco predefinito — mantengono i propri membri, le prove e il feedback, restano raggiungibili dal
pannello delle Cause radice di un Riscontro, e un collegamento salvato verso una di esse continua a
funzionare.

La copertura viene rivalutata a ogni esecuzione, in entrambe le direzioni: una CVE smette di essere
coperta non appena compare un Riscontro non coperto, e torna a essere coperta una volta che quel
Riscontro viene risolto o allontanato tramite triage. Il rifiuto di un collegamento esclude anche quel
membro dal calcolo, poiché si è dichiarato che non appartiene al cluster.

Le cause di tipo componente e risorsa non vengono mai contrassegnate come coperte, anche quando i loro
membri si sovrappongono a quelli di un'altra. Ciascuna ha una propria versione da aggiornare, quindi
ciascuna rappresenta un lavoro reale.

### Quali Riscontri sono idonei

Vengono correlati solo i Riscontri attivi e attuabili. Un Riscontro viene escluso quando è inattivo,
mitigato, duplicato, un falso positivo, fuori ambito, o a rischio accettato. I Riscontri escono dai
propri cluster man mano che vengono sottoposti a triage, quindi i conteggi di una Causa radice
descrivono sempre il lavoro ancora da svolgere.

## Lettura della pagina delle Cause radice

Aprire **Cause radice** nella sezione **Gestisci** della barra laterale. La pagina elenca ogni Causa
radice a cui si ha accesso, classificate in modo che le più ampie e rischiose compaiano per prime.

| Colonna | Cosa indica |
|---|---|
| **Root Cause** | Il componente e la versione, oppure la CVE |
| **Type** | Component, CVE, Resource o Endpoint |
| **Fix** | La versione che risolve il problema, quando i membri del cluster concordano su una |
| **CVEs** | Ogni CVE riscontrata tra i membri del cluster (cluster di componenti) |
| **Active Findings** | Quanti Riscontri in sospeso questa singola causa rappresenta |
| **Products** | Raggio d'impatto — quanti Prodotti sono interessati |
| **Risk** | Rischio aggregato, sommato dalle gravità dei membri attivi |
| **Muted** | Se il cluster è stato silenziato |

Le cause di tipo CVE già interamente coperte da una causa di tipo componente o risorsa sono nascoste a
meno che **Mostra CVE coperte** non sia attivo; vedere
[Quando una CVE è già coperta da un componente](#when-a-cve-is-already-covered-by-a-component).

Selezionando una riga si apre il cluster, che elenca ogni Riscontro membro con la sua gravità, il
Prodotto, il dominio, il tipo di **corrispondenza** e la **prova** che lo collega. Le prove vengono
registrate per ogni collegamento, così un cluster può sempre spiegare sé stesso: un collegamento di
componente registra il purl su cui si basa la corrispondenza, un collegamento CVE registra
l'identificativo, un collegamento endpoint registra l'URL e il CWE. La colonna **Match** riporta
`exact` per i collegamenti di componente, CVE e risorsa, e `heuristic` per i collegamenti endpoint,
così una valutazione non viene mai presentata come un'identità.

Il rischio aggregato è una somma deterministica delle gravità dei membri attivi (Critica 100, Alta 70,
Media 40, Bassa 10, Info 1). Non dipende dall'abilitazione del motore di prioritizzazione.

**Fix** viene ricavato dalle versioni di correzione riportate dai singoli membri, e viene mostrato solo
quando tutti i membri che ne riportano una riportano la stessa. Gli scanner non sempre concordano, e un
cluster di CVE può comprendere componenti ciascuno risolto a una versione diversa, quindi quando non
esiste una risposta univoca la colonna viene lasciata vuota anziché sceglierne una a caso.

### Ciò che si vede è limitato al proprio accesso

Membri, conteggi e raggio d'impatto vengono filtrati in base ai Riscontri che si è autorizzati a
vedere, e la classifica viene calcolata dopo tale filtraggio. Due utenti con accesso diverso ai
Prodotti vedranno quindi conteggi diversi per la stessa Causa radice, e un cluster i cui membri non si
possono vedere non compare affatto.

## Dove altro compare la correlazione

### Su un Riscontro

La pagina di ciascun Riscontro presenta un pannello **Root Causes** che elenca ogni cluster a cui
appartiene, suddiviso tra il componente vulnerabile (o la risorsa) e le CVE che condivide. È di solito
qui che la correlazione risulta più utile: si sta già effettuando il triage di un Riscontro ed essa
indica che la correzione è condivisa. I collegamenti che sono stati rifiutati non ricompaiono qui.

### Nella priorità dei riscontri

Una Causa radice che si estende su molti Prodotti rende ciascuno dei suoi Riscontri membri più
urgente, perché l'unica correzione li risolve tutti. La priorità cresce quindi in base al **raggio
d'impatto della Causa radice più ampia a cui un Riscontro appartiene**:

- Un cluster limitato a un solo Prodotto non aggiunge nulla — non esiste una storia del tipo "una
  correzione ne risolve molte".
- Ogni Prodotto interessato aggiuntivo aggiunge un piccolo contributo in più, fino a un limite massimo,
  in modo che un cluster molto ampio non possa prevalere sulla gravità.
- Conta il cluster più ampio, non la somma di tutti, in modo che un Riscontro non venga fatto salire di
  priorità solo perché porta con sé molti id CVE.
- I collegamenti che sono stati **rifiutati** smettono di contare. Un cluster **silenziato** continua
  invece a contare: il silenziamento lo nasconde dall'elenco classificato, ma non significa che i
  Riscontri non siano correlati.

Il peso è regolabile per Prodotto tramite il moltiplicatore **Correlation** nel motore di
prioritizzazione, insieme a Severity, Exploitability, Endpoints e Reachability. L'intero termine
scompare quando il feature flag è disattivato, quindi i punteggi restano invariati su un'istanza che
non utilizza la correlazione.

### Su una dashboard

**Top Root Causes** è disponibile come widget della dashboard, ed elenca i cluster con la classifica
più alta insieme ai relativi conteggi di riscontri, Prodotti interessati e rischio. Aggiungerlo dal
selettore dei widget; compare lì solo mentre la funzionalità è abilitata. I suoi conteggi sono limitati
al proprio accesso allo stesso modo della pagina.

## Fornire feedback su un cluster

La correlazione è una valutazione sui propri dati, quindi è possibile correggerla.

- **Confermare** un membro per registrare che il collegamento è corretto.
- **Rifiutare** un membro per registrare che non lo è, il che lo rimuove dall'elenco dei membri attivi
  del cluster.
- **Silenziare** un'intera Causa radice per evitare che competa per l'attenzione nell'elenco
  classificato. **Riattivare** la ripristina.

Il feedback è duraturo. Il normale avvicendamento dei reimport — un Riscontro che viene mitigato e
successivamente riattivato — non cancella una conferma o un rifiuto, e un cluster silenziato non viene
mai ripulito anche quando temporaneamente non ha membri. Solo i collegamenti creati autonomamente dal
sistema vengono rimossi per riconciliazione quando smettono di essere applicabili.

## Come e quando viene eseguita la correlazione

La correlazione viene eseguita **automaticamente e in modo asincrono dopo ogni import e reimport**, sui
Riscontri interessati dall'import. È un processo best-effort: un errore all'interno della correlazione
viene registrato e assorbito, e non fa mai fallire l'import che lo ha innescato.

Essendo idempotente, rieseguirla sugli stessi Riscontri converge sullo stesso risultato anziché
duplicare qualcosa. Man mano che i Riscontri cambiano, il motore effettua anche una riconciliazione: un
aggiornamento della versione di un componente sposta il Riscontro nel nuovo cluster ed elimina quello
vecchio una volta che è vuoto.

### Backfilling dei Riscontri esistenti

Per correlare i Riscontri precedenti all'abilitazione della funzionalità, eseguire il comando di
gestione. Omettere l'argomento per ricalcolare l'intero portfolio, oppure limitarlo a un singolo
Prodotto:

```bash
python manage.py recompute_correlations
python manage.py recompute_correlations --product-id 42
```

## Cosa espone l'API

Le Cause radice sono leggibili tramite l'API standard, così è possibile inserirle in un report, aprire
ticket a partire da esse, o tracciarle come metrica senza passare dall'interfaccia utente.

- `GET /api/v2/root_causes/` le elenca, classificate nello stesso modo della pagina.
- `GET /api/v2/root_causes/{id}/` restituisce una Causa radice insieme ai suoi Riscontri membri,
  ciascuno con la prova che lo collega e con l'indicazione se la corrispondenza sia stata esatta o
  euristica.

Entrambi sono di sola lettura. Per ora la conferma, il rifiuto e il silenziamento vengono effettuati
dall'interfaccia utente; queste operazioni non vengono deliberatamente pubblicate finché la
funzionalità è in Beta, in modo che aggiungerle in seguito non possa interrompere nulla di ciò che è
già stato costruito basandosi su di esse.

Filtri sull'elenco: `cause_type` (`exact` o `in`), `muted`, `identity_key` (`exact` o `icontains`) e
`display_name__icontains`.

Due comportamenti utili da conoscere prima di scrivere script che li utilizzino:

- **I conteggi sono limitati all'accesso del token**, esattamente come nell'interfaccia utente. Due
  token con accesso diverso ai Prodotti riporteranno valori diversi di `active_member_count`,
  `product_count` e `risk_score` per la stessa Causa radice. Questo è intenzionale — i numeri
  descrivono ciò che *quel* chiamante può vedere — quindi non vanno considerati come totali riferiti
  all'intero portfolio.
- **Le cause di tipo CVE coperte vengono escluse dall'elenco**, ma sono sempre recuperabili tramite id.
  Passare `?include_subsumed=true` per includerle; un id di Causa radice memorizzato in precedenza
  continua a funzionare tramite `GET /api/v2/root_causes/{id}/` anche dopo che diventa coperta. Ogni
  causa coperta porta con sé `subsumed_by_id` e `subsumed_by_name`, così è possibile vedere quale
  correzione la risolve.

Se il feature flag è disattivato, entrambi gli endpoint restituiscono **403**, non 404 — l'endpoint
esiste, semplicemente non è abilitato.

## Interazione con la Deduplicazione globale dei componenti

La [Deduplicazione globale dei componenti](/triage_findings/finding_deduplication/pro__global_component_deduplication/)
contrassegna come duplicati i Riscontri SCA cross-Prodotto, e i duplicati non vengono correlati. Con
entrambe le funzionalità attive, il conteggio dei membri di una Causa radice riflette quindi gli
originali sopravvissuti anziché ogni singola occorrenza. Le due funzionalità si basano inoltre su
elementi diversi — la Deduplicazione globale dei componenti confronta nome e versione del componente,
mentre la correlazione utilizza il Package URL completo — quindi abilitarle entrambe è supportato, ma i
conteggi che producono non sono direttamente comparabili.
