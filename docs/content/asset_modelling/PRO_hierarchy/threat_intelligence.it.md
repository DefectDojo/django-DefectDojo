---
title: Threat Intelligence
description: Evidenze di exploit e minacce come input di primo livello per Priorità
  e Rischio
weight: 2
audience: pro
---

DefectDojo Pro arricchisce i tuoi riscontri con **Threat Intelligence dedicata** — disponibilità di
exploit, sfruttamento noto e attività di threat actor — e la integra nel calcolo di Priorità
e Rischio. Questo va ben oltre EPSS e il flag CISA KEV.

## Cosa ottieni

Ogni riscontro con un CVE viene confrontato, ogni notte, con un feed di intelligence curato costruito
a partire da CISA KEV, Metasploit, Exploit-DB, template Nuclei e monitoraggio pubblico dei
proof-of-concept. Quando è presente un’evidenza di exploit, il riscontro mostra una scheda **Threat Intelligence**:

* un badge di **maturità dell’exploit** — *Nessuna → PoC → Weaponized → Attivo in the wild*
* un **punteggio di minaccia** (0–100)
* **chip di evidenza che rimandano alla fonte** — la voce KEV (con la relativa data di inserimento),
  l’uso in ransomware, un modulo Metasploit, una voce Exploit-DB, un template Nuclei e
  repository pubblici di proof-of-concept
* una riga in linguaggio semplice che spiega **perché** la priorità del riscontro è aumentata

Oltre alla scheda, l’intelligence è una superficie di lavoro in tutta l’app:

* una **colonna Maturità dell’Exploit** nell’elenco dei riscontri — ordinabile e filtrabile
  (ad esempio, “solo Weaponized o Attivo”)
* un riquadro **“Urgente e Attivamente Sfruttato”** nella dashboard Priority Layout, che conta i
  riscontri a rischio Urgente attivi con sfruttamento in the wild — cliccandoci sopra si apre l’elenco
  esatto dei riscontri filtrati
* un **evento di notifica** (`threat_intel_alert`) quando il CVE di un riscontro esistente acquisisce nuova
  evidenza di exploit, ad esempio entrando nel CISA KEV o ottenendo un modulo Metasploit. Solo
  aggiornamenti al rialzo — un’evidenza che invecchia silenziosamente non genera mai una notifica.

## Riscontri segnalati con un ID di advisory GitHub {#findings-reported-by-a-github-advisory-id}

Alcuni scanner segnalano una vulnerabilità solo con il suo ID di advisory GitHub (GHSA), non con il
CVE a cui corrisponde. Quando DefectDojo sa che l’advisory e un CVE descrivono la stessa vulnerabilità,
in base al bundle di intelligence o a un collegamento registrato sulla tua istanza, il riscontro riceve
la maturità dell’exploit, l’evidenza e il punteggio di minaccia di quel CVE, come un riscontro che
indica direttamente il CVE. Il riscontro mantiene il proprio ID di vulnerabilità.

Quando un advisory viene collegato per la prima volta a un CVE, o un collegamento viene rifiutato,
DefectDojo ricalcola il punteggio dei riscontri interessati. I riscontri che erano già sulla tua istanza
prima dell’introduzione di questo comportamento vengono ricalcolati una sola volta, in background, dopo
il primo caricamento del bundle successivo all’aggiornamento.

## Come cambia il punteggio

Il motore di Priorità combinava già gravità, contesto di business e un “punteggio esterno”
costruito da EPSS + KEV. La Threat Intelligence generalizza questo punteggio esterno: ogni tipo di
evidenza di exploit agisce come una soglia minima sulla scala EPSS.

| Evidenza | Soglia minima di Priorità (equivalente EPSS) |
|---|---|
| Sfruttamento attivo + ransomware/attore nominato | 45% |
| Nel CISA KEV **e** utilizzato in ransomware | 30% |
| Nel KEV o sfruttato in the wild | 20% |
| Exploit pubblico weaponized (Metasploit / Exploit-DB) | 15% |
| Esiste un template di rilevamento Nuclei | 12% |
| Solo proof-of-concept pubblico | 8% |
| Nessuna evidenza di exploit | nessuna modifica |

Il punteggio esterno del riscontro è il **maggiore** tra il suo valore derivato da EPSS e la
soglia minima di evidenza più alta indicata sopra — quindi l’intelligence può solo *aumentare* un
punteggio, mai abbassarlo, e un riscontro il cui EPSS supera già la soglia non viene influenzato. Il familiare
**scalare del punteggio esterno** per tipo di prodotto, nelle impostazioni del tuo Motore di Prioritizzazione, si applica a questo contributo
esattamente come si è sempre applicato a EPSS/KEV.

### La soglia minima di Rischio per elementi attivamente sfruttati

La tabella sopra aumenta la **Priorità**, ma in proporzione alla gravità di base di un riscontro. Questo ha
una conseguenza che vale la pena affermare chiaramente: un riscontro di gravità Bassa che porta un CVE che
viene sfruttato in the wild riceve solo un piccolo incremento assoluto, e potrebbe comunque restare in una fascia
di **Rischio** bassa. La maggior parte dei team considera questo un errore — “attivamente sfruttato” non
dovrebbe mai essere classificato come Basso.

Esiste quindi una seconda regola, categorica. Quando la Threat Intelligence segnala uno
**sfruttamento attivo in the wild**, la Priorità del riscontro viene innalzata almeno al livello di una
fascia di Rischio configurata, indipendentemente da quanto prodotto dal solo calcolo ponderato. Viene fornita
impostata su **Richiede intervento**; ogni tipo di prodotto può alzarla a Urgente, abbassarla, o azzerarla per
disattivare la soglia, nelle impostazioni del Motore di Prioritizzazione sotto *Soglia
minima di Rischio per elementi attivamente sfruttati*.

La soglia agisce solo in aumento — non abbassa mai un riscontro, e un riscontro che ottiene già un
punteggio più alto per conto proprio resta invariato. Poiché si applica alla Priorità, la fascia di Rischio e il
punteggio di Rischio ne conseguono automaticamente, quindi ogni elenco, filtro, grafico e calcolo SLA
vede lo stesso numero coerente.

## Riscontri senza CVE

La Threat Intelligence viene abbinata tramite CVE. Molti riscontri — la maggior parte dei risultati SAST,
secret, configurazioni errate, regole personalizzate — non hanno un CVE, e per essi non esiste da nessuna
parte una threat intelligence a livello di istanza di vulnerabilità (questo vale per qualsiasi fornitore, non solo per DefectDojo).
Questi riscontri:

* mantengono **esattamente** la loro Priorità e il loro Rischio attuali — la funzionalità non abbassa mai un
  punteggio
* continuano comunque a essere prioritizzati da tutti gli altri input del motore (gravità, criticità di business,
  esposizione, e così via)
* mostrano “Nessuna threat intelligence disponibile — questo riscontro non ha un CVE con cui effettuare il confronto” sulla
  scheda, distinto da un riscontro con CVE che semplicemente non ha ancora un exploit noto

Una conseguenza onesta: in una coda mista, man mano che i riscontri con CVE acquisiscono evidenza di exploit,
i riscontri senza CVE scendono in classifica *relativa* anche se il loro punteggio resta invariato.

## Fiducia e stabilità del punteggio

* **Intelligence firmata.** Ogni bundle notturno è firmato crittograficamente da DefectDojo;
  la tua istanza rifiuta dati manomessi o non firmati. Le istanze air-gapped importano lo stesso
  bundle firmato con un passaggio di verifica offline.
* **Nessuna oscillazione del punteggio.** Gli aggiornamenti di evidenza vengono applicati la notte in cui
  compaiono. Se una fonte *perde* un’evidenza, i punteggi restano stabili per una finestra di
  stabilità (14 giorni per impostazione predefinita) — un intoppo del feed non fa mai oscillare la tua coda, e
  le vere de-escalation si assestano silenziosamente al termine della finestra.
* **Supporto air-gapped.** Il bundle giornaliero (inclusi i dati EPSS) può essere trasferito e
  importato offline, in modo che le istanze isolate ricevano lo stesso arricchimento.

## Scheda Intelligence Sources {#intelligence-sources-card}

I superuser possono verificare quale intelligence sta usando l’istanza nella scheda in sola lettura
**Intelligence Sources**, in **Settings > System Settings**. La scheda mostra:

* la versione del bundle caricato
* l’età del bundle, con un avviso quando ha 14 giorni o più
* la data di scadenza del bundle
* ogni fonte contenuta nel bundle, con la sua licenza e quanto sono aggiornati i suoi dati
* l’ultimo caricamento non riuscito, se c’è stato, e il motivo dell’errore
* le attribuzioni delle fonti contenute nel bundle

Un bundle caricato da file su un’istanza air-gapped compare nella stessa scheda.

## Distribuzioni self-hosted

Le istanze DefectDojo Cloud non richiedono alcuna configurazione. Le istanze self-hosted hanno tre opzioni:

* **Connessa (predefinita).** L’istanza scarica ogni notte il bundle firmato da
  `intel.defectdojo.com` via HTTPS. Questa è una destinazione che nessun’altra funzionalità di DefectDojo
  utilizza, quindi di solito deve essere consentita esplicitamente: apri la porta 443 in uscita verso quell’host, e su
  Kubernetes aggiungila alla tua policy di rete in uscita (egress). Nota che il recupero viene eseguito sul **worker
  Celery**, non sul pod web, quindi anche le impostazioni proxy devono raggiungere quel workload.
* **Mirror interno.** Punta `DD_THREAT_INTEL_BUNDLE_URL` (e gli URL corrispondenti di digest e
  firma) verso una posizione all’interno della tua rete che sincronizzi tu stesso. La verifica della firma
  si applica comunque, quindi un mirror non può alterare i dati.
* **Air-gapped.** Trasferisci il bundle e la sua firma manualmente e importali con
  `manage.py load_threat_intel_bundle --file <bundle>`. La firma viene verificata all’importazione.

Se l’istanza non riesce a raggiungere il feed, la funzionalità fallisce in modo controllato: l’esecuzione
viene registrata come fallita e i tuoi punteggi ed evidenze esistenti restano esattamente come erano. Nulla si
degrada tranne la freschezza dell’intelligence.

### KEV ed EPSS dal bundle {#kev-and-epss-from-the-bundle}

Il bundle che un’istanza self-hosted già scarica contiene anche i dati CISA KEV ed EPSS. Dopo ogni
caricamento del bundle, DefectDojo li usa per compilare **Known Exploited (CISA KEV)**, **Ransomware Used
(CISA KEV)**, la data KEV, la data di scadenza CISA KEV e i punteggi EPSS sulle tue vulnerabilità e sui
tuoi riscontri, così li ottieni senza attivare lookup KEV ed EPSS separati. KEV ed EPSS sono gestiti
separatamente, e ciascuno viene compilato dal bundle solo se valgono tutte queste condizioni:

* La Threat Intelligence è attiva.
* Il lookup di quella fonte, in Finding Enrichment nel Tuner, è disattivato. Un lookup attivo ha
  sempre la precedenza, quindi con un solo lookup attivo il bundle fornisce solo l’altra fonte.
* Il bundle contiene dati aggiornati per quella fonte.

Il pulsante **Sync KEV/EPSS Data** nel Vulnerability Explorer, il job giornaliero di arricchimento e
l’arricchimento dei nuovi CVE al momento dell’importazione usano gli stessi dati del bundle, alle stesse
condizioni.

Known Exploited e Ransomware Used indicano che il CVE è presente nel catalogo CISA KEV. Quando uno
scanner, un connettore o una persona segnala una vulnerabilità come sfruttata, la segnalazione viene
conservata come valore separato, **Vendor Reported Exploited**, così non va persa quando CISA non elenca
il CVE. Vedi [Riscontri](/asset_modelling/engagements_tests/pro__findings/#metadata).

#### Il primo caricamento dopo l’aggiornamento {#the-first-load-after-upgrading}

Su un’istanza self-hosted con i lookup KEV ed EPSS disattivati, finora questi valori erano vuoti,
oppure contenevano quanto segnalato da uno scanner. Il primo caricamento del bundle dopo l’aggiornamento
li compila per ogni CVE noto all’istanza, quindi aspettati che:

* **Known Exploited (CISA KEV)**, **Ransomware Used (CISA KEV)** e la data KEV cambino su molti
  riscontri, sia impostati (CISA elenca il CVE) sia azzerati (CISA non lo elenca), e che la Priorità
  si sposti di conseguenza. Un riscontro che uno scanner o una persona ha segnalato come sfruttato
  mantiene la sua Priorità, perché la Priorità legge anche **Vendor Reported Exploited**.
* se una configurazione SLA ha **Cap SLA by CISA KEV Due Date** attivato, i riscontri presenti nel KEV
  abbiano la scadenza SLA anticipata alla data di scadenza CISA. La maggior parte delle date di scadenza
  CISA è già passata, quindi molti di quei riscontri risulteranno in violazione del proprio SLA subito
  dopo il primo caricamento.

## Abilitarla

La funzionalità viene fornita disattivata per impostazione predefinita. Gli amministratori possono abilitarla
direttamente, oppure eseguirla prima in **modalità shadow** — che calcola i punteggi ipotetici senza
modificare nulla in produzione e produce un report di scostamento che mostra esattamente quali riscontri
si sposterebbero — prima di attivarla. Contatta il supporto o consulta il runbook operativo per il rollout
consigliato su istanze di grandi dimensioni.
