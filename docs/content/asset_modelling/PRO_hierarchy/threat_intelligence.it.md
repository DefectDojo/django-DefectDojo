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

## Abilitarla

La funzionalità viene fornita disattivata per impostazione predefinita. Gli amministratori possono abilitarla
direttamente, oppure eseguirla prima in **modalità shadow** — che calcola i punteggi ipotetici senza
modificare nulla in produzione e produce un report di scostamento che mostra esattamente quali riscontri
si sposterebbero — prima di attivarla. Contatta il supporto o consulta il runbook operativo per il rollout
consigliato su istanze di grandi dimensioni.
