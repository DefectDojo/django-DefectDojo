---
title: Casi d'uso comuni
description: Casi d'uso ed esempi
draft: 'false'
weight: 2
chapter: true
aliases:
- /it/en/about_defectdojo/examples_of_use
---

Questo articolo si basa sull'Office Hours di DefectDojo, Inc. di febbraio 2025: “Affrontare i casi d'uso più comuni”.
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=ilRBlfo-wvX5DPVg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Esempi di casi d'uso

DefectDojo è progettato per gestire qualsiasi implementazione di sicurezza, indipendentemente dalle dimensioni del tuo team di sicurezza, dal livello di complessità IT o dal volume di reportistica. Le seguenti storie sono pensate come spunti di partenza per le tue esigenze, ma si basano su esempi reali tratti dalla nostra community e dal team di DefectDojo Pro.

### Grande impresa: RBAC ed Engagement

‘BigCorp’ è una grande azienda multinazionale, con un Chief Information Security Officer (CISO) e un gruppo IT di sicurezza centralizzato che include l'AppSec.

La sicurezza in BigCorp è altamente centralizzata. Alcune attività vengono delegate ai Business Information Security Officer (BISO).

Le principali preoccupazioni di BigCorp sono:

- Definire e mantenere un metodo di test coerente in tutte le unità di business dell'organizzazione
- Soddisfare i requisiti di conformità ed evitare problemi normativi

#### Modello di test

BigCorp gestisce dati di sicurezza provenienti da molte fonti:

- Job CI/CD che eseguono automaticamente strumenti di scansione SAST, SCA e Secret
- Pen test di terze parti per determinati Prodotti
- Audit di conformità PCI per determinati Prodotti

Ognuna di queste categorie di report può essere gestita da un Engagement separato, con un Test distinto per ogni tipo di scansione in DefectDojo.

![immagine](images/example_product_hierarchy_bigcorp.png)

- Se un Prodotto dispone di una pipeline CI/CD, tutti i risultati di quella pipeline possono essere importati continuamente in un unico Engagement aperto. Ogni strumento utilizzato creerà un Test separato all'interno dell'Engagement CI/CD, che può essere aggiornato continuamente con nuovi dati.
(Consulta la nostra guida a [Reimport](/import_data/import_intro/reimport/))
- Ogni attività di Pen Test può avere un Engagement separato creato per contenere tutti i risultati: ad es. “Q1 Pen Test 2024”, “Q2 Pen Test 2024”, ecc.
- È probabile che BigCorp voglia eseguire un proprio audit PCI simulato per essere preparata a quello reale. Anche i risultati di questi audit possono essere archiviati come Engagement separato.

#### Modello RBAC

- Ogni BISO ha accesso in lettura (Reader) assegnato per ciascuna unità di business (Tipo di prodotto) di cui è responsabile.
- Ogni Product Owner ha accesso in scrittura (Writer) per il Prodotto di cui è responsabile.  All'interno del proprio Prodotto, i Product Owner possono interagire con DefectDojo tenendo Note, configurando [pipeline CI/CD](/import_data/import_scan_files/api_pipeline_modelling/), creando Accettazioni del rischio e utilizzando altre funzionalità.
- Gli sviluppatori di BigCorp non hanno alcun accesso a DefectDojo, e non ne hanno bisogno.  Il Product Owner può inviare ticket Jira direttamente da DefectDojo, contenenti tutte le informazioni rilevanti sulla vulnerabilità.  Gli sviluppatori utilizzano già Jira, quindi non devono tracciare la remediation in modo diverso rispetto a qualsiasi altra attività di sviluppo.

### Sistemi embedded: reportistica con controllo di versione

Cyber Robotics è un'azienda che vende hardware di produzione dotato di sistemi software embedded.  Dispone di un Chief Product Officer (CPO) che supervisiona sia il prodotto sia la cybersecurity nel loro complesso.

Sebbene abbiano informazioni di sicurezza meno diversificate da gestire rispetto a BigCorp, è comunque essenziale per loro contestualizzare correttamente le informazioni di sicurezza in modo da poter rispondere in modo proattivo a qualsiasi Riscontro significativo.

Le principali preoccupazioni di Cyber Robotics:

- Hanno una linea di prodotti limitata ma **molte** versioni di ciascun prodotto che devono catalogare correttamente.
- La manutenzione dei loro prodotti è complessa e i costi sono elevati, quindi è necessario evitare lavoro superfluo.

#### Modello di test

Cyber Robotics dispone di un processo di test standardizzato per tutti i propri sistemi embedded:

- Vengono eseguiti test CI/CD, SAST e SCA
- Revisioni dei controlli di sicurezza
- Scansioni di rete
- Revisione del codice da parte di terzi

Tuttavia, poiché ogni versione del loro software è isolata, avranno inevitabilmente molti dati da organizzare, gran parte dei quali è utile solo in un unico contesto (ossia la particolare versione del software in esecuzione).

Cyber Robotics può risolvere questo problema utilizzando i Tipi di prodotto per rappresentare un'unica linea di prodotti e singoli Prodotti per ogni versione separata.  Questo permetterà loro di analizzare nel dettaglio quali Prodotti sono associati a una determinata vulnerabilità.

![immagine](images/example_product_hierarchy_robotics.png)

Assegnare le versioni software ai Prodotti, anziché agli Engagement, consente a Cyber Robotics di limitare l'accesso a una particolare versione del software, se necessario.  Ai tecnici sul campo e al personale di supporto può essere concesso l'accesso a una singola versione del software senza dover dare loro accesso all'intera linea di prodotti.

#### Modello RBAC

Il team AppSec dispone di Ruoli globali assegnati che regolano il proprio livello di interazione.

- Il CPO ha accesso globale in lettura (Global Reader) a DefectDojo, come il CISO in BigCorp.
- I singoli Product Owner hanno accesso globale in lettura (Global Reader) a qualsiasi Prodotto in DefectDojo, oltre all'accesso in scrittura (Writer) al Prodotto di loro proprietà.

Sul lato Supporto:

- Al personale di supporto viene concesso temporaneamente l'accesso in lettura (Reader) ai Prodotti specifici di cui è incaricato di occuparsi, ma non ha accesso a tutti i dati di DefectDojo.

### Ambienti IT dinamici e microservizi: azienda di servizi cloud

Kate's Cloud Service opera in un ambiente in rapida evoluzione che utilizza Kubernetes, microservizi e automazione.  Kate's Cloud Service ha un VP of Cloud che supervisiona le questioni di Cloud Security.  Dispone anche di un CISO che gestisce lo sviluppo software offerto, ma per questo esempio ci concentreremo specificamente sulle loro preoccupazioni relative alla sicurezza cloud.

Kate's Cloud Service ha automatizzato completamente tutta la propria reportistica e importa i dati in DefectDojo non appena i report vengono prodotti.

Principali preoccupazioni di Kate's Cloud Service:

- Gestire la sicurezza cloud multi-tenant, prevenendo l'interazione tra clienti diversi pur consentendo l'erogazione di servizi condivisi.
- Gestire i cambiamenti rapidi nel proprio ambiente cloud.

#### Tag per i servizi condivisi

Poiché il modello di Kate contiene molti servizi condivisi che possono avere un impatto su altri Prodotti, il team applica [Tag](/asset_modelling/tags/os__tagging_objects/) ai propri Prodotti per indicare quali offerte cloud dipendono da quei servizi.  Questo consente di filtrare eventuali problemi relativi ai servizi condivisi tra i Prodotti e di segnalarli ai team competenti.  Ognuno di questi servizi condivisi si trova in un unico Tipo di prodotto che li separa dalle offerte cloud principali.

![immagine](images/example_product_hierarchy_microservices.png)

Poiché l'azienda è in rapida crescita e i tech lead cambiano frequentemente, Kate può utilizzare i Tag per tenere traccia di quale tech lead sia attualmente responsabile di ciascun prodotto cloud, evitando la necessità di aggiornamenti manuali costanti al proprio sistema DefectDojo. Queste associazioni con i tech lead sono tracciate da un servizio esterno a DefectDojo, che può governare le pipeline di importazione o chiamare l'API di DefectDojo.

Per maggiori informazioni sui Tag, consulta la nostra guida ai [Tag](/asset_modelling/tags/os__tagging_objects/).

#### Modello RBAC

Sul lato Sicurezza/Conformità:

- Il team di Product Security proprietario di DefectDojo ha accesso da amministratore all'intero sistema.
- Agli analisti che lavorano per il VP of Cloud viene concesso l'accesso in sola lettura a tutto il sistema, consentendo loro di generare i report e le metriche necessarie affinché il VP possa valutare la sicurezza delle varie offerte cloud.

Sul lato sviluppo:

- I Tech Lead per ciascun prodotto cloud specifico (ad es. compute, storage, servizi condivisi) hanno **accesso Maintainer** al Prodotto loro assegnato per eseguire il triage dei risultati di sicurezza relativi alla loro specifica offerta di prodotto cloud. Possono esaminare i Riscontri e intervenire all'interno del proprio Prodotto, oltre a riorganizzare in modo significativo i dati dei propri Riscontri.
- Agli sviluppatori che lavorano su Prodotti specifici viene concesso l'**accesso Writer** al Prodotto su cui lavorano, che consente loro di commentare i Riscontri, richiedere Peer Review e creare Accettazioni del rischio.

### Onboarding di nuove acquisizioni: SaaSy Software

SaaSy Software è un'azienda in rapida crescita che acquisisce frequentemente altre società di software.  Ogni volta che viene acquisita una nuova azienda, il Direttore of Quality Engineering e il team AppSec si trovano improvvisamente responsabili di molti nuovi repository di codice, sviluppatori e processi.  Il loro modello DefectDojo garantisce che possano mettersi al passo il più rapidamente possibile.

Principali preoccupazioni di SaaSy Software:

- Evitare problemi di sicurezza pubblici mantenendo al contempo i programmi di conformità (come SOC2).
- Capacità di integrare con sicurezza strumenti e processi provenienti da nuovi prodotti.
- Capacità di segnalare e categorizzare le vulnerabilità sia sui branch in produzione sia su quelli in sviluppo.

#### Modello di test

I test in SaaSy si concentrano su linee generali piuttosto che sull'uso standardizzato di strumenti, poiché ogni acquisizione arriva con i propri strumenti e processi AppSec.  SaaSy deve eseguire sia valutazioni interne (CI/CD, DAST, scansioni dei container e threat modeling) sia valutazioni esterne (pen test di terze parti, audit di conformità).

Per facilitare l'onboarding di nuove applicazioni, SaaSy Software adotta un approccio standard al proprio modello dei dati: ogni volta che SaaSy integra una nuova applicazione, crea un nuovo Tipo di prodotto per quell'app e crea sotto-prodotti per i repository che la compongono (Front-End, Backend API, ecc.).

![immagine](images/example_product_hierarchy_saas.png)

Ognuno di questi Prodotti è ulteriormente suddiviso in Engagement, uno per il branch principale e uno per ciascun branch di sviluppo.  I Test all'interno di questi Engagement vengono utilizzati per categorizzare le attività di test.  I branch di sviluppo hanno Test separati che memorizzano i risultati delle scansioni CI/CD e SCA.  Anche il branch principale li possiede, ma aggiunge anche Test che memorizzano i report di Revisione manuale del codice e di Threat Model.

Tutti questi Test sono aperti e possono essere aggiornati regolarmente utilizzando Reimport.  La [Deduplicazione](/triage_findings/finding_deduplication/about_deduplication/) viene gestita solo a livello di Engagement, il che impedisce che i Riscontri in un branch di codice chiudano i Riscontri in un altro.

Applicando questo modello in modo coerente, SaaSy dispone di un modello applicabile a qualsiasi nuova acquisizione software, e il team AppSec può iniziare rapidamente a monitorare i dati per garantire la conformità.

#### Modello RBAC

Sul lato Sicurezza/Conformità:

- Il team AppSec di SaaSy Software è proprietario di DefectDojo e dispone del pieno accesso da amministratore al software.
- I team QE e Conformità hanno accesso in sola lettura all'intero sistema, per estrarre report ed esaminare i dati se necessario.

Sul lato sviluppo:

- Ogni Product Owner ha accesso in scrittura (Writer) al Prodotto di cui è proprietario in DefectDojo, il che gli consente di redigere Accettazioni del rischio e visualizzare le metriche del Prodotto.
- Gli sviluppatori hanno accesso in sola lettura a ciascun Prodotto su cui lavorano.  Possono richiedere Peer Review sui Riscontri o sui problemi che stanno cercando di correggere.
