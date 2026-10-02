---
title: Confronto dei metodi di importazione
description: Scopri come importare i dati manualmente, tramite API o tramite un connettore
weight: 1
aliases:
- /it/en/connecting_your_tools/import_intro
---

Una delle cose che comprendiamo bene in DefectDojo è che le esigenze di sicurezza di ogni azienda sono completamente diverse. Non esiste un approccio universale valido per tutti. Man mano che la tua organizzazione cambia, avere un approccio flessibile è fondamentale, e DefectDojo ti permette di collegare i tuoi strumenti di sicurezza in modo flessibile per adattarti a questi cambiamenti.

## Metodi di caricamento delle scansioni

Quando DefectDojo riceve un report di vulnerabilità da uno strumento di sicurezza, creerà dei Riscontri basati sulle vulnerabilità contenute in quel report. DefectDojo funge da repository centrale per questi Riscontri, dove possono essere sottoposti a triage, risolti o altrimenti gestiti da te e dal tuo team.

Esistono due modi principali con cui DefectDojo può caricare i report dei Riscontri.

* Tramite **importazione** diretta attraverso l'interfaccia utente
* Tramite endpoint **API** (che consente l'acquisizione automatizzata dei dati): vedi [documentazione API](/automation/api/api-v2-docs/)

#### Metodi di DefectDojo Pro

Gli utenti di <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> dispongono di altri tre metodi per gestire report e dati:

* Tramite **Universal Importer** o **DefectDojo CLI**, strumenti da riga di comando che sfruttano l'API di DefectDojo: vedi [Guide a Universal Importer e DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/)
* Tramite **Connectors** per determinati strumenti, un'integrazione dei dati "pronta all'uso": vedi [Guida ai Connectors](/connectors/upstream/about/)
* Tramite **Smart Upload** per determinati strumenti, un importatore progettato per gestire le scansioni dell'infrastruttura: vedi [Guida a Smart Upload](/import_data/pro/specialized_import/smart_upload/)

### Confronto dei metodi di caricamento

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Tipi di scansione supportati** | Tutti: vedi [Strumenti supportati](/supported_tools/) | Tutti: vedi [Strumenti supportati](/supported_tools/) | Akamai API Security, Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, IriusRisk, JFrog Xray, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automazione?** | Disponibile tramite API: endpoint `/reimport` `/import` | Attivato da [Strumenti CLI](/import_data/pro/specialized_import/external_tools/) o codice esterno | Connectors è una funzionalità intrinsecamente automatizzata | Disponibile tramite API: endpoint `/smart_upload_import` |

### Gerarchia dei Prodotti e organizzazione

Ognuno di questi metodi può creare una Gerarchia dei Prodotti al volo. La Gerarchia dei Prodotti si riferisce ai Tipi di Prodotto, Prodotti, Engagement o Test di DefectDojo: oggetti in DefectDojo che aiutano a organizzare i tuoi dati in un contesto pertinente.

* **I dati sulle vulnerabilità possono essere importati in una Gerarchia dei Prodotti esistente**. Tipi di Prodotto, Prodotti, Engagement e Test possono essere tutti creati in anticipo, e i dati possono poi essere importati in quella posizione in DefectDojo.
* **La Gerarchia dei Prodotti contestuale può essere creata al momento dell'importazione.** Durante l'importazione di un report, puoi creare un nuovo Tipo di Prodotto, Prodotto, Engagement e/o Test. Questo viene gestito da DefectDojo tramite l'opzione 'auto-create context'.  In DefectDojo OS, questa opzione è accessibile solo tramite l'API.  Le importazioni tramite interfaccia utente in DefectDojo OS richiederanno che la Gerarchia dei Prodotti sia già stata creata.
