---
title: Informazioni su DefectDojo
date: 2021-02-02 20:46:29+01:00
draft: false
type: docs
weight: 1
aliases:
- /it/en/about_defectdojo/about_docs
---

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

![image](images/Introduction_to_Dashboard_Features.png)

</div>


<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo, Inc. e i contributori open-source mantengono questa documentazione per supportare sia l'edizione Community che l'edizione Pro di DefectDojo.</span>

## Cos'è DefectDojo?

DefectDojo è una piattaforma di Developer Security Operations (DevSecOps). DefectDojo semplifica le attività DevSecOps fungendo da aggregatore automatico per la tua suite di strumenti di sicurezza, permettendoti di organizzare facilmente il tuo lavoro di sicurezza e di comunicare la postura di sicurezza della tua organizzazione ad altri stakeholder.

Sebbene l'automazione dei processi di sicurezza e le pipeline di sviluppo integrate siano gli obiettivi finali di DefectDojo, alla base questo software è un bug tracker per le vulnerabilità di sicurezza, pensato per acquisire, organizzare e standardizzare i report provenienti da molti strumenti di sicurezza.

### Cosa fa DefectDojo?

DefectDojo dispone di funzionalità intelligenti per migliorare e ottimizzare i risultati dei tuoi strumenti di sicurezza, tra cui la possibilità di:

- Tracciare e generare report sui Riscontri di sicurezza nel loro contesto
- Applicare SLA nel contesto appropriato
- Gestire Falsi positivi, Rischi accettati e altre decisioni di triage
- Distillare i duplicati utilizzando l'algoritmo di deduplicazione di DefectDojo
- Integrarsi con software esterni di Project Tracking.
- Fornire metriche/report tra repository e branch di sviluppo tramite integrazione CI/CD.
- Coordinare la gestione tradizionale dei Pen test.
- Impostare e applicare SLA per le procedure di remediation delle vulnerabilità.
- Creare e tracciare Accettazioni del rischio per le vulnerabilità di sicurezza.

In definitiva, il modello Prodotto:Engagement di DefectDojo ti consente di inventariare il tuo ambiente di sviluppo e collocare immediatamente i nuovi Riscontri di sicurezza nel loro contesto.

---
Ecco alcuni esempi di come DefectDojo può essere implementato, con il co-fondatore e CTO di DefectDojo Matt Tesauro:
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo Open-Source

Le funzionalità principali di DefectDojo sono disponibili in DefectDojo Open-Source.

Questa edizione di DefectDojo include:

- Import/Reimport per tutti gli oltre 500 strumenti supportati
- API REST
- Funzionalità di deduplicazione
- Funzionalità limitate di UI, metriche e reportistica
- Capacità di integrazione con Jira

Per i team che gestiscono un volume di Riscontri più contenuto, DefectDojo Open-Source è un ottimo punto di partenza.

### Guide all'installazione

Esistono alcuni metodi supportati per installare l'edizione Open-Source di DefectDojo ([disponibile su Github](https://github.com/DefectDojo/django-DefectDojo)):

[Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) è il metodo più semplice per installare il programma principale e i servizi necessari per eseguire DefectDojo.
La nostra guida [Architettura](/get_started/open_source/architecture/) offre una panoramica di ciascun servizio e componente utilizzato da DefectDojo.
[Esecuzione in produzione](/get_started/open_source/running-in-production/) elenca i requisiti di sistema, gli aggiustamenti delle prestazioni e i processi di manutenzione per eseguire DefectDojo su un server di produzione (con Docker Compose).

Kubernetes non è pienamente supportato a livello Open-Source, ma questa guida può essere consultata e utilizzata come punto di partenza per integrare DefectDojo in un'architettura Kubernetes.

Se riscontri problemi con un'installazione Open-Source, ti consigliamo vivamente di porre domande sulla [OWASP Slack](https://owasp.org/slack/invite). I membri della nostra community sono attivi sul canale #defectdojo e possono aiutarti con i problemi che stai affrontando.

## 🟧 Edizione DefectDojo Pro

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

DefectDojo, Inc. ospita un'edizione Pro di questo software per scopi commerciali. Oltre a un'interfaccia moderna ed elegante, DefectDojo Pro include:

* [Connettori](/connectors/upstream/about/): integrazioni API pronte all'uso con scanner di livello enterprise (come Checkmarx One, BurpSuite, Semgrep e altri)
* **Metodi di importazione configurabili**: [Universal Parser](/supported_tools/parsers/universal_parser/), [Smart Upload](/import_data/pro/specialized_import/smart_upload/)
* **[Strumenti CLI](/import_data/pro/specialized_import/external_tools/)** per un'integrazione rapida con i tuoi sistemi
* **[Integrazioni aggiuntive di Project Tracking](/connectors/issue_tracking/)**: ServiceNow, Azure DevOps, GitHub e GitLab
* **[Metriche migliorate](/metrics_reports/pro_metrics/pro__overview/)** per la reportistica esecutiva e l'analisi di alto livello
* **[Priorità e rischio](/asset_modelling/pro_hierarchy/priority_sla/)** per identificare i Riscontri di maggiore urgenza, a livello di sistema
* **Supporto Premium** e assistenza all'implementazione per la tua organizzazione

L'edizione Pro è disponibile come offerta SaaS ospitata nel cloud, ed è disponibile anche per l'installazione on-premises.

Per maggiori informazioni su DefectDojo Pro, consulta la nostra [pagina Prezzi](https://defectdojo.com/pricing).

## Demo online

Sono disponibili demo online sia per la versione Open-Source che per quella Pro di DefectDojo. Entrambe sono accessibili con le seguenti credenziali:

- Nome utente: `admin`
- Password: `1Defectdojo@demo#appsec`

Queste demo sono precaricate con dati di esempio e vengono ripristinate quotidianamente.

### Demo Open-Source

Un esempio funzionante di DefectDojo (edizione Open-Source) è disponibile su [https://demo.defectdojo.org/](https://demo.defectdojo.org/).

### Demo Pro

Un esempio funzionante di DefectDojo Pro è disponibile su
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/).

## Imparare a usare DefectDojo

Che tu sia un utente Pro o Open-Source, disponiamo di molte risorse per aiutarti a iniziare con DefectDojo.

* Consulta le nostre [integrazioni con strumenti di sicurezza supportati](/supported_tools/) per adattare DefectDojo al tuo programma DevSecOps.
* Il nostro team gestisce un [canale YouTube](https://www.youtube.com/@defectdojo) che ospita tutorial, eventi Office Hours archiviati e altri contenuti. 

## Contattaci

Per metterti in contatto con il team di DefectDojo, Inc., puoi sempre scrivere a [hello@defectdojo.com](mailto:hello@defectdojo.com).

Siamo regolarmente presenti su [LinkedIn](https://www.linkedin.com/company/33245534) e organizziamo anche presentazioni online per i professionisti AppSec, accessibili in diretta o on demand. Puoi scoprire i prossimi eventi sulla nostra [pagina Eventi](https://defectdojo.com/events) oppure guardare le presentazioni passate sul nostro [canale YouTube](https://www.youtube.com/@defectdojo).

### Adesivi

Cerchi dei fantastici adesivi DefectDojo per il tuo laptop? Come ringraziamento per far parte della community DefectDojo, puoi iscriverti per ricevere alcuni adesivi DefectDojo gratuiti. Per maggiori informazioni, consulta [questo link](https://defectdojo.com/defectdojo-sticker-request).
