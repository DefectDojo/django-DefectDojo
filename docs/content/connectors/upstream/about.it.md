---
title: Connettori Upstream
description: Collega DefectDojo alla tua suite di strumenti di sicurezza in modo semplice
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 0
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
aliases:
- /it/import_data/pro/connectors/about_connectors/
- /it/en/connecting_your_tools/connectors/about_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: i Connettori Upstream sono una funzionalità esclusiva di DefectDojo Pro.</span>

DefectDojo permette agli utenti di creare integrazioni API sofisticate e offre pieno controllo su come organizzare i propri dati di vulnerabilità.

Ma tutti hanno bisogno di un punto di partenza, ed è qui che entrano in gioco i Connettori Upstream. I Connettori Upstream (in precedenza noti come **API Connector**) sono progettati per collegare i tuoi strumenti di sicurezza e iniziare a importare dati in DefectDojo il più rapidamente possibile.

Attualmente supportiamo Connettori Upstream per i seguenti strumenti, con altri in arrivo:

* **Acunetix 360**
* **Akamai API Security**
* **Anchore**
* **AWS Security Hub**
* **Azure DevOps**
* **Backstage**
* **Bitbucket**
* **Black Duck**
* **Bright Security**
* **Bugcrowd**
* **BurpSuite**
* **Censys**
* **Checkmarx ONE**
* **Cloudflare**
* **Cobalt.io**
* **Contrast**
* **Coverity**
* **CrowdStrike Falcon**
* **Deepfence ThreatMapper**
* **Dependency-Track**
* **Docker Scout**
* **Edgescan**
* **Endor Labs**
* **Escape**
* **Fairwinds Insights**
* **Fortify**
* **GitGuardian**
* **GitHub**
* **GitHub Advanced Security**
* **GitLab**
* **Google Cloud Security Command Center**
* **Group-IB ASM**
* **HackerOne**
* **Harbor**
* **Have I Been Pwned**
* **HCL AppScan**
* **Intigriti**
* **Intruder**
* **IriusRisk**
* **JFrog Xray**
* **Jira Service Management Assets**
* **Kubescape**
* **Lacework / FortiCNAPP**
* **Mend**
* **Microsoft Defender**
* **Microsoft Defender for Cloud**
* **MobSF**
* **NeuVector**
* **Nuclei (ProjectDiscovery Cloud)**
* **OpenVAS / Greenbone**
* **Probely**
* **Prowler**
* **Qualys**
* **Quay**
* **Rapid7 InsightAppSec**
* **Rapid7 InsightVM**
* **runZero**
* **Semgrep**
* **ServiceNow CMDB**
* **Shodan**
* **Snyk**
* **Socket**
* **SonarQube**
* **Sonatype IQ**
* **Sysdig Secure**
* **Tenable**
* **Tenable Web App Scanning**
* **Veracode**
* **Wazuh**
* **Wiz**
* **YesWeHack**

Per le istruzioni di configurazione passo\-passo di ciascuno strumento, consulta il riferimento [Configurazione dei Connettori per Strumento Specifico](../toolreference/).

La maggior parte dei Connettori importa **riscontri**. Alcuni sono **Connettori di Asset (Asset Connector)** che importano invece il tuo **inventario di asset** — costruendo e mantenendo la gerarchia di Prodotto (Asset) e Tipo di Prodotto (Organizzazione) anziché importare riscontri: **Azure DevOps**, **Backstage**, **Bitbucket**, **GitHub**, **GitLab**, **Jira Service Management Assets** e **ServiceNow CMDB**. (**runZero** è principalmente un Connettore di Asset, ma può opzionalmente importare anche le vulnerabilità come riscontri.)

Queste connessioni offrono un'integrazione con DefectDojo alla velocità delle API e possono essere usate per acquisire e organizzare automaticamente i dati di vulnerabilità provenienti dallo strumento.

## Orientarsi nella pagina Connettori

I Connettori sono elencati in due sezioni, ciascuna con un conteggio accanto al proprio titolo ed entrambe ordinate alfabeticamente:

* **Connettori configurati** — ogni configurazione di connettore esistente su questa istanza. Uno strumento può comparire più volte, una per ogni configurazione, e ogni riquadro è intitolato `<Strumento> - <etichetta>` in modo da poterli distinguere. Quando più configurazioni condividono lo stesso strumento, vengono ordinate in base alla loro etichetta.
* **Connettori disponibili** — ogni strumento supportato che non hai ancora configurato.

Il conteggio accanto a un titolo è il numero di connettori attualmente mostrati, quindi segue la casella di ricerca e il filtro per tipo **Asset / Finding** anziché riportare sempre il totale. Su DefectDojo Pro Cloud, il riquadro **Request Upstream Connector** non è un connettore e non viene conteggiato.

Entrambe le sezioni hanno una propria casella di ricerca, che filtra in base al nome dello strumento.

![La pagina Connettori, con un conteggio accanto a ciascun titolo di sezione](images/upstream_counts.png)

Le pagine dei [Connettori Downstream](/connectors/downstream/about/) e dei [Connettori di Autorizzazione](/admin/sso/pro__authorization_connectors/) sono strutturate allo stesso modo.

## Avvio rapido dei Connettori Upstream

Se usi le impostazioni **Auto\-Map** di DefectDojo, puoi avere il tuo primo Connettore operativo in pochissimo tempo.

1. Configura un [Connettore](../add_edit/) da uno strumento supportato.
2. [Scopri (Discover)](../manage_operations/#discover-operations) la gerarchia dei dati del tuo strumento.
3. [Sincronizza (Sync)](../manage_operations/#sync-operations) le vulnerabilità rilevate dal tuo strumento in DefectDojo.

Tutto qui, davvero! E ricorda: anche se crei il tuo Connettore nel modo 'semplice', puoi comunque modificare facilmente in seguito come sono configurate le cose, senza perdere alcun lavoro svolto.

## Come funzionano i Connettori Upstream

Finché disponi della chiave API dello strumento che vuoi collegare, un connettore può essere aggiunto in pochi minuti. Una volta che la connessione funziona, DefectDojo eseguirà una **Discover** dell'ambiente del tuo strumento per vedere come organizzi i tuoi dati di scansione.

Supponiamo che tu abbia uno strumento BurpSuite, configurato per scansionare cinque repository diversi alla ricerca di vulnerabilità. Il tuo Connettore prenderà nota di questa struttura organizzativa e configurerà dei **Record** per aiutarti a tradurre quei repository separati nella gerarchia Prodotto / Engagement / Test di DefectDojo. Se hai abilitato **'Auto\-Map Records'**, DefectDojo apprenderà e copierà automaticamente quella struttura.

![image](images/_index.png)

Una volta configurate le mappature dei tuoi **Record**, DefectDojo inizierà a importare i dati di scansione a intervalli regolari. Sarai tenuto aggiornato su ogni nuova vulnerabilità rilevata dallo strumento e potrai iniziare a lavorare immediatamente sulle vulnerabilità esistenti, usando il sistema **Riscontri** di DefectDojo.

Quando sei pronto ad aggiungere altri strumenti a DefectDojo, puoi facilmente riorganizzare le tue mappature di importazione in qualcos'altro. Più strumenti possono essere configurati per importare vulnerabilità verso la stessa destinazione, e puoi sempre riorganizzare la tua configurazione per adattarla meglio senza perdere alcun lavoro.

## Il mio Connettore non è supportato

### Richiedi un connettore dall'interfaccia utente (DefectDojo Pro Cloud)

Su DefectDojo Pro Cloud, puoi chiedere al nostro team di sviluppare un connettore per uno strumento che non supportiamo ancora — direttamente dall'interfaccia utente:

1. Vai su **Connectors → Upstream Connectors** (per gli strumenti che importano dati *in* DefectDojo). Gli integratori di issue tracker e altre integrazioni in uscita possono essere richiesti allo stesso modo in **Connectors → Downstream Connectors**.
2. Nella sezione **Available Connectors**, fai clic su **Request a Connector**.
3. Compila il modulo di richiesta. I campi **Tool / Product Name**, **Tool API Base URL**, **Authentication Type** e le credenziali per quel tipo di autenticazione sono tutti obbligatori, perché il nostro team ha bisogno di un indirizzo raggiungibile e di una credenziale funzionante per sviluppare un connettore e confermare che funzioni con il tuo strumento. Le credenziali vengono archiviate in modo sicuro. Puoi opzionalmente aggiungere il sito web del fornitore, un link alla documentazione API dello strumento e una nota che descrive il tuo caso d'uso.
4. Fai clic su **Submit Request**. Vedrai una conferma che la tua richiesta è stata ricevuta. Il nostro team valuta ogni richiesta per stabilire se sviluppare il supporto — l'invio di una richiesta non garantisce che il connettore verrà creato.

La richiesta di un connettore richiede i permessi di **Maintainer globale** ed è disponibile solo su **DefectDojo Pro Cloud** — l'opzione non compare sulle istanze self-hosted (on-premise).

### Importazione manuale

Anche senza un connettore, DefectDojo può comunque gestire l'importazione manuale per un'ampia gamma di strumenti di sicurezza. Consulta il nostro [Elenco degli strumenti supportati](/supported_tools), oltre alla nostra guida all'importazione dei dati.

# **Prossimi passi**

* Dai un'occhiata alla pagina **Upstream Connectors** passando all'**interfaccia utente Pro** di DefectDojo e aprendo **Connectors \> Upstream Connectors** sotto l'intestazione **Import**.
* Segui la nostra guida per [creare il tuo primo Connettore Upstream](../add_edit/).
* Scopri il processo di [Gestione delle Operazioni](../manage_operations/) con i tuoi strumenti di sicurezza connessi e come possono essere configurati per importare i dati.
