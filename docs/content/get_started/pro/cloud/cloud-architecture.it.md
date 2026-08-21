---
title: Architettura Cloud
description: Come DefectDojo Cloud viene distribuito e isolato su Google Kubernetes
  Engine.
weight: 4
audience: pro
---

DefectDojo Cloud è una piattaforma SaaS multi-tenant eseguita su **Google Kubernetes
Engine (GKE)** in Google Cloud. Questa pagina descrive come è strutturata la piattaforma
e come vengono mantenuti separati gli ambienti dei clienti.

![Architettura Kubernetes di DefectDojo Cloud: il traffico dei clienti entra attraverso Google Cloud Load Balancing con TLS gestito da Google in cluster GKE regionali; ogni cliente viene eseguito nel proprio namespace Kubernetes con un database PostgreSQL dedicato, un bucket Cloud Storage e un progetto Vertex AI dedicati.](images/cloud_architecture_kubernetes.svg)

## Come viene gestita una richiesta

1. Il traffico del cliente (browser, API o CI) arriva tramite **HTTPS** a **Google
   Cloud Load Balancing**, che termina il TLS utilizzando certificati gestiti da
   Google.
2. Il load balancer instrada la richiesta nell'ambiente del cliente all'interno di un
   **cluster GKE regionale**, dove il livello web/API (django, servito da nginx e
   uWSGI) la gestisce.
3. Il livello web legge e scrive sul **database PostgreSQL dedicato** del cliente
   e sul **bucket Cloud Storage dedicato**, e utilizza una **cache all'interno del
   namespace** (Redis/Valkey) per le sessioni e come broker dei task.
4. Il lavoro più lungo, come le importazioni di scansioni, la deduplicazione e le
   notifiche, viene affidato a **worker asincroni** (Celery) in modo che le
   richieste restino reattive.

## Isolamento dei tenant

Ogni cliente viene eseguito nel proprio **namespace Kubernetes dedicato**, e i dati
memorizzati da ciascun cliente non condividono mai lo stesso storage con un altro
cliente:

- **Database dedicato**: un database PostgreSQL separato per ogni cliente (Cloud SQL).
- **Object storage dedicato**: un bucket Cloud Storage separato per ogni cliente per
  le scansioni e i media caricati, montato nei workload tramite il driver CSI GCS FUSE.
- **Cache dedicata**: ogni namespace esegue la propria istanza Redis/Valkey.
- **Credenziali per singolo cliente**: ogni ambiente ha i propri secret e il proprio
  certificato TLS e hostname.

Non esiste **alcun data plane applicativo condiviso** tra i clienti. I dati sono
cifrati in transito (TLS) e a riposo (cifratura predefinita di Google Cloud).

## Regioni e residenza dei dati

La piattaforma esegue **cluster GKE regionali distribuiti su più aree geografiche**
(ad esempio Nord America, Europa e Asia-Pacifico). L'ambiente di un cliente, insieme
al suo database e al suo bucket di storage, risiede nella regione selezionata per
quel cliente, il che supporta i requisiti di residenza dei dati.

## Workload in un ambiente cliente

Ogni namespace contiene i componenti necessari per eseguire DefectDojo Pro end to end:

| Group | Purpose |
|---|---|
| **Web & API** | Serve l'interfaccia utente e l'API REST (django · nginx + uWSGI). |
| **Elaborazione asincrona** | Job in background e pianificazione (Celery worker + beat). |
| **Orchestrazione** | Coordina i flussi di lavoro multi-fase su tutta la piattaforma. |
| **Integrazioni** | Connettori e integrazioni di ticketing. |
| **Server MCP** | Interfaccia AI per collegare i propri strumenti di intelligenza artificiale. |
| **Sensei** | Remediation basata su AI tramite la Vertex Platform di Google. |
| **Cache nel namespace** | Redis/Valkey per le sessioni e il brokering dei task. |

A ogni deploy, un **job di inizializzazione** di breve durata esegue le migrazioni
del database prima che la nuova versione inizi a servire il traffico.

## Sensei e isolamento dell'AI

Sensei, la funzionalità di remediation basata su AI di DefectDojo, viene eseguita
tramite la **Vertex Platform di Google** con lo stesso isolamento per singolo
cliente del resto del data plane:

- Le richieste Sensei di ogni cliente vengono eseguite nel **progetto GCP dedicato
  di quel cliente**, autenticate con **credenziali per singolo cliente**.
- Non esiste alcuna tenancy AI condivisa: i prompt, i riscontri e i risultati di un
  cliente non passano mai attraverso l'ambiente di un altro cliente.
- Un **provider AI esterno viene utilizzato solo se il cliente ne configura uno**
  (ad esempio tramite il server MCP o un'integrazione AI fornita dal cliente).

## Servizi e operazioni della piattaforma

Servizi condivisi, gestiti da Google, supportano ogni ambiente senza trasferire
dati dei clienti tra i tenant:

- **Artifact Registry**: immagini container firmate.
- **Secret Manager**: secret e materiale chiavi.
- **Cloud Monitoring & Logging**: metriche, log e alerting utilizzati dal nostro
  team di reperibilità. I node pool eseguono **l'autoscaling** per assorbire il carico.

L'unico dato condiviso tra i clienti è l'arricchimento pubblico delle vulnerabilità
(EPSS e KEV).

## Le integrazioni sono solo in uscita

Le connessioni verso sistemi esterni, come email (SMTP), ticketing (Jira,
ServiceNow e altri), scanner di sicurezza e monitoraggio degli errori, sono
**configurate dal cliente e avviate in uscita** dall'ambiente del cliente.

## Isolamento per livello

DefectDojo Cloud viene offerto in livelli che differiscono per quanta parte dello
stack è dedicata a un singolo cliente:

![Isolamento dei tenant di DefectDojo Cloud per livello: i tenant Standard e Pay-as-you-go vengono eseguiti in namespace isolati su un cluster GKE condiviso e condividono un'istanza PostgreSQL con database logici per singolo tenant; i tenant Premium ottengono un database PostgreSQL dedicato; il livello Dedicated viene eseguito nel proprio cluster GKE, nella propria VPC e nel proprio progetto GCP.](images/cloud_architecture_tiers.svg)

| Tier | Compute | Database | Network boundary | Sensei |
|---|---|---|---|---|
| **Standard** | Namespace isolato su un cluster condiviso | Database logico e credenziali proprie su un'istanza PostgreSQL condivisa | VPC condivisa, hostname + TLS per singolo tenant, allowlist IP opzionale | Incluso |
| **Pay-as-you-go** *(disponibile a breve)* | Namespace isolato su un cluster condiviso | Database logico e credenziali proprie su un'istanza PostgreSQL condivisa | VPC condivisa, hostname + TLS per singolo tenant, allowlist IP opzionale | Incluso |
| **Premium** | Namespace isolato su un cluster condiviso | **Database PostgreSQL dedicato** per cliente | VPC condivisa, hostname + TLS per singolo tenant, allowlist IP opzionale | Incluso |
| **Dedicated** | **Cluster GKE proprio** | **Database PostgreSQL dedicato** nella VPC propria del cliente | **Progetto GCP e VPC propri**, ingress limitato all'intervallo IP del cliente | Incluso |

Sensei è incluso in ogni livello, e in ogni livello viene eseguito tramite la Vertex
Platform di Google nel progetto GCP proprio del cliente, con credenziali per
singolo cliente.

*Hai una domanda a cui questa pagina non risponde? Contatta il tuo referente
DefectDojo.*
