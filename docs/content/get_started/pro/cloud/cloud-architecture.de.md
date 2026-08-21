---
title: Cloud-Architektur
description: Wie DefectDojo Cloud auf Google Kubernetes Engine bereitgestellt und
  isoliert wird.
weight: 4
audience: pro
---

DefectDojo Cloud ist eine Multi-Tenant-SaaS-Plattform, die auf **Google
Kubernetes Engine (GKE)** in Google Cloud läuft. Diese Seite beschreibt, wie
die Plattform strukturiert ist und wie Kundenumgebungen voneinander getrennt
gehalten werden.

![DefectDojo Cloud Kubernetes-Architektur: Kundenverkehr gelangt über Google Cloud Load Balancing mit von Google verwaltetem TLS in regionale GKE-Cluster; jeder Kunde läuft in einem eigenen Kubernetes-Namespace mit einer dedizierten PostgreSQL-Datenbank, einem Cloud-Storage-Bucket und einem Vertex-AI-Projekt.](images/cloud_architecture_kubernetes.svg)

## Wie eine Anfrage abläuft

1. Kundenverkehr (Browser, API oder CI) trifft über **HTTPS** bei **Google
   Cloud Load Balancing** ein, das TLS mit von Google verwalteten
   Zertifikaten terminiert.
2. Der Load Balancer leitet die Anfrage in die Umgebung des Kunden innerhalb
   eines **regionalen GKE-Clusters** weiter, wo die Web-/API-Schicht
   (django, ausgeliefert über nginx und uWSGI) sie verarbeitet.
3. Die Web-Schicht liest und schreibt die **dedizierte PostgreSQL-Datenbank**
   und den **dedizierten Cloud-Storage-Bucket** des Kunden und verwendet
   einen **Cache innerhalb des Namespace** (Redis/Valkey) für Sitzungen und
   als Task-Broker.
4. Länger laufende Arbeiten wie Scan-Importe, Deduplizierung und
   Benachrichtigungen werden an **asynchrone Worker** (Celery) übergeben,
   damit Anfragen reaktionsschnell bleiben.

## Mandantenisolierung

Jeder Kunde läuft in seinem **eigenen Kubernetes-Namespace**, und die von
einem Kunden gespeicherten Daten teilen sich niemals einen Speicher mit
einem anderen Kunden:

- **Dedizierte Datenbank**: eine separate PostgreSQL-Datenbank pro Kunde (Cloud SQL).
- **Dediziertes Objektspeicher**: ein separater Cloud-Storage-Bucket pro
  Kunde für hochgeladene Scans und Medien, der über den GCS-FUSE-CSI-Treiber
  in die Workloads eingebunden wird.
- **Dedizierter Cache**: Jeder Namespace betreibt seine eigene Redis/Valkey-Instanz.
- **Zugangsdaten pro Kunde**: Jede Umgebung hat eigene Secrets sowie ein
  eigenes TLS-Zertifikat und einen eigenen Hostnamen.

Es gibt **keine gemeinsam genutzte Anwendungsdatenebene** zwischen Kunden.
Daten werden während der Übertragung (TLS) und im Ruhezustand (Google Cloud
Standardverschlüsselung) verschlüsselt.

## Regionen und Datenresidenz

Die Plattform betreibt **regionale GKE-Cluster über mehrere geografische
Regionen hinweg** (zum Beispiel Nordamerika, Europa und Asien-Pazifik). Die
Umgebung eines Kunden liegt zusammen mit ihrer Datenbank und ihrem
Storage-Bucket in der für diesen Kunden ausgewählten Region, was
Anforderungen an die Datenresidenz unterstützt.

## Workloads in einer Kundenumgebung

Jeder Namespace enthält die Komponenten, die zum durchgängigen Betrieb von
DefectDojo Pro benötigt werden:

| Gruppe | Zweck |
|---|---|
| **Web & API** | Stellt die UI und die REST-API bereit (django · nginx + uWSGI). |
| **Asynchrone Verarbeitung** | Hintergrundjobs und Scheduling (Celery Worker + Beat). |
| **Orchestrierung** | Koordiniert mehrstufige Workflows über die Plattform hinweg. |
| **Integrationen** | Connectors und Ticketing-Integrationen. |
| **MCP-Server** | KI-Schnittstelle zur Anbindung eigener KI-Tools. |
| **Sensei** | KI-gestützte Behebung über Googles Vertex-Plattform. |
| **Cache innerhalb des Namespace** | Redis/Valkey für Sitzungen und Task-Brokering. |

Bei jedem Deploy führt ein kurzlebiger **Initializer-Job**
Datenbankmigrationen aus, bevor die neue Version Traffic bedient.

## Sensei und KI-Isolierung

Sensei, die KI-gestützte Behebungsfunktion von DefectDojo, läuft über
**Googles Vertex-Plattform** mit derselben kundenbezogenen Isolierung wie
der Rest der Datenebene:

- Die Sensei-Anfragen jedes Kunden laufen im **dedizierten GCP-Projekt
  dieses Kunden**, authentifiziert mit **kundenspezifischen Zugangsdaten**.
- Es gibt keine gemeinsam genutzte KI-Mandantenfähigkeit: Die Prompts,
  Befunde und Ergebnisse eines Kunden durchlaufen nie die Umgebung eines
  anderen Kunden.
- Ein **externer KI-Anbieter wird nur verwendet, wenn der Kunde einen
  solchen konfiguriert** (zum Beispiel über den MCP-Server oder eine vom
  Kunden bereitgestellte KI-Integration).

## Plattformdienste und -betrieb

Gemeinsam genutzte, von Google verwaltete Dienste unterstützen jede
Umgebung, ohne Kundendaten zwischen Mandanten zu übertragen:

- **Artifact Registry**: signierte Container-Images.
- **Secret Manager**: Secret- und Schlüsselmaterial.
- **Cloud Monitoring & Logging**: Metriken, Logs und Alerting, die von
  unserem Bereitschaftsteam genutzt werden. Node-Pools **skalieren
  automatisch**, um Last aufzufangen.

Die einzigen kundenübergreifend gemeinsam genutzten Daten sind öffentliche
Schwachstellenanreicherungen (EPSS und KEV).

## Integrationen sind ausschließlich ausgehend

Verbindungen zu externen Systemen wie E-Mail (SMTP), Ticketing (Jira,
ServiceNow und andere), Sicherheits-Scannern und Fehlerüberwachung werden
**vom Kunden konfiguriert und ausgehend** aus der Umgebung des Kunden
initiiert.

## Isolierung nach Tier

DefectDojo Cloud wird in Tiers angeboten, die sich darin unterscheiden, wie
viel des Stacks einem einzelnen Kunden dediziert ist:

![DefectDojo Cloud Mandantenisolierung nach Tier: Standard- und Pay-as-you-go-Mandanten laufen in isolierten Namespaces auf einem gemeinsam genutzten GKE-Cluster und teilen sich eine PostgreSQL-Instanz mit pro Mandant logischen Datenbanken; Premium-Mandanten erhalten eine dedizierte PostgreSQL-Datenbank; das Dedicated-Tier läuft in einem eigenen GKE-Cluster, einer eigenen VPC und einem eigenen GCP-Projekt.](images/cloud_architecture_tiers.svg)

| Tier | Compute | Datenbank | Netzwerkgrenze | Sensei |
|---|---|---|---|---|
| **Standard** | Isolierter Namespace auf einem gemeinsam genutzten Cluster | Eigene logische Datenbank und Zugangsdaten auf einer gemeinsam genutzten PostgreSQL-Instanz | Gemeinsam genutzte VPC, Hostname + TLS pro Mandant, optionale IP-Allowlist | Enthalten |
| **Pay-as-you-go** *(demnächst verfügbar)* | Isolierter Namespace auf einem gemeinsam genutzten Cluster | Eigene logische Datenbank und Zugangsdaten auf einer gemeinsam genutzten PostgreSQL-Instanz | Gemeinsam genutzte VPC, Hostname + TLS pro Mandant, optionale IP-Allowlist | Enthalten |
| **Premium** | Isolierter Namespace auf einem gemeinsam genutzten Cluster | **Dedizierte PostgreSQL-Datenbank** pro Kunde | Gemeinsam genutzte VPC, Hostname + TLS pro Mandant, optionale IP-Allowlist | Enthalten |
| **Dedicated** | **Eigener GKE-Cluster** | **Dedizierte PostgreSQL-Datenbank** in der eigenen VPC des Kunden | **Eigenes GCP-Projekt und eigene VPC**, Ingress auf den IP-Bereich des Kunden beschränkt | Enthalten |

Sensei ist in jedem Tier enthalten und läuft in jedem Tier über Googles
Vertex-Plattform im eigenen GCP-Projekt des Kunden mit kundenspezifischen
Zugangsdaten.

*Haben Sie eine Frage, die diese Seite nicht beantwortet? Wenden Sie sich an
Ihren DefectDojo-Ansprechpartner.*
