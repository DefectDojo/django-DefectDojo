---
title: Architecture Cloud
description: Comment DefectDojo Cloud est déployé et isolé sur Google Kubernetes Engine.
weight: 4
audience: pro
---

DefectDojo Cloud est une plateforme SaaS multi-tenant s'exécutant sur **Google Kubernetes
Engine (GKE)** dans Google Cloud. Cette page décrit la structure de la plateforme et la manière
dont les environnements clients sont maintenus séparés.

![Architecture Kubernetes de DefectDojo Cloud : le trafic client entre via Google Cloud Load Balancing avec TLS géré par Google dans des clusters GKE régionaux ; chaque client s'exécute dans son propre espace de noms Kubernetes avec une base de données PostgreSQL dédiée, un bucket Cloud Storage et un projet Vertex AI.](images/cloud_architecture_kubernetes.svg)

## Comment une requête circule

1. Le trafic client (navigateur, API ou CI) arrive en **HTTPS** au niveau de **Google
   Cloud Load Balancing**, qui termine le TLS à l'aide de certificats gérés par Google.
2. L'équilibreur de charge achemine la requête vers l'environnement du client à l'intérieur d'un
   **cluster GKE régional**, où la couche web/API (django, servie par nginx et
   uWSGI) la traite.
3. La couche web lit et écrit dans la **base de données PostgreSQL dédiée**
   et le **bucket Cloud Storage dédié** du client, et utilise un **cache dans l'espace de noms**
   (Redis/Valkey) pour les sessions et comme courtier de tâches.
4. Les tâches plus longues, telles que les imports de scans, la déduplication et les notifications,
   sont confiées à des **workers asynchrones** (Celery) afin que les requêtes restent réactives.

## Isolation des tenants

Chaque client s'exécute dans son **propre espace de noms Kubernetes**, et les données stockées
par chaque client ne partagent jamais de stockage avec un autre client :

- **Base de données dédiée** : une base de données PostgreSQL distincte par client (Cloud SQL).
- **Stockage d'objets dédié** : un bucket Cloud Storage distinct par client pour
  les scans téléchargés et les médias, monté dans les workloads via le pilote CSI GCS FUSE.
- **Cache dédié** : chaque espace de noms exécute sa propre instance Redis/Valkey.
- **Identifiants par client** : chaque environnement dispose de ses propres secrets ainsi que de
  son propre certificat TLS et nom d'hôte.

Il n'existe **aucun plan de données applicatif partagé** entre les clients. Les données sont
chiffrées en transit (TLS) et au repos (chiffrement par défaut de Google Cloud).

## Régions et résidence des données

La plateforme exécute des **clusters GKE régionaux répartis sur plusieurs zones géographiques**
(par exemple l'Amérique du Nord, l'Europe et l'Asie-Pacifique). L'environnement d'un client,
ainsi que sa base de données et son bucket de stockage, se trouve dans la région sélectionnée
pour ce client, ce qui permet de répondre aux exigences de résidence des données.

## Charges de travail dans un environnement client

Chaque espace de noms contient les composants nécessaires pour exécuter DefectDojo Pro de bout
en bout :

| Groupe | Objectif |
|---|---|
| **Web & API** | Sert l'interface utilisateur et l'API REST (django · nginx + uWSGI). |
| **Traitement asynchrone** | Tâches en arrière-plan et planification (workers Celery + beat). |
| **Orchestration** | Coordonne les workflows à plusieurs étapes sur l'ensemble de la plateforme. |
| **Intégrations** | Connecteurs et intégrations de ticketing. |
| **Serveur MCP** | Interface IA pour connecter vos propres outils d'IA. |
| **Sensei** | Remédiation par IA via la plateforme Vertex de Google. |
| **Cache dans l'espace de noms** | Redis/Valkey pour les sessions et le courtage de tâches. |

À chaque déploiement, un **job d'initialisation** de courte durée exécute les migrations de base
de données avant que la nouvelle version ne serve le trafic.

## Sensei et isolation de l'IA

Sensei, la fonctionnalité de remédiation par IA de DefectDojo, s'exécute via la **plateforme
Vertex de Google** avec la même isolation par client que le reste du plan de données :

- Les requêtes Sensei de chaque client s'exécutent dans le **projet GCP dédié
  de ce client**, authentifiées avec des **identifiants propres à ce client**.
- Il n'existe aucun tenant IA partagé : les prompts, constatations et résultats d'un client
  ne transitent jamais par l'environnement d'un autre client.
- Un **fournisseur d'IA externe n'est utilisé que si le client en configure un** (par
  exemple via le serveur MCP ou une intégration IA fournie par le client).

## Services et opérations de la plateforme

Des services partagés et gérés par Google prennent en charge chaque environnement sans faire
transiter de données client entre les tenants :

- **Artifact Registry** : images de conteneurs signées.
- **Secret Manager** : secrets et éléments de clés.
- **Cloud Monitoring & Logging** : métriques, journaux et alertes utilisés par notre
  équipe d'astreinte. Les pools de nœuds effectuent un **autoscaling** pour absorber la charge.

La seule donnée partagée entre les clients est l'enrichissement public des vulnérabilités
(EPSS et KEV).

## Les intégrations sont uniquement sortantes

Les connexions vers des systèmes externes, tels que l'e-mail (SMTP), le ticketing (Jira,
ServiceNow, et autres), les scanners de sécurité et la surveillance des erreurs, sont
**configurées par le client et initiées en sortie** depuis l'environnement du client.

## Isolation par palier

DefectDojo Cloud est proposé en paliers qui diffèrent selon la part de la pile dédiée
à un seul client :

![Isolation des tenants DefectDojo Cloud par palier : les tenants Standard et Pay-as-you-go s'exécutent dans des espaces de noms isolés sur un cluster GKE partagé et partagent une instance PostgreSQL avec des bases de données logiques par tenant ; les tenants Premium disposent d'une base de données PostgreSQL dédiée ; le palier Dedicated s'exécute dans son propre cluster GKE, son propre VPC et son propre projet GCP.](images/cloud_architecture_tiers.svg)

| Palier | Calcul | Base de données | Limite réseau | Sensei |
|---|---|---|---|---|
| **Standard** | Espace de noms isolé sur un cluster partagé | Base de données logique et identifiants propres sur une instance PostgreSQL partagée | VPC partagé, nom d'hôte + TLS par tenant, liste blanche d'IP optionnelle | Inclus |
| **Pay-as-you-go** *(bientôt disponible)* | Espace de noms isolé sur un cluster partagé | Base de données logique et identifiants propres sur une instance PostgreSQL partagée | VPC partagé, nom d'hôte + TLS par tenant, liste blanche d'IP optionnelle | Inclus |
| **Premium** | Espace de noms isolé sur un cluster partagé | **Base de données PostgreSQL dédiée** par client | VPC partagé, nom d'hôte + TLS par tenant, liste blanche d'IP optionnelle | Inclus |
| **Dedicated** | **Cluster GKE propre** | **Base de données PostgreSQL dédiée** dans le VPC propre du client | **Projet GCP et VPC propres**, ingress restreint à la plage d'IP du client | Inclus |

Sensei est inclus dans tous les paliers, et dans chacun d'eux, il s'exécute via la plateforme
Vertex de Google dans le projet GCP propre du client, avec des identifiants propres à ce client.

*Une question à laquelle cette page ne répond pas ? Contactez votre représentant
DefectDojo.*
