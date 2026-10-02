---
title: "CrowdStrike Falcon"
description: "Comment configurer le Connecteur Upstream CrowdStrike Falcon pour DefectDojo"
weight: 41
audience: pro
---
Le connecteur CrowdStrike Falcon importe les **vulnérabilités Spotlight** et les **détections EDR** depuis la plateforme Falcon, sous forme de deux types de constatations distincts (`CrowdStrike:Spotlight` et `CrowdStrike:Detections`). DefectDojo crée un enregistrement pour chaque **hôte** Falcon.

#### Prérequis

Un **client API** Falcon (Client ID et secret), créé dans la console Falcon sous **Support \> API Clients and Keys**. Accordez-lui les scopes correspondant aux données que vous souhaitez importer : **Hosts: Read** (requis, pour la découverte des hôtes), **Vulnerabilities (Spotlight): Read** (pour les constatations Spotlight) et **Alerts: Read** (pour les détections EDR). Les deux types de constatations sont indépendants — si le client ne dispose pas d'un scope, ce type de constatation est ignoré plutôt que de faire échouer la synchronisation ; ainsi, un client sans **Alerts: Read** importe tout de même les vulnérabilités Spotlight.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API de votre cloud Falcon dans le champ **Location**, en fonction de la région de votre console — par exemple `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1), ou `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Saisissez le Client ID du client API dans le champ **Client ID**.
3. Saisissez le secret du client API dans le champ **Client Secret**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque hôte Falcon devient un enregistrement, nommé d'après son nom d'hôte, son OS et son type. Seules les vulnérabilités Spotlight à l'état **open** et **reopened** sont importées ; une réimportation clôt donc les constatations corrigées.
