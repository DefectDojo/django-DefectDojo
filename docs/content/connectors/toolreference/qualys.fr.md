---
title: "Qualys"
description: "Comment configurer le Connecteur Upstream Qualys pour DefectDojo"
weight: 109
audience: pro
---
Le connecteur Qualys importe les **détections de vulnérabilités hôtes VMDR** — chacune jointe aux métadonnées de la base de connaissances Qualys (QID) — depuis la Qualys Cloud Platform. DefectDojo crée un Record pour chaque **hôte** Qualys de votre abonnement.

#### Prérequis

Un compte utilisateur Qualys avec **accès API VMDR**, et l'**URL du serveur API (platform)** de votre abonnement — celle\-ci diffère selon l'abonnement. Trouvez\-la dans l'interface Qualys sous **Help \> About**, ou sur la page [Platform Identification](https://www.qualys.com/platform-identification/) de Qualys (par exemple `https://qualysapi.qualys.com` pour US Platform 1, ou `https://qualysapi.qg2.apps.qualys.com` pour US Platform 2).

#### Correspondances du connecteur

1. Saisissez l'URL de votre serveur API Qualys dans le champ **Location** (par exemple `https://qualysapi.qualys.com`).
2. Saisissez le nom d'utilisateur API Qualys dans le champ **Username**.
3. Saisissez le mot de passe API Qualys dans le champ **Secret**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque hôte Qualys devient un Record. Les détections que Qualys a marquées **Fixed** sont exclues, de sorte qu'une réimportation clôt les constatations corrigées.
