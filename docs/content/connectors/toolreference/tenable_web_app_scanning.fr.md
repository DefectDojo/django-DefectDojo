---
title: "Tenable Web App Scanning"
description: "Comment configurer le Connecteur Upstream Tenable Web App Scanning pour DefectDojo"
weight: 132
audience: pro
---
Le connecteur Tenable Web App Scanning importe des **constatations d'application web (DAST)** depuis Tenable Web App Scanning. Il s'agit d'un connecteur distinct de Tenable (Vulnerability Management) : les deux produits couvrent des actifs différents et se configurent indépendamment, vous pouvez donc utiliser l'un, l'autre, ou les deux.

DefectDojo crée un Enregistrement pour chaque **application web analysée**. Les applications sont découvertes à partir de vos configurations de scan Web App Scanning ; une configuration qui n'a jamais été exécutée ne produit pas d'Enregistrement tant que son premier scan n'est pas terminé. Lorsque plusieurs configurations analysent la même application, elles partagent un seul Enregistrement.

#### Prérequis

Des **clés API** Tenable (une clé d'accès et une clé secrète) pour un utilisateur disposant des permissions Web App Scanning. Dans Tenable, allez dans **My Account > API Keys** pour les générer, et vérifiez que l'utilisateur peut voir les scans que vous souhaitez importer — les clés limitées à Vulnerability Management ne peuvent pas lire les données de Web App Scanning.

Les connecteurs Tenable sur site ne sont pas disponibles pour le moment.

#### Mappages du connecteur

1. Saisissez <https://cloud.tenable.com> dans le champ **Location**.
2. Saisissez votre **Access Key** et votre **Secret Key**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Les constatations sont importées avec la sévérité que Tenable indique pour votre compte, y compris toute sévérité que votre équipe a reclassée. Chaque constatation porte l'URL concernée comme point de terminaison, le paramètre de requête et la charge utile qui l'ont déclenchée, ainsi que la preuve et la sortie de Tenable comme étapes de reproduction, avec les valeurs CWE, CVE, CVSS et EPSS lorsque le plugin de détection les fournit.

Seules les constatations actuellement ouvertes ou rouvertes sont importées. Une constatation que Tenable a marquée comme corrigée est fermée dans DefectDojo lors de la prochaine synchronisation.
