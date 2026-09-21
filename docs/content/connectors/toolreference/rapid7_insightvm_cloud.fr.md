---
title: "Rapid7 InsightVM - Cloud Instance"
description: "Comment configurer le Connecteur Upstream Rapid7 InsightVM - Cloud Instance pour DefectDojo"
weight: 113
audience: pro
---
Le connecteur Rapid7 InsightVM - Cloud Instance importe les constatations de vulnérabilités d'actifs depuis InsightVM hébergé sur la **plateforme Rapid7 Insight** (Cloud Integrations API v4), enrichies avec le catalogue de vulnérabilités de la plateforme. DefectDojo crée un Record pour chaque **site** InsightVM.

**Remarque :** ce Connecteur concerne InsightVM exécuté sur la plateforme cloud Rapid7 Insight. Si vos constatations proviennent de votre propre **Security Console** on\-premises, utilisez plutôt le connecteur [Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/), qui s'authentifie avec des identifiants de console plutôt qu'avec une clé API de plateforme.

#### Prérequis

Un compte de la plateforme Insight avec InsightVM, et une **clé API** de plateforme : dans la [plateforme Rapid7 Insight](https://insight.rapid7.com), ouvrez le menu des paramètres (icône d'engrenage) \> **API Keys** et générez une **User Key** (n'importe quel rôle) ou une **Organization Key** (administrateurs de la plateforme). Copiez la clé lorsqu'elle s'affiche : elle n'est affichée qu'une seule fois.

Vous avez également besoin de votre **région** de plateforme, visible dans votre URL Insight (par exemple `us`, `us2`, `us3`, `eu`, `ca`, `au`, ou `ap`).

#### Correspondances du connecteur

1. Saisissez votre endpoint API régional dans le champ **Location**, par exemple `https://us.api.insight.rapid7.com` (remplacez `us` par votre région). Ce champ est pré\-rempli avec l'endpoint des États\-Unis.
2. Saisissez la clé API de la plateforme Insight dans le champ **API Key**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque site InsightVM devient un Record ; le connecteur lit les actifs d'intégration de la plateforme et importe leurs constatations de vulnérabilités, enrichies à partir du catalogue de vulnérabilités. Les constatations sont importées sous le même type **Rapid7 InsightVM - Connectors Import** que le connecteur on\-premises, de sorte que les résultats des deux connecteurs sont dédupliqués ensemble.
