---
title: "Rapid7 InsightAppSec"
description: "Comment configurer le Connecteur Upstream Rapid7 InsightAppSec pour DefectDojo"
weight: 112
audience: pro
---
Le connecteur Rapid7 InsightAppSec importe les **constatations de vulnérabilités DAST** depuis la plateforme cloud InsightAppSec, enrichies avec les métadonnées de module d'attaque (par exemple *SQL Injection*), les scores CVSS, et les preuves collectées par le scan. DefectDojo crée un Record pour chaque **app** InsightAppSec.

**Remarque :** ce Connecteur est distinct du connecteur **Rapid7 InsightVM** ci\-dessous — InsightAppSec est le produit DAST cloud de Rapid7 sur la plateforme Insight, tandis que les constatations InsightVM proviennent de votre propre Security Console.

#### Prérequis

Un compte de la plateforme Insight avec InsightAppSec, et une **clé API** de plateforme : dans la [plateforme Rapid7 Insight](https://insight.rapid7.com), ouvrez le menu des paramètres (icône d'engrenage) \> **API Keys** et générez une **User Key** (n'importe quel rôle) ou une **Organization Key** (administrateurs de la plateforme). Copiez la clé lorsqu'elle s'affiche — elle n'est affichée qu'une seule fois.

Vous avez également besoin de votre **région** de plateforme, visible dans votre URL Insight (par exemple `us`, `us2`, `us3`, `eu`, `ca`, `au`, ou `ap`).

#### Correspondances du connecteur

1. Saisissez votre endpoint API régional dans le champ **Location** — par exemple `https://us.api.insight.rapid7.com` (remplacez `us` par votre région).
2. Saisissez la clé API de la plateforme Insight dans le champ **API Key**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque app InsightAppSec devient un Record. Seules les vulnérabilités **ouvertes** (Unreviewed ou Vérifié) sont importées — les constatations que Rapid7 a marquées Remediated, Faux positif, Ignored, ou Doublon sont exclues, de sorte qu'une réimportation les clôt dans DefectDojo. Les sévérités sont associées directement (`SAFE` et `INFORMATIONAL` sont importés comme Info).
