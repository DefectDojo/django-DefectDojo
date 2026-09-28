---
title: "Shodan"
description: "Comment configurer le Connecteur Upstream Shodan pour DefectDojo"
weight: 123
audience: pro
---
Le connecteur Shodan utilise l'API REST de Shodan pour importer les vulnérabilités (CVE) que Shodan a observées sur vos hôtes exposés sur Internet. Vous fournissez une requête de recherche Shodan qui limite l'import à vos propres actifs ; DefectDojo crée un Record pour chaque hôte correspondant et importe ses CVE en tant que constatations.

#### Prérequis

Vous aurez besoin d'une clé API Shodan, disponible sur votre page **Account** Shodan. La recherche d'hôtes avec données de vulnérabilité nécessite un abonnement Shodan ou un plan API payant — le niveau gratuit ne permet pas de parcourir les pages de résultats de recherche.

#### Correspondances du connecteur

1. Saisissez `https://api.shodan.io` dans le champ **Location**.
2. Saisissez votre clé API Shodan dans le champ **API Key**.
3. Dans le champ **Search Query**, saisissez une requête Shodan qui limite l'import aux actifs de votre organisation — par exemple `hostname:example.com`, `net:203.0.113.0/24`, ou `org:"Example Inc"`. Seuls les hôtes correspondant à cette requête sont importés ; veillez donc à la limiter à l'infrastructure que vous possédez.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque hôte correspondant devient un Record, et chaque CVE détecté par Shodan sur les services exposés de cet hôte est importé en tant que constatation — la sévérité est dérivée du score CVSS, avec le contexte EPSS et CISA KEV inclus lorsqu'il est disponible. Chaque page de résultats de recherche consomme un crédit de requête Shodan.
