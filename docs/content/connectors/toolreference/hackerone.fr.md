---
title: "HackerOne"
description: "Comment configurer le Connecteur Upstream HackerOne pour DefectDojo"
weight: 69
audience: pro
---
Le connecteur HackerOne utilise l'API REST HackerOne pour importer les rapports de votre programme de bug bounty ou de divulgation de vulnérabilités. DefectDojo crée un Enregistrement pour chaque programme auquel le jeton peut accéder et importe ses rapports en tant que constatations.

#### Prérequis

Le connecteur utilise l'API **customer** de HackerOne, qui nécessite un **jeton API d'organisation** — un jeton personnel provenant de vos paramètres utilisateur ne fonctionne qu'avec l'API hacker et ne permettra pas de s'authentifier ici.

1. Dans HackerOne, accédez à **Organization Settings > API Tokens**.
2. Créez un jeton et notez à la fois l'**identifiant** et la valeur du **jeton**. Un accès en lecture au programme suffit.

#### Mappages du connecteur

1. Saisissez `https://api.hackerone.com` dans le champ **Location**.
2. Saisissez l'**identifiant** du jeton dans le champ **API Token Identifier**.
3. Saisissez la valeur du jeton dans le champ **API Token**.
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

Chaque programme devient un Enregistrement, et ses rapports sont importés en tant que constatations en conservant la note de sévérité HackerOne.
