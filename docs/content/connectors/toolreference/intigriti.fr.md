---
title: "Intigriti"
description: "Comment configurer le Connecteur Upstream Intigriti pour DefectDojo"
weight: 78
audience: pro
---
Le connecteur Intigriti utilise l'API externe Intigriti pour les entreprises afin d'importer dans DefectDojo les **soumissions** de bug bounty / pentest. Il synchronise l'ensemble du compte de l'entreprise : DefectDojo découvre chaque programme auquel le jeton peut accéder et crée un Enregistrement pour chacun, puis importe les soumissions de ce programme en tant que constatations.

#### Prérequis

Vous aurez besoin d'un **jeton API d'entreprise** Intigriti. Dans le portail entreprise Intigriti, sous **Company Settings > API** (le périmètre `company_external_api`), générez un jeton d'accès avec un accès en lecture à vos programmes et soumissions. Un jeton dédié pour DefectDojo est recommandé. Le jeton est envoyé en tant que jeton Bearer et n'est jamais journalisé.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API externe Intigriti pour les entreprises dans le champ **Location** : `https://api.intigriti.com/external/company`. L'URL doit être en HTTPS.
2. Saisissez le jeton API d'entreprise dans le champ **Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

DefectDojo mappe chaque **programme** Intigriti à un Enregistrement et chaque **soumission** à une constatation, indexée par le code de la soumission. La sévérité de la constatation suit la notation Intigriti (Exceptional/Critical → Critique, puis High/Medium/Low, sinon Informational), et l'état du cycle de vie de la soumission se mappe au statut de la constatation : les soumissions ouvertes/en triage sont actives, les soumissions acceptées sont vérifiées, et les soumissions fermées deviennent atténuées, doublon, hors périmètre, faux positif ou risque accepté selon leur motif de fermeture. La description de la constatation reprend le type de vulnérabilité du rapport, l'actif affecté, la preuve de concept et les réponses du chercheur.

Consultez la [documentation de l'API Intigriti](https://kb.intigriti.com/en/articles/6117846-intigriti-api) pour plus d'informations.
