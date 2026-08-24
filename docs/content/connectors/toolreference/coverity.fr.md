---
title: "Coverity"
description: "Comment configurer le Connecteur Upstream Coverity pour DefectDojo"
weight: 40
audience: pro
---
Le connecteur Coverity importe des constatations depuis un serveur **Coverity Connect**. DefectDojo crée un enregistrement pour chaque **projet** Coverity.

#### Mappages du connecteur

1. Saisissez l'URL de votre serveur Coverity Connect dans le champ **Location**.
2. Saisissez le **username** Coverity Connect dans le champ **Username**.
3. Saisissez le mot de passe ou la clé d'authentification de l'utilisateur dans le champ **Secret**.
4. Facultativement, définissez un **View Name** pour sélectionner la vue d'issues enregistrée que le connecteur doit lire. Laissez vide pour utiliser la vue par défaut, **Outstanding Issues**.
5. Facultativement, définissez **Import All Issue Kinds** sur `true` pour élargir l'import au-delà du filtre d'issues Security and Quality (`RESOURCE_LEAK`) par défaut.
