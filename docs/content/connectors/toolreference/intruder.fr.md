---
title: "Intruder"
description: "Comment configurer le Connecteur Upstream Intruder pour DefectDojo"
weight: 79
audience: pro
---
Le connecteur Intruder utilise l'[API REST Intruder](https://developers.intruder.io/) pour importer dans DefectDojo la posture de l'ensemble de votre compte. Chaque **cible** Intruder est découverte comme un Enregistrement (Produit) ; chaque **occurrence** d'une issue sur une cible devient une Constatation.

#### Mappages du connecteur

1. Laissez le champ **Location** à `https://api.intruder.io/` (le serveur API Intruder par défaut).
2. Saisissez un **jeton d'accès API** Intruder dans le champ **Secret**.

Générez un jeton d'accès dans Intruder sous **My account > API Access Tokens** (vous aurez besoin du mot de passe de votre compte pour le créer, et le jeton n'est affiché qu'une seule fois). Consultez la [documentation de l'API Intruder](https://developers.intruder.io/docs/creating-an-access-token) pour plus de détails.

Les constatations sont dérivées par occurrence : la sévérité provient de la sévérité de l'issue, les CVE et le CVSS proviennent de l'occurrence, l'emplacement provient de la cible/du port, et une occurrence mise en sommeil (snoozed) est importée comme une constatation inactive (faux positif ou risque accepté).
