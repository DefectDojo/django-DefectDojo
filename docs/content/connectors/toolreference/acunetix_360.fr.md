---
title: "Acunetix 360"
description: "Comment configurer le Connecteur Upstream Acunetix 360 pour DefectDojo"
weight: 12
audience: pro
---
Le connecteur Acunetix 360 importe des **constatations de vulnérabilités DAST** depuis la plateforme cloud Acunetix 360 (la plateforme Invicti). DefectDojo découvre les sites web analysés de votre compte et crée un Enregistrement pour chaque **site web** ; les constatations d'un site web proviennent de son dernier scan terminé.

**Veuillez noter :** ce connecteur est destiné à **Acunetix 360** (le produit cloud à l'adresse `online.acunetix360.com`). Il ne concerne pas le scanner Acunetix Standard/Premium sur site, qui dispose d'une API différente.

#### Prérequis

Un compte Acunetix 360 et des **identifiants API** : dans Acunetix 360, ouvrez le menu de votre compte \> **API Settings**, notez l'**API User ID** et générez un **API Token**. Le connecteur s'authentifie avec ces identifiants au format HTTP Basic ; un compte de service dédié est donc recommandé pour distinguer l'activité automatisée des actions manuelles de l'équipe.

#### Mappages du Connecteur

1. Saisissez l'URL de votre Acunetix 360 dans le champ **Location** : `https://online.acunetix360.com`.
2. Saisissez l'API User ID dans le champ **API User ID**.
3. Saisissez l'API Token dans le champ **API Token**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque site web analysé devient un Enregistrement. Les constatations proviennent du dernier scan terminé du site web ; les vulnérabilités qu'Acunetix 360 a marquées **Accepted Risk** ou **False Positive** sont tout de même importées, mais signalées comme inactives (risque accepté ou faux positif) afin que le produit DefectDojo reflète le triage effectué par l'éditeur.
