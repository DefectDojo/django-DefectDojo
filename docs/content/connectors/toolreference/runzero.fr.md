---
title: "runZero"
description: "Comment configurer le Connecteur Upstream runZero pour DefectDojo"
weight: 115
audience: pro
---
Le connecteur runZero utilise l'API Export de runZero pour synchroniser l'inventaire d'actifs de toute votre organisation dans DefectDojo. C'est principalement un connecteur d'**actifs** : DefectDojo découvre chaque actif et crée un Record pour chacun, regroupé en un Product Type par son **site** runZero. Il peut aussi, optionnellement, importer les vulnérabilités de runZero en tant que constatations.

#### Prérequis

Vous aurez besoin d'un **Export Token** d'organisation depuis runZero (Account → API), préfixé par `XT`. Le jeton est scopé à l'organisation (l'organisation est encodée dans le jeton), en lecture seule, et est envoyé comme jeton Bearer — il n'est jamais journalisé. Un niveau communautaire/starter est disponible.

#### Correspondances du connecteur

1. Saisissez l'URL de votre console runZero dans le champ **Location**, par exemple `https://console.runzero.com`. L'URL doit être en HTTPS.
2. Saisissez l'Export Token dans le champ **Secret**.
3. Optionnellement, réglez **Import Vulnerabilities** sur `true` pour aussi importer les vulnérabilités runZero en tant que constatations ; laissez vide pour ne synchroniser que les actifs.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations de vulnérabilité importées (s'applique uniquement lorsque les vulnérabilités sont importées).

DefectDojo associe chaque **actif** runZero à un Record (VEP) : le nom d'affichage provient du nom ou de l'adresse de l'actif, et son site, type, OS, adresses et étiquettes sont attachés en tant qu'attributs ; le **site** de l'actif devient son Product Type. Les actifs sont synchronisés via un export complet que DefectDojo réconcilie (ajouts/suppressions). Lorsque **Import Vulnerabilities** est activé, chaque vulnérabilité runZero devient une constatation sur son actif — en associant la sévérité, le score CVSS, le CVE, le point de terminaison du service concerné (`protocol://address:port`) et la remédiation.

Consultez la [documentation de l'API runZero](https://help.runzero.com/) pour plus d'informations.
