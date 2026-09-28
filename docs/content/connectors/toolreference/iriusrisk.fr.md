---
title: "IriusRisk"
description: "Comment configurer le Connecteur Upstream IriusRisk pour DefectDojo"
weight: 80
audience: pro
---
Le connecteur IriusRisk utilise un jeton API pour importer les données de modélisation de menaces de votre instance IriusRisk.

#### Prérequis

Vous aurez besoin d'un jeton API provenant de votre compte IriusRisk. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de bien distinguer l'activité automatisée des actions manuelles de l'équipe.

Pour générer un jeton API dans IriusRisk :

1. Connectez-vous à votre instance IriusRisk.
2. Accédez à votre **User Profile** dans le menu en haut à droite.
3. Sélectionnez **API Token** et générez un nouveau jeton.

Consultez la [documentation de l'API IriusRisk](https://support.iriusrisk.com/hc/en-us/categories/360001148511) pour plus d'informations.

#### Mappages du connecteur

1. Saisissez l'URL de votre instance IriusRisk dans le champ **Location URL**. Pour les instances hébergées dans le cloud, il s'agit généralement de `https://{your-subdomain}.iriusrisk.com`. Pour les installations sur site, utilisez l'URL de base de votre instance.
2. Saisissez votre **jeton API** dans le champ **Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne seront pas importées.
