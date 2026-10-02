---
title: "Anchore"
description: "Comment configurer le Connecteur Upstream Anchore pour DefectDojo"
weight: 16
audience: pro
---
Le connecteur Anchore utilise le jeton API d'un utilisateur pour récupérer des données depuis Anchore Enterprise.  Les Produits sont mappés et découverts à partir des « Applications », qui sont composées de plusieurs Images dans Anchore - voir la [documentation Anchore Enterprise](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) pour plus d'informations.

#### Mappages du Connecteur

1. L'URL d'Anchore dans le champ **Location** : il s'agit de l'URL à laquelle vous accédez à Anchore.
2. Saisissez une clé API valide dans le champ Secret. Il s'agit de la clé API associée à votre compte de service Burp.

Consultez la [documentation officielle d'Anchore](https://docs.anchore.com/current/docs/) pour plus d'informations sur la création d'un jeton pour Anchore.
