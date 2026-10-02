---
title: "ServiceNow CMDB"
description: "Comment configurer le Connecteur Upstream ServiceNow CMDB pour DefectDojo"
weight: 121
audience: pro
---
Le connecteur ServiceNow CMDB est un **connecteur d'actifs** : au lieu d'importer des constatations, il lit les éléments de configuration (CI) de votre base de données de gestion de configuration ServiceNow et crée un Asset DefectDojo pour chaque CI, regroupé en Organizations par classe de CI. Aucune constatation n'est importée.

#### Prérequis

Vous aurez besoin d'une instance ServiceNow et d'un compte pouvant lire les tables CMDB via l'API Table de ServiceNow. Nous recommandons un compte de service dédié, en lecture seule, pour DefectDojo. Le compte a besoin d'un accès en lecture aux tables `cmdb_ci` que vous souhaitez importer.

#### Correspondances du connecteur

1. Saisissez l'URL de votre instance ServiceNow dans le champ **Location** : `https://{your-instance}.service-now.com`.
2. Sélectionnez ou créez une **Tool Configuration** ServiceNow contenant les identifiants de l'instance (le nom d'utilisateur et le mot de passe ServiceNow).

Chaque élément de configuration devient un Record nommé d'après le CI, regroupé par sa **classe de CI** (par exemple, application, serveur, ou service métier). La Discovery et le Sync réconcilient la liste des CI : les nouveaux CI apparaissent comme des Records `NEW`, et un CI supprimé de la CMDB est marqué `MISSING` au Sync suivant afin que votre équipe puisse le trier. DefectDojo ne supprime jamais un Produit silencieusement.
