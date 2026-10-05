---
title: "Google Cloud"
description: "Comment configurer le Connecteur Upstream Google Cloud pour DefectDojo"
weight: 67
audience: pro
---
Le connecteur Google Cloud est un **connecteur d'actifs (Asset Connector)** : il lit la hiérarchie de ressources de votre Google Cloud et crée un actif DefectDojo pour chaque **projet**, regroupés en organisations par le dossier dans lequel se trouve le projet. Chaque dossier devient également un actif, si bien que votre organisation, vos dossiers et vos projets apparaissent dans DefectDojo comme la même arborescence que celle que vous voyez dans la console Cloud. Aucune constatation n'est importée.

**Remarque :** ce connecteur importe uniquement l'**inventaire** de vos projets. Pour importer les constatations de Security Command Center, utilisez le connecteur distinct [Google Cloud Security Command Center](/connectors/toolreference/google_cloud_scc/). Les deux sont indépendants et conçus pour fonctionner ensemble : un projet créé par ce connecteur est le même actif sur lequel atterrissent les constatations SCC, donc exécuter les deux ne duplique rien.

#### Prérequis

Le connecteur s'authentifie avec un **compte de service** Google et ne lit que les métadonnées de la hiérarchie : noms, ids, état du cycle de vie et labels des dossiers et projets. Il ne lit ni le contenu des ressources, ni les constatations.

1. Dans Google Cloud, créez un compte de service — un compte dédié pour DefectDojo est recommandé.
2. Accordez-lui le rôle **Browser** (`roles/browser`) au niveau de l'organisation ou du dossier que vous souhaitez importer. Le parcours de la hiérarchie nécessite `resourcemanager.folders.list` et `resourcemanager.projects.list`. Un rôle personnalisé doit aussi inclure `resourcemanager.folders.get` et `resourcemanager.organizations.get`, sinon l'Asset de premier niveau est nommé d'après son identifiant de ressource plutôt que son nom d'affichage. Si votre compte n'a pas d'organisation, il n'y a aucune ressource parente sur laquelle accorder le rôle : accordez `roles/browser` sur chaque projet à importer.
3. Accordez le rôle au **sommet** du périmètre que vous configurez. Le connecteur parcourt tout le sous-arbre, et un dossier qu'il ne peut pas lire fait échouer la synchronisation au lieu d'importer silencieusement un inventaire partiel.
4. Créez une **clé JSON** pour le compte de service et téléchargez-la.
5. Activez l'**API Cloud Resource Manager** (`cloudresourcemanager.googleapis.com`) sur le projet propriétaire du compte de service.

#### Mappages du connecteur

1. Laissez le champ **Location** à sa valeur par défaut `https://cloudresourcemanager.googleapis.com`, sauf si vous utilisez un point de terminaison non standard.
2. Dans le champ **Parent Resource**, saisissez la racine de la hiérarchie à importer : `organizations/{id}` ou `folders/{id}`. Un seul projet n'est pas une hiérarchie, donc `projects/{id}` n'est pas accepté ici — utilisez le connecteur Google Cloud SCC pour un périmètre limité à un seul projet. Si votre compte n'a pas d'organisation, laissez le champ vide : le connecteur importe alors chaque projet que le compte de service peut lire, sous forme de liste plate sans hiérarchie de dossiers.
3. Collez le contenu complet du fichier de **clé JSON** du compte de service dans le champ **Service Account Key**.

Chaque dossier `ACTIVE` et chaque projet `ACTIVE` sous le parent devient un Record. Le Record de chaque projet est nommé d'après son **ID de projet**, et son organisation dans DefectDojo est le dossier dans lequel il se trouve (ou votre organisation Google Cloud, pour un projet situé directement en dessous).

Un projet que vous supprimez dans Google Cloud passe à l'état `DELETE_REQUESTED` et sort de l'import ; son Record mappé est donc marqué `MISSING` lors de la prochaine synchronisation plutôt que supprimé — DefectDojo ne supprime jamais silencieusement un actif. Il en va de même pour un dossier que vous supprimez.

Une fois qu'un Record est mappé, ce connecteur ne met jamais à jour ses métadonnées. Si vous renommez un dossier ou déplacez un projet vers un autre dossier dans Google Cloud, DefectDojo continue d'afficher l'ancien nom ou l'ancien dossier.

#### Fonctionnement avec le connecteur Google Cloud SCC

Les deux connecteurs identifient un projet de la même manière, et tous deux nomment son actif d'après l'ID du projet. Ainsi, si vous exécutez ce connecteur en premier, les constatations SCC atterrissent sur les actifs qu'il a créés ; si SCC s'est exécuté en premier, ce connecteur adopte ces actifs et ajoute la hiérarchie de dossiers autour d'eux. Vous n'avez pas besoin de mapper quoi que ce soit deux fois.

L'organisation suit la même règle : quand ce connecteur crée l'actif, il définit son organisation comme le dossier du projet. Quand le connecteur Google Cloud SCC crée l'actif en premier, cet actif conserve son organisation existante, et ce connecteur ajoute seulement la hiérarchie de dossiers autour de lui.

Une exception : les constatations SCC qui n'appartiennent à aucun projet, comme les constatations de stratégie au niveau de l'organisation, atterrissent sur un actif distinct. Le connecteur Google Cloud SCC crée cet actif pour sa ressource parente configurée ; ce n'est pas l'actif d'organisation ou de dossier que crée ce connecteur. Si vous exécutez les deux connecteurs, attendez-vous à un actif supplémentaire pour ces constatations.
