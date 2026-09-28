---
title: Gestion des opérations
description: Vérifier le statut des opérations Discover et Sync de votre connecteur
aliases:
- /fr/import_data/pro/connectors/manage_operations/
- /fr/en/connecting_your_tools/connectors/manage_operations
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les Connecteurs en amont sont une fonctionnalité réservée à DefectDojo Pro.</span>

Une fois qu'un Connecteur en amont est configuré, il exécute deux opérations de manière récurrente :

* **Discover** apprend la structure de l'outil connecté et crée dans DefectDojo des records pour toute donnée non mappée ;
* **Sync** importe les nouvelles Constatations de l'outil en fonction de vos mappages.

Ces deux opérations sont gérées sur la page Opérations d'un connecteur. Le tableau conserve également l'historique des exécutions de ces opérations afin que vous puissiez vérifier que votre connecteur est à jour.

Pour accéder à la page Opérations d'un connecteur, ouvrez **Manage Records & Operations** pour le connecteur avec lequel vous souhaitez travailler, puis passez à l'onglet **</\> Operations From (tool)**.

![image](images/operations_discover.png)

La page **Manage Records & Operations** peut également être utilisée pour gérer les Records ; qui sont les mappages Produit individuels de votre outil connecté.  Consultez [Gestion des Records](../manage_records) pour plus d'informations.

## La page Opérations

![image](images/operations_page.png)

Chaque entrée du tableau de la page Opérations correspond à un événement d'opération, avec les caractéristiques suivantes :

* **Type** indique s'il s'agissait d'une opération **Sync** ou **Discover**.
* **Status** indique si l'événement s'est déroulé avec succès.
* **Trigger** indique comment l'événement a été déclenché \- s'agissait-il d'une opération **Scheduled** exécutée automatiquement, ou d'une opération **Manual** déclenchée par un utilisateur DefectDojo ?
* Le **Start \& End Time** de chaque opération est enregistré ici, ainsi que la **Duration**.

## Opérations Discover

La première étape qu'un connecteur DefectDojo doit effectuer est de **Discover** l'environnement de votre outil pour voir comment vous organisez vos données de scan.

Supposons que vous ayez un outil BurpSuite configuré pour analyser cinq dépôts différents à la recherche de vulnérabilités. Votre connecteur prendra note de cette structure organisationnelle et créera des **Records** pour vous aider à transposer ces dépôts distincts dans la hiérarchie Produit/Engagement/Test de DefectDojo.

### Création de nouveaux Records

Chaque fois que votre connecteur exécute une opération **Discover**, il recherche de nouveaux **Vendor\-Equivalent\-Products (VEPs)**. DefectDojo examine la façon dont l'outil du fournisseur est configuré et crée des **Records** de VEPs en fonction de l'organisation de votre outil.

![image](images/operations_discover_2.png)

### Exécuter Discover manuellement

Les opérations **Discover** s'exécutent automatiquement de façon régulière, mais elles peuvent aussi être lancées manuellement. Si vous configurez ce connecteur pour la première fois, vous pouvez cliquer sur le bouton **Discover** à côté de l'en-tête **Unmapped Records**. Après avoir actualisé la page, vous verrez votre liste initiale de **Records**.

![image](images/operations_discover_3.png)

Pour en savoir plus sur l'utilisation des records et la configuration des mappages vers les Produits, consultez notre guide [Gestion des Records](../manage_records).

## Opérations Sync

Quotidiennement, DefectDojo examine chaque **Mapped Record** à la recherche de nouvelles données de scan. DefectDojo exécute ensuite un **Reimport**, qui compare l'état des données de scan existantes à un rapport entrant.

### Où sont stockées les données de vulnérabilités ?

* DefectDojo crée un **Engagement** imbriqué sous le Produit spécifié dans le **Record Mapping**. Cet Engagement sera nommé **Global Connectors**.
* L'Engagement **Global Connectors** suit chaque connecteur distinct associé au Produit sous la forme d'un **Test**.
* Lors de cette synchronisation, et de chaque synchronisation suivante, le **Test** enregistre chaque vulnérabilité trouvée par l'outil sous la forme d'une **Finding**.

### Comment Sync traite les nouvelles données de vulnérabilités

Chaque fois que Sync s'exécute, il compare les dernières données de scan à la liste existante de Constatations pour détecter les changements. 

* Si de nouvelles Constatations sont détectées, elles sont ajoutées au Test en tant que nouvelles Constatations.
* Si des Constatations ne sont pas détectées lors du dernier scan, elles sont marquées comme Inactive dans le Test.

Pour en savoir plus sur les Produits, Engagements, Tests et Constatations, consultez notre [Vue d'ensemble de la hiérarchie des produits](/asset_modelling/os_hierarchy/product_hierarchy/).

### Exécuter Sync manuellement

Pour que DefectDojo exécute une opération Sync en dehors de sa planification :

1. Accédez à la page **Manage Records \& Operations** du connecteur que vous souhaitez utiliser. Depuis la page **Connecteurs en amont**, cliquez sur le menu déroulant **Manage Configuration** du connecteur avec lequel vous souhaitez travailler, puis sélectionnez **Manage Records \& Operations**.  
​
2. Depuis cette page, cliquez sur le bouton **Sync**. Ce bouton se trouve à côté de l'en-tête **Mapped Records**.

![image](images/operations_sync.png)
