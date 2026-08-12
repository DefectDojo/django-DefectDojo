---
title: Automatisation du Moteur de règles
description: Utilisation de l'automatisation du Moteur de règles
weight: 1
audience: pro
aliases:
- /fr/en/customize_dojo/rules_engine
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : le Moteur de règles est une fonctionnalité réservée à DefectDojo Pro.</span>

Le Moteur de règles de DefectDojo vous permet de créer des workflows personnalisés et des actions en masse pour traiter les Constatations et d'autres objets. Le Moteur de règles vous permet de créer des actions automatisées qui se déclenchent lorsqu'un objet correspond à une Règle.

Le Moteur de règles n'est accessible que via l'[interface Pro](/get_started/about/ui_pro_vs_os/).

**Vous cherchez l'éditeur de graphes ?** Le [Moteur de règles 2.0](/automation/rules_engine_2/about/) construit l'automatisation sous forme de graphes de nœuds visuels, et ajoute des embranchements, des actions sortantes telles que des tickets et des messages, des traces par exécution et un registre des livraisons. Les deux moteurs fonctionnent côte à côte, et les règles existantes peuvent être [converties vers l'autre moteur](/automation/rules_engine_2/converting_from_rules_engine/).

## Activer le Moteur de règles

Le Moteur de règles est en version bêta et est désactivé par défaut. Un superutilisateur peut l'activer depuis **Paramètres > Feature Flags**, aussi bien sur les instances Cloud que sur site (On-Premise). Voir [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Actuellement, les Règles ne peuvent être créées que pour les Constatations, mais davantage de types d'objets seront pris en charge à l'avenir.

Les Règles peuvent être déclenchées manuellement depuis la page **Toutes les règles**, ou planifiées pour s'exécuter automatiquement selon une périodicité récurrente. Lorsqu'une règle est déclenchée, elle s'applique à toutes les Constatations existantes qui correspondent aux conditions de filtre définies.

## Actions de règle possibles
Chaque Règle peut appliquer un ou plusieurs de ces changements à une Constatation lorsqu'elle se déclenche avec succès (c'est-à-dire lorsqu'elle correspond aux conditions de filtre définies).

### Modifications de champs
* **Définir un champ** sur une Constatation, notamment Titre, Description, Sévérité, Vecteur CVSSv3, Actif, Vérifié, Risque accepté, Faux positif, Atténué
* **Ajouter du texte au début ou à la fin** du Titre ou de la Description d'une Constatation
* **Définir la priorité** — remplace la valeur de priorité calculée sur une Constatation (annule le calcul automatique de la priorité)
* **Définir le risque** — remplace le niveau de risque calculé sur une Constatation (annule le calcul automatique du risque)
* **Ajouter, soustraire, multiplier ou diviser** la valeur de priorité d'une Constatation par un nombre donné

### Attributions et propriété
* **Définir un Utilisateur pour réviser** une Constatation
* **Attribuer un Groupe comme propriétaire** d'une Constatation
* **Définir une politique d'atténuation** sur une Constatation — attribue une politique d'atténuation préconfigurée à la Constatation
* **Ajouter à une acceptation du risque** — ajoute une Constatation à un enregistrement d'Acceptation du risque existant (définit risk_accepted=True, active=False, et gère l'intégration Jira ainsi que les statuts des points de terminaison)

### Étiquettes, notes et alertes
* **Ajouter des étiquettes** à une Constatation
* **Ajouter une note** à une Constatation
* **Créer une alerte** dans DefectDojo avec un texte personnalisé

### Conditions de filtre
Les Règles se déclenchent automatiquement lorsqu'une Constatation répond à des conditions de filtre spécifiques. Pour plus d'informations sur les Filtres pouvant être utilisés pour créer des Actions de règle, consultez la page [Index des filtres](/navigation/pro__filter_index).

## Créer une nouvelle règle
Démarrez ce processus depuis la page Nouvelle règle. Dans l'[interface Pro](/get_started/about/ui_pro_vs_os/), sous **Gérer la catégorie**, développez le menu déroulant **Moteur de règles** et cliquez sur **+ Nouvelle règle**.

![image](images/rules_engine_1.png)

### Étape 1 : nommez votre règle
Saisissez un Libellé servant d'identifiant pour la nouvelle règle, puis cliquez sur Suivant.

![image](images/rules_engine_2.png)

### Étape 2 : définissez les conditions de déclenchement avec un filtre
Vous verrez un tableau Toutes les Constatations. À l'aide de ce tableau, définissez les conditions de filtre afin de restreindre l'ensemble des Constatations auquel votre règle doit s'appliquer. Pour en savoir plus sur l'application de filtres à un tableau, consultez [notre guide de l'interface Pro](/get_started/about/ui_pro_vs_os/#navigational-changes).

Le tableau affiche un aperçu de la liste des Constatations existantes que vous avez filtrées.

Par exemple, dans cette capture d'écran, nous filtrons toutes les Constatations qui se trouvent dans « Product One ». Une fois ce filtre appliqué (en cliquant en dehors du menu Filtres), il est ajouté à notre liste de Filtres applicables.

![image](images/rules_engine_3.png)

Dans la capture d'écran ci-dessus, des actions seront appliquées à toutes les Constatations du Produit « Product One ».

Une fois que vous disposez de l'ensemble de Filtres que vous souhaitez appliquer, cliquez sur le bouton Suivant.

### Étape 3 : définissez les actions de la règle
Dans le menu déroulant **Action**, sélectionnez l'Action que vous souhaitez appliquer à une Constatation correspondant à tous les filtres de l'étape 2. Plusieurs Actions peuvent être appliquées.

Vous pouvez définir des Valeurs conditionnelles supplémentaires qui permettent de déclencher des actions additionnelles si certains critères sont remplis.

![image](images/rules_engine_4.png)


Par exemple, dans la capture d'écran ci-dessus, nous avons défini 4 Actions de règle. Deux de ces actions sont Conditionnelles.

Toutes les Constatations qui correspondent aux conditions de filtre déclencheront ces Actions non conditionnelles :

* La Constatation sera attribuée au groupe d'utilisateurs « Group 1 »
* La Constatation sera étiquetée avec `all_group_1`

Toute Constatation qui correspond aux conditions de filtre, ainsi qu'à ces conditions **supplémentaires**, déclenchera ces Actions conditionnelles en plus des deux Actions non conditionnelles listées ci-dessus :

* **si la Constatation a une Sévérité Critique**, elle sera étiquetée avec `critical_group_1`.
* **si la Constatation a une Sévérité Élevée**, elle sera étiquetée avec `high_group_1`.

### Étape 4 - Aperçu de votre règle

L'Aperçu de la règle affiche toutes les Constatations qui seront modifiées par cette règle une fois exécutée, ainsi qu'un aperçu des Actions effectuées. Vérifiez que les changements proposés vous conviennent, puis cliquez sur Valider pour enregistrer votre règle.

Si vous estimez que cette règle n'a pas été appliquée correctement, vous pouvez cliquer sur le bouton Précédent pour revenir à l'une des étapes précédentes.

![image](images/rules_engine_5.png)

Par exemple, dans la capture d'écran ci-dessus, nous avons une liste de Constatations qui seront affectées par la Règle une fois qu'elle sera exécutée. Nous pouvons voir que de nouvelles Étiquettes et de nouveaux Propriétaires seront appliqués à chacune de ces Constatations, dans les colonnes à droite de la liste des Constatations.

Il vous sera de nouveau demandé de confirmer la création de votre Règle. Notez que la **Règle ne sera pas appliquée immédiatement**, et devra être déclenchée manuellement.

## Exécuter une règle
Depuis la page Toutes les règles, vous pouvez sélectionner la Règle que vous souhaitez exécuter.  Cliquez sur le titre de la règle pour en voir le détail.

![image](images/rules_engine_6.png)

Sur cette page, vous pouvez consulter des informations détaillées sur cette règle sous **Métadonnées**, y compris des informations sur la date de son dernier déclenchement.  Vous pouvez également voir un aperçu des Constatations qui seront affectées par une nouvelle exécution de cette Règle, sous **Aperçu de la règle**.

Pour exécuter la Règle, cliquez sur le bouton vert Exécuter la règle.  Une fois que vous avez confirmé vouloir exécuter la règle, un message apparaît indiquant que la règle est mise en file d'attente pour s'exécuter en arrière-plan.

Une fois que la Règle a terminé son exécution avec succès, le nombre d'Éléments modifiés est mis à jour dans la section Métadonnées de la description de la Règle.

## Référence des métadonnées de la règle
* **Règle pour** : les objets régis par la Règle.
* **Nom de la règle** : le nom de la Règle.
* **Filtres** : le nombre de Filtres appliqués par cette Règle.
* **Actions** : le nombre d'Actions effectuées par cette Règle.
* **Propriétaire** : l'Utilisateur qui a créé cette Règle.
* **Statut** : le rapport de statut de la dernière exécution de cette Règle.
    'E' = 'Error', 'R' = 'Running', 'S' = 'Success'.
* **Dernière exécution** : l'horodatage de la dernière exécution de cette Règle.
* **Éléments modifiés :** le nombre d'objets modifiés lors de la dernière exécution de la règle.
* **Éléments ignorés :** le nombre d'objets ignorés lors de la dernière exécution de la règle.  Si un objet filtré correspond déjà au « résultat » d'une Action de règle qui lui serait appliquée (par exemple, s'il possède déjà les Étiquettes qu'une Action de règle appliquerait), l'objet est simplement ignoré.
