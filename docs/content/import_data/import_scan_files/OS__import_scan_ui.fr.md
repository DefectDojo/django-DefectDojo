---
title: Formulaire Import Scan
description: ''
weight: 1
audience: opensource
---

Une fois votre Hiérarchie des produits configurée avec au moins un Type de produit, un Produit, un Test et un Engagement, vous pouvez importer un fichier d'analyse dans DefectDojo et créer des Constatations.

Il est facile de réorganiser votre Hiérarchie des produits dans DefectDojo, donc ce n'est pas grave si vous ne savez pas encore exactement comment tout configurer.

Pour l'instant, il est utile de savoir que les **Engagements** peuvent stocker des données provenant de plusieurs outils, ce qui peut être utile si vous exécutez différents outils simultanément dans le cadre d'un même effort de test.

## Accéder au formulaire Import Scan (interface classique / Open Source)

Dans DefectDojo OS, vous pouvez accéder à ce formulaire depuis deux emplacements :

* La section Tests d'un Engagement :
    ![image](images/import_scan_os.png)
* La section Constatations de la barre de navigation d'un Produit :
    ![image](images/import_scan_os_2.png)

## Remplir le formulaire Import Scan

![image](images/import_scan_ui.png)
Le formulaire Import Scan crée un nouveau Test imbriqué dans un Engagement, qui contiendra une Constatation unique pour chaque vulnérabilité présente dans votre fichier d'analyse.

Le Test sera créé avec un nom correspondant au Type d'analyse : par exemple, une analyse Tenable sera intitulée « Tenable Scan ».

### Options du formulaire

* **Scan File :** en cliquant sur le bouton Choose, vous pouvez sélectionner un fichier de votre ordinateur à téléverser.
* **Scan Date (optionnel) :** si vous souhaitez sélectionner une Date d'analyse unique à appliquer à toutes les Constatations issues de cet import, vous pouvez la sélectionner dans ce champ.
Si vous ne sélectionnez pas de Date d'analyse, les Constatations créées à partir de ce rapport utiliseront la date indiquée par l'outil. Les SLA de chaque Constatation seront calculés en fonction de leur date.
* **Scan Type :** sélectionnez l'outil utilisé pour créer ces données.
* **Environment :** sélectionnez un Environnement correspondant aux données que vous téléversez.
* **Étiquettes :** si vous souhaitez utiliser des étiquettes pour mieux organiser les données de votre Test, vous pouvez ajouter des Étiquettes à l'aide de ce formulaire. Saisissez le nom de l'étiquette que vous souhaitez créer, puis appuyez sur Entrée sur votre clavier pour l'ajouter à la liste des étiquettes.

### Champs facultatifs

* **Sévérité minimale** : si vous souhaitez créer des Constatations uniquement à partir d'un certain niveau de Sévérité et au-dessus, vous pouvez sélectionner ce niveau minimal ici. Toutes les vulnérabilités dont la sévérité est inférieure à ce champ seront ignorées.
* **Actif** : si vous souhaitez définir toutes les Constatations entrantes comme Actives ou Inactives, vous pouvez le préciser ici. Sinon, DefectDojo utilisera les données de vulnérabilité de l'outil pour déterminer si la Constatation est Active ou Inactive. Cette option est pertinente si vous avez besoin que votre équipe trie et vérifie manuellement les Constatations provenant d'un outil particulier.
* **Vérifié** : comme pour Actif, vous pouvez définir par défaut le nouvel ensemble de Constatations comme Vérifié ou Non vérifié. Cela dépend des préférences de votre flux de travail. Par exemple, si votre équipe préfère considérer que les Constatations sont vérifiées sauf preuve du contraire, vous pouvez définir ce champ sur True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** peuvent tous être spécifiés si vous souhaitez inclure ces détails dans le Test.
* **Source Code Management URI** peut également être spécifié. Cette option de formulaire doit être une URI valide.
* **Group By :** si vous souhaitez créer des Groupes de constatations à partir de ce fichier, vous pouvez spécifier ici la méthode de regroupement.

### Scanners sans triage : le champ Do Not Reactivate

Certains scanners peuvent ne pas inclure d'informations de triage dans leurs rapports (par exemple tfsec). Ils se contentent d'analyser le code ou les dépendances, de signaler les problèmes, et de tout renvoyer, qu'une vulnérabilité ait déjà été triée ou non.

Pour gérer ce cas, DefectDojo inclut également une case à cocher « Do not reactivate » lors du téléversement des rapports (également disponible dans l'API de réimport), afin que vous puissiez utiliser DefectDojo comme source de vérité pour le triage, plutôt que de réactiver vos Constatations triées à chaque import / réimport.

### Utiliser le champ Date d'achèvement de l'analyse (API : `scan_date`)

DefectDojo prend en charge une multitude de rapports de scanners, mais tous ne contiennent pas les informations les plus importantes pour un utilisateur. Le champ `scan_date` est une fonctionnalité intelligente et flexible qui permet aux utilisateurs de définir la date d'achèvement d'un rapport d'analyse donné, et de la propager à toutes les constatations importées. Ce champ n'est **pas** obligatoire, mais sa valeur par défaut est la date de l'import (au moment où la requête est traitée et qu'une réponse de succès est renvoyée).

Voici les cas d'usage possibles pour ce champ :

1. Le rapport **ne définit pas** la date, et `scan_date` **n'est pas** défini lors de l'import
    - La date de la Constatation sera la valeur par défaut de `scan_date`
2. Le rapport **définit** la date, et `scan_date` **n'est pas** défini lors de l'import
    - La date de la Constatation sera celle définie par le rapport
3. Le rapport **ne définit pas** la date, et `scan_date` **est défini** lors de l'import
    - La date de la Constatation sera celle définie par l'utilisateur pour `scan_date`
4. Le rapport **définit** la date, et `scan_date` **est défini** lors de l'import
    - La date de la Constatation sera celle définie par l'utilisateur pour `scan_date`
