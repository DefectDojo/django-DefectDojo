---
title: Gestion des enregistrements
description: Orientez le flux de données de votre outil vers DefectDojo
aliases:
- /fr/import_data/pro/connectors/manage_records/
- /fr/en/connecting_your_tools/connectors/manage_records
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les connecteurs Upstream sont une fonctionnalité réservée à DefectDojo Pro.</span>

Une fois que vous avez exécuté votre première opération Découverte, vous devriez voir une liste d'enregistrements Mappés ou Non mappés sur la page **Manage Records and Operations**.

## Qu'est-ce qu'un enregistrement ?

Un enregistrement est une connexion entre un **Produit** DefectDojo et un **produit équivalent chez le fournisseur**. Vous pouvez utiliser votre liste d'enregistrements pour contrôler le flux de données entre votre outil et DefectDojo.

Les enregistrements sont créés et mis à jour lors de l'opération **[Découverte](../manage_operations/#discover-operations)**, que DefectDojo exécute quotidiennement pour rechercher de nouveaux produits équivalents chez le fournisseur.

![image](images/manage_records.png)

Les enregistrements comportent plusieurs attributs, notamment :

* L'**État** de l'enregistrement
* Le **Produit** vers lequel l'enregistrement importe les données
* La date à laquelle l'enregistrement a été **découvert pour la première et la dernière fois** (par le processus de **Découverte**)
* La date à laquelle le mappage de l'enregistrement a été **finalisé** par un utilisateur
* Un lien vers le **Produit** DefectDojo

## Comment les enregistrements sont mappés

Chaque enregistrement doit se voir attribuer un mappage. Le mappage indique à DefectDojo où stocker les données de scan provenant de l'outil. Un enregistrement mappé associe le produit équivalent chez le fournisseur à un produit DefectDojo, et indique au connecteur de commencer à importer les données de scan à cet emplacement (sous forme d'engagements et de tests).

Vous pouvez attribuer les mappages vous-même, ou laisser DefectDojo les attribuer automatiquement.

### Mappage automatique

Si le **mappage automatique** est activé, les nouveaux enregistrements seront mappés automatiquement à des produits. Chaque fois que DefectDojo **découvre** un nouvel enregistrement, un produit DefectDojo correspondant sera automatiquement créé pour chaque enregistrement. Cet enregistrement sera stocké dans les **enregistrements mappés** pour indiquer qu'il est prêt à importer des données vers DefectDojo.

Si le mappage automatique n'est pas activé, vous pouvez décider vous-même de la destination des données. Chaque fois que le connecteur trouve un nouveau produit équivalent chez le fournisseur (via la **Découverte**), il ajoute un nouvel enregistrement à votre liste d'**enregistrements non mappés**, que vous pouvez ensuite affecter manuellement à un produit nouveau ou existant dans DefectDojo.

#### Mappage - Exemple de flux de travail :

David vient de terminer la configuration d'un connecteur pour son outil BurpSuite, et exécute une opération Découverte. David a configuré Burp pour analyser 4 « Sites » différents, et DefectDojo crée un nouvel enregistrement pour chacun de ces sites.

* Si David choisit d'utiliser le mappage automatique, DefectDojo créera un nouveau produit pour chaque site. Désormais, lorsque DefectDojo exécutera une opération de synchronisation, le connecteur importera directement les données de scan du site vers le produit (via le mappage de l'enregistrement)
​
* Si David laisse le mappage automatique désactivé, DefectDojo découvrira quand même ces 4 sites et créera les enregistrements correspondants, mais n'importera aucune donnée tant que David n'aura pas créé lui-même les mappages.
​
* David peut toujours modifier ultérieurement la configuration de ces mappages. Peut-être souhaite-t-il regrouper la sortie de plusieurs sites Burp différents dans un seul produit. Ou peut-être cherche-t-il à disposer d'un produit qui enregistre les données de scan de plusieurs outils différents, y compris Burp. Il est facile pour David de modifier l'endroit où les données de scan de Burp sont stockées dans DefectDojo en changeant le mappage de ces enregistrements.

## Comment les enregistrements interagissent avec les produits

Une fois qu'un enregistrement est mappé, DefectDojo sera prêt à importer les scans de votre outil via une opération de synchronisation. Les connecteurs peuvent fonctionner aux côtés d'autres processus d'importation DefectDojo ou de tests interactifs.

* Les mappages d'enregistrements sont conçus pour être non invasifs. Si vous mappez un produit à un enregistrement contenant des engagements ou des constatations existants, ces engagements et constatations existants ne seront ni affectés ni écrasés par le processus de synchronisation des données.
​
* Toutes les données créées via un connecteur seront stockées dans un engagement unique appelé **Global Connectors**. Cet engagement créera un test distinct pour chaque connecteur mappé au produit.

![image](images/manage_records_2.jpg)

Cela permet d'envoyer des données de scan provenant de plusieurs connecteurs vers le même produit. Toutes les données seront stockées dans le même engagement, mais chaque connecteur stockera ses données dans un test distinct.

Pour en savoir plus sur les produits, les engagements et les tests, consultez notre [aperçu de la hiérarchie des produits](/asset_modelling/os_hierarchy/product_hierarchy/).

## États des enregistrements - Glossaire

Chaque enregistrement possède un état associé qui indique son fonctionnement.

La liste complète des enregistrements d'un connecteur est accessible en ouvrant le connecteur depuis **Connect \> Upstream** — la page s'intitule **All \<Connector\> Records**. Malgré son nom, elle répertorie tous les enregistrements appartenant à **ce connecteur en particulier**, et non tous les enregistrements de l'instance.

Cette liste peut être **filtrée par état** depuis la colonne **État**, et plusieurs états peuvent être sélectionnés en même temps. C'est le moyen le plus rapide de répondre aux questions les plus fréquentes sur un parc de connecteurs important : *qu'est-ce qui attend d'être mappé ?* (**Nouveau**) et *qu'est-ce qui a cessé de remonter des données ?* (**Manquant** ou **Erreur**) — sans avoir à parcourir chaque enregistrement.

Tous les états ne s'appliquent pas à tous les connecteurs. **Obsolète** est défini par le pipeline d'importation des constatations, il ne se produit donc que sur les connecteurs qui importent des constatations ; les **connecteurs d'actifs** n'atteignent jamais cet état, et il n'est pas proposé comme option de filtre pour ceux-ci.

### Nouveau

Un enregistrement Nouveau est un enregistrement non mappé que DefectDojo a découvert. Il peut être mappé à un produit ou ignoré. Pour mapper un nouvel enregistrement à un produit, consultez notre guide [Modification des enregistrements]().

### Bon

« Bon » indique qu'un enregistrement est mappé et fonctionne correctement. Les futures opérations de découverte vérifient que le produit équivalent chez le fournisseur sous-jacent existe toujours, afin de s'assurer que l'opération de synchronisation s'exécutera correctement.

### Ignoré

Les enregistrements « Ignorés » ont été découverts avec succès, mais un utilisateur de DefectDojo a décidé de ne pas mapper les données à un produit.

## États d'avertissement : Obsolète ou Manquant

Si la connexion entre l'outil et DefectDojo change, l'état d'un enregistrement changera pour vous en informer.

### Obsolète

Un mappage passe à l'état « Obsolète » lorsqu'un produit, un engagement ou un test associé a été supprimé de DefectDojo. Le mappage existe toujours, mais il n'y a plus, dans DefectDojo, d'emplacement où importer les données de l'outil.

Les enregistrements obsolètes peuvent être remappés vers un produit existant, ou ignorés si les données de scan ne sont plus pertinentes.

### Manquant

Si un enregistrement a été mappé, mais que les données source (ou le produit équivalent chez le fournisseur) ne sont plus détectées par DefectDojo, l'enregistrement sera étiqueté comme **Manquant**.

Les connecteurs DefectDojo s'adaptent aux changements de nom, de répertoire et à d'autres évolutions des données ; ceci peut donc être dû au fait que le produit équivalent associé a été supprimé de l'outil que vous utilisez.

Si vous aviez l'intention de retirer le produit équivalent de votre outil, vous pouvez supprimer un enregistrement Manquant. Sinon, vous devrez résoudre le problème au sein de l'outil afin que les données source puissent être découvertes correctement.

### Erreur

**Erreur** indique que DefectDojo n'a pas pu traiter l'enregistrement. Cet état est disponible pour tous les types de connecteurs, et peut être sélectionné dans le filtre **État** aux côtés des états ci-dessus, ce qui en fait le moyen le plus rapide de vérifier si un connecteur nécessite une attention particulière après une exécution.

## Modifier les enregistrements : remapper, ignorer ou supprimer

Les enregistrements peuvent être modifiés, ignorés ou supprimés depuis la page **Manage Records \& Operations**.

Bien que les enregistrements mappés et non mappés se trouvent dans des tableaux distincts, ils peuvent tous deux être modifiés de la même manière.

Dans le tableau des enregistrements, cliquez sur la flèche bleue ▼ à côté de la colonne État d'un enregistrement donné. Vous pouvez alors sélectionner **Edit Record**, ou **Delete Record**.

![image](images/edit_ignore_delete_records.png)

### Modifier le mappage d'un enregistrement

En cliquant sur **Edit Record**, une fenêtre s'ouvre vous permettant de modifier le produit de destination dans DefectDojo. Vous pouvez soit sélectionner un produit existant dans le menu déroulant, soit saisir le nom d'un nouveau produit que vous souhaitez créer.

![image](images/edit_ignore_delete_records_2.png)

Les données de scan associées à un enregistrement peuvent être redirigées vers un produit différent en modifiant le mappage.

Sélectionnez, ou saisissez le nom d'un nouveau produit dans le menu déroulant à droite.

#### Modifier l'état d'un enregistrement

L'état d'un enregistrement peut également être modifié depuis ce menu. Les enregistrements peuvent passer de Bon à Ignoré (ou inversement) en choisissant une option dans la liste déroulante **État**.

### Ignorer un enregistrement

Si vous souhaitez « désactiver » l'un des enregistrements ou ne pas tenir compte des données qu'il envoie à DefectDojo, vous pouvez choisir d'« ignorer » l'enregistrement. Un enregistrement « Ignoré » sera déplacé vers la liste des enregistrements non mappés et ne transmettra plus aucune nouvelle donnée à DefectDojo.

Vous pouvez ignorer un enregistrement mappé (ce qui supprimera le mappage), ou un nouvel enregistrement (depuis la liste des enregistrements non mappés).

#### Restaurer un enregistrement ignoré

Si vous souhaitez retirer le statut Ignoré d'un enregistrement, vous pouvez le repasser à Nouveau à l'aide du même menu déroulant État.

* Si le mappage automatique des enregistrements est activé, l'enregistrement retrouvera son mappage d'origine une fois que l'opération de découverte s'exécutera à nouveau.
* Si le mappage automatique des enregistrements n'est pas activé, DefectDojo ne restaurera pas automatiquement un mappage précédent ; vous devrez donc reconfigurer le mappage de cet enregistrement.

### Supprimer un enregistrement

Vous pouvez également supprimer des enregistrements, ce qui les retirera du tableau des enregistrements non mappés ou mappés.

Gardez à l'esprit que la fonction Découverte importera toujours tous les enregistrements d'un outil — ce qui signifie que même si un enregistrement est supprimé de DefectDojo, il sera redécouvert ultérieurement (et reviendra dans la liste des enregistrements à mapper à nouveau).

* Si vous prévoyez de retirer le produit équivalent sous-jacent de votre outil de scan, alors supprimer l'enregistrement est une bonne option. Sinon, la prochaine opération de découverte constatera que les données associées sont manquantes, et cet enregistrement passera à l'état « Manquant ».
​
* En revanche, si le produit équivalent sous-jacent existe toujours, il sera redécouvert lors d'une prochaine opération de découverte. Pour éviter ce comportement, vous pouvez plutôt ignorer l'enregistrement.

#### Cela affecte-t-il les données importées ?

Non. Toutes les constatations, tests et engagements créés par un enregistrement de synchronisation resteront dans DefectDojo même après la suppression de l'enregistrement. Supprimer un enregistrement ou une configuration ne fera que supprimer le processus de flux de données, et ne supprimera aucune donnée de vulnérabilité de DefectDojo ou de votre outil.
