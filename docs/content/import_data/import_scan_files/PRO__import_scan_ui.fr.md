---
title: Formulaire d'ajout de constatations
description: ''
weight: 1
audience: pro
aliases:
- /fr/en/connecting_your_tools/import_scan_files/import_scan_ui
---

Si vous disposez d'une toute nouvelle instance DefectDojo, le formulaire d'importation de scan est une première étape logique pour découvrir le logiciel et configurer votre environnement. Depuis ce formulaire, vous téléversez un fichier de scan provenant d'un outil pris en charge, ce qui créera des Constatations représentant ces vulnérabilités. En remplissant le formulaire, vous pouvez choisir de :

* Stocker ces Constatations dans un Type de produit / Produit / Engagement existant **ou**
* Créer un nouveau Type de produit / Produit / Engagement pour stocker ces Constatations

Il est facile de réorganiser votre hiérarchie de produits dans DefectDojo, donc ce n'est pas grave si vous ne savez pas encore exactement comment tout configurer. 

Pour l'instant, il est utile de savoir que les **Engagements** peuvent stocker des données provenant de plusieurs outils, ce qui peut être utile si vous exécutez différents outils simultanément dans le cadre d'un même effort de test.

## Accéder au formulaire d'importation de scan (interface Pro)

Le formulaire d'importation de scan est accessible depuis plusieurs emplacements :

1. Via l'option de menu **Import > Add Findings** dans la barre latérale
2. Depuis le menu **'⋮' (points horizontaux)** d'un **Produit**, dans un **tableau de Produits**
3. Depuis le **menu ⚙️ Engrenage** sur une **page Produit**

## Remplir le formulaire d'importation de scan

Le formulaire d'importation de scan créera un nouveau Test imbriqué sous un Engagement, qui contiendra une Constatation unique pour chaque vulnérabilité présente dans votre fichier de scan.

Le Test sera créé avec un nom correspondant au Type de scan : par exemple, un scan Tenable sera intitulé « Tenable Scan ».

### Options du formulaire

* **Scan File :** en cliquant sur le bouton Choose, vous pouvez sélectionner un fichier depuis votre ordinateur à téléverser.
* **Scan Date (optionnel) :** si vous souhaitez sélectionner une seule date de scan à appliquer à toutes les Constatations résultant de cette importation, vous pouvez la sélectionner dans ce champ.   
Si vous ne sélectionnez pas de date de scan, les Constatations créées à partir de ce rapport utiliseront la date spécifiée par l'outil. Les SLA de chaque Constatation seront calculés en fonction de cette date.
* **Scan Type :** sélectionnez l'outil utilisé pour créer ces données.
* **Product Type / Product / Engagement Name :** sélectionnez le Type de produit, le Produit et le nom de l'Engagement sous lequel vous souhaitez créer un nouveau Test. Vous pouvez également créer un nouveau Type de produit, Produit et/ou Engagement à ce moment-là si vous le souhaitez, en saisissant les noms des objets que vous voulez créer.
* **Environment :** sélectionnez un Environnement correspondant aux données que vous téléversez.
* **Tags :** si vous souhaitez utiliser des étiquettes pour mieux organiser les données de votre Test, vous pouvez ajouter des Étiquettes à l'aide de ce formulaire. Saisissez le nom de l'étiquette que vous souhaitez créer, puis appuyez sur Entrée sur votre clavier pour l'ajouter à la liste des étiquettes.
* **Process Findings Asynchronously** : ce champ est activé par défaut, mais il peut être désactivé si vous le souhaitez. Voir l'explication ci-dessous.

### Traiter les Constatations de manière asynchrone

Lorsque ce champ est activé, DefectDojo utilise un processus en arrière-plan pour remplir votre fichier de Test avec des Constatations. Cela vous permet de continuer à travailler avec DefectDojo pendant que les Constatations sont créées à partir de votre fichier de scan.

Lorsque ce champ est désactivé, DefectDojo attendra que toutes les Constatations aient été créées avec succès avant de vous permettre de passer à l'écran suivant. Cela peut prendre un temps considérable selon la taille de votre fichier.

Cette option est particulièrement pertinente lors de l'utilisation de l'API pour importer des données. Si vous téléversez des données avec l'option Process Findings Asynchronously **désactivée**, DefectDojo ne renverra pas de réponse de succès tant que toutes les Constatations n'auront pas été créées avec succès, 

### Champs optionnels

Pour ouvrir les Champs optionnels, cliquez sur le bouton intitulé **« Optional Fields + »** au-dessus du bouton **Submit**

![image](images/import_scan_ui.png)

#### Description des champs optionnels
* **Minimum Severity** : si vous souhaitez créer des Constatations uniquement pour un niveau de Sévérité donné et au-dessus, vous pouvez sélectionner ici le niveau de Sévérité minimum. Toutes les vulnérabilités dont la sévérité est inférieure à ce champ seront ignorées.
* **Active** : si vous souhaitez définir toutes les Constatations entrantes comme Actives ou Inactives, vous pouvez le spécifier ici. Sinon, DefectDojo utilisera les données de vulnérabilité de l'outil pour déterminer si la Constatation est Active ou Inactive. Cette option est pertinente si votre équipe doit trier et vérifier manuellement les Constatations provenant d'un outil donné.
* **Verified** : comme pour Active, vous pouvez définir par défaut le nouvel ensemble de Constatations comme Vérifié ou Non vérifié. Cela dépend des préférences de votre flux de travail. Par exemple, si votre équipe préfère considérer les Constatations comme vérifiées sauf preuve du contraire, vous pouvez définir ce champ sur True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** peuvent tous être spécifiés si vous souhaitez inclure ces détails dans le Test.
* **Source Code Management URI** peut également être spécifié. Cette option de formulaire doit être une URI valide.
* **Group By :** si vous souhaitez créer des Groupes de constatations à partir de ce fichier, vous pouvez spécifier ici la méthode de regroupement.

### Clôturer les anciennes Constatations

Lors de l'importation d'un scan, vous pouvez automatiquement clôturer les Constatations des scans précédents qui ne sont plus présentes dans le nouveau rapport. Activez cette option en cochant la case **Close Old Findings** dans l'interface, ou en définissant `close_old_findings: true` dans l'API.

#### Périmètre : Engagement vs. Produit

Par défaut, `close_old_findings` clôture les Constatations du même Type de scan au sein du **même Engagement**. DefectDojo Pro ajoute une seconde option — **Close Old Findings Within This Product** — qui élargit le périmètre à toutes les Constatations du même Type de scan sur l'**ensemble du Produit**, quel que soit l'Engagement auquel elles appartiennent.

| Option | Case à cocher (interface) | Paramètre API | Périmètre |
|---|---|---|---|
| Clôturer les anciennes constatations (périmètre Engagement) | **Close Old Findings** | `close_old_findings: true` | Même Engagement |
| Clôturer les anciennes constatations (périmètre Produit) | **Close Old Findings Within This Product** | `close_old_findings_product_scope: true` | Produit entier |

`close_old_findings_product_scope` nécessite que `close_old_findings` soit également activé. Définir `close_old_findings_product_scope` sans `close_old_findings` n'a aucun effet.

> **Remarque :** `close_old_findings_product_scope` s'applique uniquement au point de terminaison Import (`/import-scan`). Il n'a aucun effet sur le point de terminaison Reimport (`/reimport-scan`), où le périmètre est toujours limité au Test en cours.

Le champ `service` est également respecté : seules les Constatations ayant une valeur `service` identique (ou aucune valeur `service`, si aucune n'a été spécifiée au moment de l'importation) seront prises en compte pour la clôture.

### Scanners sans triage : champ Do Not Reactivate

Certains scanners peuvent ne pas inclure d'informations de triage dans leurs rapports (par exemple tfsec). Ils se contentent de scanner le code ou les dépendances, de signaler les problèmes, et de tout renvoyer, que la vulnérabilité ait déjà été triée ou non.

Pour gérer ce cas, DefectDojo inclut également une case à cocher « Do not reactivate » lors du téléversement des rapports (également disponible dans l'API de réimportation), afin que vous puissiez utiliser DefectDojo comme source de vérité pour le triage, au lieu de réactiver vos Constatations déjà triées à chaque import / réimport.

### Utilisation du champ Date de fin de scan (API : `scan_date`)

DefectDojo prend en charge une multitude de rapports de scanners, mais tous ne contiennent pas l'information la plus importante pour un utilisateur. Le champ `scan_date` est une fonctionnalité intelligente et flexible qui permet aux utilisateurs de définir la date de fin d'un rapport de scan donné, et de la propager à toutes les constatations importées. Ce champ n'est **pas** obligatoire, mais sa valeur par défaut est la date d'importation (au moment où la requête est traitée et qu'une réponse de succès est renvoyée).

Voici les cas d'usage possibles pour ce champ :

1. Le rapport **ne définit pas** la date, et `scan_date` **n'est pas** défini à l'importation
    - La date de la Constatation sera la valeur par défaut de `scan_date`
2. Le rapport **définit** la date, et `scan_date` **n'est pas** défini à l'importation
    - La date de la Constatation sera celle définie par le rapport
3. Le rapport **ne définit pas** la date, et `scan_date` **est défini** à l'importation
    - La date de la Constatation sera celle définie par l'utilisateur pour `scan_date`
4. Le rapport **définit** la date, et `scan_date` **est défini** à l'importation
    - La date de la Constatation sera celle définie par l'utilisateur pour `scan_date`
