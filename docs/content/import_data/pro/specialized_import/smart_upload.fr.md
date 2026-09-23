---
title: Analyses d'infrastructure / Smart Upload
description: Achemine automatiquement les Constatations entrantes vers le bon Produit
weight: 3
audience: pro
aliases:
- /fr/en/connecting_your_tools/import_scan_files/smart_upload
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Smart Upload n'est disponible que dans DefectDojo Pro.</span>

Smart Upload est un importateur spécialisé qui ingère les rapports provenant d'**outils d'analyse d'infrastructure**, notamment :

* Nexpose
* NMap
* OpenVas
* Qualys
* Tenable

Smart Upload a la particularité de pouvoir répartir les Constatations d'un fichier d'analyse entre plusieurs Produits distincts. Cela est pertinent dans un contexte d'analyse d'infrastructure, où les Constatations peuvent concerner de nombreuses équipes différentes, avoir des SLA implicites différents, ou devoir figurer dans des rapports séparés selon l'endroit où elles ont été découvertes dans votre infrastructure.

Smart Upload gère cela en triant les constatations entrantes en fonction des Points de terminaison découverts lors de l'analyse. Dans un premier temps, ces Constatations devront être assignées manuellement, ou dirigées vers le bon Produit depuis une liste de Constatations non assignées. Cependant, une fois qu'une Constatation a été assignée à un Produit, toutes les Constatations suivantes qui partagent un Point de terminaison ou un hôte seront envoyées vers ce même Produit. Si cet hôte est associé à plusieurs Produits, la Constatation est envoyée vers chacun d'eux (voir ci-dessous).

## Smart Upload menu options

Le menu Smart Upload se trouve dans une section repliable de la barre latérale.

* **Add Findings vous permet d'importer un nouveau fichier d'analyse, de façon similaire à la méthode Import Scan de DefectDojo**
* **Unassigned Findings répertorie toutes les Constatations issues de Smart Upload qui n'ont pas encore été assignées à un Produit.**

![image](images/smart_upload.png)

### The Smart Upload Form

Le formulaire Import Scan de Smart Upload est essentiellement identique au formulaire Import Scan. Consultez nos remarques sur le **formulaire Import Scan** pour plus de détails.

![image](images/smart_upload_2.png)

## Unassigned Findings

Une fois qu'un Smart Upload est terminé, toutes les Constatations qui ne sont pas automatiquement assignées à un Produit (en fonction de leur Point de terminaison) sont placées dans la liste **Unassigned Findings**. Le premier Smart Upload pour un outil donné ne dispose pas encore de méthode pour assigner les Constatations ; chaque Constatation de ce fichier sera donc envoyée vers cette page pour être triée.

Les Constatations non assignées ne sont pas incluses dans la Hiérarchie des produits et n'apparaîtront ni dans les rapports, ni dans les filtres, ni dans les métriques tant qu'elles n'auront pas été assignées.

### Working with Unassigned Findings

![image](images/smart_upload_3.png)

Vous pouvez sélectionner une ou plusieurs Constatations non assignées à trier à l'aide de la case à cocher, puis effectuer l'une des actions suivantes :

* **Assign to New Product, qui crée un nouveau Produit**
* **Assign to Existing Product, qui déplace la Constatation vers un Produit existant**
* **Disregard Selected Findings**, qui retire la Constatation de la liste

Chaque fois qu'une Constatation est assignée à un Produit nouveau ou existant, elle est placée dans un Engagement dédié appelé « Smart Upload ». Cet Engagement contiendra un Test nommé selon le Type d'analyse (par exemple, Tenable Scan). Les Constatations suivantes importées via Smart Upload qui correspondent à ces Points de terminaison seront placées sous cet Engagement \> Test.

### Disregarded Findings

Si une Constatation est ignorée, elle sera retirée de la liste des Constatations non assignées. Cependant, la Constatation ne sera pas enregistrée en mémoire, si bien que les téléversements d'analyse suivants peuvent faire réapparaître la Constatation dans la liste des Constatations non assignées.

## Constatations correspondant à plusieurs Produits

Un même hôte ou Point de terminaison peut appartenir à plusieurs Produits, par exemple un répartiteur de charge partagé ou un hôte suivi par deux équipes. Lorsque Smart Upload fait correspondre l'hôte d'une Constatation entrante à plusieurs Produits, il n'en choisit pas un seul : il crée une copie de cette Constatation dans **chaque** Produit correspondant, en plaçant chaque copie dans l'Engagement et le Test Smart Upload propres à ce Produit.

C'est intentionnel. Chaque Produit conserve une vue complète des vulnérabilités affectant les hôtes qu'il possède, et les rapports, les SLA et les métriques de chaque Produit restent indépendants.

La correspondance repose sur la valeur d'hôte découverte lors de l'analyse (le nom de domaine complet, à défaut l'adresse IP), de sorte que tout Produit possédant déjà cet hôte reçoit une copie de la Constatation.
