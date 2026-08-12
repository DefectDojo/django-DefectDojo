---
title: À propos de Rules Engine 2.0
description: Ce qu'est Rules Engine 2.0, comment l'activer, et les concepts sur lesquels
  il repose
weight: 1
audience: pro
aliases:
- /fr/automation/rules_engine_v2/about/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Rules Engine 2.0 est une fonctionnalité réservée à DefectDojo Pro.</span>

Rules Engine 2.0 est un générateur d'automatisation visuel. Au lieu d'un filtre associé à une liste plate d'actions, une règle est un **graphe** : un nœud déclencheur qui décide quand la règle se réveille, et un nombre quelconque de nœuds de logique, de Constatations et de sortie reliés entre eux pour indiquer ce qui se passe ensuite.

Rules Engine 2.0 n'est accessible que via l'[interface Pro](/get_started/about/ui_pro_vs_os/).

## Ce qu'il ajoute par rapport à Rules Engine

Le [Rules Engine](/automation/rules_engine/about/) d'origine applique une liste ordonnée d'actions à chaque Constatation correspondant à un filtre. Rules Engine 2.0 conserve cette capacité et ajoute quatre éléments :

* **Le branchement.** Un nœud **If / Filter** (Si / Filtre) dirige les éléments vers une branche vraie et une branche fausse, de sorte qu'une seule règle puisse traiter les Constatations Critiques différemment du reste sans devoir être scindée en deux règles.
* **La sortie (egress).** Une règle peut sortir de DefectDojo : ouvrir un ticket JIRA ou un ticket en aval, publier sur Slack ou Microsoft Teams, envoyer un e-mail, appeler un webhook, déclencher une alerte dans l'application, ou générer un rapport.
* **La traçabilité.** Chaque exécution est enregistrée nœud par nœud sous forme d'[Exécution](../runs/), et chaque envoi sortant est enregistré comme une [Livraison](../deliveries/) qui indique exactement ce qui a été envoyé, où cela a été envoyé, et comment cela s'est terminé.
* **Un mode de simulation.** Une règle peut enregistrer précisément ce qu'elle aurait envoyé sans rien envoyer réellement, ce qui permet de la tester en toute sécurité avant de la laisser agir à l'extérieur.

Les deux moteurs fonctionnent côte à côte. Activer Rules Engine 2.0 ne désactive ni ne convertit vos règles existantes, et il existe un [convertisseur](../converting_from_rules_engine/) pour le jour où vous voudrez les faire migrer.

## Activer Rules Engine 2.0

Rules Engine 2.0 est en version bêta et est désactivé par défaut. Un superutilisateur l'active depuis **Settings > Feature Flags** (Paramètres > Indicateurs de fonctionnalités), aussi bien sur les instances Cloud que sur les instances On-Premise. Voir [Indicateurs de fonctionnalités](/admin/feature_flags/pro__feature_flags/).

Une fois l'indicateur activé, une section **Rules Engine 2.0** apparaît dans la barre latérale avec trois pages :

| Page | À quoi elle sert |
|------|----------------|
| **All Rules** (Toutes les règles) | La liste des règles. Créez, modifiez, activez, exécutez et supprimez des règles depuis cet endroit. |
| **Runs** (Exécutions) | Chaque exécution, avec sa trace détaillée par nœud. |
| **Deliveries** (Livraisons) | Le registre de tout ce que les règles ont envoyé vers l'extérieur. |

### Permissions

L'accès est régi par deux permissions de rôle globales, partagées avec le Rules Engine d'origine :

* **Rule View** (Consultation des règles) est requise pour voir la section de la barre latérale et tout ce qu'elle contient.
* **Rule Edit** (Modification des règles) est requise pour créer, modifier, exécuter, supprimer, convertir, prendre possession et rejouer une règle.

Rule Edit se rapproche d'une permission administrative. Un auteur de règle peut atteindre toute Constatation que le propriétaire de sa règle peut voir, et peut diriger la sortie vers des systèmes externes ; accordez-la donc de façon réfléchie.

## Les concepts

### Règles et graphes

Une règle est constituée d'un nom, d'une description, d'un propriétaire, d'un mode, d'un interrupteur d'activation et d'un graphe. Le graphe est un ensemble de **nœuds** et des **arêtes** qui les relient. Il doit contenir exactement un nœud déclencheur et ne doit pas contenir de cycle. Tout le reste est à votre discrétion, y compris le fait de laisser un nœud non connecté, ce qui signifie simplement qu'il s'exécute sans rien à traiter.

Les nouvelles règles sont toujours créées **désactivées**, de sorte qu'en activer une est un acte délibéré.

### Éléments

Ce qui circule le long des arêtes d'un graphe est un **élément** : un instantané JSON d'une Constatation ainsi que le contexte qui l'entoure.

```json
{
  "finding":      { "id": 1234, "title": "...", "severity": "High", "...": "..." },
  "test":         { "id": 12, "title": "...", "scan_type": "..." },
  "engagement":   { "id": 5,  "name": "..." },
  "product":      { "id": 3,  "name": "..." },
  "product_type": { "id": 1,  "name": "..." },
  "ctx":          { "trigger": "finding.created", "depth": 0, "source": "app" }
}
```

Les conditions et les modèles de message sont écrits par rapport aux chemins de cette structure, par exemple `finding.severity` ou `product.name`. La liste complète des champs se trouve dans [Créer des règles](../building_rules/).

### Propriétaire

Chaque règle s'exécute **en tant que son propriétaire**. Elle voit exactement les Constatations que cet utilisateur peut voir, via la même autorisation utilisée partout ailleurs dans le produit. Deux conséquences sont à connaître :

* Restreindre l'accès du propriétaire d'une règle restreint la règle.
* Une règle dont le compte du propriétaire est supprimé n'a plus de propriétaire ; elle ne correspond donc à rien du tout et ne fait rien. Attribuez un nouveau propriétaire, ou utilisez **Take Ownership** (Prendre possession) depuis la liste des règles, pour la rétablir.

### Mode : Simulate ou Live

Le mode est défini par règle, et non par nœud.

* **Simulate** (Simuler, par défaut) exécute réellement l'ensemble du graphe, y compris chaque modification de Constatation, mais les nœuds de sortie enregistrent ce qu'ils *auraient* envoyé et s'arrêtent là. Rien ne sort de DefectDojo.
* **Live** effectue réellement les envois.

Les envois simulés apparaissent tout de même dans le registre des Livraisons, marqués `simulated`, avec leur charge utile complète. C'est la manière prévue de vérifier une règle avant de la laisser s'exécuter en conditions réelles.

Le mode s'applique délibérément à l'ensemble de la règle. Un graphe où certains envois sont réels et d'autres non est plus difficile à comprendre que deux règles distinctes.

### Exécutions

Une exécution d'une règle est une [Exécution](../runs/). Une exécution enregistre l'événement qui l'a déclenchée, son statut, sa trace détaillée par nœud, et toute erreur éventuelle. Une règle ne peut avoir qu'une seule exécution en cours à la fois ; une règle occupée est donc mise en file d'attente plutôt que de s'exécuter en parallèle avec elle-même.

### Livraisons

Chaque effet de bord sortant correspond à une ligne du registre des [Livraisons](../deliveries/), écrite **avant** que le moindre appel réseau n'ait lieu. La ligne contient la charge utile, la destination résolue, le statut, le nombre de tentatives, et ce que la destination a répondu. Les éléments ignorés sont également enregistrés, de sorte que « la règle n'a rien fait » et « la règle n'a rien fait car la Constatation avait déjà un ticket » soient distinguables.

### Provenance

Chaque modification qu'une règle apporte à une Constatation est attribuée à la règle, à l'exécution et au nœud qui l'a effectuée. Cette chronologie est visible directement sur la Constatation, ce qui permet de répondre à la question « pourquoi cette Constatation a-t-elle changé ? » sans avoir à lire les définitions des règles.

### Échelle

Une règle traite tout ce que son périmètre couvre. Il n'y a aucune limite au nombre de Constatations qu'une exécution peut traiter : elle les parcourt par lots afin que ce soit la mémoire qui reste bornée, et non la couverture. Seul l'aperçu (Preview) impose une limite, et il vous en informe lorsque c'est le cas.

### Rétention

Les exécutions et les livraisons sont toutes deux conservées 180 jours par défaut, puis purgées. Le produit affiche la fenêtre et la date à laquelle un enregistrement donné sera supprimé plutôt que de laisser cela implicite, et les deux fenêtres sont configurables. Voir [Configuration](../configuration/#retention).

## Pour aller plus loin

* [Créer des règles](../building_rules/) couvre l'éditeur, les déclencheurs, le périmètre, les conditions et les modèles.
* [Référence des nœuds](../node_reference/) documente les 25 nœuds.
* [Exécutions](../runs/) couvre l'exécution, les traces, l'enchaînement et les limites.
* [Livraisons](../deliveries/) couvre les canaux, les statuts, les tentatives et la relecture.
* [Conversion depuis Rules Engine](../converting_from_rules_engine/) couvre le déplacement des règles existantes.
* [Configuration](../configuration/) couvre les paramètres au niveau du déploiement.
