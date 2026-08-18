---
title: Badges de menu
description: Ce que signifient les étiquettes BETA, NEW, LEGACY et DEPRECATED dans
  la barre latérale de DefectDojo Pro, et ce que chacune vous demande de faire
weight: 7
audience: pro
---

Les entrées de la barre latérale de DefectDojo Pro peuvent porter une petite étiquette colorée. Chacune répond à une question différente concernant la fonctionnalité à côté de laquelle elle se trouve, et deux d'entre elles sont des liens.

| Badge | Couleur | Signifie | Ce qu'elle vous demande |
| --- | --- | --- | --- |
| `NEW` | Vert | Récemment publié | Rien — elle est là pour attirer votre attention sur la fonctionnalité |
| `BETA` | Orange | Fonctionnel, mais encore en cours de finalisation ; le comportement peut évoluer d'une version à l'autre | Essayez-la, en vous attendant à quelques aspérités |
| `LEGACY` | Rouge | Remplacée par une fonctionnalité plus récente, sans date de suppression annoncée | Privilégiez le remplacement pour tout nouveau travail |
| `DEPRECATED` | Rouge | Suppression prévue dans une version nommée | Migrez avant cette version |

![The LEGACY badge on the Jira menu entry](images/menu_badge_legacy.png)

## LEGACY et DEPRECATED ne sont pas la même chose

Cette distinction est délibérée, car les deux états appellent des réponses différentes.

**`DEPRECATED`** signifie qu'une suppression a été annoncée. Survoler le badge vous indique la version dans laquelle la fonctionnalité disparaît, et cliquer dessus ouvre l'avis de dépréciation :

> \<Feature\> is deprecated and will be removed by \<release\>. Click for the deprecation notice.

**`LEGACY`** signifie que la fonctionnalité a été remplacée, mais qu'aucune suppression n'est prévue. Le texte au survol ne comporte volontairement aucune date, car en inventer une serait pire que de ne rien dire. Il nomme à la place le remplacement et renvoie vers sa documentation :

> \<Feature\> is superseded by \<replacement\> and will not receive new development. Click for its documentation.

Une fonctionnalité `LEGACY` continue de fonctionner et continue de recevoir des correctifs. Elle ne gagnera simplement aucune nouvelle capacité, donc tout ce que vous construisez maintenant a intérêt à s'appuyer sur son remplacement.

Les deux badges sont des liens, car une infobulle se ferme dès que le pointeur la quitte et ne peut donc pas contenir de lien cliquable. Cliquer sur l'un ou l'autre badge ouvre son avis dans un nouvel onglet ; cela ne déclenche pas la navigation vers l'entrée de menu sous-jacente.

## Ce qui porte actuellement un badge

**`LEGACY`**

* **Connect > Jira** — l'intégration Jira d'origine par produit, remplacée par le connecteur downstream pour Jira. Voir [Pro Integrations](/connectors/downstream/about/).

**`DEPRECATED`**

* **Settings > Configuration > Tool Types**
* **Settings > Configuration > Tool Configurations**

Les deux sont supprimées dans la version **3.5.0**, ainsi que les parseurs basés sur API (pull) qu'elles servent à configurer. Les [notes de mise à niveau 3.2](/releases/os_upgrading/3.2/) expliquent vers quoi migrer et pour quand.

![DEPRECATED badges under Settings > Configuration](images/menu_badge_deprecated.png)

Lorsqu'un libellé et son badge ne tiennent pas côte à côte dans la barre latérale, le badge passe à la ligne sous le libellé plutôt que d'être tronqué.

## À voir aussi

* [Notes de mise à niveau 3.2](/releases/os_upgrading/3.2/) — les dépréciations actuelles et leur version de suppression
* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — activer et désactiver les fonctionnalités optionnelles, y compris celles en beta
