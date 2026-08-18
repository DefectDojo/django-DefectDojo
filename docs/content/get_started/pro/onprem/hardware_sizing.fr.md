---
title: Dimensionnement matériel pour DefectDojo Pro auto-hébergé
description: Recommandations générales pour dimensionner le calcul, la mémoire et
  le stockage d'un déploiement DefectDojo Pro auto-hébergé
draft: false
weight: 4
audience: pro
---

Dimensionner un déploiement DefectDojo revient à répondre à deux questions. Quelle quantité de données conservez-vous, et combien de personnes y travaillent simultanément. Cette page donne des points de départ pour les deux.

Considérez ce qui suit comme des recommandations générales plutôt qu'une spécification. Les chiffres sont délibérément prudents et supposent un déploiement effectuant un triage quotidien en parallèle d'imports de scans réguliers. Vos propres chiffres évolueront selon votre usage du produit, donc lisez les notes sous le tableau avant de provisionner quoi que ce soit.

Les spécifications sont données en chiffres génériques de vCPU et de mémoire afin de s'appliquer à tout fournisseur cloud ou matériel sur site. Les recommandations pour les nœuds applicatifs supposent Kubernetes. Si vous exécutez Docker Compose sur un seul hôte, utilisez les mêmes totaux.

## Tableau de dimensionnement

| Constatations | Utilisateurs simultanés | Base de données | Nœuds applicatifs |
| --- | --- | --- | --- |
| Up to 100K | Up to ~25 | 2–4 vCPU / 16–32 GB | 2 × (2–4 vCPU / 8–16 GB) |
| 100K–500K | ~25–50 | 4–8 vCPU / 32–64 GB | 2–3 × (4 vCPU / 16 GB) |
| 500K–1M | ~50–100 | 8 vCPU / 64–96 GB | 2–3 × (8 vCPU / 32 GB) |
| 1M–5M | ~100–250 | 8–16 vCPU / 96–128 GB | 5–6 × (8 vCPU / 32 GB) |
| 5M–10M | ~250–500 | 16–32 vCPU / 128–192 GB | 9–10 × (8 vCPU / 32 GB) |
| 500M | 500+ | 192 vCPU / 768 GB+ | 50+ × (8 vCPU / 32 GB) |

L'endroit où vous vous situez dans une plage dépend de votre charge de travail. Placez-vous vers le haut d'une plage si l'un des éléments de [Ce qui vous fait passer à un palier supérieur](#what-pushes-you-up-a-tier) s'applique à vous.

La ligne 500M est un point de référence à l'extrémité de l'échelle plutôt qu'une continuation du modèle qui la précède ; n'interpolez donc pas entre elle et le palier 10M. Un déploiement se situant entre les deux doit être dimensionné individuellement. Elle suppose également un travail que le matériel seul ne fera pas à votre place, traité dans [Très grands déploiements](#very-large-deployments).

## Comment lire ces chiffres

### La mémoire de la base de données compte plus que son CPU

DefectDojo exécute des requêtes fortement axées sur l'agrégation à travers vos constatations. Celles-ci restent rapides tant que l'ensemble de travail et ses index sont servis depuis la mémoire, et elles se dégradent rapidement dès que la base de données doit solliciter le disque. S'il faut choisir, achetez de la mémoire avant d'acheter des cœurs. Le tableau reflète cela. La mémoire double à peu près à chaque palier, tandis que le nombre de CPU évolue beaucoup plus lentement.

### Les nœuds applicatifs suivent les utilisateurs, pas les constatations

Les chiffres d'utilisateurs simultanés du tableau supposent que les petits jeux de données appartiennent à de petites équipes. Cette hypothèse est souvent mise en défaut. Si vous détenez 200K constatations mais avez 100 personnes simultanément dans l'interface, dimensionnez la couche applicative pour les utilisateurs et laissez la base de données là où votre nombre de constatations la place. Les deux évoluent indépendamment.

Il existe une exception, à l'extrémité du tableau. L'import et la déduplication s'exécutent au niveau de la couche applicative plutôt que dans la base de données, donc une fois qu'un jeu de données est assez volumineux pour que ce travail domine, le nombre de nœuds suit le volume d'ingestion plutôt que le nombre d'utilisateurs. C'est pourquoi la ligne 500M se situe bien au-dessus de ce que son seul chiffre d'utilisateurs suggérerait.

### La forme des nœuds est flexible

Kubernetes répartira la charge que vous lui donniez quelques gros nœuds ou davantage de petits nœuds, donc les nombres de nœuds ci-dessus constituent un arrangement viable plutôt qu'une exigence. Deux points méritent d'être respectés. Conservez au moins deux nœuds pour qu'en perdre un ne mette pas l'application hors service, et évitez les nœuds plus petits que 2 vCPU / 8 GB afin que les pods individuels se planifient confortablement.

## Stockage

Prévoyez 20–30 GB de stockage de base de données par million de constatations. Votre position dans cette fourchette dépend de la quantité de données que vous rattachez à chaque constatation. Des descriptions longues et un grand nombre de points de terminaison vous poussent vers le haut de cette fourchette. Les lignes de constatations elles-mêmes n'en représentent qu'une petite part. La majeure partie de l'espace va aux index et aux tables associées rattachées à chaque constatation, donc dimensionner uniquement à partir des données de ligne vous laissera largement en dessous des besoins réels.

Chaque palier jusqu'à 10M tient dans quelques centaines de GB de SSD à usage général. Le stockage est bon marché comparé au coût d'en manquer, donc provisionnez pour l'endroit où vous prévoyez d'être dans un an plutôt que pour votre situation actuelle. Si votre fournisseur propose l'autoscaling du stockage, activez-le.

La ligne 500M est dimensionnée à 2,5 TB. Ce chiffre suppose que le jeu de données actif est géré activement, les constatations les plus anciennes étant archivées hors du chemin actif plutôt que de s'accumuler indéfiniment. Appliqué naïvement, le taux par million ci-dessus placerait un déploiement 500M non géré plusieurs fois plus haut. Si vous vous dirigez vers cette échelle, traitez la stratégie d'archivage comme faisant partie de l'exercice de dimensionnement plutôt que comme quelque chose à régler plus tard.

Le stockage à cette échelle nécessite également une attention portée au débit, pas seulement à la capacité. Une fois que l'ensemble de travail ne tient plus en mémoire, les IOPS de référence par défaut des volumes à usage général deviennent le facteur limitant bien avant la capacité.

Le stockage des médias est séparé et généralement bien plus petit. Il contient les artefacts téléversés tels que les captures d'écran et les documents d'acceptation du risque ; dimensionnez-le donc en fonction de vos propres habitudes de téléversement.

## Ce qui vous fait passer à un palier supérieur

Le nombre de constatations est le chiffre principal, mais plusieurs facteurs vous amèneront à dimensionner plus haut que ce que ce seul chiffre suggère.

- **Volume et fréquence des imports.** Des scans volumineux arrivant fréquemment, en particulier plusieurs en même temps, exercent une charge soutenue à la fois sur la base de données et sur les workers asynchrones. Les pipelines CI qui importent à chaque build en sont généralement la cause.
- **Déduplication.** La déduplication compare les constatations entrantes à celles que vous détenez déjà. Plus vous avez de constatations et plus votre configuration de déduplication est large, plus chaque import demande de travail.
- **Rapports et tableaux de bord.** Les vues de métriques et la génération de rapports volumineux sont fortement axées sur la lecture, et sollicitent la base de données plus fortement que le triage quotidien.
- **Trafic API.** Les intégrations qui interrogent ou récupèrent de grands ensembles de résultats ajoutent une charge simultanée qui n'apparaît jamais dans votre nombre d'utilisateurs interactifs.
- **Rétention.** Les déploiements qui conservent tout indéfiniment passent au palier suivant comme prévu. Archiver ou supprimer les anciennes données vous permet de rester à votre niveau actuel plus longtemps.

## Très grands déploiements

Au-delà du palier 10M, le matériel cesse d'être toute la réponse. Deux choses changent.

La contrainte déterminante passe de la lecture à l'écriture. La déduplication compare chaque constatation entrante à celles que vous détenez déjà, donc le coût d'un import croît avec la taille du jeu de données sous-jacent. En haut du tableau, c'est généralement ce que l'on rencontre en premier, avant tout ce que les utilisateurs remarquent dans l'interface. Quel que soit le volume d'import qui a construit un jeu de données aussi vaste, il continue généralement de tourner, donc vous en payez le coût en continu plutôt qu'une seule fois.

Les chiffres de mémoire supposent que l'ensemble actif reste restreint. Un déploiement travaille sur les constatations récentes et laisse les plus anciennes largement intactes, ce qui permet à une base de données de contenir bien plus de données qu'elle n'a de mémoire tout en restant performante. Si votre schéma d'accès est réellement réparti sur l'ensemble du jeu de données, il vous faudra plus de mémoire que ce que le tableau indique, et au-delà d'un certain point, aucune instance unique n'en aura assez.

Ces deux constats pointent vers le même travail. Le partitionnement et l'archivage des constatations froides hors du jeu de données actif comptent davantage à cette échelle qu'un incrément de vCPU supplémentaire, et les rapports lourds ont leur place sur une réplique en lecture plutôt que sur le primaire. Planifiez cela en parallèle du matériel plutôt qu'après, et parlez-nous-en avant de provisionner.

## En cas de doute, arrondissez vers le haut

Les chiffres présentés ici sont déjà prudents, et être une taille trop grande coûte bien moins cher qu'être une taille trop petite. La pression mémoire de la base de données en particulier ne se dégrade pas en douceur. Les performances tiennent bon jusqu'à ce qu'elles ne tiennent plus.

Ajouter de la capacité applicative plus tard est simple, puisqu'il suffit d'ajouter des nœuds. Redimensionner une base de données implique généralement une interruption de service, c'est donc celui qu'il vaut la peine de bien dimensionner dès le départ.

## Questions ou assistance

Ce sont des points de départ, pas des limites. Si votre déploiement se situe en haut du tableau, ou si votre charge de travail ne ressemble pas aux hypothèses présentées ici, parlez-nous-en avant de provisionner. Contactez votre représentant de compte ou [support@defectdojo.com](mailto:support@defectdojo.com).
