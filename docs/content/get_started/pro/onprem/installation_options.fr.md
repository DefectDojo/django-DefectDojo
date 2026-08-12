---
title: Auto-hébergement de DefectDojo Pro
date: 2021-02-02 20:46:29+01:00
weight: 5
audience: pro
---

DefectDojo Pro peut être entièrement auto-hébergé dans votre propre environnement, ce qui vous donne le contrôle de votre infrastructure, de vos données et de votre posture de sécurité. Cette solution convient aux organisations soumises à des exigences de conformité, de résidence des données ou de sécurité interne qui excluent un déploiement hébergé, et elle offre les mêmes fonctionnalités que le produit hébergé dans le cloud.

Cette page présente les modèles de déploiement disponibles, ce dont vous avez besoin avant de commencer, et la place qu'occupe le reste de cette section.

## Deux modèles de déploiement

**Docker Compose sur un hôte unique** est le plus simple des deux modèles. L'application, les workers asynchrones et le cache s'exécutent tous sur une seule machine, gérée par un outil en ligne de commande que nous fournissons. Comme rien dans cette configuration ne peut monter en charge horizontalement, l'hôte doit être dimensionné pour votre pic plutôt que pour votre moyenne, et pour la plupart des déploiements, ce pic correspond à l'arrivée d'un import de scan volumineux pendant que des utilisateurs travaillent dans l'interface.

**Kubernetes, via notre chart Helm**, exécute ces mêmes composants sous forme de workloads séparés. Cela vous permet de provisionner pour un état stable et d'ajouter des réplicas lorsque la charge augmente, et de faire évoluer uniquement la partie réellement sollicitée plutôt que la machine entière.

Les deux modèles utilisent PostgreSQL. Pour la production, nous recommandons une base de données managée externe, ce que le chart Helm suppose par défaut. L'outillage Compose peut aussi exécuter PostgreSQL dans un conteneur aux côtés de l'application, ce qui est pratique pour une évaluation mais déconseillé pour des données de production.

Si vous exploitez déjà Kubernetes, utilisez-le. Un hôte unique fonctionne parfaitement, et de nombreux déploiements tournent ainsi, mais vous finissez par acheter une marge de manœuvre que vous ne pouvez pas réaffecter. Si vous n'exploitez pas Kubernetes et ne souhaitez pas le faire, Compose est un choix légitime, et non un compromis.

## Avant de commencer

Dimensionnez d'abord le déploiement. Les deux modèles dépendent du fait de savoir approximativement combien de constatations vous prévoyez de conserver et combien de personnes travailleront simultanément dans le produit ; ces deux chiffres influencent des aspects différents du déploiement. Les recommandations de dimensionnement matériel de cette section couvrent les deux.

Vous aurez besoin d'un fichier de licence et de l'outillage de déploiement correspondant au modèle choisi. DefectDojo fournit les deux au démarrage de votre abonnement. Si vous ne les avez pas, ou si vous avez besoin qu'ils soient réémis, contactez votre représentant de compte ou [support@defectdojo.com](mailto:support@defectdojo.com).

Vous aurez également besoin d'un endroit où l'exécuter, d'une base de données PostgreSQL accessible, et d'un nom d'hôte qui pointe vers le déploiement. Les pages d'installation spécifiques détaillent chaque modèle.

## Que contient également cette section

Les pages qui accompagnent celle-ci couvrent le reste du cycle de vie. On y trouve des recommandations de dimensionnement pour choisir le matériel, des instructions pour migrer une instance open source existante vers un déploiement Pro auto-hébergé, ainsi qu'une procédure d'installation pour le cas où l'hôte cible n'a aucun accès à Internet.

Pour les déploiements déjà en service, des pages traitent de la mise à niveau, de la sauvegarde, de l'augmentation des limites qui rejettent les imports de scans volumineux, et de l'extension du stockage des fichiers téléversés lorsqu'un hôte manque d'espace. Utilisez la navigation de la section pour les parcourir.

## Questions

Si vous hésitez entre les deux modèles pour votre environnement, ou si votre situation ne correspond pas aux hypothèses présentées ici, nous préférons en discuter avec vous avant que vous ne provisionniez, plutôt qu'après.

Les clients existants doivent contacter leur représentant de compte ou [support@defectdojo.com](mailto:support@defectdojo.com). Si vous évaluez DefectDojo Pro et souhaitez discuter de l'auto-hébergement, contactez-nous à [hello@defectdojo.com](mailto:hello@defectdojo.com).
