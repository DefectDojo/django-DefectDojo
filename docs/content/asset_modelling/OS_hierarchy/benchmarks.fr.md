---
title: Benchmarks OWASP ASVS
description: Comparer un Produit à la norme OWASP Application Security Verification
  Standard (ASVS)
weight: 6
audience: opensource
---

DefectDojo permet de comparer les Produits à la [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/), qui fournit une base pour tester les contrôles de sécurité technique des applications web.

Les Benchmarks vous permettent de mesurer dans quelle mesure un Produit répond aux exigences de sécurité définies par votre organisation, et de publier un score sur la page du Produit pour plus de visibilité.

## Accéder aux Benchmarks

Les Benchmarks sont accessibles depuis la page **Produit**. Pour ouvrir la vue Benchmarks, sélectionnez le menu déroulant en haut à droite de la page Produit et choisissez **OWASP ASVS v.3.1** vers le bas du menu.

## Niveaux de Benchmark

OWASP ASVS définit trois niveaux de couverture de vérification :

- **Niveau 1** – Pour tous les logiciels. Couvre les exigences de sécurité les plus critiques avec le coût de vérification le plus faible. Il s'agit du niveau par défaut dans DefectDojo.
- **Niveau 2** – Pour les applications contenant des données sensibles. Adapté à la plupart des applications.
- **Niveau 3** – Pour les applications les plus critiques, telles que celles effectuant des transactions à forte valeur ou stockant des données médicales, financières ou de sécurité sensibles.

Vous pouvez basculer entre les niveaux à l'aide du menu déroulant en haut à droite de la vue Benchmarks.

## Score de Benchmark

Le côté gauche de la vue Benchmarks affiche le score actuel de votre Produit au niveau ASVS sélectionné :

- Le **score souhaité** que votre organisation a défini comme objectif
- Le **pourcentage de benchmarks réussis** pour atteindre ce score
- Le **nombre total de benchmarks activés** pour le niveau sélectionné

Activer la case à cocher **Publish** affichera le score ASVS directement sur la page du Produit.

## Gestion des entrées de Benchmark

Les entrées individuelles de benchmark peuvent être marquées comme réussies ou échouées au fur et à mesure que votre équipe traite les contrôles ASVS. Des entrées de benchmark supplémentaires, au-delà de l'ensemble ASVS par défaut, peuvent être ajoutées ou mises à jour via le **site d'administration Django**.
