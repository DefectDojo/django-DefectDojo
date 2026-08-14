---
title: Tableau de bord principal de DefectDojo
description: Utilisation de la page d'accueil de DefectDojo
weight: 1
audience: opensource
aliases:
- /fr/en/customize_dojo/dashboards/Introduction_dashboard
- /fr/en/customize_dojo/dashboards/pro_dashboards
---

Le Tableau de bord est probablement la première page que vous verrez en ouvrant DefectDojo. Il résume les performances de votre équipe et fournit des outils de suivi pour surveiller des aspects spécifiques de votre environnement de gestion des vulnérabilités.

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

> **💡 DefectDojo Pro :** Dans DefectDojo Pro, la page d'accueil est un **tableau de bord entièrement personnalisable** — vous le construisez à partir de widgets que vous disposez vous-même, plutôt que d'utiliser la mise en page fixe décrite ci-dessous. Consultez **[Tableaux de bord personnalisables](../custom-dashboards/)** pour découvrir les concepts et une visite guidée de l'interface. Le reste de cette page décrit le Tableau de bord principal de la version open source.

</div>

<div class="version-opensource">

## Composants du tableau de bord

Le tableau de bord open source offre un aperçu global de votre posture de sécurité grâce aux composants intégrés suivants :

### Cartes de synthèse

La rangée supérieure du tableau de bord affiche quatre cartes de synthèse qui donnent une vue d'ensemble instantanée de l'activité :

* **Engagements actifs** — nombre total d'Engagements actuellement ouverts, tous Produits confondus.
* **Constatations des 7 derniers jours** — nouvelles Constatations créées au cours de la semaine écoulée.
* **Clôturées au cours des 7 derniers jours** — Constatations résolues récemment.
* **Acceptées au cours des 7 derniers jours** — Constatations dont le risque a été accepté récemment.

Chaque carte renvoie directement vers la liste filtrée correspondante, ce qui permet d'approfondir en un clic.

### Historique de la sévérité des constatations

Ce diagramme circulaire ventile l'ensemble des Constatations jamais créées dans DefectDojo par Sévérité (Critique, Élevée, Moyenne, Faible, Info), ce qui donne rapidement une idée de la répartition globale des vulnérabilités dans votre environnement.

### Sévérité des constatations signalées par mois

Ce graphique linéaire trace le volume et la sévérité des Constatations entrantes mois par mois, ce qui permet de repérer des tendances telles qu'un pic après l'intégration d'un nouveau scanner ou une amélioration durable grâce aux efforts de remédiation.

### Configuration du tableau de bord

Les superutilisateurs peuvent activer ou désactiver l'affichage de certains graphiques sur le tableau de bord. Accédez au menu en forme d'engrenage en haut à droite et sélectionnez **Modifier la configuration du tableau de bord** pour afficher ou masquer :

* **Afficher les graphiques** — contrôle les graphiques Historique de la sévérité des constatations et Sévérité des constatations signalées.
* **Afficher les questionnaires** — contrôle le tableau des questionnaires d'Engagement répondus non attribués.
* **Afficher les tableaux de données** — contrôle les tableaux des 10 meilleurs / 10 derniers Produits classés.

Sélectionnez **Réinitialiser la configuration du tableau de bord** dans le même menu pour restaurer les valeurs par défaut.

</div>
