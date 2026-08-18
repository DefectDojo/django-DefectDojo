---
title: Constatations similaires
description: Trouvez des Constatations liées sur la page Afficher la constatation
  et associez-les manuellement comme doublons
audience: opensource
weight: 3
---

Alors que la [Déduplication](../about_deduplication) s'exécute automatiquement au moment de l'import, **Constatations similaires** est un outil manuel et interactif situé sur la page **Afficher la constatation**. Il fait apparaître les autres Constatations du même Actif qui ressemblent à celle que vous consultez, et vous permet de les associer manuellement à un cluster de doublons.

Utilisez-le lorsque la déduplication automatique n'a pas regroupé des Constatations que vous pensez liées, ou lorsque vous souhaitez explorer ce qui, dans un Actif, ressemble à la vulnérabilité actuelle.

## Où le trouver

Ouvrez n'importe quelle Constatation pour accéder à sa page Afficher la constatation. Faites défiler jusqu'au panneau **Constatations similaires**. Le nombre indiqué dans le titre correspond au nombre de Constatations de l'Actif qui correspondent aux valeurs de la Constatation actuelle.

![Le titre du panneau Constatations similaires sur la page Afficher la constatation](images/similar_findings_panel.png)

Le panneau est réduit par défaut. Cliquez sur son titre (ou sur le chevron / bouton de filtre à droite) pour le développer et exécuter la requête.

## Comment les Constatations sont mises en correspondance

Lorsque vous ouvrez le panneau, DefectDojo préremplit un filtre avec les valeurs de la Constatation actuelle et recherche, dans le **même Actif**, d'autres Constatations correspondantes. Les champs utilisés pour amorcer la correspondance sont :

- IDs de vulnérabilité (par exemple, les identifiants CVE)
- CWE
- Chemin de fichier
- Numéro de ligne
- Unique ID from tool
- Type de test
- Actif (et Type d'actif)

La Constatation actuelle est toujours exclue de ses propres résultats. La correspondance est limitée à l'Actif, de sorte que Constatations similaires ne s'étend jamais à d'autres Actifs. Si l'un des deux Engagements a la déduplication au niveau de l'Engagement activée, les correspondances qui traversent une limite d'Engagement ne peuvent pas être associées (voir [Actions](#actions) ci-dessous).

Ceci diffère de l'algorithme de déduplication automatique, qui compare `hash_code` (ou Unique ID from tool) pour décider des correspondances. Constatations similaires ratisse délibérément plus large afin que vous puissiez découvrir des Constatations liées que la correspondance stricte par hachage manquerait.

## Affiner la correspondance

Les valeurs pré-remplies ne sont qu'un point de départ. Le panneau de filtres en haut de la section vous permet de rendre la correspondance plus stricte ou plus souple : supprimez un champ pour élargir les résultats, ou ajoutez des critères (sévérité, statut, point de terminaison, dates, EPSS, et plus encore) pour les restreindre.

![Le panneau de filtres de Constatations similaires](images/similar_findings_filters.png)

- **Clear filters** vide tous les champs afin que vous puissiez construire une requête à partir de zéro.
- **Restart** revient à la correspondance par défaut basée sur les valeurs de la Constatation actuelle.

## Lecture des résultats

Chaque Constatation correspondante est répertoriée dans un tableau. La colonne **Relationship** indique comment cette Constatation est liée à celle que vous consultez :

- **Original** – la Constatation racine/originale du cluster de doublons de la Constatation actuelle
- **Duplicate** – une Constatation déjà marquée comme doublon de la Constatation actuelle
- **Similar** – une correspondance qui ne fait pas encore partie du cluster de la Constatation actuelle

![Le tableau des résultats de Constatations similaires](images/similar_findings_list.png)

Le tableau affiche également la Sévérité, le Titre, la Date, le Statut, le Test, l'Engagement, le CWE, l'ID de vulnérabilité, le score EPSS, le Fichier (avec le numéro de ligne), et JIRA (lorsque l'intégration JIRA est activée). Chaque colonne est triable, et les résultats peuvent être exportés (Copy, Excel, CSV, PDF).

## Actions

Si vous disposez de la permission de modification sur une Constatation, la colonne **Action** propose un menu déroulant pour gérer le cluster de doublons directement depuis cette page :

![Le menu d'action de ligne de Constatations similaires](images/similar_findings_actions.png)

- **Mark as duplicate** – associe la Constatation similaire au cluster de doublons de la Constatation actuelle.
- **Set as original** – promeut une Constatation au rang d'originale (racine du cluster).
- **Reset finding duplicate status** – retire une Constatation de son cluster.

Une action peut être indisponible (affichée comme **None**) lorsqu'elle n'est pas valide, par exemple lorsque la Constatation similaire se trouve dans un Engagement différent et que la déduplication au niveau de l'Engagement est activée, ou lorsqu'elle est déjà l'originale d'un autre cluster. Ces actions manipulent les mêmes relations de doublons que celles utilisées par la déduplication automatique, de sorte qu'une Constatation que vous marquez ici se comporte exactement comme un doublon détecté automatiquement.

## Activer et désactiver Constatations similaires

Constatations similaires est contrôlé par un paramètre système global. Accédez à **Configuration > System Settings** et activez/désactivez **Enable Similar Findings**. Cette option est activée par défaut.

![Le paramètre système Enable Similar Findings](images/similar_findings_enable_setting.png)

Comme la requête porte sur l'ensemble d'un Actif, elle peut être coûteuse sur les Actifs volumineux. Si vous constatez une lenteur des pages Afficher la constatation, vous pouvez désactiver cette fonctionnalité ici, ou limiter le nombre de résultats retournés à l'aide de la variable d'environnement `DD_SIMILAR_FINDINGS_MAX_RESULTS` (valeur par défaut `25`).
