---
title: Constatations similaires
description: Trouvez des constatations associées sur la page Afficher la constatation
  et associez-les manuellement comme doublons
audience: pro
weight: 3
---

Alors que la [Déduplication](../about_deduplication) s'exécute automatiquement au moment de l'import, **Constatations similaires** est un outil manuel et interactif sur la page **Afficher la constatation**. Il fait apparaître d'autres Constatations du même Actif qui ressemblent à celle que vous consultez, et vous permet de les relier manuellement dans un cluster de doublons.

Utilisez-le lorsque la déduplication automatique n'a pas regroupé des Constatations que vous pensez liées, ou lorsque vous souhaitez explorer ce qui, dans un Actif, ressemble à la vulnérabilité actuelle.

## Où le trouver

Ouvrez n'importe quelle Constatation et faites défiler jusqu'à la carte **Doublons et constatations similaires**. Elle comporte deux onglets :

- **Doublons** – les Constatations déjà reliées à celle-ci comme doublons (le cluster automatique).
- **Constatations similaires** – d'autres Constatations de l'Actif qui correspondent aux valeurs de la Constatation actuelle mais ne font pas encore partie de son cluster.

Sélectionnez l'onglet **Constatations similaires** pour lancer la requête.

![La carte Doublons et constatations similaires sur la page Afficher la constatation](images/pro_similar_findings.png)

## Comment les constatations sont mises en correspondance

DefectDojo recherche dans le **même Actif** des Constatations qui ressemblent à la constatation actuelle, en se basant sur des valeurs telles que les identifiants de vulnérabilité (par exemple les identifiants CVE), le CWE, le chemin du fichier, le numéro de ligne et l'identifiant unique de l'outil. La Constatation actuelle est toujours exclue de ses propres résultats, et la correspondance ne s'étend jamais au-delà des Actifs.

Ceci diffère de l'algorithme de déduplication automatique, qui compare `hash_code` (ou Unique ID from tool) pour décider des correspondances. Constatations similaires ratisse délibérément plus large afin que vous puissiez découvrir des Constatations liées que la correspondance stricte par hachage manquerait.

## Travailler avec les résultats

L'onglet Constatations similaires est un tableau de données complet, avec les mêmes contrôles que ceux utilisés ailleurs dans l'interface Pro :

- La **Recherche par mot-clé**, ainsi que les filtres par colonne (icône entonnoir) et les contrôles de tri, permettent d'affiner la liste.
- Le menu déroulant des **vues enregistrées** (**Par défaut**) et l'icône d'enregistrement permettent de sauvegarder une disposition de filtres/colonnes pour la réutiliser.
- Les boutons de paramètres de colonnes et de disposition contrôlent les colonnes affichées.
- **Export** télécharge les résultats actuels, et **Effacer les filtres** réinitialise le tableau.

Chaque ligne affiche l'ID de la Constatation correspondante, la Sévérité, la Priorité, le Risque, le nom de la Constatation, le CWE, les scores CVSS, les identifiants de vulnérabilité, les données EPSS, les renseignements sur l'exploitation (Known Exploited / Ransomware), le statut, l'Actif, et plus encore. Cliquez sur un nom de Constatation pour l'ouvrir.

## Actions

Ouvrez le menu d'action (le bouton **⋮** au début d'une ligne) pour gérer le cluster de doublons directement depuis cette page :

![Le menu d'action de ligne de Constatations similaires](images/pro_similar_findings_actions.png)

- **Définir comme constatation d'origine** – promouvoir une Constatation au rang d'originale (racine du cluster).
- **Marquer comme doublon** – relier la Constatation similaire au cluster de doublons de la Constatation actuelle.

Ces actions manipulent les mêmes relations de doublon que celles utilisées par la déduplication automatique, de sorte qu'une Constatation que vous reliez ici se comporte exactement comme un doublon détecté automatiquement. Toute Constatation que vous marquez comme doublon apparaît ensuite sous l'onglet **Doublons** de cette carte.

Une action peut être indisponible lorsqu'elle n'est pas valide, par exemple lorsque la Constatation similaire est déjà l'originale d'un autre cluster, ou lorsque l'associer franchirait une limite d'Engagement alors que la déduplication au niveau de l'Engagement est activée.

## Activer et désactiver Constatations similaires

Constatations similaires est contrôlée par le paramètre système global **Activer les constatations similaires**, qui est activé par défaut. Comme la requête parcourt un Actif entier, elle peut être coûteuse sur de grands Actifs ; si vous constatez une lenteur des pages Afficher la constatation, ce paramètre peut être désactivé.
