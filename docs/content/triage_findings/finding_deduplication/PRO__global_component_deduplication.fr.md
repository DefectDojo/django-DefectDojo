---
title: Déduplication des composants globaux
description: Dédupliquez les constatations d'analyse de composition logicielle par
  nom et version de composant sur tous les Produits
weight: 5
audience: pro
---

La déduplication des composants globaux est un algorithme de DefectDojo Pro qui identifie les constatations en double sur **tous les Produits** en se basant sur le nom et la version du composant auquel elles font référence. Il est destiné aux outils d'analyse de composition logicielle (Software Composition Analysis, SCA), où la même dépendance vulnérable (par exemple, `timespan@2.3.0`) peut apparaître dans de nombreux Produits, et où vous souhaitez que DefectDojo traite ces occurrences comme des doublons d'une seule constatation d'origine.

Contrairement aux autres algorithmes de déduplication, la correspondance par composant global **n'est pas limitée à un seul Produit ou Engagement**. Une constatation importée dans le Produit B peut être marquée comme un doublon d'une constatation plus ancienne dans le Produit A, même si les deux Produits n'ont aucun lien entre eux.

> **Composant global et Emplacements globaux :** le composant global ne fait correspondre que le nom et la version du composant. Si votre instance utilise le modèle de données Emplacements, la [déduplication des emplacements globaux](/triage_findings/finding_deduplication/pro__global_locations_deduplication/) en est le successeur plus précis — elle indexe les dépendances sur le Package URL complet et déduplique en plus les constatations URL/DAST sur l'ensemble des Produits. Consultez le tableau comparatif de cette page pour savoir lequel choisir.

## Activer l'algorithme de composant global

La déduplication des composants globaux est conditionnée par un indicateur de fonctionnalité et est **désactivée par défaut**. Un superutilisateur peut l'activer depuis **Settings > Feature Flags**, aussi bien sur les instances Cloud que sur site (On-Premise). Voir [Indicateurs de fonctionnalité](/admin/feature_flags/pro__feature_flags/).

Une fois la fonctionnalité activée, **Composant global** devient disponible comme option dans le menu déroulant **algorithme de déduplication**, pour les paramètres de déduplication par le même outil et entre outils dans le Tuner.

## Configurer la déduplication des composants globaux

Composant global peut être appliqué à la déduplication par le même outil, à la déduplication entre outils, ou aux deux, et se configure par outil de sécurité depuis **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** sur les instances utilisant encore l'ancienne disposition de menu ; voir [Le menu Paramètres](/navigation/pro__settings_menu/)).

### Même outil

Utilisez la déduplication par le même outil avec l'algorithme de composant global lorsque vous souhaitez dédupliquer les constatations d'un seul outil SCA sur plusieurs Produits.

1. Ouvrez l'onglet **Déduplication par le même outil**.
2. Sélectionnez l'outil SCA dans le menu déroulant **outil de sécurité** (par exemple, `Dependency Track Finding Packaging Format (FPF) Export`).
3. Réglez l'**algorithme de déduplication** sur **Composant global**.
4. Validez le formulaire.

Les champs de code de hachage ne sont pas utilisés par cet algorithme et sont masqués lorsqu'il est sélectionné.

### Entre outils

Utilisez la déduplication entre outils avec l'algorithme de composant global lorsque vous souhaitez dédupliquer les constatations d'un même composant entre différents outils SCA et Produits.

La correspondance entre outils nécessite que le composant global soit configuré sur **chaque** outil devant y participer.

1. Ouvrez l'onglet **Déduplication entre outils**.
2. Pour chaque outil à inclure : sélectionnez-le dans le menu déroulant **outil de sécurité**, réglez l'algorithme sur **Composant global**, puis validez.

## Fonctionnement de la correspondance

Une nouvelle constatation est marquée comme un doublon d'une constatation existante lorsque :

- le nom et la version du composant correspondent exactement, **et**
- une constatation plus ancienne portant le même nom et la même version de composant existe quelque part dans l'instance DefectDojo — dans n'importe quel Produit ou Engagement.

La correspondance de version de composant est exacte. Une constatation pour `timespan@2.3.0` ne se dédupliquera **pas** avec une constatation pour `timespan@2.3.1`.

Le paramètre de déduplication limité à l'Engagement est ignoré pour cet algorithme ; la correspondance est toujours globale.

## Exemple

Supposons que le composant global soit activé sur `Dependency Track Finding Packaging Format (FPF) Export` (même outil) et sur un outil Generic Findings Import (entre outils) :

| Étape | Import | Dans le Produit | Résultat |
| --- | --- | --- | --- |
| 1 | Analyse Dependency Track pour `timespan@2.3.0` | Application 0 | 1 constatation active créée |
| 2 | Même analyse Dependency Track | Application 1 | 1 constatation créée, marquée comme doublon de la constatation d'Application 0 |
| 3 | Generic Findings Import pour `timespan@2.3.0` | Application 2 | 1 constatation créée, marquée comme doublon de la constatation d'Application 0 (correspondance entre outils) |
| 4 | Analyse Dependency Track pour `timespan@2.3.1` | Application 3 | 1 constatation active créée — version différente, aucune correspondance |

Chaque constatation en double affiche son original en bas de la page de la constatation, dans la chaîne de doublons.

## Visibilité inter-Produits

Comme la correspondance par composant global traverse les limites des Produits, la constatation d'origine dans une chaîne de doublons peut se trouver dans un Produit auquel l'utilisateur consultant le doublon n'a pas accès.

Dans ce cas, la constatation est visible et étiquetée comme un doublon, mais l'utilisateur ne pourra pas ouvrir l'original ni y accéder. Tenez-en compte avant d'activer le composant global sur des outils dont les constatations sont sensibles aux contrôles d'accès au niveau des Produits.

## Revenir en arrière

Pour cesser d'utiliser le composant global pour un outil donné, ouvrez ses paramètres de déduplication et remettez l'algorithme sur l'une des options limitées en portée.

Pour la déduplication **par le même outil** :

- Code de hachage
- Identifiant unique de l'outil
- Identifiant unique de l'outil ou code de hachage

Pour la déduplication **entre outils** :

- Code de hachage
- Désactivé

Le changement d'algorithme déclenche un recalcul en arrière-plan des hachages de déduplication pour les constatations existantes de l'outil.
