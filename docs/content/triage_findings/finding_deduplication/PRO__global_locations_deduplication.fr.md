---
title: Déduplication des emplacements globaux
description: Dédupliquez les constatations par emplacement partagé (URL ou dépendance)
  sur tous les Produits
weight: 6
audience: pro
---

La déduplication des emplacements globaux est un algorithme de DefectDojo Pro qui identifie les constatations en double sur **tous les Produits** en se basant uniquement sur un **emplacement partagé** : une URL, ou une dépendance (identifiée par son Package URL). Deux constatations qui partagent un emplacement d'un type sélectionné sont traitées comme des doublons, quels que soient leur titre, leur sévérité, leur CWE ou leurs identifiants de vulnérabilité — seul l'emplacement fait foi pour l'identité.

Il s'agit du pendant tenant compte de l'emplacement à la [déduplication des composants globaux](/triage_findings/finding_deduplication/pro__global_component_deduplication/), appliqué au modèle de données Emplacements de DefectDojo. Là où le composant global ne fait correspondre qu'un nom et une version de composant, les emplacements globaux font correspondre la même dépendance **par Package URL complet** *et* par **URL** partagées — il peut ainsi dédupliquer les constatations DAST/web sur l'ensemble des Produits, ce que le composant global ne peut pas faire.

Contrairement aux algorithmes limités en portée, la correspondance par emplacements globaux **n'est pas limitée à un seul Produit ou Engagement**. Une constatation importée dans le Produit B peut être marquée comme un doublon d'une constatation plus ancienne dans le Produit A, même si les deux Produits n'ont aucun lien entre eux.

## Prérequis

Les emplacements globaux sont définis sur le modèle de données **Emplacements** de DefectDojo et ne sont proposés que lorsque la fonctionnalité **Emplacements** est activée. Sur les instances où Emplacements est désactivé, l'indicateur de fonctionnalité des emplacements globaux apparaît verrouillé (« Requires Locations to be enabled », c'est-à-dire nécessite l'activation d'Emplacements) et l'algorithme n'apparaît pas dans le Tuner.

## Activer l'algorithme d'emplacements globaux

La déduplication des emplacements globaux est conditionnée par un indicateur de fonctionnalité et est **désactivée par défaut**. Une fois Emplacements activé, un superutilisateur peut l'activer depuis **Settings > Feature Flags**, aussi bien sur les instances Cloud que sur site (On-Premise). Voir [Indicateurs de fonctionnalité](/admin/feature_flags/pro__feature_flags/).

Une fois la fonctionnalité activée, **Emplacements globaux** devient disponible comme option dans le menu déroulant **algorithme de déduplication**, pour les paramètres de déduplication par le même outil et entre outils dans le Tuner.

## Configurer la déduplication des emplacements globaux

Emplacements globaux peut être appliqué à la déduplication par le même outil, à la déduplication entre outils, ou aux deux, et se configure par outil de sécurité depuis **Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** sur les instances utilisant encore l'ancienne disposition de menu ; voir [Le menu Paramètres](/navigation/pro__settings_menu/)).

Lorsque vous sélectionnez **Emplacements globaux**, le sélecteur de champs de code de hachage est masqué (il ne s'applique pas) et un sélecteur **types d'emplacement** apparaît à la place.

### Types d'emplacement

Choisissez les types d'emplacement qui participent à la correspondance :

- **URL** — deux constatations correspondent lorsqu'elles partagent une URL (comparée sur les champs de point de terminaison configurés, `DEDUPE_ALGO_ENDPOINT_FIELDS`).
- **Dépendances** — deux constatations correspondent lorsqu'elles font référence à la même dépendance, par identité de Package URL complet.

Au moins un type doit être sélectionné ; les deux sont sélectionnés par défaut. Un outil configuré uniquement pour les **URL** ignore les dépendances partagées, et un outil configuré uniquement pour les **Dépendances** ignore les URL partagées.

### Même outil

Utilisez la déduplication par le même outil avec l'algorithme d'emplacements globaux lorsque vous souhaitez dédupliquer les constatations d'un seul outil sur plusieurs Produits par emplacement partagé.

1. Ouvrez l'onglet **Déduplication par le même outil**.
2. Sélectionnez l'outil dans le menu déroulant **outil de sécurité**.
3. Réglez l'**algorithme de déduplication** sur **Emplacements globaux**.
4. Choisissez les **types d'emplacement** sur lesquels effectuer la correspondance.
5. Validez le formulaire.

### Entre outils

Utilisez la déduplication entre outils avec l'algorithme d'emplacements globaux lorsque vous souhaitez dédupliquer les constatations qui partagent un emplacement entre **différents** outils et Produits.

La correspondance entre outils utilise la sélection de types d'emplacement de l'outil d'importation ; configurez donc les emplacements globaux sur **chaque** outil devant y participer, avec des types d'emplacement correspondants.

1. Ouvrez l'onglet **Déduplication entre outils**.
2. Pour chaque outil à inclure : sélectionnez-le dans le menu déroulant **outil de sécurité**, réglez l'algorithme sur **Emplacements globaux**, choisissez les types d'emplacement, puis validez.

## Fonctionnement de la correspondance

Une nouvelle constatation est marquée comme un doublon d'une constatation existante n'importe où dans l'instance lorsque les deux partagent **au moins un emplacement concret d'un type sélectionné** :

- **une URL** dont tous les champs de point de terminaison configurés (`DEDUPE_ALGO_ENDPOINT_FIELDS`) correspondent, **ou**
- **une dépendance** avec le même Package URL (une correspondance purl exacte, donc `pkg:npm/timespan@2.3.0` ne correspond **pas** à `pkg:npm/timespan@2.3.1`).

La correspondance est **stricte et non triviale** : deux constatations qui n'ont aucun emplacement d'un type sélectionné ne sont **jamais** dédupliquées (contrairement à la correspondance d'emplacement limitée en portée, où « les deux vides » ne constitue pas une correspondance). Si la comparaison des champs de point de terminaison est désactivée (`DEDUPE_ALGO_ENDPOINT_FIELDS = []`), les URL ne peuvent établir aucune correspondance — seule une dépendance partagée le peut.

La correspondance par le même outil reste au sein d'un seul outil (type de test). La correspondance entre outils traverse intentionnellement les outils. Le paramètre de déduplication limité à l'Engagement est ignoré pour cet algorithme ; la correspondance est toujours globale, et le champ `service` continue de partitionner la déduplication comme pour les autres algorithmes globaux.

## Exemple

Supposons que les emplacements globaux (les deux types d'emplacement) soient activés sur un outil DAST (même outil) et, pour la ligne entre outils, sur un second outil DAST :

| Étape | Import | Dans le Produit | Résultat |
| --- | --- | --- | --- |
| 1 | Constatation DAST à `https://shared.example.com/login` | Application 0 | 1 constatation active créée |
| 2 | Même URL, vulnérabilité **différente** (titre + sévérité) | Application 1 | 1 constatation créée, marquée comme doublon de la constatation d'Application 0 (seul l'emplacement correspond) |
| 3 | Second outil DAST, même URL | Application 2 | 1 constatation créée, marquée comme doublon de la constatation d'Application 0 (correspondance entre outils) |
| 4 | Constatation DAST à `https://other.example.com/admin` | Application 3 | 1 constatation active créée — URL différente, aucun emplacement partagé |
| 5 | Constatation sans URL ni dépendance | Application 4 | 1 constatation active créée — aucun emplacement à partager |

Chaque constatation en double affiche son original en bas de la page de la constatation, dans la chaîne de doublons.

## Composant global et Emplacements globaux

Les deux sont des algorithmes globaux (inter-Produits) qui ignorent la portée de l'Engagement et se basent sur une identité unique plutôt que sur les champs de hachage. Choisissez en fonction de ce qui identifie un doublon pour votre outil :

| | Composant global | Emplacements globaux |
| --- | --- | --- |
| Correspond sur | **Nom + version** du composant | Un **emplacement** partagé : une URL et/ou une dépendance |
| Identité de dépendance | Nom et version | **Package URL** complet (type, espace de noms, nom, version, qualificateurs) |
| Constatations URL / DAST | Non prises en compte | Prises en compte (sur les champs de point de terminaison configurés) |
| Configurable | Non | Oui — choisissez URL, Dépendances, ou les deux, par outil |
| Modèle de données | Fonctionne avec ou sans Emplacements | Nécessite **Emplacements** (Pro) |
| Idéal pour | Les outils SCA où un nom + version de paquet fait office d'identité | Les outils Web/DAST et SCA sous le modèle Emplacements, où l'URL ou la dépendance exacte fait office d'identité |

Pour une nouvelle instance utilisant le modèle de données Emplacements, les emplacements globaux constituent le successeur plus précis du composant global : ils indexent les dépendances sur le Package URL exact et dédupliquent en plus les constatations basées sur l'URL. Le composant global reste disponible et inchangé pour les outils où le nom + version du composant est l'identité recherchée.

## Visibilité inter-Produits

Comme la correspondance par emplacements globaux traverse les limites des Produits, la constatation d'origine dans une chaîne de doublons peut se trouver dans un Produit auquel l'utilisateur consultant le doublon n'a pas accès.

Dans ce cas, la constatation est visible et étiquetée comme un doublon, mais l'utilisateur ne pourra pas ouvrir l'original ni y accéder. Tenez-en compte avant d'activer les emplacements globaux sur des outils dont les constatations sont sensibles aux contrôles d'accès au niveau des Produits.

## Revenir en arrière

Pour cesser d'utiliser les emplacements globaux pour un outil donné, ouvrez ses paramètres de déduplication et remettez l'algorithme sur l'une des options limitées en portée.

Pour la déduplication **par le même outil** :

- Code de hachage
- Identifiant unique de l'outil
- Identifiant unique de l'outil ou code de hachage

Pour la déduplication **entre outils** :

- Code de hachage
- Désactivé

Le changement d'algorithme déclenche un recalcul en arrière-plan des hachages de déduplication pour les constatations existantes de l'outil.
