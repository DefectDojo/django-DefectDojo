---
title: Vue d'ensemble des emplacements
description: Ce que sont les emplacements et pourquoi ils remplacent les points de
  terminaison
audience: pro
weight: 1
---

Les **emplacements** (Locations) sont un nouvel outil de modélisation des actifs dans DefectDojo Pro. Ils remplacent l'ancien modèle **Endpoints** et absorbent les anciennes données de **Composants** (bibliothèques), offrant à DefectDojo une manière unique et polymorphe de décrire *où* vit une Constatation — qu'il s'agisse d'une URL, d'une dépendance logicielle issue d'un **SBOM**, ou, à l'avenir, d'un **identifiant de ressource cloud**, d'une **image de conteneur** ou d'un **dépôt de code**.

Les emplacements doivent être activés sur votre instance avant de pouvoir être utilisés. Vous pouvez les activer vous-même depuis la [page des indicateurs de fonctionnalités](/admin/feature_flags/pro__feature_flags/) — aucune demande auprès du support n'est nécessaire. Notez que les emplacements ne peuvent pas être désactivés une fois activés.

## Pourquoi remplacer les Endpoints ?

Le modèle Endpoints d'origine était construit autour des URL et des adresses IP — il comportait des champs propres aux applications web comme `protocol`, `host`, `port`, `path`, ainsi qu'une table de statut fixe étroitement couplée aux Constatations. Trois problèmes en découlaient :

1. **Fidélité limitée.** Les Endpoints ne pouvaient pas décrire proprement des actifs non-URL tels que les bibliothèques tierces, les images de conteneurs ou les ressources cloud, alors même que les scanners produisent de plus en plus de constatations à ce sujet.
2. **Plafond de performance.** Les lignes Endpoint_Status par Constatation et le schéma en forme d'URL ne montaient pas bien en charge pour les gros volumes clients.
3. **Les composants étaient de seconde classe.** Les bibliothèques logicielles n'existaient que comme des champs dénormalisés sur une Constatation, si bien qu'une bibliothèque ne pouvait pas exister indépendamment d'une vulnérabilité — rendant impossible une véritable gestion des SBOM.

Les emplacements corrigent ces trois problèmes en introduisant un **objet de base `Location`** doté d'une charge utile typée, ainsi que des **sous-types** dédiés pour chaque forme d'actif :

- **Emplacements URL** — équivalent fonctionnel des anciens Endpoints, avec les mêmes champs protocole/hôte/port/chemin/requête/fragment.
- **Emplacements de dépendance** — bibliothèques logicielles identifiées par [Package URL (pURL)](https://github.com/package-url/purl-spec), utilisées pour modéliser le contenu des SBOM.
- **[Emplacements de code source](/asset_modelling/locations/pro__source_code_locations/)** — l'endroit où vit dans le code source une constatation d'analyse statique, identifié par un chemin de fichier et un numéro de ligne. Géré par le scan, et le socle permettant de [suivre les constatations lorsque leur code se déplace](/triage_findings/finding_deduplication/pro__location_drift_matching/).

Parmi les futurs types d'emplacements envisagés figurent les identifiants de ressources des fournisseurs cloud (AWS ARN, Azure Resource ID, GCP Full Resource Name) et les images de conteneurs (registry/repository:tag et empreintes SHA256).

## Concepts clés

### Emplacements et sous-types

Un **Location** est le parent commun. Il porte :

- Un `Location Type` (par ex. `"url"`, `"dependency"`)
- Une chaîne `Location Value` canonique utilisée pour l'affichage, la recherche et la déduplication
- Des `Tags` et des étiquettes héritées de l'Actif parent
- Des métadonnées (paires clé/valeur personnalisées)

Un **sous-type** (URL ou Dependency) contient les champs structurés propres à ce type d'emplacement. Les URL et les Dependencies vivent toujours aux côtés d'un objet Location parent ; le `Location Value` du sous-type est généré à partir de ses champs structurés.

### Références

Les emplacements ne sont pas directement rattachés aux Produits ou aux Constatations. Deux objets **Reference** les relient à la place :

- **Asset References** — les relations que l'emplacement entretient avec les Actifs (par ex. `libFoo` est *possédée par* l'Actif 6, *utilisée par* l'Actif 9). Chaque référence porte un statut (`Active` ou `Mitigated`) et une **relation** optionnelle (« Used By » ou « Owned By »).
- **Finding References** — les relations que l'emplacement entretient avec les Constatations. Chaque référence porte un statut plus riche (`Active`, `Mitigated`, `False Positive`, `Risk Accepted`, `Out of Scope`), ainsi que l'auditeur et l'heure de l'audit.

Cette séparation est ce qui permet à une bibliothèque d'exister sur un Produit *sans* qu'une Constatation soit nécessaire — une capacité absente de l'ancien modèle de Composants.

### Association automatique lors de l'importation

Lorsqu'un parseur produit une Constatation référençant une URL ou une bibliothèque, l'importateur :

1. Recherche un emplacement existant correspondant à l'URL ou au pURL ; s'il n'en existe aucun, il en crée un.
2. Crée une Finding Reference reliant la Constatation à l'emplacement avec le statut `Active`.
3. Crée (ou réutilise) une Asset Reference afin que l'emplacement vive également sur l'Actif parent.

Les parseurs existants ont été mis à jour pour émettre des données d'emplacement lorsque l'indicateur de fonctionnalité est activé, et pour revenir à l'ancien modèle Endpoint lorsqu'il est désactivé. Aucune reconfiguration n'est nécessaire une fois les emplacements activés — la prochaine importation passera automatiquement par le pipeline des emplacements.

## Contenu du MVP

| Fonctionnalité | État |
| --- | --- |
| Modèles de base `Location`, `URL`, `Dependency` | Livré |
| API REST pour les emplacements et les références | Livré (`Location` en lecture seule, CRUD complet sur les références) |
| Compatibilité en lecture avec l'ancienne API Endpoint | Livré |
| Commande de migration Endpoint → URL (à sens unique) | Livré |
| Mises à jour des parseurs (URL et dépendances) | Livré pour les principaux parseurs |
| Import de SBOM (CycloneDX, SPDX v2/v3) | Livré via `/api/v2/sbom-import/` |
| Interface Pro pour les emplacements, URL et dépendances | Livré |
| Recherche/filtre par pURL | Livré |
| Suivi des licences sur les dépendances | Partiel (champ `license_expression`) |
| Format SBOM SWID Tag | Absent du MVP |

## Prochaines étapes

- **Activer la fonctionnalité** — contactez [support@defectdojo.com](mailto:support@defectdojo.com) pour activer les emplacements sur votre instance.
- **Migrer depuis les Endpoints** — voir [Migrating from Endpoints](../pro__migrating_from_endpoints) pour savoir ce que la migration préserve, et comment se comporte ensuite l'ancienne API Endpoint.
- **Flux de travail quotidiens sur les URL** — voir [Working with URLs](../pro__working_with_urls).
- **SBOM et dépendances** — voir [Working with SBOMs](../pro__working_with_sboms).
