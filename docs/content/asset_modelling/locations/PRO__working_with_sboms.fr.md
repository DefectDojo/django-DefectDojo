---
title: Utilisation des SBOM
description: Gérer les dépendances logicielles et les SBOM en tant qu'Emplacements
audience: pro
weight: 5
---

DefectDojo Pro modélise les bibliothèques logicielles sous forme d'**Emplacements de dépendance**. Une Dépendance est un sous-type d'Emplacement identifié par une [Package URL (pURL)](https://github.com/package-url/purl-spec) et destiné à représenter une bibliothèque ou un paquet unique — `org.apache.logging.log4j:log4j-core@2.17.0`, `pypi/django@5.0.2`, `npm/react@18.2.0`, etc.

Les Dépendances remplacent l'ancien modèle **Composants**, qui n'était rattaché qu'aux Constatations. Avec les Emplacements, les bibliothèques peuvent exister indépendamment de toute vulnérabilité — vous pouvez importer un SBOM sur un Actif, puis laisser les Constatations se rattacher automatiquement aux dépendances qu'elles référencent au fur et à mesure des analyses.

## Ce que contient une Dépendance

Chaque Dépendance est identifiée de manière unique par une pURL, décomposée en champs atomiques sur lesquels vous pouvez effectuer des recherches et des filtres :

| Champ | Signification | Exemple |
| --- | --- | --- |
| `purl_type` | Écosystème de la bibliothèque | `npm`, `pypi`, `maven`, `cargo`, `nuget`, `gem` |
| `namespace` | Éditeur ou organisation | `org.apache.logging` |
| `name` | Nom de la bibliothèque | `log4j-core` |
| `version` | Version spécifique | `2.17.0` |
| `qualifiers` *(optionnel)* | Détails d'implémentation | `arch=amd64` |
| `subpath` *(optionnel)* | Chemin au sein d'une archive ou d'un monorepo | `src/lib/foo` |
| `artifact_hashes` *(optionnel)* | Empreintes | sommes SHA256 |
| `license_expression` *(optionnel)* | Expression de licence SPDX | `Apache-2.0`, `MIT` |
| `file_path` *(optionnel)* | Où la bibliothèque a été trouvée dans le projet | `package-lock.json` |

Cette décomposition atomique est ce qui rend la recherche par pURL utile : vous pouvez demander *« tous les paquets `pypi` dans l'espace de noms `django` en version 4.x »* et DefectDojo peut répondre sans analyser une chaîne de texte libre.

## Owned-By vs Used-By

Lorsqu'une Dépendance est associée à un Actif, l'Asset Reference porte une **relation** optionnelle décrivant *comment* la bibliothèque appartient à l'Actif :

- **`owned_by`** — *« cette bibliothèque est possédée par cet Actif »*. Utilisez cette valeur pour les bibliothèques internes qu'un Actif publie ou maintient.
- **`used_by`** — *« cette bibliothèque est utilisée par cet Actif »*. Utilisez cette valeur pour les dépendances tierces qu'un Actif consomme.

La même bibliothèque peut être `owned_by` pour un Actif et `used_by` pour plusieurs autres, ce qui est exactement la relation nécessaire pour répondre à *« qui consomme le paquet publié par mon équipe ? »* lors du triage des vulnérabilités.

## Importer un SBOM

Pour peupler les Dépendances en masse, importez un fichier SBOM sur un Produit. Le point de terminaison est :

```
POST /api/v2/sbom-import/
```

| Champ | Description |
| --- | --- |
| `product` | L'identifiant du Produit (Actif) cible |
| `file` | Le fichier SBOM |
| `scan_type` | Le format du SBOM — voir les formats pris en charge ci-dessous |
| `replace` *(optionnel)* | Si `true`, les associations de Produit obsolètes non adossées à une référence de Constatation existante sont supprimées. Par défaut : `false` (cumulatif) |

L'importeur analyse le fichier, extrait les enregistrements `Dependency`, les déduplique par rapport aux Emplacements existants (en créant de nouveaux si nécessaire), et crée des Asset References reliant chaque Dépendance au Produit. L'interface Pro expose le même flux d'import — voir l'action **Importer un SBOM** dans l'onglet Emplacements d'un Produit.

### Formats pris en charge

Le MVP fournit des parseurs pour les deux formats de SBOM dominants :

- **CycloneDX** — JSON et XML
- **SPDX** — JSON (v2 et v3), XML, et tag-value

Le format SWID Tag n'est pas encore pris en charge.

### Remplacer vs ajouter

Par défaut, les imports répétés sont **additifs** : les dépendances déjà présentes sur l'Actif sont conservées, les nouvelles sont ajoutées, et rien n'est supprimé. Cela correspond au flux de travail habituel des mises à jour incrémentales de SBOM.

Définissez `replace=true` pour élaguer. Lorsque le mode remplacement est activé, après un import réussi, l'importeur supprime les associations de Produit qui n'étaient pas présentes dans le nouveau SBOM **et** qui ne sont actuellement référencées par aucune Constatation active. Les références liées à des Constatations actives sont préservées même en mode remplacement, afin de ne pas perdre le contexte de vulnérabilité simplement parce qu'un nouveau SBOM omet un paquet.

## Constatations référençant des bibliothèques

Lorsqu'un parseur ingère une vulnérabilité liée à une bibliothèque — par exemple, un outil SCA signalant `CVE-2021-44228` sur `log4j-core@2.14.1` — l'importeur :

1. Recherche un Emplacement de dépendance existant par pURL, ou en crée un nouveau.
2. Crée une `LocationFindingReference` reliant la Constatation à la Dépendance avec le statut **Actif**.
3. Crée une `LocationProductReference` afin que la Dépendance apparaisse également sur le Produit parent, si ce n'est pas déjà le cas.

Comme les Constatations et les imports de SBOM partagent les mêmes objets Dépendance sous-jacents, une Constatation ingérée *avant* un import de SBOM sera visible rétroactivement dans la vue SBOM, et inversement.

## API REST

| Tâche | Point de terminaison |
| --- | --- |
| Importer un SBOM | `POST /api/v2/sbom-import/` |
| Lister les Dépendances | `GET /api/v2/dependencies/` |
| Créer une Dépendance manuellement | `POST /api/v2/dependencies/` |
| Lister les Emplacements de dépendance | `GET /api/v2/location/?location_type=dependency` |
| Relier une Dépendance à une Constatation | `POST /api/v2/location_findings/` |
| Relier une Dépendance à un Produit (avec `owned_by` / `used_by`) | `POST /api/v2/location_products/` |

Les filtres sur `/api/v2/dependencies/` incluent les champs composants de la pURL, les étiquettes, et le tri sur `name`, `version`, et le nombre de constatations actives.

## Dans l'interface Pro

Lorsque les Emplacements sont activés, la navigation expose :

- **Emplacements / Dépendances** — Liste globale de toutes les Dépendances de l'instance, avec des filtres pURL.
- **Emplacements sur un Produit/Actif** — Vue par Actif qui affiche à la fois les URL et les Dépendances, avec l'action **Importer un SBOM** accessible depuis l'onglet Dépendances.
- **Nouvelle Dépendance** — Formulaire permettant de créer une seule bibliothèque en saisissant manuellement ses composants pURL.
- **Détail des Constatations** — Une Constatation qui touche une bibliothèque affiche ses Emplacements de dépendance aux côtés de tout Emplacement URL, afin de voir en un seul endroit que *« ce CVE affecte `log4j-core@2.14.1` sur l'Actif 6 et l'Actif 9 »*.

## Ce qui n'est pas dans le MVP

- **Format de SBOM SWID Tag** — Non analysé. CycloneDX ou SPDX est requis.
- **Notation du risque de licence** — Le champ `license_expression` est capturé lorsqu'il est présent dans le SBOM, mais DefectDojo ne signale pas encore de constatations en cas d'incompatibilité de licence. Le reporting basé sur les licences figure sur la feuille de route en tant que suite du MVP Emplacements.
- **Emplacements d'image de conteneur et de ressource cloud** — Futurs sous-types d'Emplacement. Pour l'instant, les bibliothèques découvertes à l'intérieur d'une image de conteneur sont enregistrées comme des Dépendances ; l'image de conteneur elle-même n'est pas encore un Emplacement de premier niveau.
