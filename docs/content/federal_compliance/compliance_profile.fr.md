---
title: Profil de conformité
description: Inscrire un Asset en tant que système et définir les informations qui
  apparaissent sur chaque livrable
weight: 1
audience: pro
---

Le Compliance Profile inscrit un Asset en tant que système et conserve les informations qui apparaissent sur chaque
livrable qu'il produit. Ouvrez l'Asset qui représente le périmètre de votre système, allez dans l'onglet
**Compliance**, puis **Profile**.

![The Compliance Profile form](images/01-compliance-profile.png)

## Champs du profil

| Field | What it does |
| --- | --- |
| **Enabled** | Active le suivi de conformité pour ce produit. |
| **Automatic Sync** | Maintient les éléments du POA&M synchronisés avec les constatations. |
| **POA&M ID Prefix** | Numérotation des éléments. Obligatoire. Les éléments sont numérotés `V-1`, `V-2`, et ainsi de suite par défaut. |
| **Impact Level** | LI-SaaS, Low, Moderate, ou High. |
| **Cloud Service Provider** | Le nom du CSP, tel qu'il doit apparaître sur les données de couverture du POA&M. |
| **System / Offering Name** | Le nom du système, tel qu'il doit apparaître sur les données de couverture du POA&M. |
| **FedRAMP System Identifier** | L'identifiant de votre système, par exemple `F00000042`. |
| **Default Point of Contact** | Le point de contact appliqué aux éléments qui n'en portent pas de leur propre. |
| **Scan Item Policy** | Inclure soit tous les éléments ouverts, soit uniquement les éléments de scan en retard. |
| **OSCAL SSP Reference** | Optionnel. Une fois défini, les POA&M OSCAL générés y font référence via `import-ssp`. |

### Choisir une politique d'élément de scan

Uniquement les éléments en retard est le minimum FedRAMP ConMon. **Include all open items** est le choix le plus
prudent, et il s'agit du réglage par défaut.

## Enregistrer et synchroniser

**Save Compliance Profile** inscrit l'Asset. Le registre POA&M se remplit alors à partir des constatations
existantes de l'Asset, et le reste de l'onglet Compliance devient disponible.

Avec **Automatic Sync** activé, le registre se maintient à jour de lui-même — voir
[Le registre POA&M](../poam_ledger). **Sync POA&M Now** exécute une synchronisation immédiatement, ce qui est utile
juste après avoir modifié le profil ou importé un nouveau scan.

## Paramètres disponibles uniquement via l'API

Deux paramètres du profil ne figurent pas sur le formulaire et se définissent via l'API de conformité :

* **Default scan controls** — les contrôles attribués aux constatations de scanner qui ne portent pas de mapping
  de contrôle propre. `RA-5` est le choix courant pour les résultats de scan de vulnérabilités. Les constatations qui
  *portent* leurs propres références de contrôle sont mappées à partir de celles-ci à la place ; voir
  [Couverture des contrôles](../control_coverage).
* **Configuration test types** — les types de test dont les constatations sont traitées comme des éléments de
  configuration, ce qui pilote la consolidation CM-6 dans le registre.

## Traçabilité

Les profils de conformité sont sous historique d'audit : chaque modification enregistre qui a changé quoi, et quand.
