---
title: Prise en charge des versions CVSS
description: Quelles versions de CVSS DefectDojo stocke, affiche et accepte sur les
  Constatations
weight: 1
---

DefectDojo prend en charge les métadonnées CVSS sur les Constatations, y compris la norme CVSS 4.0. Cette page décrit les versions de CVSS stockées de bout en bout, où vous pouvez les saisir ou les consulter, et à quoi vous attendre en matière de couverture côté analyseur.

## Ce que DefectDojo stocke

Les Constatations peuvent porter les données CVSS suivantes :

| Version | Vecteur stocké | Score stocké | Générateur de vecteur et calculateur (UI) |
| --- | --- | --- | --- |
| **CVSS v4.0** | ✅ | ✅ | ✅ (interface Pro) |
| **CVSS v3 (v3.0 / v3.1)** | ✅ | ✅ | ✅ (interface Pro) |
| **CVSS v2** | Stocké implicitement via le champ **Sévérité** de la Constatation ; aucun champ de vecteur v2 distinct n'est stocké | N/A | N/A |

Chaque Constatation possède des champs dédiés `cvssv3` / `cvssv3_score` et `cvssv4` / `cvssv4_score` sur le modèle sous-jacent. Ils sont accessibles via l'API ainsi que via l'interface utilisateur.

## Où saisir les données CVSS manuellement

CVSSv3 et CVSSv4 peuvent tous deux être saisis manuellement sur une Constatation :

- **Formulaire de modification de la Constatation** — collez une chaîne de vecteur CVSS complète dans le champ correspondant. Lorsque vous enregistrez, DefectDojo analyse le vecteur et calcule automatiquement le score.
- **Générateur de vecteur (interface Pro)** — cliquez sur le bouton 🛠️ à côté de l'entrée CVSSv3 ou CVSSv4 dans le formulaire de modification de la Constatation pour ouvrir le générateur de vecteur. Construisez le vecteur de manière interactive, puis cliquez sur le bouton calculatrice pour obtenir un score à partir du vecteur résultant.

> Les chaînes de vecteur CVSSv4 et le générateur de vecteur ont été ajoutés à l'interface Pro dans la v2.50.3 (22 septembre 2025), et le bouton calculatrice explicite qui l'accompagne est arrivé dans la v2.51.1 (14 octobre 2025).

## Paramètres d'affichage

La vue Constatation respecte deux paramètres système qui contrôlent si les données CVSSv3 et CVSSv4 s'affichent pour les utilisateurs :

- **Activer l'affichage CVSS 3** — affiche les vecteurs et scores CVSSv3 sur les Constatations.
- **Activer l'affichage CVSS 4** — affiche les vecteurs et scores CVSSv4 sur les Constatations.

Les deux peuvent être configurés indépendamment dans les Paramètres système. Si les deux sont activés, les deux versions s'affichent côte à côte sur les Constatations qui portent les deux.

## Couverture des analyseurs et des outils

DefectDojo peut stocker des données CVSSv4 sur n'importe quelle Constatation, mais **le fait qu'un analyseur donné renseigne les champs CVSSv4 dépend de l'outil source** :

- Si l'outil source émet des vecteurs ou des scores CVSSv4 dans son format d'export, l'analyseur mappe généralement ces champs.
- Si l'outil n'émet que des données CVSSv2 ou CVSSv3, l'analyseur ne synthétise pas de vecteur v4 — il n'existe pas de conversion v3 vers v4 intégrée.
- Certains analyseurs plus anciens peuvent ne pas encore mapper les champs CVSSv4 même si l'outil source les émet. Si vous trouvez un analyseur qui omet les champs CVSSv4 d'un outil qui les émet pourtant, merci de signaler un problème.

En attendant, deux méthodes vous donnent une couverture CVSSv4 complète, indépendamment de la prise en charge par l'analyseur :

1. **[Generic Findings Import](/supported_tools/parsers/generic_findings_import/)** — accepte les colonnes `CVSSV4` (vecteur) et `CVSSV4_score` en CSV, et les clés `cvssv4` / `cvssv4_score` en JSON.
2. **[Universal Parser](/import_data/pro/specialized_import/universal_parser/)** (Pro) — prend en charge les vecteurs CVSSv4 comme champ mappable (ajouté dans la v2.57.0, 7 avril 2026). Utilisez-le lorsque votre outil émet du JSON ou du CSV avec des noms de champs personnalisés que les analyseurs intégrés ne mappent pas.

La saisie manuelle dans le formulaire de modification de la Constatation reste disponible comme solution de repli universelle pour tout outil ou rapport qui ne fait pas remonter automatiquement les données CVSSv4.
