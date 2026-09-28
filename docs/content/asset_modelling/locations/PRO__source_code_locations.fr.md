---
title: Emplacements de code source
description: Les emplacements de code modélisent l'endroit où vit une constatation
  d'analyse statique dans le code source, et enregistrent son historique de déplacement
  à mesure que le code évolue
weight: 6
audience: pro
---

**Les Emplacements de code source** étendent le modèle d'Emplacements à l'analyse statique : aux côtés des URL (DAST) et des Dépendances (SCA), un emplacement de type **Code** décrit où vit une constatation SAST dans le code source — identifiée par son **chemin de fichier et son numéro de ligne**.

> Les Emplacements de code source nécessitent la fonctionnalité Emplacements (Bêta). Pour activer les Emplacements sur votre instance, contactez [support@defectdojo.com](mailto:support@defectdojo.com).

## Ce qu'ils modélisent

Chaque constatation statique qui signale un chemin de fichier obtient un emplacement de type Code. La valeur canonique de l'emplacement est `path/to/file.py:42` (ou simplement le chemin de fichier lorsque l'outil ne signale aucune ligne). Comme tous les Emplacements, les emplacements de code sont des objets partagés : deux constatations situées au même fichier et à la même ligne référencent le même emplacement, et l'emplacement porte des statuts de référence par constatation et par actif.

Les emplacements de code sont **gérés par les analyses** : ils sont créés et mis à jour par les imports et réimports, pas manuellement. Il n'existe pas d'action « Nouvel emplacement de code source » — le scanner fait autorité quant à l'endroit où vivent les constatations de code.

## Où les trouver

- **Tout le code source** dans la barre latérale répertorie chaque emplacement de code de l'instance, avec le même filtrage et le même étiquetage que les URL et les Dépendances.
- **Afficher le code source** dans le menu Emplacements d'un Actif restreint la liste à cet actif.
- La page d'une constatation affiche son emplacement de code actuel et, lorsque la constatation a été déplacée, son **historique d'emplacement**.

## Historique de déplacement

Le code source se déplace en permanence : les commits décalent les numéros de ligne, les refactorisations renomment les fichiers. Lorsque le [Rapprochement par dérive d'emplacement](/triage_findings/finding_deduplication/pro__location_drift_matching/) est activé pour un outil, une constatation qui se déplace conserve son identité, et ses références d'emplacement de code enregistrent la trace :

- La référence de la constatation vers l'**ancien** emplacement est marquée comme atténuée et estampillée avec *où la constatation s'est déplacée* et *pourquoi la correspondance a été établie* (ligne la plus proche, flux de données, renommage de fichier...).
- Une référence vers le **nouvel** emplacement est créée et reste active.

Le résultat est une chaîne de succession consultable — « cette constatation vivait à `auth.py:42`, puis à `auth.py:57`, puis à `session.py:31` » — représentée sous forme de chronologie sur la page de la constatation. Le même mécanisme d'historique couvre les déplacements d'URL et les montées de version de dépendances, de sorte que les trois types d'emplacements partagent une seule interface de chronologie.

L'historique est enregistré à partir du moment où les Emplacements sont activés sur l'instance. Les constatations qui se sont déplacées avant cela conservent leur emplacement actuel ; les déplacements passés ont été appliqués mais non enregistrés. Pour les instances disposant de plusieurs années d'historique antérieur à la fonctionnalité, la [commande de consolidation du churn](/triage_findings/finding_deduplication/pro__location_drift_matching/#consolidating-historical-churn) peut reconstituer les traces tout en fusionnant les anciennes chaînes de fermeture-recréation.

## Exactitude des statuts

Les statuts de référence des emplacements de code sont maintenus exacts par le réimport, quel que soit l'algorithme de correspondance utilisé, que le rapprochement par dérive soit activé ou non :

- La référence de code actuelle d'une constatation appariée est synchronisée à chaque réimport, de sorte qu'une constatation déplacée ne laisse pas son ancienne référence active indéfiniment.
- La même synchronisation, indépendante de ce réglage, s'applique aux références de dépendance : lorsque la version du paquet d'une constatation SCA change, la référence de l'ancienne version est atténuée plutôt que de rester active aux côtés de la nouvelle.

## Relation avec les champs de la constatation

Les propres champs `file_path` / `line` de la constatation restent les valeurs scalaires faisant autorité (ce sont elles qu'exposent les filtres, les hachages et l'API) ; l'emplacement de code est la vue partagée et comptabilisée par référence de cette même coordonnée. Le réimport actualise les scalaires à partir de la dernière analyse, et le mécanisme d'emplacement en dérive les emplacements — les deux ne peuvent pas diverger.
