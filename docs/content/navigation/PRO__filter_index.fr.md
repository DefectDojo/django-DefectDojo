---
title: Index des filtres
description: Référence de tous les filtres dans DefectDojo
weight: 5
aliases:
- /fr/en/working_with_findings/organizing_engagements_tests/filter_index
---

**Remarque : cet article ne couvre actuellement que les filtres de Constatations disponibles dans l'interface DefectDojo Pro, mais il sera étendu à l'avenir pour couvrir davantage de types d'objets, ainsi que les filtres Open-Source.**

Voici une liste des filtres pouvant être appliqués dans l'interface DefectDojo Pro pour trier les listes de Constatations.  Les filtres DefectDojo permettent de faciliter la navigation dans les listes d'objets, de créer des [tableaux de bord](/metrics_reports/dashboards/custom-dashboards/) personnalisés, ou de créer des automatisations via le [Rules Engine](/automation/rules_engine/about).

## Comment les filtres de date sont évalués

Les filtres qui prennent une date — **Date Created**, **SLA Expiration Date**, **Last Status Update**, **Planned Remediation Date**, et les filtres de date Jira listés ci-dessous — proposent cinq opérateurs :

| Opérateur | Correspond à |
| --- | --- |
| **On** | La journée entière du jour indiqué. |
| **Before** | Tout ce qui précède le début du jour indiqué. Le jour indiqué lui-même n'est **pas** inclus. |
| **After** | Tout ce qui suit le début du jour indiqué — le jour indiqué **est** donc inclus. |
| **During** | Une journée de début jusqu'à une journée de fin, toutes deux **incluses**. |
| **Within** | Une fenêtre glissante se terminant maintenant : les 7, 14, 30, 90 ou 180 derniers jours, ou l'année écoulée. |

Notez que **Before** et **After** ne sont volontairement pas le miroir l'un de l'autre : *Before 8 August* exclut le 8 août, tandis que *After 8 August* l'inclut.

### Limites de journée et votre fuseau horaire

**On**, **Before**, **After** et **During** déterminent leurs limites de journée dans **votre propre fuseau horaire**, détecté à partir de votre navigateur. Une plage de dates couvre donc minuit à minuit tel que *vous* le vivez, plutôt qu'en UTC ou dans le fuseau horaire du serveur. Deux personnes situées dans des fuseaux horaires différents peuvent obtenir des résultats légèrement différents pour un même filtre, concernant des Constatations proches d'une limite de journée.

**Within** n'est pas concerné — il s'agit d'une fenêtre glissante mesurée à partir du moment présent, qui n'a donc aucune limite de journée à déterminer.

> **Où cela ne s'applique pas.** Seules les requêtes provenant de l'interface Pro transmettent votre fuseau horaire. Tout ce qui s'exécute sans navigateur — l'API REST `/api/v2`, les rapports planifiés et le Rules Engine — utilise par défaut le fuseau horaire configuré sur le serveur (`DD_TIME_ZONE`, `UTC` sauf si votre administrateur l'a modifié). Si votre fuseau horaire diffère de celui du serveur, un rapport planifié et un filtre à l'écran utilisant la même date peuvent renvoyer des lignes légèrement différentes. Les exports lancés depuis un tableau filtré dans l'interface ne sont pas concernés — ils utilisent votre fuseau horaire, correspondant à ce que vous consultiez.

## Comment les filtres numériques sont évalués

Les filtres numériques — dont **Age** et **SLA** — proposent un opérateur de correspondance en plus de la valeur : **Equals**, **Not Equals**, **Greater Than**, **Greater Than or Equal To**, **Less Than**, **Less Than or Equal To**, **In List**, et **Not In List**. Saisir une valeur sans choisir d'opérateur applique une correspondance **Equals**.

## Filtres SLA

Trois filtres couvrent le SLA, et répondent à des questions différentes :

| Filtre | Type | Ce qu'il filtre |
| --- | --- | --- |
| **SLA Expiration Date** | Date, avec les opérateurs ci-dessus | La date à laquelle le SLA de la Constatation expire. |
| **SLA** | Nombre, avec opérateurs | **Nombre de jours restants** sur le compteur du SLA. Les valeurs négatives indiquent un retard ; ainsi `Less Than 0` trouve tout ce qui a actuellement dépassé son échéance, et `Less Than 7` trouve ce qui arrive à échéance dans la semaine. |
| **Mitigated Within SLA** | True / False | Indique si une Constatation qui **a été atténuée** l'a été avant l'expiration de son SLA. |

**Mitigated Within SLA est plus restrictif qu'il n'y paraît, et cela piège souvent les utilisateurs.** Les deux valeurs ne correspondent qu'aux Constatations **déjà atténuées** et qui ne sont **pas de sévérité Info** :

* **True** — atténuée à la date d'expiration du SLA ou avant.
* **False** — atténuée après la date d'expiration du SLA.

Une Constatation **ouverte** déjà en retard ne correspond à **aucune** des deux valeurs, car elle n'a pas encore été atténuée. Pour trouver ces cas, utilisez plutôt **SLA** `Less Than 0`. Les Constatations de sévérité Info sont exclues des deux côtés.

> Si la configuration du SLA d'une Constatation a l'option **Cap SLA by CISA KEV Due Date** activée, **SLA** et **SLA Expiration Date** reflètent l'échéance resserrée et plafonnée par le KEV, plutôt que la simple fenêtre basée sur la sévérité. Il n'existe aucun indicateur distinct pour cela dans les filtres — voir [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/).

## Constatations
Ces champs sont spécifiques aux Constatations DefectDojo et servent à organiser une Constatation.  Chacun de ces filtres correspond à une colonne distincte dans le tableau All Findings.

Les Constatations dans DefectDojo peuvent être filtrées par :

### Métadonnées DefectDojo
Ces filtres sont directement liés aux fonctionnalités principales de DefectDojo.

##### Ne peuvent pas être modifiés
Ces filtres sont attribués au moment de la création du problème, et ne peuvent pas être modifiés directement via Edit Finding.

* Sévérité de la Constatation (Info, Faible, Moyenne, Élevée ou Critique)
* Produit
* Type de produit
* Engagement
* Version de l'Engagement
* Test
* Type de Test
* Version du Test
* Date Created
* Age (âge de la Constatation en jours)
* SLA (jours restants sur le compteur du SLA — une valeur négative signifie un retard ; voir [Filtres SLA](#sla-filters))
* SLA Expiration Date (voir [Filtres SLA](#sla-filters))
* Mitigated Within SLA (True ou False — notez que cela ne correspond qu'aux Constatations déjà Atténuées ; voir [Filtres SLA](#sla-filters))
* Reporter (utilisateur ou service ayant créé la Constatation)
* Found by (fait référence à l'outil)

##### Peuvent être modifiés
Ces champs sont définis à la création d'un problème, mais peuvent être modifiés au fur et à mesure de son avancement.

* [Status](/triage_findings/findings_workflows/finding_status_definitions/)
* Last Status Update (horodatage)
* Mitigated (True ou False)

##### Fonctions de modèle supplémentaires
Ces fonctions de DefectDojo permettent d'organiser davantage vos Constatations ou de suivre la remédiation.

* Étiquettes de la Constatation
* Reviewers (Utilisateur assigné)
* Has Notes (True/False)
* Group (fait référence au [Groupe de Constatations](/triage_findings/findings_workflows/editing_findings/#finding-group-actions), s'il en existe un)
* Risk Acceptance (sélectionnez une ou plusieurs Acceptations du risque existantes dans la liste)

### Métadonnées spécifiques à l'outil
Ces champs n'ont pas d'impact direct sur les fonctionnalités de DefectDojo, mais fournissent des informations supplémentaires pour aider à expliquer et à corriger les problèmes.  Ils peuvent être définis lors de la création initiale d'une Constatation (à partir des informations d'un rapport entrant), ou modifiés par un utilisateur.

* CWE Value
* Vulnerability ID (généralement un CVE)
* EPSS Score
* EPSS Percentile
* Service
* Planned Remediation Date
* Planned Remediation Version
* Has Component (True/False)
* Component Name
* Component Version
* File Path
* Effort for Fixing

### Métadonnées Jira
Si vous utilisez l'intégration Jira, ces filtres suivent les mises à jour des tickets Jira liés.

* Jira Issue (permet de filtrer selon qu'un ticket Jira est associé à la Constatation ou non)
* Jira Age (ancienneté du ticket Jira)
* Jira Change (dernière fois que des modifications ont été envoyées vers Jira)
