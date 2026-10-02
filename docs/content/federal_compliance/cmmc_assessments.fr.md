---
title: Évaluations CMMC de niveau 2
description: Noter une auto-évaluation par rapport à NIST 800-171 Rev 2
weight: 5
audience: pro
---

L'onglet Compliance peut noter une auto-évaluation CMMC de niveau 2 par rapport à NIST 800-171 Rev 2, en utilisant les
pondérations de points de la DoD Assessment Methodology.

![A CMMC Level 2 assessment scorecard](images/05-cmmc-scorecard.png)

**Bêta : considérez le score comme une estimation.** Tant que cette fonctionnalité est en bêta, les pondérations de points fournies
et le score SPRS qui en résulte sont indicatifs et en attente de validation. Vérifiez tout score par rapport à la
méthodologie d'évaluation officielle DoD NIST SP 800-171 avant de vous y fier pour une soumission d'évaluation
ou toute autre finalité contractuelle.

## Enregistrer les résultats

Enregistrez un résultat pour chacune des 110 exigences :

* **Met**
* **Not met**
* **Not applicable**
* **Planned** (sur le POA&M)

![The requirements workflow](images/06-cmmc-requirements.png)

### Crédit partiel

Quelques exigences ont une condition partielle documentée que la méthodologie note avec une déduction réduite
plutôt qu'avec le poids complet. Lorsqu'une telle condition existe, la colonne **Partial Credit** permet de le
consigner, et l'exigence déduit alors les points réduits. `3.13.11` en est l'exemple :
un chiffrement employé, mais non validé FIPS, déduit 3 points au lieu de 5.

Les exigences sans condition partielle documentée déduisent toujours leur poids complet.

## Ce que l'évaluation calcule

### Score SPRS

110 moins la déduction pour chaque exigence non satisfaite ou simplement planifiée. Les pondérations sont de 1, 3,
ou 5 points, donc les scores vont de 110 jusqu'à -203.

L'exigence 3.12.4 (l'exigence de System Security Plan) est notée non applicable, selon la
méthodologie.

### Si un statut conditionnel est possible

CMMC autorise une certification conditionnelle à partir d'un score d'au moins **88** (80 pour cent) avec chaque
écart ouvert éligible à un POA&M.

La méthodologie exclut entièrement certaines exigences des POA&M. Parmi les exigences pondérées à plus d'
un point, seule **3.13.11** (cryptographie validée FIPS) peut être différée.

### Le compte à rebours de clôture

Une évaluation conditionnelle dispose de **180 jours** pour clore ses éléments de POA&M. L'évaluation passe à
expirée si le délai est dépassé.

## Statuts

Les statuts évoluent de **in progress** à **conditional** ou **final**. Les évaluations conditionnelles affichent
le nombre de jours restants sur leur compte à rebours de clôture.

Les évaluations sont sous historique d'audit : chaque modification enregistre qui, quoi, et quand.
