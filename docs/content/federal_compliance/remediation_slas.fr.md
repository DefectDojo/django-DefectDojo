---
title: Délais de remédiation
description: Les préréglages de SLA FedRAMP Rev 5 et FedRAMP VDR
weight: 4
audience: pro
---

Deux configurations de SLA prêtes à l'emploi sont fournies avec la fonctionnalité. Attribuez l'une d'elles à vos produits depuis les paramètres de configuration des SLA, ou copiez-en une pour l'ajuster.

## FedRAMP Rev 5

| Sévérité | Échéance |
| --- | --- |
| Critique | 30 jours à compter de la découverte |
| Élevée | 30 jours à compter de la découverte |
| Modérée | 90 jours |
| Faible | 180 jours |

Les échéances sont appliquées de manière stricte, et une constatation figurant dans le catalogue CISA KEV n'est jamais planifiée au-delà de sa date d'échéance CISA.

## FedRAMP VDR

Les mêmes fenêtres de base, encore resserrées en fonction de l'exploitabilité et de l'exposition :

| Condition | Échéance |
| --- | --- |
| Exploitabilité crédible **et** accessible depuis Internet | 4 jours |
| Exploitabilité crédible uniquement | 14 jours |
| Accessible depuis Internet uniquement | 30 jours |
| Ni l'un ni l'autre | Les fenêtres FedRAMP Rev 5 ci-dessus |

**Exploitabilité crédible** signifie que la constatation figure dans la liste KEV, ou que son score EPSS est égal ou supérieur à votre seuil. **Accessible depuis Internet** est signalé par une étiquette de constatation — `internet-reachable` par défaut.

Tous les seuils, noms d'étiquettes et nombres de jours sont modifiables dans la configuration du SLA.

**FedRAMP VDR devient obligatoire le 7 décembre 2026.** La norme Vulnerability Detection and Response de FedRAMP devient obligatoire pour les fournisseurs de services cloud à cette date. Il est recommandé d'adopter le préréglage VDR avant cette échéance.

## Relation avec le registre

Les échéances de SLA déterminent les dates d'achèvement planifiées des éléments POA&M, et déterminent quels éléments sont comptabilisés comme en retard dans les métriques mois par mois d'un instantané. Elles décident également de ce qu'inclut une politique d'éléments d'analyse **past-due-only** — voir [Profil de conformité](../compliance_profile).

Pour savoir comment la priorité et les SLA fonctionnent en dehors d'un contexte fédéral, voir [Attribuer la priorité, le risque et les SLA](/asset_modelling/pro_hierarchy/priority_sla/).
