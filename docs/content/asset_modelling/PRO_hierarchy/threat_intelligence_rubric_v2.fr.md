---
title: "Renseignement sur les menaces : score fondé sur les preuves (Rubric v2)"
description: "Comment les preuves d'exploitation vérifiées alimenteront le plancher de Priorité du renseignement sur les menaces"
weight: 3
audience: pro
---

> **Pas encore disponible.** Cette page décrit une fonctionnalité en cours de développement. Elle
> ne figure pas sur la page **Feature Flags** et ne peut pas encore être activée, ni sur
> DefectDojo Cloud ni sur une instance auto-hébergée. Aujourd'hui, chaque constatation est notée
> comme décrit dans [Renseignement sur les menaces](../threat_intelligence/).

Le [renseignement sur les menaces](../threat_intelligence/#comment-cela-modifie-le-calcul-du-score)
transforme les preuves d'exploit en un **plancher** sur l'échelle EPSS : le score externe d'une
constatation est au moins égal au plancher qu'atteint sa preuve la plus forte. Le tableau des
planchers s'appelle la **grille** (rubric). Rubric v2 en est la prochaine version. Elle conserve la
valeur de chaque plancher et ajoute un type de preuve : **les signalements d'exploitation que les
analystes de DefectDojo ont examinés et confirmés**.

## Ce qui change

| Preuve | Plancher de Priorité (équivalent EPSS) |
|---|---|
| Preuve d'exploitation confirmée **et** un acteur de menace confirmé et nommé derrière elle (nouveau) | 45% |
| Dans CISA KEV **et** utilisé dans un ransomware | 30% |
| Dans KEV, exploité en conditions réelles ou **toute preuve d'exploitation confirmée**, y compris une observation de canary confirmée (nouveau) | 20% |
| Exploit public armé (Metasploit / Exploit-DB) | 15% |
| Un modèle de détection Nuclei existe | 12% |
| Preuve de concept publique uniquement | 8% |
| Aucune preuve d'exploit | aucun changement |

Les planchers gardent les mêmes valeurs qu'aujourd'hui, et le score externe de la constatation reste
la valeur la plus élevée entre sa valeur dérivée de l'EPSS et son plancher le plus haut : la grille
ne fait donc jamais qu'augmenter un score.

En pratique :

- **Davantage de constatations atteignent le plancher « exploitation connue ».** Un CVE absent de
  CISA KEV mais pour lequel il existe une preuve d'exploitation vérifiée (un rapport d'incident, un
  avis d'éditeur qui l'indique, une observation de honeypot ou de canary) reçoit le même plancher de
  20% qu'une inscription au KEV.
- **Le plancher le plus haut devient atteignable.** Avec Rubric v1, le plancher de 45% exigeait une
  télémétrie d'éditeur que le flux ne contient pas, si bien qu'aucune constatation ne l'a jamais
  atteint. Avec Rubric v2, il est atteint par une preuve confirmée derrière laquelle se trouve un
  acteur de menace confirmé et nommé, et par rien de moins.
- **Rien ne s'affaiblit.** Sans preuve vérifiée, une vulnérabilité est notée exactement comme
  aujourd'hui. Une inscription au KEV avec utilisation dans un ransomware reste à 30% : l'indicateur
  ransomware de la CISA ne nomme aucun acteur.

Ce qui **n'augmente pas** un plancher : un signalement non vérifié ou rejeté, une preuve de concept à
elle seule et l'indicateur « exploit disponible » d'un scanner ou d'un éditeur (ils restent affichés
comme aujourd'hui et ne comptent pas comme preuve).

## Avant l'activation

Passer une instance à Rubric v2 peut augmenter la Priorité de certaines constatations ; DefectDojo
mesure donc le passage avant de l'effectuer : pour chaque instance, combien de constatations
passeraient de quel plancher à quel autre et, pour chaque passage, les vulnérabilités derrière le
plus grand nombre de constatations. Vos priorités actuelles restent sur Rubric v1 jusqu'à la
publication de Rubric v2.
