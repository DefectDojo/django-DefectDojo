---
title: Atteignabilité
description: Comment DefectDojo Pro enregistre si le code vulnérable d'une Constatation
  est réellement atteignable, et comment ce verdict ajuste la priorité
audience: pro
weight: 3
---

Un CVE Critique présent dans du code que votre application n'appelle jamais ne représente pas le même risque que
ce même CVE situé sur un chemin de requête actif. **L'Atteignabilité** capture cette
différence : DefectDojo Pro enregistre si le code vulnérable de chaque Constatation peut
réellement être atteint, indique d'où provient cette conclusion, et l'intègre au calcul
de la **priorité** de la Constatation.

L'Atteignabilité est une fonctionnalité en **bêta** et est **désactivée par défaut**. Un superutilisateur
l'active dans **Settings > Feature Flags**. Tant qu'elle est désactivée, aucun verdict n'est
enregistré, la priorité n'est pas affectée, et aucune interface liée à l'atteignabilité n'apparaît.

## Verdicts

Chaque verdict est normalisé selon les cinq mêmes valeurs, quel que soit l'outil qui l'a produit :

| Verdict | Meaning |
|---|---|
| **Atteignable (exécution)** | Le code vulnérable a été observé en cours d'exécution. |
| **Atteignable (statique)** | Un chemin d'appel vers le code vulnérable existe depuis un point d'entrée de l'application. |
| **Potentiellement atteignable** | Preuve partielle — par exemple le paquet vulnérable est utilisé, mais la fonction spécifique n'a pas pu être confirmée. |
| **Inatteignable** | L'analyse n'a trouvé aucun chemin vers le code vulnérable. |
| **Inconnu** | Aucune analyse d'atteignabilité ne couvre encore cette Constatation. |

Cette normalisation est importante car les outils ne s'accordent pas sur le vocabulaire :
le « aucun chemin trouvé » d'un scanner et le « non utilisé » d'un autre ne signifient pas
la même chose, et DefectDojo enregistre les deux comme des verdicts comparables plutôt que
de les réduire à un simple oui/non.

## Les règles que suit l'atteignabilité

Ces comportements sont délibérés et ne varient pas d'un outil à l'autre :

- **Inconnu ne pénalise jamais une Constatation.** La plupart des instances démarrent avec
  une couverture d'atteignabilité faible ou nulle. Une Constatation qu'aucun outil n'a
  analysée est notée exactement comme elle le serait avec la fonctionnalité désactivée.
- **Inatteignable abaisse la priorité. Cela ne clôture jamais une Constatation.** Un
  verdict « inatteignable » atténue le score afin que les problèmes réellement actifs soient
  classés au-dessus, mais la Constatation reste ouverte et visible. L'analyse d'atteignabilité
  n'est pas parfaite, et un verdict « inatteignable » erroné qui masquerait silencieusement un
  Critique actif serait le pire échec possible.
- **Chaque verdict indique sa source.** Aucun verdict n'apparaît sans l'outil qui l'a
  produit, son niveau de confiance, et le commit analysé lorsqu'il est connu.
- **Les verdicts suivent la déduplication.** Lorsque plusieurs scanners signalent la même
  vulnérabilité et qu'un seul d'entre eux fournit l'atteignabilité, le verdict s'applique à
  l'ensemble du groupe de doublons, afin que vous ne perdiez pas le signal en important un
  autre outil.

## D'où viennent les verdicts

Vous n'avez pas besoin d'adopter un nouveau scanner pour en tirer parti — DefectDojo lit
l'atteignabilité produite par des outils que vous utilisez peut-être déjà :

- **Les scanners qui la signalent dans leur sortie.** Plusieurs analyseurs pris en charge
  transportent l'atteignabilité, sous forme de données structurées ou dans le texte de leur
  rapport. Aucune configuration n'est requise au-delà de l'import habituel du rapport.
- **Les connecteurs.** Un connecteur qui prend en charge l'atteignabilité envoie des
  verdicts pour les produits qu'il synchronise, actualisés selon sa planification habituelle.

La couverture est normalement partielle, ce qui est attendu. Les outils qui ne signalent pas
l'atteignabilité laissent simplement leurs Constatations à **Inconnu**.

## Comment l'atteignabilité modifie la priorité

L'atteignabilité est une entrée de plus dans le score de priorité décrit dans
[Notation et priorisation](../). Les verdicts atteignables augmentent la priorité d'une
Constatation, inatteignable l'abaisse proportionnellement à la confiance de la source, et
inconnu la laisse inchangée.

L'intensité de cet ajustement est réglable par moteur de priorisation, comme tout autre
facteur : réglez le coefficient d'atteignabilité sur `0` pour enregistrer les verdicts sans
qu'ils n'affectent les scores, ou augmentez-le pour pondérer l'atteignabilité plus fortement.
Vous pouvez prévisualiser l'effet avec le simulateur de priorisation avant de l'appliquer.

Comme l'activation de l'atteignabilité modifie les scores, revoyez les seuils de risque de
votre moteur après l'avoir activée, afin que les Constatations se répartissent dans les
tranches attendues.

### Règles de risque liées à l'atteignabilité

Cet ajustement est proportionnel à la sévérité d'une Constatation, ce qui signifie qu'il ne
peut pas exprimer deux choses que vous pourriez souhaiter. Une Constatation de sévérité
Faible dont le code est confirmé atteignable ne reçoit qu'un léger bonus et reste dans une
bande basse ; un Critique signalé inatteignable peut malgré tout rester en tête de file.
Deux règles optionnelles du moteur de priorisation fixent directement une bande à la place :

- **Plancher de risque pour code atteignable** — la bande de Risque minimale pour les
  Constatations dont le code vulnérable est confirmé atteignable. Elle ne fait jamais
  qu'augmenter une bande.
- **Plafond de risque pour code inatteignable** — la bande de Risque maximale pour les
  Constatations signalées inatteignables. Elle ne fait jamais que diminuer une bande, et ne
  clôture ni ne masque jamais une Constatation ; elle se contente de plafonner son classement.

Les deux sont vides par défaut, donc rien ne change tant que vous ne les définissez pas. Le
plafond dispose également d'une **confiance minimale** : il ne s'applique que lorsque le
verdict inatteignable atteint au moins ce niveau de confiance, car plafonner une bande sur un
verdict à faible confiance est précisément la manière dont un Critique actif finit enterré.

Une Constatation dont le CVE est signalé comme activement exploité en conditions réelles
n'est jamais plafonnée — la preuve d'exploitation prime sur une simple affirmation d'absence
de chemin.

## Ce que vous voyez

**Sur une Constatation** — un badge d'atteignabilité, ainsi qu'un panneau **Sources
d'atteignabilité** listant chaque source ayant signalé un verdict, le verdict et la confiance
de chaque source, et celle qui s'applique actuellement. Lorsqu'un outil fournit un chemin
d'appel, la preuve associée est affichée avec.

**Sur la liste des Constatations** — une colonne et un filtre Atteignabilité, permettant de
construire des vues telles que « Critique et atteignable » et de les enregistrer.

**Sur un actif** — un panneau **Couverture d'atteignabilité** montrant la répartition des
verdicts pour cet actif, combien de ses Constatations portent un verdict quel qu'il soit, et
combien de Critiques ont été rétrogradés ou confirmés par l'atteignabilité. Chaque chiffre
renvoie vers les Constatations correspondantes. La part encore à Inconnu est affichée avec le
reste : elle indique la portion de l'actif sur laquelle l'atteignabilité peut actuellement se
prononcer.
