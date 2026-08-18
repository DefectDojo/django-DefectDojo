---
title: Exécutions
description: Comment une règle s'exécute, ce qu'une exécution enregistre, et comment
  l'enchaînement est limité
weight: 4
audience: pro
aliases:
- /fr/automation/rules_engine_v2/runs/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : le Moteur de règles 2.0 est une fonctionnalité réservée à DefectDojo Pro.</span>

Une **exécution** correspond à un déclenchement d'une règle. Chaque exécution est enregistrée, qu'elle ait réussi ou échoué, et chaque nœud qui la compose laisse une trace. **Moteur de règles 2.0 > Exécutions** les répertorie.

## Ce qu'une exécution enregistre

| Field | Meaning |
|-------|---------|
| **Règle** | La règle qui a été exécutée. |
| **Déclencheur** | L'événement qui l'a démarrée, par exemple `finding.created`, `schedule` ou `manual`. |
| **Déclenchée par** | La personne à l'origine du déclenchement, quand une personne en est à l'origine : celle qui a cliqué sur Exécuter, ou celle qui a enregistré la Constatation qui l'a déclenchée. Vide pour une planification, et pour un changement effectué sans intervention humaine, comme un import ou un appel API sans utilisateur. Ceci est distinct du propriétaire de la règle, qui est l'identité **au nom de laquelle** l'exécution s'est déroulée. |
| **Statut** | `Running`, `Success` ou `Error`. |
| **Démarrée** et **Terminée** | Quand elle s'est exécutée. Terminée reste vide uniquement tant qu'elle est encore en cours. |
| **Erreur** | L'erreur qui y a mis fin, en cas d'échec. |
| **Statistiques** | Totaux par nœud, événements enchaînés et travail différé. |
| **Profondeur** | Le nombre de sauts d'enchaînement séparant cette exécution de l'événement d'origine. |
| **Exécution source** | L'exécution dont l'événement émis a déclenché celle-ci, dans le cas d'une exécution enchaînée. |

### La trace des nœuds

Au sein d'une exécution, chaque nœud enregistre sa propre ligne :

| Field | Meaning |
|-------|---------|
| **Ordre** | La position du nœud dans l'ordre d'exécution. |
| **Nœud** | Son identifiant, son type, et son libellé si vous lui en avez donné un. |
| **Statut** | Si le nœud s'est terminé normalement ou a levé une erreur. |
| **Éléments entrants** | Le nombre d'éléments entrés. |
| **Éléments sortants** | Le nombre d'éléments sortis, ventilé par sortie, de sorte qu'un nœud If / Filter affiche séparément ses décomptes vrai et faux. |
| **Résumé** | Les compteurs rapportés par le nœud, par exemple le nombre de Constatations qu'il a modifiées. |
| **Erreur** | L'erreur levée, en cas d'échec. |

La trace est ce que vous consultez lorsqu'une règle n'a pas fait ce que vous attendiez. Un nœud If / Filter signalant 400 éléments entrants et 0 vers la branche vraie vous indique que les conditions sont erronées, sans que vous ayez à le deviner.

## Modèle d'exécution

Les nœuds s'exécutent dans un ordre topologique : un nœud s'exécute une fois que tout ce qui l'alimente s'est exécuté. Un nœud possédant plusieurs arêtes entrantes reçoit l'ensemble de leurs sorties concaténées. Un nœud sans rien qui l'alimente s'exécute quand même, avec une liste d'entrée vide.

### Une exécution échouée ne change rien

Une exécution est atomique. Si un nœud lève une erreur, chaque modification de Constatation effectuée par l'exécution est annulée.

La trace, elle, n'est pas annulée. Les lignes des nœuds et le statut `Error` sont écrits après coup, si bien qu'une exécution échouée vous indique exactement quel nœud a posé problème, sans laisser de modifications partiellement appliquées. C'est la garantie la plus importante à garder à l'esprit en lisant la page Exécutions : une exécution en erreur est une exécution qui n'a rien fait.

La sortie (egress) suit la même règle. Les livraisons sont enregistrées au sein de la transaction de l'exécution et ne sont envoyées qu'une fois celle-ci validée, de sorte qu'une exécution annulée n'envoie rien.

### Une seule exécution par règle à la fois

Une règle ne peut avoir qu'une seule exécution en cours. Un second déclenchement de la même règle pendant qu'elle est encore en cours ne se produit pas en concurrence avec elle. Il attend et réessaie.

Des règles différentes s'exécutent en parallèle complet, de sorte qu'une règle lente ne bloque jamais les autres.

Si une exécution se retrouve abandonnée, par exemple parce que le worker qui l'exécutait a été tué, son verrou est libéré après une fenêtre d'inactivité (30 minutes par défaut) afin que la règle ne reste pas bloquée indéfiniment. Une exécution qui approche de cette fenêtre s'arrête elle-même en premier, en se désengageant proprement, de sorte qu'une exécution simplement lente ne peut jamais finir par s'exécuter en même temps que son propre remplacement.

## Enchaînement

Une règle qui modifie une Constatation produit exactement le type d'événement sur lequel une autre règle peut se déclencher. Le Moteur de règles 2.0 l'autorise, de sorte que des chaînes `A -> B -> C` fonctionnent, et le limite de deux façons indépendantes :

* **Profondeur.** Un événement peut parcourir au maximum **3** sauts d'enchaînement depuis le changement qui l'a produit.
* **Appartenance à la chaîne.** Chaque événement porte la liste des règles déjà traversées dans sa chaîne, et une règle ne s'exécute jamais deux fois dans la même chaîne. Une règle ne peut donc pas se redéclencher elle-même, et deux règles ne peuvent pas se relancer mutuellement en boucle.

Les champs **Profondeur** et **Exécution source** d'une exécution permettent de remonter une chaîne jusqu'au changement qui l'a déclenchée. **Déclenchée par** est propagé tout au long de la chaîne, de sorte qu'un enchaînement déclenché par une personne lui reste attribuable à chaque saut.

Les changements effectués *par* une règle en cours d'exécution sont attribués à l'enchaînement propre de cette règle plutôt que de ressembler à une nouvelle activité utilisateur, de sorte qu'une règle déléguant du travail en interne ne gonfle pas la chaîne.

## Échelle et limites

**Une exécution n'est pas plafonnée.** Une règle traite tout ce que son périmètre couvre, quelle que soit son ampleur. Une règle qui s'arrêterait silencieusement aux N premières Constatations serait une règle à laquelle on ne pourrait pas faire confiance.

À la place, une exécution est traitée par **lots**, 1 000 Constatations à la fois par défaut. Seul le lot est conservé en mémoire, de sorte qu'un balayage sur un très large périmètre est borné en mémoire plutôt qu'en couverture. La seule exception est **Aperçu**, qui plafonne bel et bien, et l'indique dans sa trace lorsqu'il tronque.

Deux autres nombres déterminent la façon dont le travail est réparti :

* **Constatations par événement**, 500 par défaut. Un changement en masse est réparti sur plusieurs événements, chacun devenant sa propre exécution. L'effet pratique pour un import volumineux est un nombre gérable d'exécutions plutôt qu'une exécution par Constatation.
* **Plafond d'envoi par Constatation**, 1 000 par défaut. Un nœud de sortie configuré pour envoyer un message par Constatation s'arrête à ce nombre au sein d'une même exécution et enregistre un rejet visible indiquant combien de Constatations n'ont pas fait l'objet d'un envoi. Cela borne les lignes de livraison et les tâches en file d'attente, que le traitement par lots ne borne plus à lui seul.

Ces trois paramètres sont des réglages de déploiement, documentés dans [Configuration](../configuration/).

### Combien de temps une exécution peut durer

Une exécution horodate un **signal de vie** (heartbeat) après chaque lot. La détection de blocage lit ce signal de vie plutôt que l'heure de démarrage, de sorte qu'un long balayage encore en progression n'est jamais confondu avec un worker planté.

Deux fenêtres s'appliquent, toutes deux configurables :

* Une exécution qui reste 30 minutes sans signal de vie est considérée comme abandonnée, passe en erreur, et son verrou est libéré.
* Une exécution est purement et simplement arrêtée au bout de six heures, en garde-fou contre une exécution qui ne se terminerait jamais.

## Rétention

Les exécutions sont conservées **180 jours** par défaut, ainsi que leurs lignes par nœud et leur provenance de Constatation. Les livraisons sont conservées 180 jours séparément.

Le produit vous l'indique plutôt que de le laisser implicite : le détail d'une exécution affiche la fenêtre de rétention et la date à laquelle cette exécution sera supprimée. Une exécution qui détient encore des livraisons est conservée jusqu'à ce que celles-ci soient purgées.

Les deux fenêtres sont configurables, et chacune peut être réglée pour conserver les enregistrements indéfiniment. Voir [Configuration](../configuration/#retention).

## Exécuter une règle manuellement

Une règle dont le déclencheur est **Exécution manuelle** s'exécute via l'action **Exécuter** sur la liste des règles. Les règles ayant d'autres déclencheurs s'exécutent quand leur déclencheur se produit.

**Aperçu**, dans l'éditeur, est l'autre façon d'exécuter un graphe. Il fait tourner le véritable moteur puis annule tout, n'enregistre aucune exécution, et force la sortie à simuler. Utilisez l'aperçu pendant la construction, et les exécutions pour voir ce qui s'est réellement passé.

## Provenance sur une Constatation

Les exécutions répondent à la question « qu'a fait cette règle ? ». La provenance répond à la question inverse : « pourquoi cette Constatation a-t-elle changé ? ».

Chaque changement effectué par une règle est enregistré sur la Constatation avec la règle, l'exécution et le nœud responsables, et apparaît sous forme de chronologie sur la Constatation elle-même. Les actions enregistrées sont :

| Action | Meaning |
|--------|---------|
| `created`, `updated`, `closed`, `reopened` | Le cycle de vie de la Constatation a changé. |
| `duplicate`, `status_change` | Ses indicateurs de doublon ou de statut ont changé. |
| `notified` | Une notification a été envoyée à son sujet. |
| `delivered` | Une livraison sortante l'a couverte. |

Les modifications de champs enregistrent ce qui a changé, y compris la valeur avant et après de chaque champ. Les valeurs très longues sont tronquées dans l'enregistrement, de sorte que la chronologie reste un historique du changement plutôt qu'une seconde copie de la Constatation.

Les notifications et les livraisons sont également enregistrées ici. C'est voulu : une règle qui envoie un message sans modifier aucun champ ne laisserait sinon aucune trace sur la Constatation.

La provenance survit à la règle. La suppression d'une règle ou d'une exécution conserve les entrées de la chronologie et se contente de les dissocier, de sorte que l'historique ne disparaît pas lorsque quelqu'un fait du ménage.

## Supprimer des règles ayant un historique

Une règle ayant produit des livraisons ne peut pas être supprimée tant que celles-ci existent encore. Supprimez d'abord les livraisons, ou conservez la règle et désactivez-la. C'est intentionnel : les livraisons conservent la trace de ce qui a réellement été envoyé aux systèmes externes, et une suppression en cascade emporterait avec elle les envois en cours.
