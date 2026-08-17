---
title: Livraisons
description: Le registre de tout ce que les règles envoient vers l'extérieur, ainsi
  que le fonctionnement des nouvelles tentatives et de la relecture
weight: 5
audience: pro
aliases:
- /fr/automation/rules_engine_v2/deliveries/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Rules Engine 2.0 est une fonctionnalité réservée à DefectDojo Pro.</span>

Chaque effet secondaire sortant produit par une règle correspond à une ligne du registre des livraisons. **Rules Engine 2.0 > Livraisons** les répertorie.

La ligne est écrite **avant** tout appel réseau, et elle contient exactement ce qui sera, ou a été, envoyé. C'est ce qui rend les envois sortants auditables plutôt qu'une ligne de journal que l'on espère avoir conservée, et c'est pourquoi **Simulate** n'est pas un chemin de code distinct : un envoi simulé correspond à la même ligne, l'étape de dispatch étant simplement ignorée.

## Ce qu'une livraison enregistre

| Champ | Signification |
|-------|---------|
| **Exécution** et **Nœud** | L'exécution et le nœud de sortie qui l'ont produite. |
| **Constatation** | La Constatation concernée, pour un envoi par Constatation. Les envois groupés enregistrent le groupe à la place. |
| **Canal** | Le type d'envoi. |
| **Cible** | La destination résolue : une clé de projet JIRA, un canal, une URL, une adresse. |
| **Titre** | Une description en une ligne de l'envoi. |
| **Payload** | Exactement ce qui sera, ou a été, envoyé. |
| **Mode** | `simulate` ou `live`. |
| **Statut** | Où en est la livraison. |
| **Tentatives** | Le nombre d'envois déjà tentés, par rapport au maximum autorisé. |
| **Dernière erreur** | La raison de l'échec de la dernière tentative, ou de l'omission de la livraison. |
| **Réponse** | Ce que la destination a répondu. |
| **Référence externe** et **URL** | La clé de ticket, l'identifiant de message ou le chemin de fichier renvoyé par la destination, ainsi qu'un lien vers celui-ci lorsqu'il existe. |

## Canaux

| Canal | Produit par |
|---------|-------------|
| **JIRA** | Créer un ticket JIRA |
| **Downstream connector** | Créer un ticket en aval |
| **Slack** | Envoyer un message Slack, ainsi que les annonces de rapports envoyées vers Slack |
| **Microsoft Teams** | Envoyer un message Microsoft Teams |
| **Email** | Envoyer un e-mail, ainsi que les annonces de rapports envoyées par e-mail |
| **Webhook** | Appeler un webhook |
| **Rapport** | Générer un rapport |
| **In-app alert** | Déclencher une alerte intégrée |

## Statuts

| Statut | Signification |
|--------|---------|
| `simulated` | La règle était en mode Simulate. Rien n'a été envoyé, et rien ne le sera jamais. |
| `skipped` | Un élément couvrait déjà cet envoi, ou le filtrage l'a refusé. La raison figure dans le champ Dernière erreur. |
| `pending` | Enregistrée en mode Live, en attente de sa tâche de livraison. |
| `dispatched` | Transmise au service d'intégration, en attente de confirmation. |
| `sent` | Livraison confirmée. |
| `failed` | Rejetée définitivement, par exemple une erreur 4xx ou une erreur du fournisseur. Peut être rejouée. |
| `dead` | Nouvelles tentatives épuisées, ou aucune confirmation n'est jamais arrivée. Peut être rejouée. |

`skipped` mérite qu'on s'y attarde. Les omissions sont enregistrées plutôt que silencieuses, car « la règle n'a rien fait » et « la règle n'a rien fait parce que cette Constatation avait déjà un ticket » sont deux réponses différentes, et une seule d'entre elles pose problème.

Il existe trois raisons courantes à une omission, et le champ Dernière erreur indique toujours laquelle :

* **Idempotence.** Un élément couvrait déjà cet envoi.
* **Le canal est désactivé.** Une règle comportant un nœud Slack sur une instance où Slack est désactivé enregistre une omission l'expliquant, plutôt que d'échouer. Une règle enregistrée alors qu'un canal était actif ne doit pas se mettre à générer des erreurs quand quelqu'un le désactive. Voir [disponibilité des nœuds](../node_reference/#when-a-channel-is-unavailable).
* **Le plafond d'envoi par Constatation a été atteint.** Un nœud envoyant un message par Constatation s'arrête par défaut après 1 000 envois au cours d'une même exécution, et enregistre le nombre de Constatations pour lesquelles il n'a pas envoyé de message.

### Fidélité du payload

Le registre indique honnêtement à quel point le payload enregistré est proche du corps réel envoyé sur le réseau, car cela varie selon le canal.

| Fidélité | Signification |
|----------|---------|
| `exact` | Équivalent, octet pour octet, à ce qui a été envoyé. |
| `rendered` | Généré par les mêmes fonctions d'assistance réelles, mais le filtrage au moment de l'envoi peut encore le réduire. |
| `dojo request` | La requête exacte transmise au service d'intégration. Le payload propre au fournisseur est composé en aval. |
| `summary` | Une description de l'envoi plutôt qu'une reproduction de celui-ci. Un rapport généré en est l'exemple : le fichier est construit à partir de données en direct au moment de l'envoi, si bien qu'une copie stockée serait erronée dès que quelque chose changerait. |

## La protection contre les doubles envois

Une seule livraison **active** peut exister par clé d'idempotence, ce qui est imposé au niveau de la base de données plutôt que par convention. Active signifie `pending`, `dispatched` ou `sent`.

Un second envoi qui entrerait en collision avec un envoi actif devient une ligne `skipped` dont la raison est enregistrée. Ce n'est jamais une absence d'action silencieuse, et ce n'est jamais un ticket en double.

Comme les lignes `simulated`, `skipped`, `failed` et `dead` ne détiennent pas de réservation, une livraison échouée peut être rejouée sur place sans qu'une seconde ligne n'entre en conflit avec elle pour la même clé.

## Nouvelles tentatives

Une livraison en mode Live fait l'objet de nouvelles tentatives automatiques. Chaque ligne porte son propre compteur de tentatives et son propre plafond, six tentatives par défaut, de sorte qu'une destination défaillante ne peut pas entraîner ses voisines dans sa chute. Les nouvelles tentatives s'espacent progressivement entre chaque essai.

Une fois la dernière tentative épuisée, la ligne est marquée `dead` plutôt que laissée à l'état `pending`. L'épuisement des tentatives est visible, pas silencieux.

Si un worker est interrompu en pleine transmission, le message est redélivré. La ligne est verrouillée et son statut est revérifié avant tout nouvel envoi, de sorte qu'une redélivrance ne peut pas se transformer en double envoi.

Les livraisons transmises au service d'intégration passent à l'état `dispatched` et attendent un rappel de confirmation. Si aucun rappel n'arrive dans un délai de six heures, la ligne est marquée `dead` afin de pouvoir être rejouée. Ce délai est délibérément généreux : une file d'attente en aval accumulant du retard pendant une heure est normal, et enterrer une ligne trop rapidement transformerait une relecture en ticket en double.

## Rejouer une livraison

Une livraison `failed` ou `dead` peut être renvoyée depuis la page Livraisons. Le registre enregistre quand elle a été rejouée et par qui.

La relecture nécessite la permission **Rule Edit**.

La relecture renvoie le payload enregistré. Pour un rapport, cela régénère le rapport à partir des données actuelles, car le payload est une description de ce qu'il faut générer plutôt que le fichier lui-même.

## Simulate

En mode Simulate, chaque nœud de sortie écrit sa ligne de livraison avec le statut `simulated`, le payload complet et la cible résolue, puis s'arrête. Aucun dispatch n'est enregistré, si bien que rien ne peut être envoyé plus tard, quelle que soit la façon dont l'exécution se déroule. Preview se comporte de la même manière, et n'insère même pas les lignes.

C'est la manière prévue de revoir une règle avant de la mettre en production : l'activer en mode Simulate, la laisser s'exécuter sur des Constatations réelles, puis lire les payloads qu'elle a enregistrés.

Gardez à l'esprit que Simulate ne retient **que** les envois sortants. Les nœuds de type Constatations continuent de modifier les Constatations.

## Rétention

Les livraisons sont conservées **180 jours** par défaut, après quoi une tâche de rétention les supprime.

C'est la table qui croît le plus rapidement dans cette fonctionnalité, car un nœud envoyant un message par Constatation écrit une ligne par Constatation, aussi bien en mode Simulate qu'en mode Live. La valeur par défaut est une véritable fenêtre plutôt que « tout conserver », afin que cette croissance ne devienne pas discrètement votre problème.

Vous en êtes informé plutôt que d'avoir à le découvrir. Le détail d'une livraison affiche la fenêtre de rétention et la date à laquelle cette ligne sera supprimée, et cette date est recalculée à chaque lecture, de sorte que la modification de la fenêtre prend effet immédiatement.

Allongez la fenêtre si vous avez besoin d'une piste d'audit sortante plus longue, ou réglez-la sur `0` pour tout conserver. Voir [Configuration](../configuration/#retention).
