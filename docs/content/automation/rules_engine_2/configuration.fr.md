---
title: Configuration
description: Paramètres au niveau du déploiement pour Rules Engine 2.0
weight: 7
audience: pro
aliases:
- /fr/automation/rules_engine_v2/configuration/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Rules Engine 2.0 est une fonctionnalité réservée à DefectDojo Pro.</span>

Rules Engine 2.0 fonctionne dès l'installation. Les paramètres de cette page s'adressent aux déploiements qui ont besoin d'ajuster le débit, la rétention ou la politique réseau sortante. Ils s'appliquent tous de la même manière que n'importe quel autre paramètre DefectDojo (voir [Configuration](/get_started/open_source/configuration/)).

Rules Engine 2.0 se configure séparément du Rules Engine d'origine. Les deux moteurs ne partagent aucun réglage : un paramètre `DD_RULES_ENGINE_*` n'affecte pas Rules Engine 2.0, et un paramètre `DD_RULES_V2_*` n'affecte pas le moteur d'origine.

```python
DD_RULES_V2_EVENT_BATCH=(int, 500),
DD_RULES_V2_CHUNK_SIZE=(int, 1000),
DD_RULES_V2_STALLED_AFTER_MINUTES=(int, 30),
DD_RULES_V2_RUN_TIME_LIMIT_MINUTES=(int, 360),
DD_RULES_V2_ALLOW_PRIVATE_EGRESS=(bool, False),
DD_RULES_V2_DELIVERY_RETENTION_DAYS=(int, 180),
DD_RULES_V2_RUN_RETENTION_DAYS=(int, 180),
DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS=(int, 8000),
DD_RULES_V2_MAX_PER_ITEM_SENDS=(int, 1000),
```

## Débit

### Constatations par événement (`DD_RULES_V2_EVENT_BATCH`)

**Par défaut : 500.**

Le nombre d'identifiants de Constatation qu'un seul événement transporte. Les événements traversent une frontière asynchrone, ils sont donc gardés assez petits pour rester un message peu coûteux. Une écriture plus importante se répartit en plusieurs événements, chacun devenant sa propre exécution.

Augmenter cette valeur produit des exécutions moins nombreuses mais plus volumineuses. La diminuer en produit davantage, mais plus petites.

### Constatations par lot (`DD_RULES_V2_CHUNK_SIZE`)

**Par défaut : 1000.**

Le nombre de Constatations qu'une exécution conserve en mémoire à la fois. Une exécution est traitée par lots, il s'agit donc d'un réglage de mémoire et **non** d'un plafond sur ce qu'une règle traite : une règle traite toujours tout ce que son périmètre couvre.

Une enveloppe pèse environ 2,7 Ko par Constatation, de sorte que la valeur par défaut occupe quelques mégaoctets à la fois. L'augmenter échange de la mémoire contre moins d'allers-retours. La diminuer fait l'inverse.

### Plafond de texte de l'enveloppe (`DD_RULES_V2_ENVELOPE_TEXT_MAX_CHARS`)

**Par défaut : 8000. Réglez sur 0 pour désactiver.**

Le nombre de caractères de `description`, `mitigation` et `impact` qu'un élément transporte.

Ces trois champs représentent l'essentiel de la taille d'une enveloppe. Le plafond existe pour le cas inhabituel d'une Constatation à la description très longue, où un lot complet de celles-ci serait bien plus volumineux que ce que suggère la taille du lot. Il est suffisamment généreux pour qu'une instance ordinaire ne le remarque jamais.

Notez que cela affecte ce que les conditions et les modèles peuvent voir. Une condition portant sur la fin d'une description très longue ne verra pas le texte au-delà du plafond.

## Durée de vie de l'exécution

### Fenêtre de blocage (`DD_RULES_V2_STALLED_AFTER_MINUTES`)

**Par défaut : 30.**

Le temps qu'une exécution peut rester sans pulsation avant d'être considérée comme abandonnée, marquée en erreur, et son verrou par règle libéré.

Une exécution émet une pulsation après chaque lot ; cette mesure part donc de la dernière pulsation plutôt que du début. Un long balayage encore en progression n'est ainsi jamais confondu avec un worker planté, ce qui permet à la fenêtre de rester courte.

### Limite de temps d'exécution (`DD_RULES_V2_RUN_TIME_LIMIT_MINUTES`)

**Par défaut : 360, soit six heures.**

La durée maximale qu'une exécution unique peut prendre avant que le worker ne la termine de force.

Il s'agit d'une protection contre une règle qui ne se terminerait jamais tout en occupant un emplacement de worker et le verrou d'exécution de sa règle. Elle est délibérément généreuse, car un balayage par lots sur un périmètre très large est précisément le type de charge de travail pour lequel ce moteur est conçu.

## Rétention

Deux tâches limitent les trois tables que cette fonctionnalité fait grossir. Les deux ont par défaut **180 jours**, et les deux acceptent `0` pour désactiver totalement la purge.

La rétention est mise en avant dans le produit plutôt que laissée implicite : l'API fournit à la fois la fenêtre et la date à laquelle un enregistrement donné sera supprimé, et les pages qui affichent une exécution ou une livraison l'indiquent en une phrase. La date est calculée à la lecture, de sorte que modifier la fenêtre prend effet immédiatement plutôt que de ne s'appliquer qu'aux nouveaux enregistrements.

### `DD_RULES_V2_DELIVERY_RETENTION_DAYS`

**Par défaut : 180.**

Le nombre de jours pendant lequel une livraison terminée est conservée.

C'est la table qui croît le plus rapidement dans cette fonctionnalité. Un nœud de sortie par Constatation écrit jusqu'à un lot entier de lignes par exécution, y compris en mode Simulate. Augmentez cette valeur si vous avez besoin d'une piste d'audit sortante plus longue, et diminuez-la si le volume pose problème.

### `DD_RULES_V2_RUN_RETENTION_DAYS`

**Par défaut : 180.**

Le nombre de jours pendant lequel une exécution terminée est conservée, avec ses lignes par nœud et sa provenance de Constatation.

Le côté exécution croît plus vite que les livraisons, car la provenance représente une ligne par Constatation, par nœud de modification, par exécution. Une règle horaire sur un large périmètre en génère beaucoup.

Une exécution qui contient encore des livraisons est conservée jusqu'à ce que celles-ci soient purgées ; définir une fenêtre d'exécution plus courte que la fenêtre de livraison n'orpheline donc rien.

## Validation de la destination sortante

Deux paramètres de nœud prennent une destination sous forme de texte libre plutôt que depuis un objet configuré : l'**URL** de Call a Webhook (Appeler un webhook), et le **To** (Destinataire) de Send an Email (Envoyer un e-mail). Les deux sont validés lors de l'enregistrement de la règle.

Pour les URL de webhook :

* Seuls `http` et `https` sont acceptés. Les autres schémas sont rejetés d'emblée.
* L'URL doit comporter un hôte.
* Par défaut, un hôte qui se résout vers une adresse loopback, link-local, privée, réservée ou multicast est rejeté.

Pour les adresses e-mail, une adresse vide est rejetée, tout comme une adresse contenant un saut de ligne, ce qui constitue une injection d'en-tête.

La raison de cette vérification réseau est que le worker qui envoie la requête se trouve généralement à l'intérieur de votre cluster et peut atteindre une bien plus grande partie du réseau interne que la personne qui rédige la règle. Sans cette vérification, une URL en texte libre est un vecteur de falsification de requête : il suffit de la pointer vers un service de métadonnées ou un port d'administration interne pour que la réponse revienne via le registre des livraisons.

Il s'agit d'une défense en profondeur plutôt que du seul contrôle. Rule Edit se rapproche de toute façon d'une permission administrative. Cela vaut la peine de l'avoir afin que le rayon d'impact d'un rôle trop généreusement accordé ne soit pas « lire n'importe quel point de terminaison HTTP interne », et pour qu'une faute de frappe échoue à l'enregistrement avec un message clair plutôt qu'à l'envoi avec une erreur de connexion.

### Autoriser les adresses privées (`DD_RULES_V2_ALLOW_PRIVATE_EGRESS`)

**Par défaut : désactivé.**

Désactive la vérification d'adresse réseau, de sorte que les webhooks peuvent envoyer vers des adresses loopback, link-local et privées. La validation du schéma et de la forme s'applique toujours.

Activez ceci si vous envoyez véritablement des webhooks vers quelque chose situé sur une adresse privée, ce qu'est normalement un récepteur de chat ou de webhook auto-hébergé.

## Plafond d'envoi par Constatation

### `DD_RULES_V2_MAX_PER_ITEM_SENDS`

**Par défaut : 1000. Réglez sur 0 pour supprimer le plafond.**

Le nombre maximal d'envois par Constatation qu'un seul nœud de sortie enregistrera au cours d'une exécution.

Un nœud avec **One Message per Finding** (Un message par Constatation) activé produit une ligne de livraison et une tâche mise en file d'attente par Constatation. Comme une exécution n'a pas de plafond d'éléments, une règle avec un périmètre très large et l'envoi par Constatation activé signifierait sinon un nombre illimité des deux.

Au-delà de ce plafond, le nœud enregistre un **saut visible** indiquant combien de Constatations n'ont pas fait l'objet d'un envoi. Cela ne fait pas échouer l'exécution, et ne s'arrête pas silencieusement.

## Paramètres associés

Certains nœuds de Rules Engine 2.0 utilisent une configuration d'intégration à l'échelle du système plutôt que la leur propre :

* **Send a Slack Message** (Envoyer un message Slack) utilise le jeton Slack du système, et se rabat sur le canal Slack du système lorsque le nœud n'en nomme aucun.
* **Send a Microsoft Teams Message** (Envoyer un message Microsoft Teams) utilise le webhook Microsoft Teams des paramètres système.
* **Create a JIRA Issue** (Créer un ticket JIRA) utilise la configuration JIRA du produit pour le résumé, la description et la priorité.
* **Raise an In-App Alert** (Déclencher une alerte dans l'application) respecte le paramètre de notification **Rules Engine Match** (Correspondance Rules Engine) propre à chaque destinataire.
