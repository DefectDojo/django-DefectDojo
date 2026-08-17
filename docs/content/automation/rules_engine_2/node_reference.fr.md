---
title: Référence des nœuds
description: Tous les nœuds fournis avec Rules Engine 2.0, et ce que fait chacun d'eux
weight: 3
audience: pro
aliases:
- /fr/automation/rules_engine_v2/node_reference/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Rules Engine 2.0 est une fonctionnalité réservée à DefectDojo Pro.</span>

Rules Engine 2.0 est fourni avec 25 nœuds répartis en quatre catégories. Cette page les documente tous.

Sauf indication contraire, un nœud reçoit une entrée, produit une sortie appelée `out`, et transmet à cette sortie chaque élément qu'il a reçu. Cela compte lorsque vous enchaînez des nœuds : un nœud de type Constatations modifie la Constatation puis transmet l'élément à la suite, de sorte que plusieurs nœuds enchaînés s'appliquent tous.

## Déclencheurs

Chaque graphe possède exactement un déclencheur, et seul un déclencheur peut démarrer une exécution. Les trois déclencheurs produisent des éléments de type Constatation, et tous trois disposent d'une **Portée** qui restreint les Constatations qu'ils produisent. Voir [Créer des règles](../building_rules/) pour savoir comment fonctionne la portée.

### Sur un événement de Constatation

`trigger.finding`

S'exécute lorsque des Constatations sont créées, mises à jour, clôturées ou rouvertes.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Événement** | `created` | Le changement de Constatation qui déclenche cette règle : `created`, `updated`, `closed`, `reopened`, ou `any` pour les quatre. |
| **Portée** | vide | Les Constatations que cette règle prend en compte. Vide signifie toutes les Constatations que le propriétaire de la règle peut voir. |

Les Constatations désignées par l'événement sont comparées à la portée avant d'entrer dans le graphe : l'événement décide *quand*, et la portée décide *lesquelles*.

### Sur une planification

`trigger.schedule`

Balaie toutes les Constatations de la portée selon une planification. Cette planification est configurée sur la règle et se limite à des créneaux au quart d'heure.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Portée** | vide | Les Constatations que cette règle prend en compte. |

### Exécution manuelle

`trigger.manual`

Balaie toutes les Constatations de la portée lorsque vous appuyez sur **Run** pour la règle.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Portée** | vide | Les Constatations que cette règle prend en compte. |

## Logique

### Si / Filtre

`filter.if`

Oriente chaque élément vers la branche **true** ou la branche **false**, selon des conditions. C'est le seul nœud à posséder deux sorties, et c'est ainsi qu'un graphe se ramifie.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Conditions** | vide | Chaque ligne est un chemin, un opérateur et une valeur. Voir [Conditions](../building_rules/#conditions). |
| **Correspondance** | `all` | Indique si toutes les conditions doivent être vérifiées (`all`), ou une seule d'entre elles (`any`). |

Une liste de conditions vide fait passer tous les éléments par la branche true. Les deux branches sont facultatives : laisser la branche false non connectée se contente d'écarter les éléments qui ont échoué.

### Limite

`flow.limit`

Laisse passer les N premiers éléments et écarte les autres. Utile comme soupape de sécurité pendant que vous testez une règle, et pour plafonner le nombre de tickets ou de messages qu'une seule exécution peut produire.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Conserver les premiers** | `100` | Le nombre d'éléments à transmettre. |

### Dédupliquer au sein de l'exécution

`flow.dedupe_batch`

Conserve le premier élément par clé et écarte les suivants portant la même clé. Limité à l'exécution en cours, ce nœud déduplique au sein d'une seule exécution et non entre plusieurs exécutions.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Chemin de la clé** | `finding.hash_code` | Le chemin de l'élément dont la valeur identifie un doublon. |

Un usage courant consiste à utiliser `finding.component_name`, pour notifier une fois par composant affecté plutôt qu'une fois par Constatation.

## Constatations

Ces nœuds modifient des Constatations. Chaque modification est attribuée à la règle, à l'exécution et au nœud qui l'a effectuée, et apparaît dans la chronologie de provenance de la Constatation.

### Définir la sévérité

`finding.set_severity`

Définit la sévérité, et recalcule en conséquence la date de SLA et la priorité.

| Setting | Options |
|---------|---------|
| **Sévérité** | `Critical`, `High`, `Medium`, `Low`, `Info` |

### Définir un champ

`finding.set_field`

Définit, ajoute à la fin de, ou ajoute au début d'un champ texte.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Champ** | aucun | L'un des suivants : `component_name`, `component_version`, `cvssv3`, `cwe`, `description`, `file_path`, `impact`, `mitigation`, `service`, `title`. |
| **Mode** | `set` | `set`, `append` ou `prepend`. Un vecteur CVSSv3 ne peut être que remplacé. |
| **Valeur** | aucune | Le texte à écrire. Prend en charge les espaces réservés du type `{{finding.title}}`. |

### Définir le statut

`finding.set_status`

Fait passer la Constatation à un statut.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Statut** | aucun | `active`, `inactive`, `verified`, `unverified`, `false_positive`, `mitigated`, `reopen`. |
| **Note** | vide | Une note facultative enregistrée avec le changement de statut. |

### Ajouter des étiquettes

`finding.add_tags`

Ajoute des étiquettes à la Constatation. Les étiquettes existantes sont conservées.

| Paramètre | Remarques |
|---------|-------|
| **Étiquettes** | Séparées par des virgules. Prend en charge les espaces réservés du type `{{product.name}}`, pour pouvoir étiqueter avec des données de la Constatation. |

### Ajouter une note

`finding.add_note`

Ajoute une note à la Constatation.

| Paramètre | Remarques |
|---------|-------|
| **Note** | Le texte de la note. Prend en charge les espaces réservés. |

### Définir les responsables

`finding.set_owners`

Rend un groupe responsable de la Constatation.

| Paramètre | Remarques |
|---------|-------|
| **Groupe** | Le groupe responsable de ces Constatations. |

### Définir les réviseurs

`finding.set_reviewers`

Soumet la Constatation à la revue des utilisateurs sélectionnés.

| Paramètre | Remarques |
|---------|-------|
| **Réviseurs** | Un ou plusieurs utilisateurs devant réviser ces Constatations. |

### Accepter le risque

`finding.risk_accept`

Applique une acceptation de risque simple à la Constatation, ou l'ajoute à une fiche d'acceptation du risque.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Méthode** | `simple` | `simple` applique une acceptation de risque simple à la Constatation. `acceptance` l'ajoute à une fiche d'acceptation du risque. |
| **Accepté** | activé | Affiché pour `simple`. Désactivez pour annuler l'acceptation du risque. |
| **Acceptation du risque** | aucune | Affiché pour `acceptance`. La fiche d'acceptation du risque à laquelle ajouter ces Constatations. |

### Définir la politique d'atténuation

`finding.set_mitigation_policy`

Définit la politique d'atténuation sous laquelle la Constatation est corrigée.

| Paramètre | Remarques |
|---------|-------|
| **Politique d'atténuation** | La politique à appliquer. |

### Modifier la priorité

`finding.set_priority`

Définit la priorité, ou l'ajuste arithmétiquement. Cela remplace la priorité calculée.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Opération** | `set` | `set`, `add`, `subtract`, `multiply`, `divide`. |
| **Valeur** | aucune | La priorité à définir, ou la quantité de l'ajustement. |

### Définir le risque

`finding.set_risk`

Définit le risque, en remplaçant celui calculé.

| Setting | Options |
|---------|---------|
| **Risque** | `Low`, `Medium`, `Needs Action`, `Urgent` |

## Sorties

Les nœuds de sortie sont les nœuds qui quittent DefectDojo. Chacun d'eux enregistre une [Livraison](../deliveries/) avant tout envoi, et chacun d'eux respecte le mode **Simulate** ou **Live** de la règle.

Plusieurs d'entre eux proposent le même choix **Un message par Constatation**. Désactivé, le nœud envoie un seul message décrivant l'ensemble du lot, avec une répartition par sévérité et une liste plafonnée de Constatations. Activé, il envoie un message par Constatation.

Un nœud envoyant un message par Constatation s'arrête par défaut après 1 000 envois au cours d'une même exécution, et enregistre une omission visible indiquant le nombre de Constatations pour lesquelles il n'a pas envoyé de message. Voir [Configuration](../configuration/#per-finding-send-ceiling).

### Lorsqu'un canal est indisponible

Un nœud de sortie dépend de quelque chose d'extérieur à la règle : un jeton Slack, un webhook Microsoft Teams, une configuration JIRA, un connecteur sous licence. Lorsque cet élément est manquant ou désactivé, le nœud ne peut pas fonctionner, et Rules Engine 2.0 le signale à trois moments différents plutôt que d'échouer silencieusement :

* **Dans la palette**, un nœud indisponible est marqué comme tel, avec la raison, avant même que vous ne le glissiez sur le canevas.
* **À l'enregistrement**, un graphe contenant un nœud indisponible est refusé. C'est le moment où quelqu'un est présent pour en choisir un autre.
* **À l'exécution**, la livraison est **omise**, sans être mise en échec. Une règle enregistrée alors que Slack était actif ne doit pas se mettre à générer des erreurs le jour où quelqu'un désactive Slack. L'enregistrement honnête est une livraison omise indiquant que Slack est désactivé.

### Créer un ticket JIRA

`ticket.jira`

Crée ou met à jour le ticket JIRA de la Constatation.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Ignorer les Constatations ayant déjà un ticket** | activé | Laisse inchangées les Constatations qui ont déjà un ticket JIRA. |
| **Mettre à jour un ticket existant** | désactivé | Affiché lorsque l'option ci-dessus est désactivée. Pousse les Constatations qui ont déjà un ticket, afin que JIRA soit mis à jour. |

Le résumé, la description et la priorité proviennent de la configuration JIRA du produit, et non de ce nœud. Un ticket créé par une règle est donc identique à celui créé par push all issues.

### Créer un ticket en aval

`ticket.downstream`

Crée ou met à jour un ticket via un [connecteur en aval](/connectors/downstream/about/).

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Systèmes de tickets** | `auto` | `auto` utilise les systèmes de tickets affectés à l'engagement ou au produit. `mapping` cible un mappage spécifique. |
| **Mappage de système de tickets** | aucun | Affiché pour `mapping`. Le mappage vers lequel pousser. |
| **Opération** | `create` | `create` un ticket, ou `update` celui qui existe déjà. Une mise à jour sans ticket existant le crée. |
| **Ignorer les Constatations ayant déjà un ticket** | activé | Laisse inchangées les Constatations qui ont déjà un ticket dans le mappage cible. |

La règle remplace les paramètres de poussée automatique de l'affectation : les filtres de sévérité et « actif uniquement » ne sont pas réappliqués ici. Une Constatation dont le ticket existe déjà est ignorée, quelle que soit la manière dont ce ticket a été créé.

### Envoyer un message Slack

`notify.slack`

Publie dans un canal Slack via un connecteur de messagerie. La connexion porte le jeton du bot ; les paramètres Slack globaux de l'instance, sous **System Settings**, ne sont pas utilisés et ne servent pas de repli.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Connexion** | aucune | Un [connecteur de messagerie](/issue_tracking/pro_integration/messaging_connectors/) de ce type. Obligatoire. |
| **Destination** | vide | Affiché une fois une connexion choisie. Les champs dépendent du fournisseur de la connexion. |
| **Un message par Constatation** | désactivé | Désactivé envoie un seul message pour le lot. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Généré pour chaque Constatation. |
| **Constatations répertoriées dans la synthèse** | `10` | Affiché pour les messages groupés. Le nombre de Constatations que le message liste avant d'indiquer combien il y en avait de plus. |

### Envoyer un message Microsoft Teams

`notify.msteams`

Publie une carte via un connecteur de messagerie. La connexion porte l'URL du workflow Power Automate ; le webhook Teams global de l'instance, sous **System Settings**, n'est pas utilisé et ne sert pas de repli.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Connexion** | aucune | Un [connecteur de messagerie](/issue_tracking/pro_integration/messaging_connectors/) de ce type. Obligatoire. |
| **Destination** | vide | Affiché une fois une connexion choisie. Les champs dépendent du fournisseur de la connexion. |
| **Un message par Constatation** | désactivé | Désactivé envoie une seule carte pour le lot. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Généré pour chaque Constatation. |
| **Constatations répertoriées dans la synthèse** | `10` | Affiché pour les messages groupés. |

### Envoyer un e-mail

`notify.email`

Envoie un e-mail à une liste fixe d'adresses via un connecteur de messagerie. Les destinataires correspondent à la destination de la connexion.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Connexion** | aucune | Un [connecteur de messagerie](/issue_tracking/pro_integration/messaging_connectors/) de ce type. Obligatoire. |
| **Destination** | vide | Affiché une fois une connexion choisie. Les champs dépendent du fournisseur de la connexion. |

| **Objet** | `[DefectDojo] {{ctx.count}} finding(s) from rule {{ctx.rule_name}}` | Généré une fois par message. |
| **Corps** | un corps HTML contenant `{{ctx.findings_html}}` | HTML. `{{ctx.findings_html}}` génère la liste des Constatations. |
| **Un message par Constatation** | désactivé | Désactivé envoie un seul e-mail pour le lot. |
| **Constatations répertoriées dans le corps** | `25` | Le nombre de Constatations que `{{ctx.findings_html}}` liste avant d'indiquer combien il y en avait de plus. |

### Appeler un webhook

`notify.webhook`

Envoie une requête POST JSON vers un point de terminaison webhook.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Point de terminaison du webhook** | aucun | Un [webhook de notification](/automation/api/notification_webhooks/) configuré. Son en-tête personnalisé est envoyé avec la requête. |
| **URL** | vide | Affiché lorsqu'aucun point de terminaison n'est sélectionné. Où envoyer le POST. |
| | | L'un des deux paramètres ci-dessus est requis. |
| **Secret de signature** | vide | Signe le corps sous la forme `X-DefectDojo-Signature: sha256=HMAC`. |
| **Un message par Constatation** | désactivé | Désactivé envoie le lot entier en une seule requête. |

Deux choses à savoir. Un secret de signature saisi ici est stocké avec la règle ; pour tout élément sensible, préférez donc un point de terminaison configuré avec son propre en-tête. Et un webhook appelé par une règle ne modifie jamais l'état de santé propre de ce point de terminaison, si bien qu'une règle ne peut pas désactiver vos webhooks de notification en échouant.

Les URL en texte libre sont validées à l'enregistrement. Voir [Configuration](../configuration/#outbound-destination-validation) pour savoir ce qui est rejeté et comment autoriser les adresses privées.

### Déclencher une alerte intégrée

`notify.alert`

Crée une alerte intégrée à propos du lot.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Titre** | `Rules Engine 2.0: {{ctx.rule_name}}` | Généré une fois pour l'ensemble du lot. |
| **Description** | `{{ctx.count}} finding(s) matched the rule {{ctx.rule_name}}.` | Généré une fois pour l'ensemble du lot. |
| **Destinataires** | vide | Noms d'utilisateur, séparés par des virgules. Vide alerte les administrateurs. |

Les destinataires gardent le contrôle via leur propre paramètre de notification **Rules Engine Match**, de sorte qu'une alerte ne peut pas contourner les préférences de notification d'un utilisateur.

### Générer un rapport

`report.generate`

Génère un rapport à partir d'un modèle, limité aux Constatations ayant atteint ce nœud, et peut annoncer le lien de téléchargement.

| Paramètre | Valeur par défaut | Remarques |
|---------|---------|-------|
| **Modèle de rapport** | aucun | Le modèle à partir duquel générer le rapport. Obligatoire. |
| **Format** | `pdf` | `pdf` ou `html`. |
| **Constatations incluses** | `batch_findings` | `batch_findings` limite le rapport aux Constatations ayant atteint ce nœud. `template_default` laisse le modèle utiliser ses propres filtres. |
| **Annoncer via** | aucun | Un [connecteur de messagerie](/issue_tracking/pro_integration/messaging_connectors/) via lequel publier le lien de téléchargement une fois le rapport généré. Laisser vide pour ne pas annoncer. |
| **Annoncer à** | vide | Affiché une fois une connexion choisie. Où cette connexion envoie : un identifiant de canal Slack, des adresses e-mail, etc. |
| **Annonce** | `Report ready: {{ctx.report_url}}` | Affiché lors de l'annonce. `{{ctx.report_url}}` est le lien de téléchargement. |

`batch_findings` représente ce qu'une règle peut faire et qu'un rapport planifié ne peut pas : produire un rapport sur exactement les Constatations qui viennent de correspondre.

L'annonce est enregistrée comme une livraison à part entière, distincte de la génération du rapport, de sorte que vous pouvez voir le rapport réussir et l'annonce échouer indépendamment l'une de l'autre.
