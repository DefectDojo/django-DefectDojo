---
title: Créer des règles
description: L'éditeur de graphe, les déclencheurs, le périmètre, les conditions et
  les modèles de message
weight: 2
audience: pro
aliases:
- /fr/automation/rules_engine_v2/building_rules/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Rules Engine 2.0 est une fonctionnalité réservée à DefectDojo Pro.</span>

Une règle est construite sur un canevas. Vous glissez des nœuds depuis une palette, vous les reliez entre eux, et vous configurez chacun d'eux dans un panneau latéral. Cette page couvre les aspects de ce processus qui sont identiques quels que soient les nœuds utilisés. Les nœuds eux-mêmes sont décrits dans la [Référence des nœuds](../node_reference/).

## L'éditeur

Ouvrez **Rules Engine 2.0 > All Rules** et choisissez **New Rule** (Nouvelle règle), ou ouvrez une règle existante pour la modifier.

La palette est organisée en quatre catégories, qui correspondent aussi à l'ordre dans lequel les éléments traversent un graphe typique :

| Catégorie | Ce que font les nœuds |
|----------|-------------------|
| **Triggers** (Déclencheurs) | Décident quand la règle se réveille et quelles Constatations y entrent. Exactement un par graphe. |
| **Logic** (Logique) | Acheminent, limitent et dédupliquent les éléments qui circulent. |
| **Findings** (Constatations) | Modifient les Constatations. |
| **Egress** (Sortie) | Envoient quelque chose vers l'extérieur : un ticket, un message, un rapport. |

La palette est générée à partir du moteur lui-même, de sorte que ce que vous voyez dans l'éditeur est toujours exactement ce que le moteur peut exécuter.

### Règles du graphe

Un graphe est vérifié lors de son enregistrement, puis à nouveau avant chaque exécution. Il doit satisfaire toutes les conditions suivantes :

* Il comporte au moins un nœud.
* Il comporte **exactement un** nœud déclencheur.
* Chaque nœud possède un identifiant unique et non vide de 100 caractères ou moins.
* Chaque nœud est d'un type que le moteur connaît.
* Chaque arête relie deux nœuds qui existent.
* Il ne contient aucun cycle.

Un nœud auquel rien n'est relié est valide. Il s'exécute avec une liste d'entrée vide, ce qui, en général, signifie qu'il ne fait rien.

Un nœud comportant plusieurs arêtes entrantes reçoit la concaténation de toutes leurs sorties.

### Prévisualiser avant d'enregistrer

**Preview** (Aperçu) exécute à blanc le graphe actuellement présent sur le canevas et affiche la trace par nœud qu'il produirait : combien d'éléments sont entrés dans chaque nœud, combien en sont sortis par chaque sortie, et ce que chaque nœud aurait modifié.

Preview exécute le véritable moteur, et non une simulation de celui-ci, puis annule l'ensemble. Rien n'est écrit, aucune exécution n'est enregistrée, et la sortie est forcée à simuler quel que soit le mode indiqué par la règle. C'est le moyen le plus rapide de vérifier que vos conditions correspondent à ce que vous attendiez.

Preview est la seule exécution qui plafonne le nombre de Constatations examinées, afin de rester rapide. Lorsqu'elle tronque, elle le signale dans la trace. Une exécution réelle n'a pas une telle limite.

## Déclencheurs et périmètre

Chaque graphe démarre avec l'un des trois déclencheurs suivants.

* **On Finding Event** (Sur événement de Constatation) réveille la règle lorsque des Constatations sont créées, modifiées, clôturées ou rouvertes. Choisissez lequel de ces événements dans le paramètre **Event** (Événement) du nœud, ou `any` pour les quatre.
* **On a Schedule** (Sur une planification) balaie les Constatations selon une planification récurrente.
* **Manual Run** (Exécution manuelle) balaie les Constatations lorsque vous appuyez sur **Run** (Exécuter) sur la règle.

### Périmètre

Les trois déclencheurs acceptent un **Scope** (Périmètre), et le périmètre est ce qui vous permet de restreindre ce que la règle prend en compte. C'est le même vocabulaire de filtres que celui utilisé par le Rules Engine d'origine, soit une soixantaine de filtres couvrant les Constatations et les objets qui les entourent ; un filtre que vous savez déjà écrire là-bas signifie donc la même chose ici.

Deux points concernant le périmètre méritent d'être compris :

* **Le périmètre s'applique par-dessus l'autorisation, jamais à sa place.** La règle s'exécute en tant que son propriétaire, de sorte que le périmètre restreint un ensemble de Constatations déjà autorisé. Laisser le périmètre vide ne signifie pas « toutes les Constatations de l'instance », mais « toutes les Constatations que le propriétaire de la règle peut voir ».
* **Un périmètre invalide fait échouer l'exécution plutôt que de l'élargir.** Si une clé de filtre n'existe pas, ou si une valeur est de celles que le filtre rejetterait silencieusement, l'exécution se termine en erreur. Une règle qui ne fait rien est récupérable. Une règle qui modifie silencieusement toutes les Constatations de l'instance ne l'est pas.

Pour un déclencheur d'événement, le périmètre agit comme une seconde porte : les Constatations nommées dans l'événement y sont confrontées, et seules celles qui passent entrent dans le graphe.

### Planification

Une règle dont le déclencheur est **On a Schedule** est planifiée depuis la règle elle-même. Définir la planification nécessite Rule Edit, la même permission que pour modifier la règle, car une règle déclenchée par planification ne fait absolument rien tant qu'elle n'en a pas une.

Les planifications sont limitées aux quarts d'heure. Le champ des minutes d'une expression cron doit être `0`, `15`, `30` ou `45`.

Exemples valides :

```
0 * * * *     every hour, on the hour
15 9 * * *    every day at 09:15
0 15 * * 1    every Monday at 15:00
30 2 * * *    every day at 02:30
```

## Faire référence aux données de Constatation

Deux endroits d'une règle lisent des valeurs à partir de l'élément qui les traverse : les **conditions** et les **modèles**. Tous deux utilisent les mêmes chemins pointés.

```
finding.severity
finding.title
finding.vulnerability_ids.0
product.name
product_type.name
test.scan_type
ctx.rule_name
```

Un chemin qui ne se résout pas ne produit aucune valeur plutôt qu'une erreur.

### Champs disponibles

Chaque élément porte un ensemble fixe de champs de Constatation. Cette liste est un contrat, elle ne change donc que délibérément.

| Groupe | Champs |
|-------|--------|
| Identité | `id`, `title`, `hash_code`, `unique_id_from_tool` |
| Sévérité et notation | `severity`, `numerical_severity`, `cvssv3`, `cvssv3_score`, `epss_score`, `epss_percentile`, `priority`, `risk`, `risk_score` |
| Texte | `description`, `mitigation`, `impact` |
| Statut | `active`, `verified`, `false_p`, `duplicate`, `is_mitigated`, `out_of_scope`, `risk_accepted`, `under_review` |
| Dates | `date`, `mitigated`, `last_status_update`, `sla_expiration_date` |
| Emplacement | `file_path`, `line`, `component_name`, `component_version`, `service` |
| Classification | `cwe`, `vulnerability_ids`, `tags` |

En plus de `finding`, chaque élément porte `test` (`id`, `title`, `scan_type`), `engagement` (`id`, `name`), `product` (`id`, `name`), `product_type` (`id`, `name`), et `ctx`.

Les dates sont des chaînes ISO-8601. C'est délibéré : cela signifie que `gt` et `lt` les ordonnent correctement en tant que texte, de sorte que `2026-07-28` est correctement supérieur à `2026-01-01`.

`priority`, `risk` et `risk_score` proviennent de la priorisation de Pro. Une Constatation qui n'a pas encore été notée ne porte aucune valeur pour ces champs.

### Conditions

Un nœud **If / Filter** contient une liste de lignes de condition. Chaque ligne est un chemin, un opérateur et une valeur. **Match** (Correspondance) détermine si toutes les lignes doivent être vraies (`all`) ou une seule d'entre elles (`any`).

| Opérateur | Signification |
|----------|---------|
| `eq` | est égal à |
| `neq` | n'est pas égal à |
| `contains` | contient |
| `not_contains` | ne contient pas |
| `in` | fait partie de |
| `not_in` | ne fait pas partie de |
| `gt` | est supérieur à |
| `gte` | est supérieur ou égal à |
| `lt` | est inférieur à |
| `lte` | est inférieur ou égal à |
| `startswith` | commence par |
| `endswith` | se termine par |
| `exists` | est défini |
| `not_exists` | n'est pas défini |

Les comparaisons sont **souples**. Un nombre est d'abord tenté, et si cela échoue, les valeurs sont comparées comme du texte, sans tenir compte de la casse et après suppression des espaces superflus. Ainsi, une condition écrite comme `finding.severity eq high` correspond à une Constatation dont la sévérité est `High`, ce qui est presque toujours ce que l'auteur voulait dire.

#### Transformations

Une ligne de condition peut post-traiter la valeur qu'elle a lue avant de la comparer.

| Transformation | Effet |
|-----------|--------|
| `int` | nombre entier |
| `float` | nombre décimal |
| `str` | texte |
| `first` | première entrée d'une liste |
| `list` | sous forme de liste |
| `join` | jointe par des virgules |
| `upper` | MAJUSCULES |
| `lower` | minuscules |
| `strip` | espaces superflus supprimés |
| `cwe_int` | numéro CWE |
| `severity` | sévérité normalisée, de sorte que des valeurs comme `critical`, `error` et `warning`, propres à différents scanners, soient ramenées aux cinq niveaux de DefectDojo |
| `numerical_severity` | code de sévérité triable, pour ordonner les comparaisons |

### Modèles

Tout paramètre étiqueté comme message, note, titre ou valeur accepte des espaces réservés `{{ path }}`, résolus par élément :

```
{{finding.severity}}: {{finding.title}} ({{product.name}})
```

Un chemin sans valeur s'affiche comme une chaîne vide. Une liste s'affiche jointe par des virgules.

Les modèles voient également un bloc `ctx` transportant des détails sur l'exécution elle-même. Les clés disponibles dépendent du nœud, mais les plus courantes sont :

| Espace réservé | Signification |
|-------------|---------|
| `{{ctx.rule_name}}` | Le nom de la règle |
| `{{ctx.count}}` | Le nombre de Constatations couvertes par le message |
| `{{ctx.trigger}}` | L'événement qui a déclenché l'exécution |
| `{{ctx.findings_html}}` | La liste des Constatations mise en forme, dans le nœud d'e-mail |
| `{{ctx.report_url}}` | Le lien de téléchargement, dans le nœud de rapport |
| `{{ctx.template_name}}` | Le nom du modèle de rapport, dans le nœud de rapport |

Les modèles reposent sur une simple substitution. Il n'y a aucune évaluation d'expression, aucune exécution de code, et aucun accès aux attributs d'objets nulle part dans la configuration d'une règle.

## Tester une règle en toute sécurité

L'ordre recommandé pour une règle qui envoie quelque chose :

1. Construisez le graphe et utilisez **Preview** jusqu'à ce que les décomptes d'éléments semblent corrects.
2. Enregistrez-la. Les nouvelles règles sont créées désactivées.
3. Laissez le mode sur **Simulate** et activez la règle.
4. Laissez-la s'exécuter, puis consultez **Deliveries** et vérifiez que les charges utiles enregistrées correspondent à ce que vous vouliez.
5. Basculez le mode sur **Live**.

Simulate n'est pas une exécution partielle. Chaque modification de Constatation dans le graphe se produit réellement en mode simulation. Seuls les envois sortants sont retenus.
