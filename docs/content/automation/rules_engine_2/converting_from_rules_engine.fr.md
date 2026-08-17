---
title: Conversion depuis Rules Engine
description: Faire migrer les règles Rules Engine existantes vers des graphes Rules
  Engine 2.0
weight: 6
audience: pro
aliases:
- /fr/automation/rules_engine_v2/converting_from_rules_engine/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Rules Engine 2.0 est une fonctionnalité réservée à DefectDojo Pro.</span>

Les deux moteurs fonctionnent côte à côte. Activer Rules Engine 2.0 ne change rien à vos règles [Rules Engine](/automation/rules_engine/about/) existantes, et il n'y a aucune échéance à laquelle vous devriez les faire migrer.

Lorsque vous souhaitez les faire migrer, un convertisseur est disponible. Il traduit une règle Rules Engine (un filtre associé à une liste ordonnée d'actions) en un graphe Rules Engine 2.0 équivalent.

## Ce que le convertisseur garantit

**Une règle se convertit proprement ou ne se convertit pas du tout.** Chaque conversion produit deux types de résultats :

* Les **problèmes** signifient que la règle n'a pas été écrite. Rien de partiel n'est enregistré.
* Les **avertissements** signifient que la règle a été convertie, mais que quelque chose à son sujet a changé et mérite d'être examiné.

Rien n'est approximé silencieusement. Tout l'intérêt du convertisseur est que vous pouvez faire confiance à une règle convertie sans remarque, et vérifier manuellement celle qui ne l'a pas été.

**Les règles converties sont toujours créées désactivées.** Les deux moteurs fonctionnent en même temps, et avoir deux règles qui font la même chose aux mêmes Constatations est le seul résultat qu'un convertisseur ne doit jamais produire de lui-même. Passez en revue chaque règle convertie et activez-la délibérément.

**Une règle ne se convertit qu'une fois.** Chaque règle convertie se souvient de la règle dont elle provient, de sorte qu'exécuter le convertisseur une seconde fois ignore ce qu'il a déjà fait plutôt que de créer des doublons. Utilisez l'option d'écrasement pour remplacer délibérément un graphe déjà converti.

## Exécuter le convertisseur

### Depuis l'interface

La liste des règles propose une action de conversion, qui indique pour chaque règle ce qui a été converti, ce qui a été ignoré, et ce qui a échoué.

### Depuis la ligne de commande

```bash
python manage.py convert_rules_to_v2
```

| Option | Effet |
|--------|--------|
| `--dry-run` | Affiche le graphe que chaque règle produirait et n'écrit rien. |
| `--rule-ids 1,2,3` | Ne convertit que ces règles. Convertit toutes les règles si omis. |
| `--overwrite` | Remplace le graphe d'une règle déjà convertie et incrémente sa version, au lieu de l'ignorer. |
| `--activate-schedules` | Copie également chaque planification sur sa règle convertie. Désactivé par défaut. |
| `--drop-invalid-filters` | Supprime les filtres de périmètre que l'ensemble de filtres ne reconnaît plus et avertit, au lieu de faire échouer la règle. |
| `--json` | Affiche le rapport au format JSON plutôt qu'en texte. |

La commande se termine avec un code non nul uniquement lorsqu'une règle échoue à se convertir. Les éléments ignorés sont signalés mais ne sont pas des échecs.

Commencez par `--dry-run` sur l'ensemble complet pour voir ce qui vous attend, puis convertissez pour de bon.

## Ce que produit la conversion

| Concept Rules Engine | Devient |
|----------------------|---------|
| Le filtre de la règle | Le **Scope** (Périmètre) du nœud déclencheur. |
| Une règle avec une planification | Un déclencheur **On a Schedule** (Sur une planification). |
| Une règle sans planification | Un déclencheur **Manual Run** (Exécution manuelle). |
| Chaque action, dans l'ordre | Un nœud, enchaîné dans le même ordre. |
| Une action protégée par une condition | Un nœud **If / Filter** placé devant ce nœud. |

Le vocabulaire de filtres est partagé entre les deux moteurs, de sorte qu'un périmètre se convertit sans traduction. C'est délibéré : il s'agit du même ensemble de filtres, avec une seule implémentation.

Les graphes convertis sont validés de la même manière qu'un graphe construit à la main, y compris la configuration par nœud et les valeurs autorisées de chaque liste déroulante. Une règle contenant une valeur de sévérité ou de risque que le produit a depuis abandonnée est détectée à la conversion plutôt qu'à l'exécution.

## Ce qui ne se reporte pas

Quatre points à anticiper. Le convertisseur les signale sous forme de notes à chaque exécution.

* **L'historique des exécutions reste où il est.** L'historique des exécutions existant, ainsi que ses enregistrements affectés et ignorés, reste dans l'interface de Rules Engine. Il n'est pas copié.
* **Les planifications ne sont pas activées par défaut.** Une règle déclenchée par planification se convertit, mais sa planification n'est pas copiée sauf si vous passez `--activate-schedules`. Cela conserve la seule propriété des planifications actives au moteur d'origine tant que les deux fonctionnent, de sorte qu'une règle convertie ne peut pas commencer à se déclencher à votre insu. Lorsque vous copiez effectivement une planification, la copie reçoit un nom distinct afin de ne pas entrer en collision avec l'original.
* **Le modèle de concurrence est différent.** Rules Engine possède un seul verrou d'exécution à l'échelle de l'instance. Rules Engine 2.0 sérialise par règle, de sorte que des règles distinctes s'exécutent simultanément. Un ensemble de règles qui se relayaient auparavant se chevauchera désormais.
* **Une action n'a pas d'équivalent.** Une action « définir faux positif sur false » ne peut pas être exprimée comme un nœud Rules Engine 2.0 et doit être convertie manuellement.

Une règle dont le propriétaire n'est pas défini se convertit, avec un avertissement. Rappelez-vous qu'une règle sans propriétaire ne voit aucune Constatation ; attribuez-lui donc un propriétaire avant de l'activer.

## Un ordre suggéré

1. Activez Rules Engine 2.0 et laissez vos règles existantes en cours d'exécution.
2. Exécutez le convertisseur avec `--dry-run` et lisez le rapport.
3. Convertissez. Tout est créé désactivé.
4. Ouvrez chaque règle convertie, vérifiez le graphe, et laissez le mode sur **Simulate**.
5. Activez la règle convertie, et laissez-la s'exécuter parallèlement à l'originale pendant un certain temps. Simulate signifie qu'elle modifie les Constatations mais n'envoie rien, ce qui permet de comparer ses exécutions à ce que l'originale a fait.
6. Lorsque vous êtes satisfait, désactivez la règle d'origine et basculez la règle convertie sur **Live**.
7. Copiez la planification en dernier, une fois que plus rien n'exécute l'ancienne règle.

L'étape 5 est celle qu'il ne faut pas sauter. Que les deux moteurs modifient les mêmes Constatations est acceptable à observer, mais vous voulez être celui qui décide du moment où les envois commencent.
