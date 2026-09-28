---
title: À propos de la déduplication
description: Principes fondamentaux et concepts clés de la déduplication
weight: 1
aliases:
- /fr/en/working_with_findings/finding_deduplication/about_deduplication
- /fr/en/working_with_findings/finding_deduplication/delete_deduplicates
- /fr/en/working_with_findings/findings_workflows/manage_duplicate_findings
---

DefectDojo est conçu pour ingérer des rapports en masse provenant d'outils, créant une ou plusieurs Constatations en fonction du contenu du rapport. Lorsque vous utilisez DefectDojo, vous serez très probablement amené à ingérer régulièrement des rapports provenant du même outil, ce qui rend les Constatations en double hautement probables.

C'est là qu'intervient la Déduplication, une fonctionnalité intelligente que vous pouvez configurer pour gérer automatiquement les Constatations en double.

## Comment DefectDojo gère les doublons

1. Tout d'abord, vous importez **Test 1\.** Votre rapport contient une vulnérabilité qui est enregistrée comme Constatation A.
2. **Plus tard, vous importez le Test 2, qui contient la même vulnérabilité. Celle-ci sera enregistrée comme Constatation B, et la Constatation B sera marquée comme doublon de la Constatation A.**
3. Plus tard encore, vous importez **Test 3**, qui contient également cette vulnérabilité. Celle-ci sera enregistrée comme Constatation C, qui sera marquée comme doublon de la Constatation A.

En créant et en marquant les doublons de cette manière, DefectDojo garantit que tout le travail concernant la vulnérabilité « originale » est centralisé sur la page de la Constatation d'origine, sans créer de contextes distincts ni donner à votre équipe l'impression qu'il existe plusieurs vulnérabilités distinctes à traiter.

### Quelle Constatation devient l'originale

La Déduplication considère toujours la Constatation **créée le plus tôt** dans une chaîne de doublons comme l'originale canonique, de sorte qu'une Constatation issue d'un import antérieur n'est jamais rétrogradée en doublon d'une Constatation plus récente — une originale déjà établie ne change jamais de statut.

Au sein d'*un même* rapport, l'ordre dans lequel le scanner répertorie ses constatations ne détermine pas laquelle l'emporte. Les Constatations d'un même import sont créées selon un ordre stable, dérivé du contenu, de sorte qu'un rapport contenant plusieurs constatations en collision sur la même clé de déduplication produit **la même originale à chaque import**. Le fait de rescanner et de réimporter les mêmes résultats ne changera pas la Constatation sur laquelle votre équipe travaille.

Par défaut, ces Tests doivent être imbriqués sous le même Produit pour que la Déduplication s'applique. Si vous le souhaitez, vous pouvez limiter davantage la portée de la Déduplication à un seul Engagement.

![Déduplication au niveau du produit et de l'engagement](images/deduplication.png)

Les Constatations en double sont définies comme Inactives par défaut. Cela ne signifie pas que la Constatation en double elle-même est inactive. Il s'agit plutôt de faire en sorte que votre équipe n'ait qu'une seule Constatation active sur laquelle travailler et à corriger, ce qui implique qu'une fois la Constatation originale Atténuée, les doublons seront également Atténués.

## Déduplication lors du réimport

La Déduplication et le Réimport sont des processus similaires, mais ils utilisent des algorithmes différents pour identifier les correspondances entre Constatations.

* Lorsque vous réimportez dans un Test, le processus de Réimport examine les Constatations entrantes, **compare les codes de hachage, puis élimine toute correspondance**. Ces correspondances ne seront jamais créées en tant que Constatations ou Doublons de Constatation.

Cependant, toute Constatation restant après la Déduplication de Réimport reste soumise à la Déduplication du même outil.  Ainsi, si vous utilisez une portée plus étroite pour la Déduplication du même outil, vous pouvez tout de même vous retrouver avec des doublons au sein d'un pipeline de Réimport.

### Exemple

Voici un outil dont l'algorithme de Déduplication de Réimport diffère de l'algorithme de Déduplication du même outil.

| Deduplication Algorithm | Hash Code Fields |
| ----- | ---- |
| Réimport | Titre, CWE, Sévérité, Description, Numéro de ligne |
| Même outil | Titre, CWE, Sévérité, Description |

Supposons que vous ayez une Constatation dans DefectDojo avec un numéro de ligne donné.  Vous rescannez votre environnement et le numéro de ligne de cette vulnérabilité change.  Vous réimportez dans le même Test.  Voici ce qui se passera pendant le réimport et la déduplication :

* Pendant le Réimport, la Constatation ne sera associée à aucune Constatation déjà existante, car le numéro de ligne est différent.  Une nouvelle Constatation sera donc créée dans le Test.
* Une fois le Réimport terminé, l'algorithme de Déduplication du même outil s'exécutera.  Dans cette configuration, la Déduplication du même outil ne prend pas en compte le numéro de ligne, donc la nouvelle Constatation sera étiquetée comme doublon.

Le Réimport peut complètement éliminer des Constatations avant même qu'elles soient enregistrées, les paramètres de Déduplication de Réimport doivent donc être ajustés avec prudence.

## Quand les doublons sont-ils appropriés ?

Les doublons sont utiles lorsque vous traitez des contextes de Test partagés mais distincts. Par exemple, si votre Produit télécharge des résultats de Test pour deux dépôts différents qui doivent être comparés, il est utile de savoir quelles vulnérabilités sont partagées entre ces dépôts.

Cependant, si DefectDojo crée un excès de doublons, cela peut également être le signe que vous devez ajuster vos pipelines ou vos processus d'import.

## Que révèlent mes doublons ?

* **La même vulnérabilité, mais trouvée dans un contexte différent :** c'est la façon appropriée d'utiliser les Constatations en double. Si plusieurs composants sont affectés par la même vulnérabilité, vous voudrez probablement savoir lesquels sont concernés afin de comprendre l'étendue du problème.
​
* **La même vulnérabilité, trouvée dans le même contexte** : de meilleures options existent dans ce cas. Si la Constatation en double ne vous apporte aucun nouveau contexte sur la vulnérabilité, ou si vous vous surprenez à ignorer ou supprimer fréquemment vos Constatations en double, c'est le signe que votre processus peut être amélioré. Par exemple, le Réimport vous permet de gérer efficacement les rapports entrants provenant d'un pipeline CI/CD. Plutôt que de créer un tout nouvel objet Constatation pour chaque doublon, le Réimport prendra note du doublon entrant sans créer la Constatation en double du tout.

## Aperçu

DefectDojo Open Source prend en charge quatre algorithmes de déduplication qui peuvent être sélectionnés par parseur (type de test) :

- **Unique ID From Tool** : utilise l'identifiant unique fourni par le scanner.
- **Hash Code** : utilise un ensemble configuré de champs pour calculer un hachage.
- **Unique ID From Tool or Hash Code** : privilégie l'identifiant unique de l'outil, avec repli sur le hachage lorsqu'aucun identifiant unique correspondant n'est trouvé.
- **Legacy** : algorithme historique à conditions multiples, disponible uniquement dans la version Open Source.

**DefectDojo Pro en ajoute davantage.** Deux algorithmes supplémentaires établissent des correspondances entre **tous les Produits** de l'instance plutôt qu'au sein d'un seul Produit ou Engagement — **Global Component** (par nom et version de composant) et **Global Vulnerability ID** (par CVE, GHSA, …). Les deux sont désactivés par défaut et activés par le support DefectDojo. Pro permet également à l'algorithme Hash Code de traiter les identifiants de vulnérabilité et les CWE d'une Constatation comme des **ensembles**, en établissant une correspondance sur l'ensemble exact, sur toute valeur partagée (`_partial`), ou sur le fait que l'un soit un sous-ensemble de l'autre (`_subset`). Consultez [Réglage de la déduplication (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/) pour la liste complète, les champs de correspondance par ensemble, et les règles qui les régissent.

### Une alternative à la Déduplication : l'historique des faux positifs

Les instances qui choisissent délibérément de **ne pas** dédupliquer peuvent utiliser à la place l'[historique des faux positifs](/triage_findings/finding_deduplication/false_positive_history/), qui marque automatiquement une Constatation entrante comme faux positif lorsqu'une Constatation correspondante dans le même Produit a déjà été triée ainsi. Cette fonctionnalité est **mutuellement exclusive avec la Déduplication** — DefectDojo ne permet pas d'activer les deux — et elle est toujours signalée comme expérimentale.

## Comment les points de terminaison sont évalués selon l'algorithme

Les points de terminaison peuvent influencer la déduplication de différentes manières selon l'algorithme et la configuration.

### Unique ID From Tool

- La déduplication utilise `unique_id_from_tool` (ou `vuln_id_from_tool`).
- **Les points de terminaison sont ignorés** pour la correspondance des doublons.
- Le hachage d'une constatation peut néanmoins être calculé pour d'autres fonctionnalités, mais cela n'affecte pas la déduplication dans cet algorithme.

### Hash Code

- La déduplication utilise un hachage calculé à partir des champs spécifiés par `HASHCODE_FIELDS_PER_SCANNER` pour le parseur donné.
- Le hachage inclut également les champs de `HASH_CODE_FIELDS_ALWAYS` (voir la section sur le champ Service ci-dessous).
- Les points de terminaison peuvent affecter la déduplication de deux manières :
  - Si les champs de hachage du scanner incluent `endpoints`, ils font partie du hachage et doivent correspondre en conséquence.
- Si les champs de hachage du scanner n'incluent pas `endpoints`, une correspondance optionnelle basée sur les points de terminaison peut être activée via `DEDUPE_ALGO_ENDPOINT_FIELDS` (paramètre Open Source). Une fois configuré :
    - Définissez-le sur une liste vide `[]` pour ignorer entièrement les points de terminaison.
    - Définissez-le sur une liste d'attributs de point de terminaison (par ex. `["host", "port"]`). Si au moins une paire de points de terminaison entre les deux constatations correspond sur tous les attributs listés, la déduplication peut se produire.

### Unique ID From Tool or Hash Code
Une constatation est un doublon d'une autre si elles ont le même unique_id_from_tool OU le même hash_code.

Les points de terminaison doivent également correspondre pour que les constatations soient considérées comme des doublons ; voir l'algorithme Hash Code ci-dessus.

### Legacy (Open Source uniquement)

- La déduplication prend en compte plusieurs attributs, y compris les points de terminaison.
- Le comportement diffère entre constatations statiques et dynamiques :
  - **Constatations statiques** : la nouvelle constatation doit contenir tous les points de terminaison de l'originale. Des points de terminaison supplémentaires sur la nouvelle constatation sont autorisés.
  - **Constatations dynamiques** : les points de terminaison doivent correspondre strictement (généralement par hôte et port) ; des points de terminaison différents empêchent la déduplication.
- S'il n'y a aucun point de terminaison et que `file_path` et `line` sont tous deux vides, la déduplication ne se produit généralement pas.

## Traitement en arrière-plan

- La déduplication est déclenchée lors de l'import/réimport et lors de certaines mises à jour exécutées en arrière-plan via Celery.

### Mode d'exécution de la déduplication lors de l'import/réimport

Pour l'import et le réimport, vous pouvez contrôler la manière dont le post-traitement de déduplication est déclenché et si la réponse de l'API l'attend. Configurez-le par utilisateur sur la page de profil (**Deduplication execution mode**), ou remplacez-le par requête avec le champ `deduplication_execution_mode` sur les points de terminaison d'import/réimport (la valeur de la requête est prioritaire sur celle du profil).

- `async` (par défaut) : la déduplication et le reste du post-traitement s'exécutent en arrière-plan et la réponse est renvoyée immédiatement. Comportement historique ; la réponse est produite avant que les constatations ne soient dédupliquées.
- `async_wait` : le post-traitement est toujours envoyé en arrière-plan, mais la requête attend la fin de la déduplication avant de répondre. La notification `scan_added` et les statistiques de la réponse reflètent alors l'état dédupliqué (les constatations qui se révèlent être des doublons ne sont plus comptées/listées comme nouvelles). Le push JIRA, la notation des produits et les autres tâches non liées à la déduplication restent asynchrones et ne sont pas attendues. L'attente est bornée par `DD_DEDUPLICATION_ASYNC_WAIT_TIMEOUT` (par défaut `60` secondes) ; si aucun worker ne prend en charge le travail à temps, la requête répond quand même plutôt que de rester bloquée.
- `sync` : la déduplication de l'import s'exécute directement dans la requête web.

La réponse d'import/réimport inclut un booléen `deduplication_complete` indiquant si la déduplication était terminée au moment où la réponse a été produite (`true` pour `sync` et pour un `async_wait` terminé, `false` pour `async`).

Ceci est indépendant de l'indicateur de profil global `block_execution`, qui force **toutes** les tâches asynchrones d'un utilisateur (notifications, push JIRA, notation des produits, déduplication, ...) au premier plan. Lorsqu'aucun mode d'exécution n'est défini, `block_execution=True` se replie sur `sync`.

## Le champ Service et son impact

- Par défaut, `HASH_CODE_FIELDS_ALWAYS = ["service"]`, ce qui signifie que le `service` associé à une constatation est ajouté au hachage pour tous les scanners.
- Implications pratiques :
  - Deux constatations par ailleurs identiques mais avec des valeurs `service` différentes produiront des hachages différents et ne seront pas dédupliquées via les méthodes basées sur le hachage.
  - Lors de l'import/réimport, le champ `Service` saisi dans l'interface peut remplacer le service fourni par le parseur. Le modifier peut changer le hachage et donc affecter les résultats de la déduplication.
  - Si vous souhaitez que le service n'ait aucun impact sur la déduplication, configurez `HASH_CODE_FIELDS_ALWAYS` en conséquence (voir la page de réglage Open Source). Retirer `service` de la liste toujours incluse l'empêchera d'affecter les hachages.

## Supprimer les constatations dédupliquées

Si vous avez un nombre excessif de Constatations en double que vous souhaitez supprimer, vous pouvez activer l'option **Delete Deduplicate Findings** dans les **System Settings**.

**Delete Deduplicate Findings**, combiné au champ **Maximum Duplicates**, permet à DefectDojo de limiter la quantité de Constatations en double stockées. Lorsque ce champ est activé, DefectDojo ne conservera qu'un certain nombre de Constatations en double.

### Quels doublons seront supprimés ?

La Constatation originale ne sera jamais supprimée automatiquement de DefectDojo, mais une fois le seuil du champ Maximum Duplicates dépassé, DefectDojo supprimera automatiquement la plus ancienne Constatation en double.

Par exemple, supposons que vous ayez défini le champ Maximum Duplicates sur « 1 ».

1. Tout d'abord, vous importez **Test 1\.** Votre rapport contient une vulnérabilité qui est enregistrée comme Constatation A.
2. **Plus tard, vous importez le Test 2, qui contient la même vulnérabilité. Celle-ci sera enregistrée comme Constatation B, et la Constatation B sera marquée comme doublon de la Constatation A.**
3. Plus tard encore, vous importez **Test 3**, qui contient également cette vulnérabilité. Celle-ci sera enregistrée comme Constatation C, qui sera marquée comme doublon de la Constatation A. À ce moment-là, la Constatation B sera supprimée de DefectDojo, le seuil du nombre maximal de doublons ayant été dépassé.

### Application de ce paramètre

L'application de **Delete Deduplicate Findings** déclenchera immédiatement un processus de suppression. Ce paramètre peut être appliqué sur la page **System Settings**. Consultez la section Activer la déduplication pour plus d'informations.

## Dépannage de la déduplication

Il arrive que la Déduplication ne fonctionne pas comme prévu.  Voici quelques exemples de situations où la Déduplication pourrait ne pas fonctionner correctement, accompagnés de solutions possibles.

| What you see | Most likely cause | What to tune |
| --- | --- | --- |
| Le Réimport clôture une ancienne Constatation et en crée une nouvelle alors que seul le numéro de ligne a changé | La correspondance de Réimport utilise des champs instables (par exemple, le numéro de ligne) | <strong>Déduplication de Réimport</strong> (privilégier des identifiants stables ou des champs de hachage stables) |
| Plusieurs Constatations sont créées dans le même Test alors que vous pensez qu'elles devraient être des doublons | La correspondance de déduplication n'est pas configurée pour cet outil ou cette portée | <strong>Déduplication du même outil</strong> (et envisagez le comportement « Delete Deduplicate Findings ») |
| Des doublons sont créés entre différents outils | La correspondance inter-outils est désactivée ou trop stricte | <strong>Déduplication inter-outils (Pro uniquement)</strong> (correspondance basée sur le hachage) |
| La même dépendance SCA importée dans plusieurs Produits crée des Constatations distinctes au lieu de doublons | La déduplication est limitée par Produit par défaut | <strong>Déduplication globale des composants (Pro uniquement)</strong> ([activer pour vos outils SCA](/triage_findings/finding_deduplication/pro__global_component_deduplication/)), ou, dans le modèle de données Locations, <strong>Déduplication globale des emplacements (Pro uniquement)</strong> ([correspondance sur un emplacement partagé](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| La même URL / Constatation web importée dans plusieurs Produits crée des Constatations distinctes au lieu de doublons | La déduplication est limitée par Produit par défaut, et Global Component ne fait correspondre que les composants | <strong>Déduplication globale des emplacements (Pro uniquement)</strong> ([faire correspondre les Constatations DAST/URL entre Produits](/triage_findings/finding_deduplication/pro__global_locations_deduplication/)) |
| Un excès de doublons de la même Constatation est créé, entre plusieurs Tests | La hiérarchie des actifs (Asset Hierarchy) n'est pas configurée correctement | [Envisagez le Réimport pour les tests continus](/triage_findings/finding_deduplication/avoid_excess_duplicates/) |

Lorsque la déduplication automatique ne détecte pas des Constatations que vous pensez liées, vous pouvez les relier manuellement depuis la page Afficher la Constatation. Consultez Constatations similaires pour savoir comment découvrir des Constatations liées et les marquer manuellement comme doublons ([Open Source](/triage_findings/finding_deduplication/os__similar_findings/) | [Pro](/triage_findings/finding_deduplication/pro__similar_findings/)).
