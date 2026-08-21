---
title: Réglage de la déduplication
description: 'Configurer la déduplication dans DefectDojo Open Source : algorithmes,
  champs de hachage, points de terminaison et service'
weight: 5
audience: opensource
aliases:
- /fr/en/working_with_findings/finding_deduplication/deduplication_tuning_os
- /fr/en/working_with_findings/finding_deduplication/deduplication_algorithms
---

L'édition Open Source de DefectDojo utilise des fichiers de configuration et des variables d'environnement pour régler la déduplication.

Voir aussi : [Configuration Open Source](/get_started/open_source/configuration/) pour plus de détails sur les variables d'environnement et les surcharges de `local_settings.py`.

## Ce que vous pouvez configurer

- **Algorithme par analyseur** : Choisissez parmi Unique ID From Tool, Hash Code, Unique ID From Tool or Hash Code, ou Legacy (OS uniquement).
- **Champs de hachage par scanner** : Déterminez quels champs contribuent au hachage pour chaque analyseur.
- **Autoriser un CWE nul** : Contrôlez si un CWE manquant/à zéro est acceptable lors du hachage.
- **Prise en compte des points de terminaison** : Utilisez éventuellement les points de terminaison pour la déduplication lorsqu'ils ne font pas partie du hachage.
- **Champs toujours inclus** : Ajoutez des champs (par exemple, `service`) à tous les hachages, quels que soient les paramètres par scanner.

## Paramètres clés (valeurs par défaut affichées)

Toutes les valeurs par défaut sont définies dans `dojo/settings/settings.dist.py`. Vous pouvez les surcharger via l'environnement ou `local_settings.py`.

### Algorithme par analyseur

- Paramètre : `DEDUPLICATION_ALGORITHM_PER_PARSER`
- Valeurs par analyseur : l'une des valeurs `unique_id_from_tool`, `hash_code`, `unique_id_from_tool_or_hash_code`, `legacy`.
- Exemple (chaîne JSON de variable d'environnement) :

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### Champs de hachage par scanner

- Paramètre : `HASHCODE_FIELDS_PER_SCANNER`
- Exemple de valeur par défaut pour Trivy dans OS :

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- Exemple de surcharge (chaîne JSON de variable d'environnement) :

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### Autoriser un CWE nul par scanner

- Paramètre : `HASHCODE_ALLOWS_NULL_CWE`
- Contrôle, par analyseur, si un CWE nul/à zéro est acceptable dans le hachage. Si la valeur est False et que la constatation a `cwe = 0`, le hachage revient au calcul legacy pour cette constatation.

### Champs toujours inclus dans le hachage

- Paramètre : `HASH_CODE_FIELDS_ALWAYS`
- Valeur par défaut : `["service"]`
- Impact : Ajouté au hachage pour chaque scanner. Retirer `service` ici l'empêche d'influencer les hachages de manière globale.

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### Déduplication optionnelle basée sur les points de terminaison

- Paramètre : `DEDUPE_ALGO_ENDPOINT_FIELDS`
- Valeur par défaut : `["host", "path"]`
- Objectif : Si les points de terminaison ne font pas partie des champs de hachage, vous pouvez tout de même exiger une correspondance minimale des points de terminaison pour dédupliquer. Si la liste est vide `[]`, les points de terminaison sont ignorés dans le processus de déduplication.

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## Points de terminaison : comment régler

Les points de terminaison peuvent affecter la déduplication via deux mécanismes :

1) Inclure `endpoints` dans `HASHCODE_FIELDS_PER_SCANNER` pour un analyseur. Les points de terminaison font alors partie du hachage et doivent correspondre exactement selon les règles de hachage de l'analyseur.
2) Si les points de terminaison ne figurent pas dans les champs de hachage, utilisez `DEDUPLE_ALGO_ENDPOINT_FIELDS` pour spécifier les attributs à comparer. Exemples :
   - `[]` : les points de terminaison sont ignorés pour la déduplication.
   - `["host"]` : les constatations sont dédupliquées si une paire de points de terminaison correspond par host.
   - `["host", "port"]` : les constatations sont dédupliquées si une paire de points de terminaison correspond par host ET port.

Remarques :

- Pour l'algorithme Legacy, les constatations statiques et dynamiques ont des règles de correspondance de points de terminaison différentes (voir la page sur les algorithmes). Le paramètre `DEDUPLE_ALGO_ENDPOINT_FIELDS` s'applique au chemin de hash-code, et non à la logique intrinsèque de l'algorithme Legacy.
- Pour la correspondance `unique_id_from_tool` (basée sur l'ID), les points de terminaison sont ignorés pour la décision de déduplication.

## Champ Service : déduplication et réimport

- Avec la valeur par défaut `HASH_CODE_FIELDS_ALWAYS = ["service"]`, le champ `service` est ajouté au hachage. Deux constatations par ailleurs identiques avec des valeurs `service` différentes ne seront pas dédupliquées sur les chemins basés sur le hachage.
- Lors d'un import via l'UI/API, le champ `Service` peut remplacer le service fourni par l'analyseur. Le modifier change le hachage et peut altérer le comportement de déduplication ainsi que la correspondance au réimport.
- Si vous souhaitez une déduplication indépendante du service, retirez `service` de `HASH_CODE_FIELDS_ALWAYS` ou laissez le champ `Service` vide lors de l'import.

## Après avoir modifié les paramètres de déduplication

Après avoir modifié les algorithmes ou le calcul du hachage, vous devrez **recalculer les hachages** pour l'analyseur/type de test concerné avant que le nouveau comportement de correspondance ne s'applique de manière cohérente aux données existantes.

Remarque : Le recalcul des hachages peut entraîner de longs délais d'attente sur les instances volumineuses. Planifiez vos fenêtres de maintenance en conséquence.

Les modifications de la configuration de déduplication (par exemple `HASHCODE_FIELDS_PER_SCANNER`, `HASH_CODE_FIELDS_ALWAYS`, `DEDUPLICATION_ALGORITHM_PER_PARSER`) ne sont pas appliquées rétroactivement automatiquement. Pour réévaluer les constatations existantes, vous devez exécuter la commande de gestion ci-dessous.

### Exécuter la déduplication sur un ensemble de données préexistantes

Lorsque vous configurez les paramètres de déduplication pour la première fois (ou que vous les modifiez ultérieurement), les Constatations importées avant le changement conservent leurs anciens hachages jusqu'à ce que vous relanciez explicitement la déduplication. Utilisez la commande de gestion `dedupe` pour recalculer le hachage et/ou réévaluer les Constatations existantes.

Exécutez-la dans le conteneur uwsgi. Exemple (codes de hachage uniquement, sans déduplication) :

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

Pour **recalculer les hachages et exécuter la déduplication** pour tous les analyseurs (le flux de travail typique « je viens d'activer la déduplication et je veux nettoyer l'arriéré ») :

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe"
```

Pour cibler un seul analyseur en particulier :

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --parser 'Trivy Scan'"
```

Aide/utilisation :
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

Si vous soumettez la déduplication à Celery (sans `--dedupe_sync`), laissez le temps aux tâches de se terminer avant d'évaluer les résultats. Sur les instances volumineuses, cela peut prendre un temps considérable : surveillez les journaux des workers Celery pour suivre la progression.

## Où configurer

- Privilégiez les variables d'environnement dans les déploiements. Pour le développement local ou les surcharges avancées, utilisez `local_settings.py`.
- Consultez `configuration.md` pour plus de détails sur la façon de définir des variables d'environnement et de configurer des surcharges locales.

### Dépannage

Pour vous aider à dépanner la déduplication, utilisez les outils suivants :

- Observez les journaux dans la catégorie `dojo.specific-loggers.deduplication`. Il s'agit d'un logger indépendant des classes qui fournit des détails sur le processus de déduplication et ses paramètres lors du traitement des constatations.
- Observez les valeurs `unique_id_from_tool` et `hash_code` en survolant le champ `ID` ou la colonne `Status` :

![Unique ID from Tool et Hash Code sur la page Afficher la constatation](images/hash_code_id_field.png)

![Unique ID from Tool et Hash Code dans la colonne Statut de la liste des constatations](images/hash_code_status_column.png)
