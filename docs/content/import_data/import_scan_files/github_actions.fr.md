---
title: Importer depuis GitHub Actions
description: Importez des résultats de scan depuis un workflow GitHub Actions avec
  l'action DefectDojo officielle
weight: 3
---

L'[action DefectDojo](https://github.com/marketplace/actions/defectdojo) officielle importe un rapport de scan dans DefectDojo depuis un workflow GitHub Actions. Elle fonctionne avec DefectDojo Pro et avec l'édition Open Source, et lit tous les formats de rapport pris en charge par DefectDojo, y compris SARIF.

Chaque exécution effectue un Reimport dans le même Test : les Constatations que le scanner ne signale plus sont donc clôturées, et chaque Constatation conserve son historique. L'action enregistre le build, la branche, le commit et le dépôt sur le Test, et peut faire échouer l'étape du workflow lorsque des Constatations d'une sévérité choisie restent actives.

## Avant de commencer

1. Créez une clé API v2 pour un utilisateur autorisé à importer dans l'Asset (et à le créer, si vous laissez l'action créer des Assets). La clé se trouve sous **API v2 Token** dans le Menu utilisateur (**API v2 Key** dans l'interface Open Source).
2. Dans le dépôt GitHub, ajoutez la clé comme secret nommé `DEFECTDOJO_API_TOKEN` sous **Settings > Secrets and variables > Actions**.

## Ajouter l'action à un workflow

Exécutez votre scanner, puis transmettez son rapport à l'action :

```yaml
name: Security scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` est le nom du format de rapport tel que DefectDojo le répertorie, par exemple `SARIF`, `Trivy Scan` ou `Semgrep JSON Report`. Consultez [Outils pris en charge](/supported_tools/) pour connaître tous les noms.

## Destination des Constatations

Sauf si vous les définissez, l'action utilise des noms issus du dépôt et crée ceux qui n'existent pas encore :

| Objet DefectDojo | Valeur par défaut | Input |
| --- | --- | --- |
| Organisation (Type de produit) | Propriétaire du dépôt | `organization-name` ou `product-type-name` |
| Asset (Produit) | Nom du dépôt | `asset-name` ou `product-name` |
| Engagement | Nom de la branche | `engagement-name` |
| Test | Type de scan | `test-title` |

Lorsqu'un même Engagement reçoit plusieurs rapports du même type de scan, donnez à chacun son propre `test-title` afin que chaque Reimport retrouve son propre Test.

### Branches, pull requests et tags

Chaque branche dispose de son propre Engagement : le scan d'une pull request ne clôture donc jamais, et ne rouvre jamais, des Constatations de la branche par défaut. Les pull requests utilisent leur branche source, les tags utilisent le nom du tag, et la file de fusion (merge queue) utilise un Engagement par branche de base.

Les Engagements que l'action crée pour toute autre branche que la branche par défaut ne dédupliquent qu'à l'intérieur d'eux-mêmes (**Déduplication au sein de cet engagement uniquement**). Sans cela, une Constatation vue d'abord sur une branche marquerait comme doublon sa copie sur la branche par défaut. Si vous définissez vous-même `engagement-name` ou `deduplication-on-engagement`, ce comportement est désactivé : un Engagement que vous nommez dédoublonne alors sur l'ensemble de l'Asset, comme d'habitude. Les Engagements de branche restent dans DefectDojo après la fusion de la branche. Exécutez donc l'import uniquement sur la branche par défaut si vous souhaitez les exclure des compteurs de l'Asset.

## Faire échouer le build

Définissez `fail-on` sur `low`, `medium`, `high` ou `critical` pour faire échouer l'étape lorsque le Test comporte, après l'import, des Constatations actives de cette sévérité ou d'une sévérité supérieure. Les doublons ne sont pas comptés. Le résumé du job affiche les compteurs par sévérité ainsi qu'un lien vers le Test.

## Fonctionnalités Pro

Avec DefectDojo Pro, l'action peut également :

- Envoyer les nouvelles Constatations vers les Connectors configurés pour l'Asset (`push-to-connector: true`).
- Importer de gros rapports en arrière-plan (`background-import: true`). L'action attend la fin du traitement du Test avant de communiquer les compteurs ou d'appliquer `fail-on`.
- Avertir lorsqu'un Asset a été renommé ou déplacé, afin que vous puissiez mettre à jour les noms dans le workflow.

Avec l'édition Open Source, `push-to-connector` et `background-import` sont ignorés avec un avertissement, et l'import s'exécute malgré tout. Définissez `strict: true` pour faire échouer l'étape à la place.

## Pull requests issues de forks

GitHub ne transmet pas les secrets aux workflows exécutés sur des pull requests issues de forks : l'action ne peut donc pas s'y authentifier et l'étape échoue. Exécutez l'import sur `push`, ou ignorez-le pour les pull requests issues de forks :

```yaml
      - name: Import into DefectDojo
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: DefectDojo/defectdojo-action@v1
```

N'utilisez pas `pull_request_target` pour contourner cette limitation : il s'exécute avec vos secrets tout en récupérant du code que vous ne contrôlez pas.

## Tous les inputs et outputs

Le [README de l'action](https://github.com/DefectDojo/defectdojo-action#inputs) répertorie tous les inputs et outputs. La plupart des inputs correspondent à un champ du point de terminaison **/reimport** décrit dans [Importer depuis l'API](/import_data/import_scan_files/api_pipeline_modelling/).
