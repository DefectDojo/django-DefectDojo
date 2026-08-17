---
title: Automatiser les rapports avec l'API
description: Créez des thèmes, des blocs et des modèles, puis exécutez des rapports
  et téléchargez les résultats via l'API REST DefectDojo Pro
draft: false
audience: pro
weight: 21
slug: report-builder-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : l'API REST Report Builder (thèmes de rapport, blocs, modèles et rapports générés) est une fonctionnalité de DefectDojo Pro, actuellement en version bêta.</span>

L'API REST Report Builder vous permet d'automatiser les mêmes thèmes, blocs et modèles que vous assemblez manuellement dans l'[interface Report Builder](../report-builder/) — et elle va plus loin en vous permettant d'**exécuter** un modèle et de **télécharger** le PDF ou le HTML final. Ce guide parcourt l'ensemble du cycle de vie : s'authentifier, découvrir le vocabulaire des champs et des filtres, créer les blocs de construction, puis générer et récupérer un rapport.

> **Vous cherchez plutôt un export rapide des constatations ?** Si vous avez seulement besoin d'une liste plate de constatations au format JSON, HTML, CSV ou Excel — sans thèmes, blocs ni modèles à configurer — utilisez le point de terminaison plus simple `generate_report/` documenté dans [Générer des rapports](/automation/api/api-v2-docs/#generating-reports). L'API Report Builder décrite sur cette page sert à construire des rapports conçus, à sections multiples.

## Authentification

Chaque requête s'authentifie à l'aide d'un jeton d'API personnel envoyé dans l'en-tête `Authorization` avec le préfixe `Token` (et non `Bearer`).

Récupérez votre jeton depuis l'interface DefectDojo Pro sous **User Settings → API v2 Key**. Stockez-le dans une variable d'environnement afin qu'il ne se retrouve jamais dans votre historique de shell ou dans un script commité :

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

L'URL de base pour tous les appels est votre instance suivie de `/api/v2` :

```text
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

En-têtes requis :

| En-tête | Valeur | Quand |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | Chaque requête |
| `Accept` | `application/json` | Chaque requête |
| `Content-Type` | `application/json` | `POST` / `PATCH` avec un corps JSON |

Voici à quoi ressemble une requête authentifiée minimale :

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

Les points de terminaison de liste sont paginés à l'aide des paramètres de requête `limit` et `offset`.

> **⚠️ Avis de sécurité :** Votre jeton d'API donne un accès complet à vos données DefectDojo. Ne le collez jamais dans une conversation, une capture d'écran, un ticket ou un fichier commité. Lisez-le depuis une variable d'environnement, régénérez-le s'il est un jour exposé, et limitez la portée des jetons à des comptes de service lorsque c'est possible.

## Aperçu de l'API de reporting

Quatre ressources composent l'API Report Builder. Chacune prend en charge les opérations standard de liste (`GET`), de création (`POST`), de récupération (`GET {id}/`), de mise à jour (`PATCH {id}/`) et de suppression (`DELETE {id}/`), ainsi que quelques actions personnalisées.

| Ressource | Chemin | Description | Actions personnalisées |
|----------|------|------------|----------------|
| Thèmes | `/report_themes/` | Couleurs, polices, images d'en-tête/pied de page, numéros de page | — |
| Blocs | `/report_blocks/` | Un élément de contenu unique : une page de couverture, un tableau ou une section détaillée | `field_options/`, `preview/`, `{id}/preview/`, `{id}/duplicate/` |
| Modèles | `/report_templates/` | Une liste ordonnée de blocs associée à un thème | `{id}/duplicate/` |
| Rapports générés | `/generated_reports/` | Une exécution d'un modèle qui produit un fichier téléchargeable | `{id}/download/` |

Deux points de terminaison supplémentaires vous aident à découvrir le vocabulaire dont vous avez besoin :

| Point de terminaison | Objectif |
|----------|---------|
| `GET /report_blocks/field_options/` | Les chemins de champs de colonnes valides et les options de tri pour chaque modèle |
| `GET /oa3/schema/?format=json` | Le schéma OpenAPI complet — utilisé pour découvrir les noms de filtres valides |

## Étape 1 : découvrir le vocabulaire

Deux éléments d'un bloc sont faciles à mal renseigner si vous devinez : les **champs de colonnes** que vous listez, et les **filtres** que vous appliquez. L'API vous fournit une source de vérité pour les deux. Récupérez-les d'abord, puis construisez en fonction de ce que le serveur accepte réellement.

### Champs de colonnes et tri

`field_options` renvoie les `fields` (chemins de colonnes) et les `ordering_fields` valides pour chaque modèle que vous pouvez placer dans un bloc tabulaire ou détaillé :

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

Voici la forme de la réponse (tronquée) :

```json
{
  "fields": {
    "finding": [
      {"path": "title", "label": "Title"},
      {"path": "severity", "label": "Severity"},
      {"path": "age_days", "label": "Age (days)"}
    ],
    "asset": [ ... ]
  },
  "ordering_fields": {
    "finding": [ ... ]
  }
}
```

N'utilisez que les valeurs `path` renvoyées ici pour la liste `fields` d'un bloc. Certains chemins sont en format long ou en markdown et sont destinés aux blocs **detail** plutôt qu'à des colonnes tabulaires étroites — `field_options` est la liste faisant autorité, donc vérifiez-la plutôt que de coder en dur un ensemble exhaustif.

### Noms de filtres à partir du schéma

Les filtres d'un bloc résident dans `filter_entries`, où chaque entrée est une paire `{field, value}`. Les noms de `field` valides sont les **noms des paramètres de requête GET** du point de terminaison REST de l'entité sous-jacente — *pas* les libellés que vous voyez dans l'interface. Découvrez-les en lisant le schéma OpenAPI :

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

Lisez ensuite les paramètres GET pour l'entité que vous filtrez. Pour les constatations, consultez `paths` → `/api/v2/findings/` → `get` → `parameters`. Les points de terminaison analogues sont `/api/v2/assets/` pour les **assets** (anciennement Products), `/api/v2/organizations/` pour les **organizations** (anciennement Product Types), `/api/v2/engagements/`, `/api/v2/tests/`, `/api/v2/test_types/`, et `/api/v2/risk_acceptance/`. Chaque `name` de paramètre est un `field` de filtre valide.

> **💡 Astuce :** Dans DefectDojo Pro, les **Assets** s'appelaient auparavant **Products** et les **Organizations** s'appelaient auparavant **Product Types**. Les chemins de champs de filtre sous-jacents sur les constatations utilisent toujours l'ancienne terminologie `product` (par exemple, `test__engagement__product`), même si les entités sont désormais des Assets et des Organizations.

> **🔑 Important :** Le serveur **ignore silencieusement** tout `filter_entry` dont le `field` n'est pas un véritable paramètre GET pour ce modèle. Aucune erreur n'est levée — le filtre n'existe tout simplement pas sur le bloc enregistré. Récupérez toujours le bloc avec un GET après l'avoir créé et comparez les `filter_entries` renvoyées à ce que vous avez envoyé.

### Champs de filtre courants

Les tableaux ci-dessous listent des filtres vérifiés et à forte valeur. Toutes les valeurs sont envoyées sous forme de **chaînes à valeur unique** ; les booléens sont les chaînes littérales `"true"` / `"false"`.

**Filtres de constatation**

| Champ | Exemple de valeur | Remarques |
|-------|---------------|-------|
| `active` | `"true"` | Chaîne booléenne |
| `verified` | `"true"` | Chaîne booléenne |
| `is_mitigated` | `"false"` | Chaîne booléenne |
| `risk_accepted` | `"false"` | Chaîne booléenne |
| `duplicate` | `"false"` | Chaîne booléenne |
| `false_p` | `"false"` | Chaîne booléenne |
| `out_of_scope` | `"false"` | Chaîne booléenne |
| `severity` | `"Critical"` | Valeur unique seulement — **pas** de liste séparée par des virgules. Utilisez un bloc par sévérité. |
| `known_exploited` | `"true"` | Chaîne booléenne |
| `ransomware_used` | `"true"` | Chaîne booléenne |
| `outside_of_sla` | `"1"` | Chaîne **numérique**, pas une chaîne booléenne |
| `priority_min` | `"800"` | Utilisez `_min`/`_max`, pas `_greater_than` |
| `priority_max` | `"1000"` | Utilisez `_min`/`_max` |
| `tag` | `"DR"` | Une seule étiquette |
| `tags` | `"kev,pci"` | Au moins une (correspond à n'importe quelle étiquette listée) |
| `tags__and` | `"kev,pci"` | Toutes (doit correspondre à chaque étiquette listée) |
| `test__engagement__product` | `"42"` | ID de l'asset (les Assets s'appelaient auparavant Products) |
| `test__engagement__product__prod_type` | `"3"` | ID de l'organization (anciennement Product Type) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**Filtres d'asset** (les Assets s'appelaient auparavant Products ; ce sont les paramètres de `/api/v2/assets/`)

| Champ | Exemple de valeur | Remarques |
|-------|---------------|-------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | Chaîne booléenne |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | Une seule étiquette |

**Filtres d'acceptation du risque**

| Champ | Exemple de valeur | Remarques |
|-------|---------------|-------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | ID utilisateur |
| `expiration_date_before` | `"2025-12-31"` | Aucun filtre `tag` n'existe sur ce modèle |

Pour les blocs **engagement**, **test**, **test type** et **organization**, lisez les paramètres GET directement dans le schéma comme décrit ci-dessus. Parmi les plus utiles figurent `engagement__product` et `status` sur les tests, ainsi que `name` sur les types de test — mais confirmez toujours le nom exact dans `schema.json` avant de vous y fier.

> **⚠️** Ces noms hérités / de type interface utilisateur sont **ignorés silencieusement** et ne doivent PAS être utilisés : `status_any`, `priority_greater_than`, `severity__in`, `mitigated_within_sla`, ainsi que toute valeur `severity` **séparée par des virgules** (par ex. `"Critical,High"`). Utilisez à la place les véritables noms de paramètres de requête issus du schéma, et répartissez les besoins multi-sévérité dans des blocs séparés.

> **🔑 Important :** Un `PATCH` qui inclut `filter_entries` **remplace la liste entière** — il n'y a pas de fusion. Envoyez toujours l'ensemble complet des filtres souhaités à chaque mise à jour, sinon vous supprimerez ceux que vous omettez.

## Étape 2 : créer le thème, les blocs et les modèles

Construisez les éléments dans l'ordre des dépendances : un **thème**, puis les **blocs**, puis un **modèle** qui référence les deux.

### Créer un thème

Les couleurs sont des chaînes hexadécimales à 7 caractères. Tout champ que vous omettez reprend sa valeur par défaut (primaire `#1e3a5f`, secondaire `#4a90a4`, accent `#e67e22`, texte `#333333`, arrière-plan `#ffffff`).

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/" \
  -d '{
    "name": "Quarterly Review Theme",
    "primary_color": "#1e3a5f",
    "secondary_color": "#4a90a4",
    "accent_color": "#e67e22",
    "text_color": "#333333",
    "background_color": "#ffffff",
    "footer_text": "Confidential — Internal Use Only",
    "show_page_numbers": true
  }'
```

La réponse inclut le nouvel `id` de thème. Les images d'en-tête et de pied de page sont facultatives et sont téléversées sous forme de champs de formulaire multipart (`header_image` / `footer_image`) ; l'exemple JSON ci-dessus les omet.

### Créer des blocs

Un bloc possède un `name`, un `block_type` et un objet de configuration correspondant. Les valeurs prises en charge pour `block_type` sont `stock`, `tabular` et `detail`. (Un type `chart` existe dans le modèle de données mais n'est pas encore exposé via l'API.)

**Une page de couverture stock.** Les blocs stock contiennent du contenu fixe. `stock_type` vaut `cover_page`, `table_of_contents`, `page_break`, `image` ou `text_block`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Cover Page",
    "block_type": "stock",
    "header": "Cover",
    "stock_configuration": {
      "stock_type": "cover_page",
      "title": "Quarterly Security Report",
      "subtitle": "Q4 — Active Critical Findings"
    }
  }'
```

**Un bloc de constatations tabulaire avec filtres.** Les blocs tabulaires affichent les lignes d'un modèle choisi. `model_choice` vaut exactement `organization`, `asset`, `engagement`, `test`, `finding`, `test_type` ou `risk_acceptance`. Les `fields` proviennent de `field_options` (vérifiez chaque `path`), et `filter_entries` délimite les lignes.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Active Critical Findings",
    "block_type": "tabular",
    "header": "Active Critical Findings",
    "tabular_configuration": {
      "model_choice": "finding",
      "fields": ["severity", "title", "age_days", "sla_days_remaining"],
      "ordering": "-age_days"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

**Un bloc de constatations détaillé.** Les blocs detail affichent une section développée par enregistrement et peuvent inclure des champs longs / en markdown qui ne conviennent pas à une colonne de tableau étroite. Là encore, vérifiez les `fields` par rapport à `field_options`.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Critical Finding Detail",
    "block_type": "detail",
    "header": "Critical Findings — Detail",
    "detail_configuration": {
      "model_choice": "finding",
      "fields": ["title", "severity", "description", "mitigation"],
      "ordering": "-severity"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

Chaque réponse de bloc inclut son `id`. Notez que `filter_entries` reflète ce que le serveur a réellement stocké — comparez-le à ce que vous avez envoyé (voir [Vérifier ce que vous avez construit](#verify-what-you-built)).

### Créer un modèle

Un modèle associe un thème à une liste ordonnée de blocs. Le champ en lecture seule est `template_blocks` ; à la création et à la mise à jour, vous **écrivez** `template_blocks_write`. Chaque entrée nécessite un `order` et un `block_id`, et le même `block_id` peut apparaître plusieurs fois.

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/" \
  -d '{
    "name": "Quarterly Critical Report",
    "description": "Cover page, critical findings table, then per-finding detail",
    "theme_id": 1,
    "template_blocks_write": [
      {"order": 0, "block_id": 10},
      {"order": 1, "block_id": 11},
      {"order": 2, "block_id": 12}
    ]
  }'
```

Remplacez `theme_id` et chaque `block_id` par les identifiants renvoyés lors des étapes précédentes. La réponse inclut l'`id` du modèle.

## Étape 3 : exécuter le rapport et télécharger le résultat

La génération d'un rapport est asynchrone : vous créez une exécution, vous interrogez son statut, puis vous téléchargez le fichier une fois celle-ci terminée.

**Démarrer une exécution.** Envoyez en POST un `template_id` et un `file_format` valant `pdf` ou `html` :

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/" \
  -d '{
    "template_id": 5,
    "file_format": "pdf"
  }'
```

La réponse renvoie le nouvel `id` de rapport avec `status` défini sur `pending`.

**Interroger le statut.** Récupérez le rapport jusqu'à ce que son `status` atteigne un état terminal. Le déroulement est `pending` → `processing` → `completed`. En cas de `failed`, consultez `error_message` pour connaître la raison.

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**Télécharger le fichier.** Une fois que `status` vaut `completed`, le point de terminaison de téléchargement renvoie le fichier en pièce jointe. Il répond avec `404` jusque-là.

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## Tout assembler : un script de cycle de vie complet

Le script ci-dessous exécute l'ensemble du flux en utilisant uniquement la bibliothèque standard de Python 3 — pas de `requests`, pas de paquet tiers. Il lit le jeton depuis `DD_IMPORTER_DOJO_API_TOKEN`, crée un thème, trois blocs et un modèle, lance un rapport, interroge avec un backoff jusqu'à ce qu'il se termine ou échoue, télécharge le résultat, et écrit les identifiants créés dans `created.json`.

Définissez l'URL de votre instance et exécutez-le :

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_report.py
```

```python
#!/usr/bin/env python3
"""Build and run a DefectDojo Pro report end-to-end using only the stdlib."""

import json
import os
import time
import urllib.error
import urllib.request

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset
FILE_FORMAT = "pdf"  # "pdf" or "html"


def api_request(method, path, body=None, accept_json=True):
    """Make an authenticated request. Returns parsed JSON (or raw bytes)."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
    if accept_json:
        request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        # Surface the server's error body to make debugging easy.
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {path} failed ({error.code}): {detail}")

    if accept_json:
        return json.loads(payload) if payload else {}
    return payload


def main():
    created = {}

    # 1. Create a theme.
    theme = api_request("POST", "/report_themes/", {
        "name": "Quarterly Review Theme",
        "primary_color": "#1e3a5f",
        "secondary_color": "#4a90a4",
        "accent_color": "#e67e22",
        "text_color": "#333333",
        "background_color": "#ffffff",
        "footer_text": "Confidential - Internal Use Only",
        "show_page_numbers": True,
    })
    created["theme_id"] = theme["id"]
    print(f"Created theme id={theme['id']}")

    # 2. Create a stock cover page block.
    cover = api_request("POST", "/report_blocks/", {
        "name": "Cover Page",
        "block_type": "stock",
        "header": "Cover",
        "stock_configuration": {
            "stock_type": "cover_page",
            "title": "Quarterly Security Report",
            "subtitle": "Q4 - Active Critical Findings",
        },
    })
    created["cover_block_id"] = cover["id"]
    print(f"Created stock block id={cover['id']}")

    # 3. Create a tabular finding block scoped to active criticals.
    #    Confirm the chosen fields against /report_blocks/field_options/.
    table = api_request("POST", "/report_blocks/", {
        "name": "Active Critical Findings",
        "block_type": "tabular",
        "header": "Active Critical Findings",
        "tabular_configuration": {
            "model_choice": "finding",
            "fields": ["severity", "title", "age_days", "sla_days_remaining"],
            "ordering": "-age_days",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["table_block_id"] = table["id"]
    print(f"Created tabular block id={table['id']}")

    # 4. Create a detail finding block.
    detail = api_request("POST", "/report_blocks/", {
        "name": "Critical Finding Detail",
        "block_type": "detail",
        "header": "Critical Findings - Detail",
        "detail_configuration": {
            "model_choice": "finding",
            "fields": ["title", "severity", "description", "mitigation"],
            "ordering": "-severity",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["detail_block_id"] = detail["id"]
    print(f"Created detail block id={detail['id']}")

    # 5. Create a template binding the theme to the ordered blocks.
    #    Note: we WRITE template_blocks_write; template_blocks is read-only.
    template = api_request("POST", "/report_templates/", {
        "name": "Quarterly Critical Report",
        "description": "Cover, critical findings table, then per-finding detail",
        "theme_id": created["theme_id"],
        "template_blocks_write": [
            {"order": 0, "block_id": created["cover_block_id"]},
            {"order": 1, "block_id": created["table_block_id"]},
            {"order": 2, "block_id": created["detail_block_id"]},
        ],
    })
    created["template_id"] = template["id"]
    print(f"Created template id={template['id']}")

    # 6. Kick off a report run.
    report = api_request("POST", "/generated_reports/", {
        "template_id": created["template_id"],
        "file_format": FILE_FORMAT,
    })
    report_id = report["id"]
    created["report_id"] = report_id
    print(f"Started report id={report_id} (status={report['status']})")

    # 7. Poll until completed or failed, backing off up to 10 seconds.
    delay = 2
    while True:
        time.sleep(delay)
        report = api_request("GET", f"/generated_reports/{report_id}/")
        status = report["status"]
        print(f"  status={status}")
        if status == "completed":
            break
        if status == "failed":
            raise SystemExit(
                f"Report failed: {report.get('error_message', 'unknown error')}"
            )
        delay = min(delay + 2, 10)  # linear backoff, capped

    # 8. Download the finished file.
    content = api_request(
        "GET",
        f"/generated_reports/{report_id}/download/",
        accept_json=False,
    )
    out_name = f"report.{FILE_FORMAT}"
    with open(out_name, "wb") as handle:
        handle.write(content)
    print(f"Downloaded {out_name} ({len(content)} bytes)")

    # 9. Record the created IDs for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Vérifier ce que vous avez construit

Comme les filtres invalides sont abandonnés silencieusement, la vérification fait partie intégrante du flux de travail — ce n'est pas une réflexion après coup.

**Confirmez que les filtres d'un bloc ont bien été conservés.** Récupérez chaque bloc avec un GET et comparez ses `filter_entries` à ce que vous avez envoyé en POST :

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

Si un filtre que vous avez envoyé est absent de `filter_entries`, c'est que son nom de `field` n'était pas un paramètre GET valide pour ce modèle — vérifiez à nouveau le nom dans `schema.json`.

**Confirmez l'ordre du modèle et le thème.** Récupérez le modèle avec un GET et vérifiez que `template_blocks` liste les blocs dans l'`order` attendu et que le thème associé correspond :

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**Corrigez les filtres abandonnés avec PATCH.** Pour corriger les filtres d'un bloc, envoyez en PATCH l'ensemble **complet** souhaité — un PATCH remplace `filter_entries` en totalité :

```bash
curl -s -X PATCH \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/" \
  -d '{
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"},
      {"field": "outside_of_sla", "value": "1"}
    ]
  }'
```

## Prochaines étapes

- Construisez et prévisualisez les mêmes thèmes, blocs et modèles de manière interactive dans l'[interface Report Builder](../report-builder/).
- Laissez un LLM assembler les configurations de rapport pour vous grâce à l'[intégration LLM du Report Builder](../report-builder-llm/).
