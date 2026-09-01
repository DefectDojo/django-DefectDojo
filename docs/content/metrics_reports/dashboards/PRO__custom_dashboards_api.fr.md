---
title: Automatiser les tableaux de bord avec l'API
description: Découvrez le catalogue de widgets, créez et mettez à jour des mises en
  page de tableaux de bord, et générez les données de widgets via l'API REST de DefectDojo
  Pro
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : l'API REST des tableaux de bord personnalisables (mises en page, catalogue de widgets et données de widgets) est une fonctionnalité de DefectDojo Pro. Elle est désactivée par défaut — un superutilisateur peut activer les tableaux de bord personnalisables depuis **Settings > Feature Flags**, aussi bien sur les instances Cloud que On-Premise.</span>

L'API REST des tableaux de bord personnalisables vous permet de construire, entièrement depuis du code, les mêmes tableaux de bord que vous assemblez à la main dans l'[interface des tableaux de bord](../custom-dashboards/). Vous pouvez découvrir le catalogue de widgets, créer et mettre à jour des mises en page, définir votre mise en page par défaut, partager des mises en page avec votre équipe, et même générer à la demande les données d'un widget sans réimplémenter le filtrage de DefectDojo. La surface des mises en page a été conçue comme le point d'entrée principal pour les agents d'IA qui construisent des tableaux de bord ; les formes de requête sont donc délibérément introspectables.

Ce guide parcourt le cycle de vie complet : s'authentifier, découvrir le vocabulaire des widgets, créer une mise en page, puis la vérifier et la générer.

## Authentification

Chaque requête s'authentifie au moyen d'un jeton API personnel envoyé dans l'en-tête `Authorization`, avec le préfixe `Token` (et non `Bearer`).

Récupérez votre jeton dans l'interface de DefectDojo Pro, sous **User Settings → API v2 Key**. Stockez-le dans une variable d'environnement afin qu'il ne se retrouve jamais dans l'historique de votre shell ni dans un script versionné :

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

L'URL de base pour tous les appels est celle de votre instance suivie de `/api/v2` :

```
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
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 Important :** L'ensemble de l'API des tableaux de bord dépend de la fonctionnalité des tableaux de bord personnalisables. Tant qu'elle n'est pas activée, chaque point de terminaison renvoie `403 Dashboards 2.0 is not enabled.` — voir [Activer les tableaux de bord personnalisables](../custom-dashboards/#enabling-customizable-dashboards).

> **⚠️ Avis de sécurité :** Votre jeton API donne un accès complet à vos données DefectDojo. Ne le collez jamais dans un chat, une capture d'écran, un ticket ou un fichier versionné. Lisez-le depuis une variable d'environnement, faites-le tourner s'il est un jour exposé, et limitez la portée des jetons à des comptes de service lorsque c'est possible.

## Aperçu de l'API des tableaux de bord

L'API des tableaux de bord se compose de trois groupes de ressources, tous sous `/api/v2/dashboards/`.

| Ressource | Chemin | Ce que c'est | Opérations |
|----------|------|------------|------------|
| Mises en page | `/dashboards/layouts/` | Vos tableaux de bord enregistrés (et les modèles partagés par l'équipe) | `GET` liste, `POST` création, `GET {id}/`, `PATCH {id}/`, `DELETE {id}/`, ainsi que `{id}/clone/`, `{id}/set_default/`, `shared/`, `for_current_user/` |
| Catalogue de widgets | `/dashboards/widget_catalog/` | Le menu des types de widgets, avec un exemple de configuration pour chacun | `GET` (lecture seule) |
| Données de widget | `/dashboards/widget_data/<action>/` | Données générées à la demande pour un widget | 21 actions par widget |

Ces points de terminaison acceptent l'authentification par Token, par Session ou Basic. Toute l'autorisation ligne par ligne et le périmètre des données suivent le contrôle d'accès basé sur les rôles standard de DefectDojo — partager une mise en page n'élargit jamais ce que ses lecteurs peuvent voir.

> **💡 Astuce :** L'interface Vue appelle un miroir interne de ces points de terminaison sous `/api/vue/dashboard_v2/`. Automatisez toujours vos scripts en vous appuyant sur les chemins stables et destinés aux clients `/api/v2/dashboards/` documentés ici.

## Étape 1 : découvrir le vocabulaire

Trois éléments d'un widget sont faciles à mal deviner : le **type de widget**, sa **dimension de regroupement** (group-by, pour les graphiques) et ses **filtres**. L'API vous fournit une source de vérité pour chacun. Récupérez-les d'abord, puis construisez en fonction de ce que le serveur accepte réellement.

### Le catalogue de widgets

`GET /dashboards/widget_catalog/` renvoie chaque type de widget, la catégorie à laquelle il appartient, le ou les points de terminaison de données sur lesquels il s'appuie et — c'est le plus utile — un `config_example` minimal et fonctionnel que vous pouvez copier comme point de départ :

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

La réponse a la forme suivante (tronquée) :

```json
{
  "categories": [
    {"id": "numbers", "label": "Numbers", "description": "Single-glance metrics — counts, KPIs, gauges."},
    {"id": "charts",  "label": "Charts",  "description": "Time-series and distribution visualisations."},
    {"id": "lists",   "label": "Lists & Feeds", "description": "Ranked lists, feeds, and embedded tables."},
    {"id": "static",  "label": "Static & Utility", "description": "Notes, shortcuts, and quick actions."}
  ],
  "widgets": [
    {
      "type": "count",
      "label": "Count",
      "category": "numbers",
      "description": "Single number rendered from a filtered queryset...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/count/"],
      "config_example": {
        "model": "finding",
        "filters": {"status_any": "Active", "severity": "Critical"},
        "icon": "fas fa-ban",
        "color": "danger"
      }
    },
    {
      "type": "graph",
      "label": "Graph",
      "category": "charts",
      "description": "Generic chart over any model + group-by dimension...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/aggregate/"],
      "config_example": {
        "model": "finding",
        "filters": {"duplicate": "false"},
        "group_by": "severity",
        "aggregation": "count",
        "chart_type": "pie",
        "time_bucket": null,
        "limit": null,
        "stacked": false
      }
    }
  ]
}
```

Utilisez le `type` d'un widget comme `type` du widget, et son `config_example` comme point de départ pour le `config` du widget. Le catalogue liste 26 types de widgets répartis dans les quatre catégories.

### Dimensions de regroupement et métriques d'enregistrement

Les widgets de graphique et de classement limitent le regroupement ou le classement à une liste d'autorisation organisée. Découvrez-les par modèle plutôt que de deviner :

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/` renvoie, pour chaque dimension, sa `key` (la valeur à passer comme `group_by`), un `label` lisible et un `kind` :

```json
{
  "model": "finding",
  "dimensions": [
    {"key": "severity",  "label": "Severity",        "kind": "categorical"},
    {"key": "status",    "label": "Status",          "kind": "banded"},
    {"key": "date",      "label": "Discovered Date", "kind": "time"},
    {"key": "test_type", "label": "Test Type",       "kind": "categorical"}
  ]
}
```

Le `kind` a son importance : une dimension `time` (comme `date`) exige que vous envoyiez également un `time_bucket` (`day`/`week`/`month`/`quarter`/`year`) ; une dimension `categorical` ou `banded` n'en a pas besoin. Le champ `priority` n'est volontairement **pas** une dimension de regroupement (c'est un score continu) — utilisez la dimension `risk` pour une vue par bandes, ou le widget dédié **Priority Histogram**.

### Filtres

Les `config.filters` d'un widget utilisent **la même forme de filtre que la vue liste de l'objet** — les valeurs que la page liste émet dans son URL, et non les paramètres de requête REST bruts. Par exemple, sur les constatations : `{"status_any": "Active"}`, `{"severity": "Critical"}`, `{"duplicate": "false"}`, `{"date_past_days": 7}`, `{"sla_days_remaining_less_than_equal_to": 7}` ; sur les assets : `{"grade": "A,B,C"}`, `{"last_scanned_past_days": 90}`. Le moyen le plus rapide de trouver le bon filtre pour un besoin est de l'appliquer sur la page liste correspondante dans l'interface et de le relire depuis la boîte de dialogue de configuration du widget, ou de copier les filtres des modèles partagés préchargés.

> **🔑 Important :** Les **clés** de filtre inconnues **sont ignorées silencieusement** — un filtre mal orthographié ou inexistant ne déclenche pas d'erreur, il ne s'applique simplement pas, laissant le widget afficher une population plus large que prévu. Des *valeurs* invalides pour un filtre réel renvoient `400`. Pensez toujours à [vérifier ce que vous avez construit](#verify-what-you-built) en relisant la mise en page. (Les filtres sont validés via le même FilterSet que celui utilisé par la vue liste, donc des valeurs de liste peuvent être passées sous forme de tableaux pour une correspondance « any-of » : `{"severity": ["Critical", "High"]}`.)

> **💡 Astuce :** La plupart des widgets prennent un `model` valant `finding`, `product`, `engagement` ou `test` — notez l'ancien nom `product` (l'interface appelle ces éléments **Assets**). Le widget **Embedded Table** fait exception : son `model` utilise les noms plus récents `finding`, `asset`, `engagement`, `test`, `risk_acceptance`, `organization` ou `test_type`.

## Étape 2 : créer une mise en page

Une mise en page est créée avec un `POST` vers `/dashboards/layouts/`. Les deux champs qui portent le contenu du tableau de bord sont `widgets` et `layout`, et ils doivent être cohérents entre eux.

### L'objet widget

Chaque entrée du tableau `widgets` a la forme suivante :

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** — un UUID que vous générez. Il relie le widget à sa position dans la grille.
- **`type`** — une valeur `type` issue du catalogue de widgets.
- **`title`** — le titre affiché sur le widget (jusqu'à 200 caractères).
- **`refresh_interval`** — l'intervalle d'actualisation automatique en secondes : `0` (désactivé), `30`, `60`, `300` ou `900`.
- **`config`** — la configuration spécifique au type. Partez du `config_example` du catalogue et ajustez-le. Chaque type de widget valide sa propre configuration côté serveur et renvoie un `400` descriptif en cas de problème.
- **`title_styling`** *(facultatif)* — `{"bold": true, "size": "md"}`, où `size` vaut `sm`, `md` ou `lg`.

### La carte de mise en page (grille)

`layout` est une correspondance entre l'`id` de chaque widget et sa position sur la grille à 12 colonnes :

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`, `y`** — coordonnées de grille en haut à gauche (indexées à partir de 0 ; `x` va de 0 à 11).
- **`w`, `h`** — largeur (en colonnes) et hauteur (en lignes).
- **`min_w`, `min_h`** *(facultatif, valeur par défaut 1)* et **`max_w`, `max_h`** *(facultatif)* — bornes de taille.

> **🔑 Important :** La carte `layout` et la liste `widgets` doivent être cohérentes : **chaque widget a besoin d'une position, et chaque position doit référencer un widget qui existe.** Une incohérence renvoie `400`. Le script de cycle de vie ci-dessous construit les deux ensemble afin que leurs identifiants correspondent toujours.

### Créer la mise en page

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/" \
  -d '{
    "name": "Exec Overview (API)",
    "widgets": [
      {"id": "11111111-1111-4111-8111-111111111111", "type": "count", "title": "Active Critical Findings",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban"}},
      {"id": "22222222-2222-4222-8222-222222222222", "type": "graph", "title": "Findings by Severity",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"duplicate": "false"}, "group_by": "severity", "aggregation": "count", "chart_type": "pie", "time_bucket": null, "limit": null, "stacked": false}}
    ],
    "layout": {
      "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2},
      "22222222-2222-4222-8222-222222222222": {"x": 3, "y": 0, "w": 9, "h": 4, "min_w": 3, "min_h": 3}
    },
    "settings": {}
  }'
```

La réponse renvoie la mise en page enregistrée telle quelle, y compris son nouvel `id`, ainsi que des champs auxiliaires en lecture seule (`is_default`, `is_owned`, `is_catalog`, `category`, `icon`, et des horodatages).

### Actions personnalisées

| Action | Appel | Ce que ça fait |
|--------|------|--------------|
| Définir par défaut | `POST /dashboards/layouts/{id}/set_default/` | Fait de cette mise en page celle que charge votre page d'accueil. Vous ne pouvez définir par défaut qu'une mise en page dont vous êtes propriétaire. |
| Cloner | `POST /dashboards/layouts/{id}/clone/` (corps facultatif `{"name": "..."}`) | Copie une mise en page (la vôtre ou un modèle partagé) dans votre espace, avec de nouveaux identifiants de widgets. Par défaut : `"Copy of <name>"`. |
| Lister les partagées | `GET /dashboards/layouts/shared/` | Liste toutes les mises en page partagées — modèles organisés et mises en page publiées par l'équipe. |
| Amorçage | `GET /dashboards/layouts/for_current_user/` | Renvoie `{"results": [...vos mises en page...], "default_id": <id>}`. Au premier appel, elle clone automatiquement le modèle de démarrage afin que vous récupériez toujours au moins une mise en page. |

Publier une mise en page partagée (`"is_shared": true` à la création ou à la mise à jour) nécessite le rôle global **Maintainer**.

## Étape 3 : générer les données d'un widget (facultatif)

Vous n'avez généralement pas besoin de générer les données vous-même — le tableau de bord s'en charge lorsqu'il affiche un widget. Mais les mêmes points de terminaison `widget_data` sont directement disponibles, ce qui est pratique pour des scripts ou des résumés de chat voulant citer un chiffre en direct. Envoyez le `config` du widget (ou le sous-ensemble pertinent) comme charge utile.

**Un comptage filtré** (`POST`) :

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**Une agrégation par regroupement** (`POST`), les données derrière un Graph :

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/aggregate/" \
  -d '{"model": "finding", "filters": {}, "group_by": "severity", "aggregation": "count"}'
```

```json
{
  "labels": ["Critical", "High", "Medium", "Low", "Info"],
  "series": [{"name": "count", "data": [15, 23, 8, 12, 5]}],
  "group_by": "severity",
  "group_by_label": "Severity",
  "model": "finding",
  "model_label": "Findings",
  "aggregation": "count",
  "time_bucket": null
}
```

L'ensemble complet des actions `widget_data` :

| Action | Méthode | Charge utile / paramètres clés | Renvoie |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | dimensions de regroupement valides |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | métriques valides du mode « records » |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | séries de taux / numérateur / dénominateur |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy` (1 à 2 dimensions) | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | bandes par fenêtre |
| `risk_matrix` | POST | `filters`, `x_dim?` | cellules EPSS × risque (constatations uniquement) |
| `priority_histogram` | POST | `filters`, `bin_count?` | classes d'histogramme (constatations uniquement) |
| `treemap` | POST | `filters`, `metric?` | arborescence de portefeuille imbriquée |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | cellules calendaires par jour |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | séries empilées par tranche d'âge |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | séries MTTR/MTTD appariées |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | séries créées vs clôturées |
| `my_work` | GET | `?buckets=`, `?limit=` | vos affectations / mentions / revues en attente |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | constatations proches de la violation du SLA |
| `recent_activity` | GET | `?model=`, `?limit=` | flux des enregistrements récents |
| `saved_reports` | GET | `?limit=` | modèles de rapport enregistrés *(nécessite Reporting)* |
| `usage` | GET | — | répartition de l'utilisation de la licence *(nécessite Maintainer)* |

## Assembler le tout : un script de cycle de vie complet

Le script ci-dessous exécute l'ensemble du flux en utilisant uniquement la bibliothèque standard de Python 3 — pas de `requests`, pas de paquet tiers. Il lit le jeton depuis `DD_IMPORTER_DOJO_API_TOKEN`, découvre le catalogue de widgets, construit une mise en page à deux widgets (avec la liste `widgets` et la carte `layout` générées ensemble afin que leurs identifiants correspondent toujours), la crée, la définit comme mise en page par défaut, la relit pour vérification, et écrit l'identifiant créé dans `created.json`.

Définissez l'URL de votre instance et exécutez-le :

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_dashboard.py
```

```python
#!/usr/bin/env python3
"""Build a DefectDojo Pro dashboard layout end-to-end using only the stdlib."""

import json
import os
import urllib.error
import urllib.request
import uuid

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset


def api_request(method, path, body=None):
    """Make an authenticated request. Returns parsed JSON."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
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

    return json.loads(payload) if payload else {}


def make_widget(widget_type, title, config, *, x, y, w, h, min_w=2, min_h=2):
    """Build a (widget, position) pair sharing a freshly generated UUID."""
    widget_id = str(uuid.uuid4())
    widget = {
        "id": widget_id,
        "type": widget_type,
        "title": title,
        "refresh_interval": 0,
        "config": config,
    }
    position = {"x": x, "y": y, "w": w, "h": h, "min_w": min_w, "min_h": min_h}
    return widget_id, widget, position


def main():
    created = {}

    # 1. Discover the catalog so we build against real widget types.
    #    (We don't strictly need the response here, but fetching it first
    #    is the recommended pattern — copy a config_example as a starting
    #    point instead of guessing the config shape.)
    catalog = api_request("GET", "/dashboards/widget_catalog/")
    known_types = {w["type"] for w in catalog["widgets"]}
    for required in ("count", "graph"):
        if required not in known_types:
            raise SystemExit(f"Widget type {required!r} not in catalog.")
    print(f"Discovered {len(known_types)} widget types.")

    # 2. Build two widgets and their grid positions together.
    widgets = []
    layout = {}

    _id, widget, pos = make_widget(
        "count",
        "Active Critical Findings",
        {
            "model": "finding",
            "filters": {"status_any": "Active", "severity": "Critical"},
            "color": "danger",
            "icon": "fas fa-ban",
        },
        x=0, y=0, w=3, h=2,
    )
    widgets.append(widget)
    layout[_id] = pos

    _id, widget, pos = make_widget(
        "graph",
        "Findings by Severity",
        {
            "model": "finding",
            "filters": {"duplicate": "false"},
            "group_by": "severity",
            "aggregation": "count",
            "chart_type": "pie",
            "time_bucket": None,
            "limit": None,
            "stacked": False,
        },
        x=3, y=0, w=9, h=4, min_w=3, min_h=3,
    )
    widgets.append(widget)
    layout[_id] = pos

    # 3. Create the layout.
    created_layout = api_request("POST", "/dashboards/layouts/", {
        "name": "Exec Overview (API)",
        "widgets": widgets,
        "layout": layout,
        "settings": {},
    })
    layout_id = created_layout["id"]
    created["layout_id"] = layout_id
    print(f"Created layout id={layout_id} with {len(created_layout['widgets'])} widgets")

    # 4. Make it the default landing dashboard.
    api_request("POST", f"/dashboards/layouts/{layout_id}/set_default/")
    print(f"Set layout id={layout_id} as the default")

    # 5. Read it back to verify widgets + positions survived intact.
    verified = api_request("GET", f"/dashboards/layouts/{layout_id}/")
    assert verified["is_default"] is True, "Layout did not become the default"
    assert len(verified["widgets"]) == len(widgets), "Widget count mismatch"
    assert set(verified["layout"]) == {w["id"] for w in verified["widgets"]}, \
        "Layout map and widgets are out of sync"
    print("Verified: default set, widgets and positions consistent")

    # 6. Record the created ID for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## Vérifier ce que vous avez construit

Comme les clés de filtre invalides sont abandonnées silencieusement, la vérification fait partie du flux de travail — ce n'est pas une pensée après coup.

**Confirmer qu'une mise en page a été enregistrée comme prévu.** Relisez-la avec `GET` et vérifiez `widgets` et `layout` :

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

Pour chaque widget, comparez le `config.filters` renvoyé à ce que vous avez envoyé. Si un filtre attendu est absent, sa clé n'était pas un filtre valide pour ce modèle — vérifiez-la à nouveau par rapport aux filtres de la vue liste de l'objet. Confirmez que `is_default` vaut `true` si vous l'avez défini, et que chaque clé de `layout` correspond à un `id` de widget.

**Vérifier ponctuellement les données d'un widget.** Générez son point de terminaison de données et confirmez que le chiffre correspond à ce que vous attendez :

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**Corriger un widget avec PATCH.** Un `PATCH` vers `/dashboards/layouts/{id}/` avec des `widgets` et un `layout` complets les remplace — envoyez l'ensemble complet souhaité, pas un ensemble partiel.

## Prochaines étapes

- Construisez et organisez les mêmes mises en page de façon interactive dans l'[interface des tableaux de bord personnalisables](../custom-dashboards/).
- Laissez un LLM concevoir et construire des tableaux de bord pour vous avec l'[intégration LLM des tableaux de bord](../custom-dashboards-llm/).
