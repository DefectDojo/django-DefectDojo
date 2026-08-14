---
title: Migration depuis les Points de terminaison
description: Ce qui se passe lorsque vous migrez des données de Points de terminaison
  existantes vers les Emplacements
audience: pro
weight: 3
---

Lorsque vous activez les Emplacements sur une instance DefectDojo Pro existante, les données déjà stockées sous forme de Points de terminaison doivent être reportées dans le nouveau modèle d'Emplacements. Cette page décrit la migration, ce qu'elle préserve, et comment se comporte l'API Endpoint héritée une fois la migration exécutée.

Notez que la migration est **à sens unique**. Il n'existe aucun chemin de restauration automatisé qui recrée des Points de terminaison à partir des Emplacements.

## Ce que fait la migration

Pour chaque Point de terminaison existant, la migration va :

1. **Créer un Emplacement URL** (ou réutiliser un existant) en utilisant les champs `protocol`, `userinfo`, `host`, `port`, `path`, `query` et `fragment` du Point de terminaison. La nouvelle URL est automatiquement rattachée à un objet `Location` parent.
2. **Reporter les étiquettes.** Chaque étiquette du Point de terminaison est ajoutée à l'ensemble d'étiquettes de l'Emplacement.
3. **Reporter les métadonnées.** Chaque ligne `DojoMeta` rattachée au Point de terminaison est repointée vers le nouvel Emplacement.
4. **Créer une `LocationProductReference`** afin que l'URL apparaisse sous le bon Actif (Produit).
5. **Créer une `LocationFindingReference` pour chaque `Endpoint_Status`** :

   | Indicateur Endpoint_Status | Statut d'Emplacement résultant |
   | --- | --- |
   | `risk_accepted=True` | **Risque accepté** |
   | `false_positive=True` | **Faux positif** |
   | `out_of_scope=True` | **Hors périmètre** |
   | `mitigated=True` | **Atténué** |
   | (aucun des cas ci-dessus) | **Actif** |

   Le mappage est sensible à l'ordre : le *premier* indicateur correspondant l'emporte. Cela réduit intentionnellement les anciennes combinaisons multi-indicateurs à l'unique statut canonique utilisé par les Emplacements.


## Ce que la migration ne fait pas

- Elle ne crée **pas** d'Emplacements de dépendance. Les données de SBOM et de bibliothèques n'ont jamais existé sous forme de Points de terminaison ; il n'y a donc rien à convertir. Pour peupler les Dépendances, importez des SBOM (voir [Utilisation des SBOM](../pro__working_with_sboms)) ou relancez des analyses avec des parseurs qui produisent des données de dépendance.
- Elle ne supprime **pas** les lignes Endpoint ou Endpoint_Status d'origine. Elles restent dans la base de données pour alimenter l'API héritée en lecture seule. Elles ne sont pas utilisées par la nouvelle interface ni par les imports une fois la fonctionnalité activée.

## API Endpoint après la migration

Une fois les Emplacements activés, l'API Endpoint héritée passe dans un mode de **compatibilité en lecture** conçu pour que les automatisations existantes continuent de fonctionner sans modification de code — mais uniquement pour le trafic en lecture.

### Ce qui fonctionne toujours

- `GET /api/v2/endpoints/` — Renvoie des lignes qui *ressemblent* à des Points de terminaison mais qui sont en réalité projetées à partir de lignes Location Product Reference jointes à des Emplacements URL. Les champs familiers (`protocol`, `host`, `port`, `path`, `query`, `fragment`, `tags`, `product`, `active_finding_count`) sont tous présents.
- `GET /api/v2/endpoints/{id}/` — La récupération d'un Point de terminaison unique fonctionne de la même manière. L'`id` est l'identifiant Endpoint d'origine et est préservé pendant la migration via le mappage Asset Reference.
- `GET /api/v2/endpoint_status/` et `GET /api/v2/endpoint_status/{id}/` — Renvoient des lignes projetées à partir de `LocationFindingReference`. Les champs booléens hérités `mitigated`, `false_positive`, `out_of_scope` et `risk_accepted` sont reconstruits.
- Le filtrage par `protocol`, `host`, `port`, `path`, `query`, `fragment`, `product` et `tag(s)` continue de fonctionner.
- L'action `generate_report` sur les Points de terminaison individuels continue de fonctionner.

### Ce qui renvoie 403

- `POST`, `PUT`, `PATCH` et `DELETE` sur `/api/v2/endpoints/` et `/api/v2/endpoint_status/` renvoient tous `HTTP 403` avec le corps suivant :

  > Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled

  Les clients qui écrivent des données Endpoint doivent migrer vers les nouveaux points de terminaison Reference (`POST /api/v2/location_findings/`, `POST /api/v2/location_products/`) et vers le point de terminaison URL (`POST /api/v2/urls/`).

### Différences de comportement à surveiller

Certains éléments se comportent différemment de l'API Endpoint d'origine :

- **Un seul statut au lieu d'indicateurs.** Les Emplacements n'ont qu'un seul statut à la fois. Si votre code s'appuyait sur une Constatation étant *à la fois* `mitigated=True` *et* `false_positive=True` simultanément sur un Endpoint_Status, cela n'est plus représentable — la migration retient l'indicateur de priorité la plus élevée (l'ordre indiqué dans le tableau ci-dessus).
- **Champ `endpoint` sur Endpoint_Status.** Le champ hérité `endpoint` est reconstruit en recherchant l'Asset Reference correspondante. Dans de rares cas où l'Actif d'une Constatation ne correspond plus aux références d'Actif de son Emplacement, ce champ peut être nul.
- **Pagination et tri.** Les champs de tri disponibles sur la couche de compatibilité en lecture sont `host`, `product`, `id` et `active_finding_count`. Si votre client trie sur un autre champ, passez à l'un de ceux-ci ou migrez vers les nouveaux points de terminaison Emplacements.

## Étiquettes et métadonnées

Les étiquettes appliquées aux Points de terminaison deviennent des étiquettes sur l'objet Emplacement (et non sur le sous-type URL). Les filtres basés sur les étiquettes dans l'API héritée continuent de fonctionner.

Les métadonnées des Points de terminaison sont repointées vers l'Emplacement pendant la migration. Les automatisations existantes qui lisent les métadonnées via `/api/v2/endpoint_meta/` devraient continuer de fonctionner ; les nouvelles métadonnées doivent être écrites via les points de terminaison Emplacements.
