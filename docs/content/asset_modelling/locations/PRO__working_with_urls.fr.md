---
title: Utilisation des URL
description: Utilisation quotidienne des Emplacements URL en remplacement des Points
  de terminaison
audience: pro
weight: 4
---

Les Emplacements URL constituent le remplacement fonctionnel de l'ancien modèle Endpoints. Ils stockent les mêmes champs en forme d'URL que ceux que vous connaissez déjà — `protocol`, `host`, `port`, `path`, `query`, `fragment` — et jouent le même rôle : identifier *où* vit une Constatation d'application web.

Cette page couvre ce qui change lorsque vous commencez à utiliser les Emplacements URL au quotidien, les nouvelles surfaces d'interface, et les points de terminaison d'API à utiliser à la place de l'API Endpoint héritée.

## Le sous-type URL

Chaque URL est un Emplacement. Cela signifie qu'une URL possède à la fois :

- Les champs URL structurés (`protocol`, `user_info`, `host`, `port`, `path`, `query`, `fragment`, ainsi qu'un `hash` utilisé pour la déduplication).
- Les champs Emplacement partagés (`location_type="url"`, une chaîne canonique `location_value` pour l'affichage et la recherche, les étiquettes, les étiquettes héritées, les métadonnées, et les liens Reference vers les Actifs et les Constatations).

Lorsque vous créez ou importez une URL, DefectDojo l'analyse pour en extraire les champs structurés et écrit à la fois la ligne URL et sa ligne Emplacement parente dans une seule transaction. La déduplication des URL se fait par correspondance exacte sur les champs structurés — deux URL sont considérées comme identiques si chaque composant correspond, avec la réduction standard du port par défaut (`http://example.com:80/` et `http://example.com/` correspondent à la même URL).

## Dans l'interface Pro

Lorsque la fonctionnalité Emplacements est activée, la navigation expose :

- **Emplacements / Tous** — Une liste de tous les Emplacements, tous sous-types URL et Dépendance confondus. Filtrez par type, statut, Actif, Constatation ou étiquette.
- **Emplacements / URL** — Une liste restreinte aux seuls Emplacements URL. C'est l'équivalent le plus proche de l'ancienne page Endpoints.
- **Nouvelle URL** — Un formulaire pour créer une seule URL avec des champs structurés, des étiquettes, et des associations optionnelles à un Actif/une Constatation.
- **Emplacements sur un Actif** — Depuis n'importe quel Actif, l'onglet **Emplacements** affiche les URL et Dépendances rattachées à cet Actif, avec des décomptes de statut et des actions rapides.

Les flux de travail courants de l'interface Endpoints sont préservés :

- **Mises à jour groupées de statut.** Sélectionnez plusieurs Emplacements URL et appliquez un statut (Actif, Atténué, Faux positif, Risque accepté, Hors périmètre) à leurs références de Constatation en une seule action.
- **Ajout d'URL existantes à un Actif.** Utilisez **Ajouter existant** dans l'onglet Emplacements d'un Actif pour relier des URL déjà présentes dans le système plutôt que de créer des doublons.
- **Étiquettes.** Les étiquettes appliquées à un Emplacement URL se propagent en tant qu'étiquettes héritées sur les Constatations qui le référencent, de la même manière que le faisaient auparavant les étiquettes des Points de terminaison.

## Modèle de statut

Les Emplacements URL utilisent les mêmes libellés de statut unique que tous les autres Emplacements :

| Statut | Signification |
| --- | --- |
| **Actif** | La Constatation à cette URL est ouverte. |
| **Atténué** | La Constatation a été corrigée pour cette URL. |
| **Faux positif** | La Constatation n'est pas une vraie vulnérabilité pour cette URL. |
| **Risque accepté** | La Constatation est reconnue mais acceptée pour cette URL. |
| **Hors périmètre** | Cette URL est exclue de l'engagement. |

Notez que l'ancien modèle Endpoint Status autorisait plusieurs indicateurs simultanément (par ex. `mitigated=True` et `false_positive=True`). Les Emplacements n'appliquent qu'un seul statut à la fois. Si vous avez migré depuis les Points de terminaison, l'indicateur le plus spécifique a été préservé (voir le tableau de mappage dans [Migration depuis les Points de terminaison](../pro__migrating_from_endpoints)).

Les Asset References utilisent un statut plus simple : uniquement **Actif** ou **Atténué**, car le statut au niveau de l'Actif n'a pas besoin du détail d'audit.

## API REST

Utilisez ces points de terminaison à la place de l'API Endpoint héritée :

| Tâche | Point de terminaison |
| --- | --- |
| Lister les URL | `GET /api/v2/urls/` |
| Créer une URL | `POST /api/v2/urls/` |
| Mettre à jour les étiquettes ou métadonnées d'une URL | `PATCH /api/v2/urls/{id}/` |
| Lister tous les Emplacements (URL + Dépendances) | `GET /api/v2/location/?location_type=url` |
| Relier une URL à une Constatation | `POST /api/v2/location_findings/` |
| Relier une URL à un Actif | `POST /api/v2/location_Assets/` |
| Mettre à jour le statut d'un lien de Constatation | `PATCH /api/v2/location_findings/{id}/` |
| Supprimer un lien de Constatation | `DELETE /api/v2/location_findings/{id}/` |

Les filtres sur `/api/v2/urls/` incluent les champs URL structurés ainsi que `tag(s)`, `has_tags`, `Asset`, et le tri par `host`, `Asset`, ou le nombre de constatations actives.

Le point de terminaison hérité `/api/v2/endpoints/` continue de servir le trafic en **lecture** via une couche de compatibilité — voir [Migration depuis les Points de terminaison](../pro__migrating_from_endpoints) pour savoir ce qui est préservé et où cette couche diffère du comportement d'origine. Les **écritures** vers les points de terminaison hérités renvoient `403` et doivent être déplacées vers les points de terminaison ci-dessus.

## Import d'URL depuis les analyses

Les imports de scanners créent automatiquement des Emplacements URL. Lorsqu'un parseur émet une URL pour une Constatation (de la même manière qu'il émettait auparavant un Point de terminaison), l'importeur :

1. Recherche une URL existante dont les champs structurés correspondent, ou en crée une.
2. Crée une Finding Reference reliant la Constatation à l'URL avec le statut **Actif**.
3. Crée (ou réutilise) une Asset Reference afin que l'URL apparaisse également sur l'Actif parent.

Les parseurs DefectDojo qui créaient auparavant des Points de terminaison ont été mis à jour pour créer automatiquement des Emplacements dans Pro.

## Éléments qui se comportent différemment

Quelques petits changements de comportement méritent d'être signalés :

- **Un seul statut par paire URL/Constatation.** Comme décrit ci-dessus, le modèle Endpoint_Status à indicateurs multiples est réduit à un seul statut. Les flux de travail qui basculaient les indicateurs indépendamment doivent choisir une transition unique.
- **Les étiquettes vivent sur l'Emplacement, pas sur l'URL.** Le sous-type URL ne porte pas son propre ensemble d'étiquettes ; les étiquettes appartiennent à l'Emplacement parent. Si vous lisez une URL via l'API, le champ `tags` provient de `location.tags`.
- **La déduplication se fait par URL canonique, pas par Actif.** Deux Actifs ayant la même URL partagent un seul Emplacement URL sous-jacent et le référencent deux fois (une Asset Reference chacun). Ceci est intentionnel et c'est ce qui permet le reporting inter-Actifs.
- **Le champ `endpoints` sur les Constatations.** Lorsque l'indicateur est activé, ce champ de l'API Finding renvoie toujours des lignes, mais celles-ci sont projetées à partir des Emplacements URL plutôt que de la table Endpoint. Traitez-le comme étant en lecture seule et écrivez plutôt via `/api/v2/location_findings/`.
