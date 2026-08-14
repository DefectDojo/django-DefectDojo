---
title: Historique des faux positifs
description: Marque automatiquement les nouvelles Constatations comme faux positif
  lorsqu'une Constatation correspondante a déjà été triée ainsi
weight: 7
---

**L'historique des faux positifs** évite à votre équipe de trier sans cesse le même faux positif. Lorsqu'il est activé et qu'une Constatation est importée, DefectDojo recherche les Constatations existantes dans le même Produit qui lui correspondent, et si l'une d'elles est déjà marquée **Faux positif**, la Constatation entrante est également marquée Faux positif.

> **Cette fonctionnalité est marquée EXPÉRIMENTALE dans le produit**, et elle **ne peut pas être utilisée en même temps que la Déduplication.** Lisez [Quand pouvez-vous l'utiliser](#when-you-can-use-it) avant de l'activer.

## Ce qu'elle fait

Supposons qu'un scanner signale une constatation que votre équipe examine et marque comme faux positif. À chaque scan ultérieur, cette même constatation revient. Normalement, quelqu'un doit la rejeter à chaque fois. Avec l'Historique des faux positifs activé, DefectDojo reconnaît la constatation récurrente et la marque automatiquement comme Faux positif.

Les Constatations marquées de cette manière sont également définies comme **inactives** et **non vérifiées**, pas seulement Faux positif. C'est intentionnel — la constatation sort entièrement de votre file active — mais cela surprend les personnes qui s'attendent à ce que seul l'indicateur Faux positif change.

La règle que DefectDojo applique est la suivante : *au sein d'un Produit, si une Constatation est un faux positif, toutes les Constatations correspondantes le sont aussi.*

### Mode rétroactif

L'**historique rétroactif des faux positifs** applique la même règle à l'envers. Lorsque vous marquez une Constatation comme faux positif, toute autre Constatation **active** correspondante dans ce Produit est également marquée Faux positif.

Cela réécrit des données existantes. Il n'y a ni aperçu ni invite de confirmation — le changement se produit simplement à travers le Produit. Activez-le délibérément.

## Quand pouvez-vous l'utiliser

**L'historique des faux positifs et la Déduplication sont mutuellement exclusifs.** Les deux résolvent des problèmes qui se recoupent, DefectDojo ne permet donc pas d'exécuter les deux à la fois : dans les System Settings, activer l'un grise l'autre, et activer la Déduplication efface les paramètres de l'Historique des faux positifs.

C'est l'élément le plus important à comprendre à propos de cette fonctionnalité. La plupart des instances utilisent la Déduplication, et pour celles-ci, l'Historique des faux positifs n'est pas disponible. Il est destiné aux instances qui ont délibérément choisi de ne pas dédupliquer.

## Activer la fonctionnalité

Les deux paramètres se trouvent dans les **System Settings**, dans le bloc de déduplication, et sont tous deux **désactivés par défaut** :

| Setting | What it does |
| --- | --- |
| **Enable False Positive History** | Active la fonctionnalité pour l'instance. |
| **Enable Retroactive False Positive History** | Applique également la règle à l'envers, comme décrit ci-dessus. Nécessite le paramètre ci-dessus. |

Ces paramètres sont **valables pour toute l'instance**. Il n'existe pas de dérogation par Produit ou par outil — l'activation de cette fonctionnalité affecte tous les Produits de l'instance.

## Ce qui constitue une correspondance

L'Historique des faux positifs détermine si deux Constatations sont « identiques » en utilisant **l'algorithme de déduplication configuré pour l'outil qui les a signalées** — même si la fonctionnalité de Déduplication elle-même doit être désactivée.

| Tool's deduplication algorithm | Findings match when they share |
| --- | --- |
| **Hash Code** | le même code de hachage, construit à partir des champs de code de hachage configurés pour cet outil |
| **Unique ID From Tool** | le même identifiant unique fourni par l'outil |
| **Unique ID From Tool or Hash Code** | l'un ou l'autre |
| **Legacy** | le même titre (insensible à la casse) et la même sévérité |

La précision de cette fonctionnalité dépend donc entièrement de la qualité de la configuration de la déduplication pour cet outil. **Réglez l'algorithme et les champs de hachage de l'outil avant d'activer l'Historique des faux positifs** — voir [Réglage de la déduplication](/triage_findings/finding_deduplication/pro__deduplication_tuning/) (Pro) ou [Réglage de la déduplication](/triage_findings/finding_deduplication/os__deduplication_tuning/) (Open Source).

La correspondance est limitée **à un seul Produit**. Elle ne s'étend jamais entre plusieurs Produits, et ne s'applique jamais à l'échelle de l'instance.

### Correspondance par ensemble (Pro)

Dans DefectDojo Pro, la correspondance respecte également les **champs de code de hachage basés sur des ensembles** — les correspondances d'identifiant de vulnérabilité et de CWE (`vulnerability_ids_partial`, `vulnerability_ids_subset`, `cwes_partial`, `cwes_subset`, et leurs formes de correspondance exacte), avec la même signification que dans la déduplication.

Cela rend la correspondance de Pro **plus étroite** que celle d'Open Source, et c'est précisément le but : sans cela, l'Historique des faux positifs pourrait propager un faux positif à des Constatations que la déduplication du même outil n'aurait jamais considérées comme des doublons. Ce raffinement ne peut que réduire l'ensemble des Constatations marquées — activer Pro ne provoquera jamais le marquage automatique de *davantage* de Constatations.

Sur Open Source, la correspondance repose uniquement sur le code de hachage, elle est donc plus large. Gardez cela à l'esprit lors du réglage.

## Risques à comprendre avant d'activer la fonctionnalité

Cette fonctionnalité marque des Constatations comme faux positif sans qu'un humain ne les examine. Son rayon d'impact est déterminé par votre configuration de déduplication ; une configuration trop permissive est donc dangereuse.

* **Une clé de correspondance trop permissive peut rejeter silencieusement des Constatations non liées.** L'algorithme **Legacy** ne se base que sur le titre et la sévérité — une seule décision de faux positif pourrait donc marquer comme faux positif chaque Constatation partageant le même titre et la même sévérité dans le Produit, y compris les véritables vulnérabilités. Il en va de même pour un ensemble trop large de champs de code de hachage. Resserrez d'abord l'algorithme.
* **Le mode rétroactif réécrit les Constatations existantes** sans aperçu, sans invite, et sans résumé des changements effectués.
* **Les Constatations sont désactivées et non vérifiées**, pas simplement signalées.
* **La mise à jour en masse contourne le traitement habituel effectué à l'enregistrement**, de sorte que les automatisations réagissant à la mise à jour des Constatations peuvent ne pas se déclencher pour les Constatations modifiées de cette manière.
* **Elle est toujours étiquetée EXPÉRIMENTALE** dans DefectDojo lui-même.

Pour la plupart des équipes, une approche plus sûre consiste à conserver la Déduplication activée et à laisser les doublons hériter du statut de leur Constatation originale, plutôt que de passer à l'Historique des faux positifs. Voir [À propos de la déduplication](/triage_findings/finding_deduplication/about_deduplication/).
