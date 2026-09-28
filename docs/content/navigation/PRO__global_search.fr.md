---
title: Recherche globale
description: Recherchez parmi les Constatations, Assets et objets associés depuis
  la barre supérieure de DefectDojo Pro
audience: pro
weight: 3
---

DefectDojo Pro inclut une **recherche globale** qui explore vos Constatations et les objets associés depuis une seule zone de recherche dans la barre supérieure. Elle s'appuie sur la recherche plein texte native de Postgres avec une correspondance floue, tolérante aux fautes de frappe, afin que vous puissiez trouver un objet sans vous souvenir de sa formulation exacte.

## Lancer une recherche

- **Zone de recherche de la barre supérieure** — cliquez sur la zone **Search** dans la navigation supérieure et commencez à taper. Au fur et à mesure de votre saisie, un menu déroulant affiche un aperçu des meilleures correspondances **groupées par type d'objet**, avec un compteur à côté de chaque type et un lien **See all *N* results** en bas.
- **Page de résultats complète** — appuyez sur **Enter**, ou cliquez sur **See all *N* results**, pour ouvrir la page de résultats complète. Il s'agit d'un tableau unique, triable et filtrable, regroupant toutes les correspondances tous types d'objets confondus.

Les résultats sont toujours **limités à ce que vous êtes autorisé à consulter** — la recherche globale ne fait jamais apparaître d'objets auxquels vous n'auriez pas accès autrement. (Les Finding Templates constituent la seule exception : comme ailleurs dans DefectDojo, ils sont visibles par tout utilisateur connecté.)

## Ce que vous pouvez rechercher

La recherche globale couvre les types d'objets suivants :

| Type d'objet | Remarques |
| --- | --- |
| **Constatations** | |
| **Assets** | (Produits) |
| **Organizations** | (Types de produit) |
| **Engagements** | |
| **Tests** | |
| **Points de terminaison** *ou* **Locations** | Selon ce qu'utilise votre instance — les instances avec [Locations](/asset_modelling/locations/pro__locations_overview/) activées recherchent parmi les Locations ; les autres recherchent parmi les Points de terminaison. |
| **Finding Templates** | |
| **Technologies** | |
| **Vulnerability IDs** | par exemple les CVE |

Pour la plupart des types, la recherche porte sur le **nom/titre et la description** de l'objet. Pour les Constatations, les Assets, les Engagements et les Tests, elle porte également sur les **étiquettes** (par préfixe). Les Vulnerability IDs sont recherchés sur la valeur de l'identifiant lui-même.

## Syntaxe de requête

### Texte libre

Saisissez n'importe quels mots-clés pour rechercher sur tout à la fois. Les résultats sont classés par pertinence, les correspondances sur le titre/nom étant classées avant celles sur la description. La correspondance floue (voir ci-dessous) permet aux termes proches mais non exacts de tout de même correspondre.

### Expressions entre guillemets

Placez une expression entre guillemets doubles pour la garder groupée — `"space inside"` est traité comme un seul terme plutôt que deux mots-clés.

### Opérateurs

Préfixez un terme avec un opérateur (`operator:value`) pour restreindre la recherche. Opérateurs pris en charge :

| Opérateur | Ce qu'il fait |
| --- | --- |
| `finding:` `product:` `engagement:` `test:` `template:` `technology:` | Limite la recherche à un seul type d'objet et y recherche la valeur (par exemple `finding:sqli`). |
| `id:` | Recherche une Constatation par son ID numérique (par exemple `id:12345`). |
| `endpoint:` | Trouve les Constatations dont l'hôte endpoint/location contient la valeur. |
| `vulnerability_id:` | Correspondance exacte sur un Vulnerability ID. Accepte une liste séparée par des virgules, et peut être répété (par exemple `vulnerability_id:CVE-2020-1234,CVE-2018-7489`). |
| `tag:` / `tags:` | Filtre les objets par étiquette. `tag:` correspond à une seule étiquette par sous-chaîne ; `tags:` correspond à n'importe quelle étiquette d'une liste. |
| `test-tag:` `engagement-tag:` `product-tag:` (et leurs pluriels `-tags`) | Filtre par une étiquette sur le Test, l'Engagement ou l'Asset associé, plutôt que sur l'objet lui-même. |
| `not-tag:` `not-tags:` (et les variantes relationnelles `not-…-tag`) | Inverse n'importe lequel des opérateurs d'étiquette ci-dessus pour **exclure** des correspondances. |

Vous pouvez combiner des opérateurs avec des mots-clés en texte libre dans la même requête.

### Correspondance floue

Pour les requêtes de **trois caractères ou plus**, la recherche globale effectue également une correspondance par trigrammes (similarité de mots). Cela tolère les fautes de frappe et permet de trouver des termes **à l'intérieur** de valeurs plus longues comportant des points ou des tirets — par exemple, `internal` correspond à `api.internal.example.com`.

## Filtrer et trier la page de résultats

Sur la page de résultats complète, les colonnes peuvent être filtrées et triées indépendamment du texte de la requête — filtrez par **type d'objet**, **sévérité**, **titre** ou **contexte**, et triez par n'importe quelle colonne. Ces options sont distinctes de la syntaxe `operator:` décrite ci-dessus et s'appliquent au tableau de résultats fusionné.

## Limites de résultats

- La page de résultats complète est **paginée** (25 lignes par page par défaut).
- Chaque type d'objet contribue jusqu'à un **nombre maximal de correspondances** par recherche — **100** par défaut. Lorsqu'il existe plus de correspondances que celles affichées, les résultats sont signalés comme tronqués ; affinez votre requête pour voir les résultats les plus pertinents.
- Le menu déroulant de la barre supérieure affiche un aperçu plus restreint (les meilleures correspondances par type) avec les totaux, de sorte que **See all *N* results** reflète toujours les totaux réels.
