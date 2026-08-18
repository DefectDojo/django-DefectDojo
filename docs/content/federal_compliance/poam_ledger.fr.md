---
title: Le registre POA&M
description: Comment les éléments du POA&M sont créés à partir des constatations,
  et les conventions suivies par le registre
weight: 2
audience: pro
---

Les éléments du POA&M sont créés et mis à jour automatiquement à partir des constatations. La synchronisation
s'exécute peu après les imports et les modifications de constatations, et un balayage nocturne rattrape tout ce
qui serait passé au travers. Vous pouvez également ajouter des éléments manuellement, pour les faiblesses
qu'aucun scanner ne signale.

![The POA&M ledger](images/02-poam-items.png)

## Conventions du registre

Le registre suit les conventions FedRAMP :

* **Numérotation stable.** Chaque élément conserve un numéro de séquence au sein de son système, et les numéros
  ne sont jamais réutilisés.
* **Les constatations groupées se consolident.** Le même CVE présent sur de nombreux hôtes devient un seul
  élément, avec chaque asset concerné répertorié dessus.
* **Les constatations de configuration peuvent se consolider sous CM-6**, plutôt que de saturer le registre d'un
  élément par règle de benchmark. Dans la capture d'écran ci-dessus, `V-4` est cet élément consolidé.
* **Les éléments clos ne rouvrent jamais.** Si la même faiblesse revient, le registre ouvre un nouvel élément
  qui référence l'ancien, de sorte que votre historique de remédiation reste intact.

## Modifier un élément

Le crayon sur n'importe quelle ligne ouvre l'élément pour modification.

![Editing a POA&M item](images/03-poam-item-detail.png)

À partir de là, vous définissez le point de contact, les ressources nécessaires, et le plan de remédiation, et
vous enregistrez toute dérogation.

### Dérogations

Les dérogations sont suivies sous forme de trois états distincts sur chaque élément :

| Deviation | Values |
| --- | --- |
| Faux positif | No, Pending, or Yes |
| Risk Adjustment | No, Pending, or Yes |
| Operational Requirement | No, Pending, or Yes |

Chacune porte une **Deviation Rationale** partagée. Un ajustement de risque enregistre également l'**Adjusted
Risk Rating** à côté de l'original, et les deux apparaissent sur les livrables générés.

### Dépendances fournisseur

Les éléments peuvent porter un indicateur **Vendor Dependency** et le nom **Vendor Product**, pour les faiblesses
que vous ne pouvez pas remédier directement. La date de votre dernier point de contact avec le fournisseur est
suivie avec l'élément.

## Suivi KEV

Les éléments liés à une CISA Known Exploited Vulnerability portent la date d'échéance KEV. Cette date plafonne
également le délai de remédiation — voir [Délais de remédiation](../remediation_slas).

## Jalons

Les jalons portent une description avec des dates prévues et effectives, et apparaissent à la fois dans les
sorties Excel et OSCAL. Ils sont gérés via l'API de conformité plutôt que sur le formulaire de l'élément.

## Ajouter un élément manuellement

Ajoutez un élément pour une faiblesse qu'aucun scanner ne signale. Les éléments créés manuellement se comportent
comme les éléments synchronisés : ils prennent le numéro de séquence suivant, acceptent les dérogations et les
jalons, et apparaissent sur le prochain instantané.

## Traçabilité

Les éléments du POA&M, les jalons, et les dérogations sont tous sous historique d'audit. Chaque modification
enregistre qui, quoi, et quand.
