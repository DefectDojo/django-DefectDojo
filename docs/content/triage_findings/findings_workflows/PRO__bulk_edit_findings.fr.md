---
title: Modification groupée des Constatations
description: Appliquez des modifications de métadonnées, des étiquettes, des notes
  et des demandes de révision à plusieurs Constatations à la fois dans l'interface
  DefectDojo Pro
audience: pro
weight: 3
---

Dans l'interface DefectDojo Pro, les Constatations peuvent être modifiées en masse depuis n'importe quelle liste de Constatations — la page **All Findings**, ou la liste des Constatations au sein d'un Test.

## Sélectionner des Constatations pour une modification groupée

Dans n'importe quel tableau de Constatations, utilisez les cases à cocher situées à côté des Constatations pour les sélectionner. La sélection d'une ou plusieurs Constatations fait apparaître une **barre d'actions groupées** comportant les commandes suivantes :

* **Bulk Edit** — ouvre un formulaire unique permettant d'appliquer des modifications de métadonnées, des étiquettes, des notes et des demandes de révision à toutes les Constatations sélectionnées. C'est la principale interface consolidée (détaillée ci-dessous).
* **Risk Acceptance** — ajoute les Constatations sélectionnées à une **acceptation du risque complète** nouvelle ou existante.
* **Finding Group** — ajoute les Constatations sélectionnées à un **groupe de Constatations** nouveau ou existant, ou les retire de leur groupe.
* **Merge** — fusionne les Constatations sélectionnées en une seule Constatation.
* **Delete** — supprime les Constatations sélectionnées (avec confirmation).

Une commande est désactivée lorsque l'action ne peut pas s'appliquer à votre sélection actuelle — voir [Disponibilité et Constatations ignorées](#availability-and-skipped-findings).

## Bulk Edit

Le bouton **Bulk Edit** ouvre un formulaire unique regroupant toutes les actions groupées au niveau des champs. Ne renseignez que les champs que vous souhaitez modifier et laissez les autres inchangés, puis cliquez sur **Update Selected Findings** pour appliquer les changements. Les actions disponibles sont les suivantes :

* **Severity** — définit la sévérité (Critical, High, Medium, Low ou Info).
* **Status** — applique l'un des statuts suivants : Active, Verified, False Positive, Out of Scope, Mitigated ou Under Defect Review.
* **Date** — définit la date de découverte.
* **Planned Remediation Date** et **Planned Remediation Version**.
* **Simple Risk Acceptance** — Accept Risk ou Unaccept Risk. Cette action ne s'applique qu'aux Constatations dont le Produit a l'acceptation du risque simple activée ; les autres sont ignorées.
* **Tags** — ajoute des étiquettes aux Constatations sélectionnées, ou utilise le bouton bascule **Append / Replace** pour écraser l'ensemble des étiquettes de chaque Constatation (**Append** ajoute les étiquettes ; **Replace** remplace toutes les étiquettes existantes).
* **Replace Specific Tag** — remplace une étiquette nommée par une autre (voir ci-dessous).
* **Note** — ajoute une note, avec un type de note facultatif, à chaque Constatation sélectionnée.
* **Review** — demande ou efface une révision sur les Constatations sélectionnées (voir ci-dessous).
* **Push to Jira** — met en file d'attente les Constatations sélectionnées pour un envoi vers Jira. Affiché uniquement lorsque l'intégration Jira est activée.
* **Push to Connector** — envoie les Constatations sélectionnées vers votre connecteur configuré. Affiché uniquement lorsque cette fonctionnalité est activée.

### Replace Specific Tag

**Replace Specific Tag** effectue un remplacement d'étiquette ciblé et non destructif. Saisissez l'étiquette à remplacer dans **Existing Tag to Replace** et son remplacement dans **New Tag**. Pour chaque Constatation sélectionnée qui porte réellement l'ancienne étiquette, DefectDojo supprime cette étiquette et ajoute la nouvelle — toutes les autres étiquettes sont conservées, et les Constatations qui ne possèdent pas l'ancienne étiquette restent inchangées.

Cette action diffère du champ **Tags** ci-dessus : **Tags** permet soit d'*ajouter* des étiquettes (Append), soit d'*écraser l'ensemble des étiquettes* (Replace), tandis que **Replace Specific Tag** ne modifie que l'étiquette nommée.

### Review

L'action **Review** gère la révision par les pairs pour l'ensemble des Constatations sélectionnées :

* **Request Review** — choisissez un ou plusieurs **Reviewers** et saisissez une **Review Note** (obligatoire). Chaque Constatation sélectionnée passe à l'état *Under Review* (Active, non Verified), les réviseurs choisis sont assignés, une note de demande de révision est ajoutée, et les réviseurs sont notifiés.
* **Clear Review** — saisissez une **Review Note** (obligatoire) pour sortir les Constatations sélectionnées de l'état *Under Review* et effacer leurs réviseurs assignés.

Les réviseurs proposés sont les utilisateurs disposant d'un accès en modification sur les Constatations sélectionnées.

## Risk Acceptance, Finding Group, Merge et Delete

Les autres boutons d'actions groupées ouvrent chacun leur propre boîte de dialogue :

* **Risk Acceptance** — crée une nouvelle **acceptation du risque complète** pour régir les Constatations sélectionnées, ou les ajoute à une acceptation du risque complète existante.
* **Finding Group** — crée un nouveau **groupe de Constatations**, ajoute les Constatations à un groupe existant, ou les retire de leur groupe actuel. Les groupes de Constatations ne peuvent être créés qu'au sein d'un seul **Test** — des Constatations provenant de Tests, d'Engagements ou de Produits différents ne peuvent pas partager le même groupe.
* **Merge** — fusionne plusieurs Constatations sélectionnées (toutes provenant du même Asset) en une seule.
* **Delete** — supprime les Constatations sélectionnées après confirmation dans une fenêtre contextuelle.

## Disponibilité et Constatations ignorées

Chaque action groupée n'est disponible que si elle peut s'appliquer à l'ensemble de votre sélection :

* **Bulk Edit**, les étiquettes et la révision nécessitent que chaque Constatation sélectionnée soit modifiable par vous.
* **Risk Acceptance** est indisponible si l'une des Constatations sélectionnées n'est pas modifiable, a déjà fait l'objet d'une acceptation du risque, ou est un doublon.
* La création d'un **Finding Group** exige que chaque Constatation soit modifiable, non groupée, et appartienne au même Test.
* **Merge** exige plus d'une Constatation, toutes modifiables et provenant du même Asset.
* **Delete** exige que chaque Constatation sélectionnée soit supprimable par vous.

Lorsqu'une action est exécutée mais que certaines Constatations ne peuvent pas être mises à jour — par exemple parce qu'elles ne sont pas modifiables par vous, sont déjà en cours de révision, ou appartiennent à un Produit sans acceptation du risque simple activée — DefectDojo applique la modification aux autres et affiche un avertissement **« One or More Findings Skipped »** expliquant la raison de chaque exclusion.
