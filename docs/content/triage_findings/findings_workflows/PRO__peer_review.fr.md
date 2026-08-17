---
title: Révision par les pairs et revendication
description: Demandez une révision à des personnes spécifiques, revendiquez une révision
  pour indiquer aux autres qu'elle est prise en charge, et contrôlez qui peut être
  sollicité
audience: pro
weight: 4
---

La révision par les pairs vous permet de demander à quelqu'un d'examiner une Constatation avant sa clôture. Dans l'interface DefectDojo Pro, une révision peut également être **revendiquée**, afin que, lorsque plusieurs personnes sont éligibles, chacun puisse voir qui l'a prise en charge.

## Demander une révision

Ouvrez une Constatation et choisissez **Request Review** dans le menu de la Constatation, ou sélectionnez plusieurs Constatations dans une liste et utilisez l'[éditeur groupé](../pro__bulk_edit_findings/).

Vous pouvez demander une révision à des utilisateurs et des groupes nommés, ou cocher **Allow Eligible Reviewers** pour solliciter toutes les personnes éligibles sur cet asset.

La demande de révision fait passer la Constatation à l'état **Under Review** et notifie les réviseurs.

## Revendiquer une révision

Lorsqu'une révision a été demandée à plusieurs personnes, n'importe laquelle d'entre elles peut la prendre en charge :

* Sur la Constatation, utilisez **Claim Review** dans le menu de la Constatation, ou le bouton présent dans la bannière de révision.
* La Constatation indique alors qui détient la révision, directement sur la Constatation, dans une colonne **Claimed By** des listes de Constatations, ainsi que dans la file [My Work](/metrics_reports/dashboards/pro__my_work/) de cette personne.

Une fois qu'une révision est revendiquée :

* Seule la personne qui la détient, la personne qui l'a demandée, ou un superutilisateur peut effectuer un **Clear Review**. Les autres réviseurs éligibles sont informés de l'identité du détenteur.
* Le détenteur peut la restituer avec **Release Review**, ce qui la renvoie dans le pool sans mettre fin à la révision.

Si deux personnes la revendiquent au même moment, l'une réussit et l'autre est informée de qui a obtenu la revendication — la révision ne peut être détenue que par une seule personne à la fois.

Les revendications se gèrent automatiquement dans certaines situations que vous auriez sinon dû traiter manuellement :

* Effacer la révision marque la revendication comme **completed**.
* Retirer le détenteur de la liste des réviseurs, ou fermer ou rouvrir la Constatation, **libère** la revendication.
* Une tâche en arrière-plan libère les revendications dont le détenteur n'est plus un réviseur demandé.

Les états completed et released sont enregistrés séparément, ce qui permet de distinguer une révision abandonnée d'une révision achevée.

La revendication est contrôlée par l'[indicateur de fonctionnalité](/admin/feature_flags/pro__feature_flags/) **Review Claiming**, activé par défaut.

## Contrôler qui peut être sollicité pour une révision

« All eligible reviewers » désigne toute personne disposant de la permission **Review Findings** sur cet asset — et non toute personne pouvant modifier la Constatation.

Cela importe lorsque vous souhaitez une visibilité large mais un petit pool de réviseurs. Comme **Review Findings** est une permission distincte, vous pouvez :

1. Créer un rôle — par exemple « Security Reviewer » — accordant la permission **Review Findings**.
2. L'accorder à la poignée de personnes qui doivent réellement être sollicitées.
3. Retirer **Review Findings** de vos rôles plus larges, sans modifier leur accès aux Constatations.

Consultez [Custom RBAC Roles](/admin/user_management/pro__custom_rbac_roles/) pour savoir comment créer un rôle.

Lors d'une mise à niveau, tout rôle pouvant déjà modifier des Constatations se voit également accorder la permission **Review Findings**, de sorte que « all eligible reviewers » conserve exactement son sens antérieur tant que vous ne le modifiez pas délibérément.

## Assigner une Constatation à une personne

La révision consiste à demander à quelqu'un de *regarder*. L'assignation rend quelqu'un *responsable*, et ne place pas la Constatation en cours de révision.

**Assignees** figure aux côtés d'**Owners** dans le formulaire de modification de la Constatation. Owners désigne un groupe — l'équipe à qui appartient cette file d'attente — tandis qu'Assignees désigne des personnes individuelles.

* Assignez depuis le formulaire de modification de la Constatation, ou à plusieurs Constatations à la fois depuis l'éditeur groupé.
* Dans l'éditeur groupé, les personnes assignées sont **ajoutées** à celles déjà assignées. Cochez **Replace existing assignees** pour faire de votre sélection la liste complète — ce qui retire toute personne non sélectionnée, y compris tout le monde si vous ne sélectionnez personne.
* Les listes de Constatations comportent une colonne **Assignees** et un filtre par personne assignée, et les rapports peuvent inclure une colonne **Assignees**.
* Les assignations de chaque personne apparaissent dans sa file [My Work](/metrics_reports/dashboards/pro__my_work/).

Vous ne pouvez assigner une Constatation qu'à une personne qui peut déjà la voir. L'assignation n'accorde aucun accès.

Le [Rules Engine](/automation/rules_engine/) peut définir les personnes assignées automatiquement : choisissez **Set Users** et le champ **assignees**.

L'assignation est contrôlée par l'[indicateur de fonctionnalité](/admin/feature_flags/pro__feature_flags/) **Work Assignment**.
