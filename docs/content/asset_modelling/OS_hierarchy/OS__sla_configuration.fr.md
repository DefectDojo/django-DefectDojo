---
title: Configuration SLA
description: Configurer les accords de niveau de service (SLA) pour différents Produits
weight: 2
audience: opensource
aliases:
- /fr/en/working_with_findings/sla_configuration
---

Chaque Produit dans DefectDojo peut avoir sa propre configuration d'accord de niveau de service (SLA), qui représente le nombre de jours dont dispose votre organisation pour remédier à une Constatation ou la gérer autrement.

Le SLA peut être défini en fonction de la **[Sévérité de la Constatation](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** ou du **[Risque de la Constatation](/asset_modelling/pro_hierarchy/priority_sla/)** (dans DefectDojo Pro).

![image](images/sla_multiple.png)

Les SLA appliquent un compte à rebours de jours à une Constatation, basé sur le jour où la Constatation a été créée dans DefectDojo.  Si une Constatation n'est pas clôturée avant l'expiration du délai, elle sera étiquetée comme étant en violation du SLA.

## Utilisation des SLA

Vous pouvez utiliser les SLA pour représenter les politiques de remédiation de votre organisation.  Vous pouvez également les utiliser pour prioriser les Constatations les plus critiques et actives depuis le plus longtemps dans votre instance DefectDojo.

* Vous pouvez trier ou filtrer les tableaux de Constatations par jours de SLA.
* Les violations de SLA peuvent être configurées pour déclencher des [Notifications](/admin/notifications/about_notifications/) aux utilisateurs DefectDojo assignés au Produit concerné.
* Dans **DefectDojo Pro**, la performance du SLA est également suivie sur les tableaux de bord de métriques [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/).
* La conformité SLA peut également être affichée sur un [tableau de bord](/metrics_reports/dashboards/custom-dashboards/) personnalisé dans **DefectDojo Pro** — par exemple avec un widget SLA Burndown ou un widget Count filtré.

### Statut Atténué dans les délais du SLA

Si une Constatation est atténuée avec succès avant l'échéance du SLA, elle enregistrera une coche verte ✅ dans la colonne Atténué dans les délais du SLA.

![image](images/sla_mitigated_within.png)

Si une Constatation a été atténuée, mais pas avant que le SLA ne soit violé, elle enregistrera un X rouge ❌ dans la colonne Atténué dans les délais du SLA.

### Violation des SLA

Lorsque le SLA d'une Constatation donnée est violé (la Constatation n'est pas clôturée dans le délai du SLA), la coche verte ✅ se transformera en X rouge ❌.  Le SLA continuera d'être suivi avec un nombre négatif, représentant le nombre de jours de dépassement du SLA.

![image](images/sla_breached.png)

## Gestion des configurations SLA (Pro)

Dans DefectDojo Pro, une ou plusieurs configurations SLA sont gérées dans la section **Configuration > Service Level Agreements** de la barre latérale.  Vous pouvez créer un **New Service Level Agreement** ou travailler avec les configurations SLA existantes depuis la page **All Service Level Agreements**.

![image](images/pro_sla_risk.png)

Les configurations SLA ne peuvent être modifiées que par des Superusers ou par un utilisateur disposant de la [permission de Configuration](/admin/user_management/user_permission_chart/#configuration-permission-chart) correspondante.

### Configurer le SLA

Les configurations SLA contiennent le nombre de jours attribué à chaque valeur de **Sévérité** ou de **Risque** de DefectDojo.

![image](images/pro_new_sla.png)

Chaque accord de niveau de service peut avoir un nom unique, ainsi qu'une description optionnelle.

**Restart SLA on Finding Reactivation** : si cette option est activée, elle relancera le SLA à zéro lorsqu'une Constatation est rouverte.  Sinon, le SLA sera basé sur la date de création de la Constatation.

Lors de la modification d'un SLA, vous pouvez choisir si ce SLA utilisera la **Sévérité** ou le **Risque** comme référence pour l'attribution des jours de remédiation.  Cela se fait en sélectionnant l'option correspondante dans la section **Service Level configuration Type** du formulaire.

À partir de là, vous pouvez définir le nombre de jours autorisé pour chaque niveau de **Sévérité** ou de **Risque**.  Vous pouvez également appliquer les SLA de manière sélective ; en décochant **Enforce ___ Finding Days**, vous pouvez ignorer le calcul du SLA pour ces niveaux de Sévérité ou de Risque.

## Appliquer une configuration SLA à un Produit (Pro)

Les Produits nouvellement créés dans DefectDojo appliqueront toujours la **Default SLA Configuration**, qui peut être définie sur des valeurs différentes si vous le souhaitez.

Si vous disposez de configurations SLA, vous pouvez choisir celle qui est appliquée à votre Produit depuis le formulaire **Edit Product**.

![image](images/pro_sla_product.png)

### Recalcul du SLA

Une fois qu'un nouveau SLA a été sélectionné pour un Produit, les SLA de toutes les Constatations associées devront être recalculés par DefectDojo.  Pendant l'exécution de ce processus, le SLA d'un Produit ne peut pas être modifié.

## Remarques sur les SLA

* Les SLA peuvent être optionnellement relancés lorsqu'une Constatation [Risque accepté](/triage_findings/findings_workflows/os__risk_acceptance/) se réactive.  Cela se configure lors de la création de l'Acceptation du risque en définissant le champ **Restart SLA Expired**.
* Réimporter une Constatation ne relance pas le SLA - les SLA sont toujours calculés à partir du moment où une Constatation a été détectée pour la première fois, sauf si **Restart SLA on Finding Reactivation** est activé.
* L'expiration de l'Acceptation du risque ou la réactivation d'une Constatation clôturée sont les seuls moyens de réinitialiser ou de recalculer le SLA d'une Constatation une fois celle-ci créée (sans modifier la configuration SLA du Produit).
