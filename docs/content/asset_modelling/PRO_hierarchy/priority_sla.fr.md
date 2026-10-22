---
title: Attribuer la priorité, le risque et les SLA
description: Comment DefectDojo classe vos constatations
weight: 1
audience: pro
aliases:
- /fr/en/working_with_findings/finding_priority
- /fr/en/working_with_findings/priority_adjustments
---

![image](images/pro_finding_priority.png)

Une gestion efficace des vulnérabilités basée sur le risque nécessite une approche qui prend en compte à la fois le contexte métier et l'exploitabilité technique. Grâce à la fonctionnalité Priorité et Risque de DefectDojo Pro, les utilisateurs peuvent trier automatiquement les Constatations selon un contexte pertinent, garantissant que les vulnérabilités à fort impact puissent être traitées en priorité.

**Priorité** est un rang numérique calculé, appliqué à toutes les Constatations de votre instance DefectDojo. Il vous permet de comprendre rapidement les vulnérabilités dans leur contexte, en particulier au sein de grandes organisations qui supervisent les besoins de sécurité pour de nombreuses Constatations et/ou Produits.

**Risque** est un système de classement à 4 niveaux qui prend davantage en compte l'exploitabilité d'une Constatation. Il s'agit d'une version moins granulaire, plus « au niveau exécutif », de la Priorité.

![image](images/pro_risk_example.png)

Les valeurs de Priorité et de Risque peuvent être utilisées avec d'autres filtres pour comparer les Constatations dans n'importe quel contexte, par exemple :

* au sein d'un seul Produit, Engagement ou Test
* globalement dans tous les Produits DefectDojo
* entre quelques Produits spécifiques

L'application de la Priorité et du Risque des Constatations aide votre équipe à répondre aux vulnérabilités les plus pertinentes de votre organisation, et fournit également un cadre pour faciliter la conformité aux normes réglementaires.


Pour en savoir plus sur la Priorité et le Risque avec DefectDojo, Inc., consultez les Office Hours de mai 2025 :
<iframe width="560" height="315" src="https://www.youtube.com/embed/4SN0BWWsVm4?si=VYUzEGNeijjhoD22" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


## Comment la Priorité et le Risque sont calculés
La plage des valeurs de Priorité va de 0 à 1150. Plus le nombre est élevé, plus la Constatation nécessite un triage ou une remédiation urgente.

Comme pour la Sévérité, le Risque est noté de Faible -> Moyenne -> Nécessite une action -> Urgent.  Le **Risque** prend en compte les champs de Priorité et peut donc différer de la Sévérité rapportée par un outil.

![image](images/priority-overview.png)

## Champs de Priorité : niveau Produit

Chaque Produit dans DefectDojo possède des métadonnées qui suivent la criticité métier et les facteurs de risque. Ces métadonnées sont utilisées pour aider à calculer la Priorité et le Risque des Constatations associées.

Tous ces champs de métadonnées peuvent être définis dans le formulaire **Modifier le Produit** pour un Produit donné.

![image](images/priority_edit_product.png)

* **Criticité** peut être définie sur l'une des valeurs suivantes : Aucune, Très faible, Faible, Moyenne, Élevée ou Très élevée. La Criticité est un champ subjectif ; lors de son attribution, tenez donc compte de la comparaison du Produit avec les autres Produits de votre organisation.
* **Enregistrements utilisateurs** est une estimation numérique du nombre d'enregistrements utilisateurs dans une base de données (ou un système pouvant accéder à cette base de données).
* **Revenu** est une estimation numérique du chiffre d'affaires annuel du Produit. Pour calculer la Priorité, DefectDojo calculera un pourcentage en comparant le revenu de ce Produit à la somme des revenus de tous les Produits du même Type de Produit.

Il n'est pas possible de définir un type de devise dans DefectDojo, assurez-vous donc que toutes vos estimations de Revenu utilisent la même devise. (« 50000 » peut désigner 50 000 dollars américains ou 50 000 yens japonais - la devise n'a pas d'importance tant que tous vos Produits calculent leur revenu dans la même devise).
* **Audience externe** est une valeur vrai/faux - définissez-la sur Vrai si ce Produit peut être consulté par une audience externe. Par exemple, des clients, des utilisateurs ou toute personne extérieure à votre organisation.
* **Accessible depuis Internet** est une valeur vrai/faux. Si ce Produit peut se connecter à Internet, vous devez définir cette valeur sur Vrai.

La Priorité est un calcul « relatif », destiné à comparer différents Produits au sein de votre instance DefectDojo. C'est en fin de compte à votre organisation de décider comment ces filtres sont définis. Ces valeurs doivent être aussi précises que possible, mais l'objectif principal est de mettre en évidence vos Produits clés afin de pouvoir prioriser les vulnérabilités selon les politiques de votre organisation, si bien que ces champs n'ont donc pas nécessairement besoin d'être définis parfaitement.

## Champs de Priorité : niveau Constatation

Les Constatations d'un Produit peuvent avoir des métadonnées supplémentaires qui peuvent encore ajuster le niveau de Priorité et de Risque de la Constatation :

* Si la Constatation possède un **Score EPSS** ; celui-ci est ajouté automatiquement aux Constatations et tenu à jour pour les utilisateurs Pro.  Le **Score EPSS** est le champ qui contribue au Score de Priorité — le **Percentile EPSS** est suivi sur la Constatation à titre indicatif mais n'alimente pas directement le calcul.
* Le nombre de Points de terminaison du Produit concernés par cette Constatation
* Si la Constatation est en cours de révision (Under Review)
* Si la Constatation figure dans la base KEV (Known Exploited Vulnerabilities), vérifiée régulièrement par DefectDojo
* La Sévérité rapportée par l'outil pour une Constatation (Info, Faible, Moyenne, Élevée, Critique)

#### Score EPSS et Percentile EPSS

Deux Constatations qui semblent identiques sur les facteurs visibles (Sévérité, Criticité métier, Accessible depuis Internet, Exploit disponible) peuvent malgré tout obtenir des Scores de Priorité différents si leurs **Scores EPSS** diffèrent.  C'est normal : le Score EPSS est une donnée contextuelle du calcul.

Le Percentile EPSS est affiché sur la Constatation à titre indicatif, mais il n'est pas utilisé dans le calcul du Score de Priorité.  Si vous devez comparer deux Constatations pour comprendre un écart de Score de Priorité, examinez les valeurs de Score EPSS, et non les valeurs de Percentile.

Le poids exact du Score EPSS (et des autres facteurs) dans le calcul du Score de Priorité n'est volontairement pas publié.  Si vous devez influencer le poids du Score EPSS dans le calcul de votre environnement, ajustez le curseur **Exploitabilité** dans votre [Moteur de priorisation](#prioritization-engines).


## Calcul du Risque d'une Constatation

![image](images/risk_table.png)

La colonne Risque d'un tableau de Constatations est un autre moyen de prioriser rapidement les Constatations.  Le Risque est calculé à partir du niveau de Priorité d'une Constatation, mais prend également davantage en compte son exploitabilité.  Il s'agit d'une version moins granulaire, plus « au niveau exécutif », de la Priorité.

Les quatre niveaux de Risque attribuables sont :

![image](images/pro_risk_levels.png)

L'EPSS / l'exploitabilité d'une Constatation est beaucoup plus mise en avant dans le calcul du Risque.  Par conséquent, une Constatation peut avoir à la fois une priorité élevée et une valeur de risque faible.

Le calcul du Risque lui-même ne peut actuellement pas être ajusté directement.  Cependant, si le [Renseignement sur les menaces](/asset_modelling/pro_hierarchy/threat_intelligence/) est activé, le **plancher de Risque pour exploitation active** vous permet de contrôler le résultat pour le cas qui compte le plus : une Constatation confirmée comme étant exploitée en conditions réelles est relevée à au moins la bande de Risque que vous choisissez, plutôt que d'être laissée dans une bande faible en raison de sa sévérité de base Faible.  Elle est livrée configurée sur **Nécessite une action**, et chaque Moteur de priorisation peut la relever, l'abaisser ou la désactiver pour couper ce plancher.  Voir [le plancher de Risque pour exploitation active](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor).

## Tableau de bord Priority Insights

Les utilisateurs peuvent avoir une vue de niveau exécutif de la Priorité et du Risque dans leur environnement grâce au Tableau de bord Priority Insights (Métriques > Priority Insights dans la barre latérale)

![image](images/priority_dashboard.png)

Ce tableau de bord peut être filtré pour inclure des Produits ou des plages de dates spécifiques. Comme pour les autres tableaux de bord Pro, ce tableau de bord peut être exporté depuis DefectDojo au format PDF pour produire rapidement un rapport.

## Définir la Priorité et le Risque pour la conformité réglementaire

Voici une liste non exhaustive de normes réglementaires exigeant spécifiquement des méthodes de priorisation des vulnérabilités :

* La conformité [SOX (Sarbanes-Oxley Act](https://www.sarbanes-oxley-act.com/)) exige une priorisation basée sur le revenu pour les systèmes impactant les données financières. Dans DefectDojo, le revenu d'un système peut être saisi au niveau du Produit.
* La conformité [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) exige une priorisation basée sur les évaluations de risque et la criticité pour les environnements de données des titulaires de cartes. La Criticité métier et l'Audience externe peuvent être définies au niveau du Produit, tandis que la synchronisation EPSS au niveau des Constatations de DefectDojo prend en charge l'approche basée sur le risque de PCI.
* [NIST SP 800-40](https://csrc.nist.gov/pubs/sp/800/40/r4/final) est un guide de maintenance préventive qui préconise spécifiquement une priorisation des vulnérabilités basée sur l'impact métier, la criticité du produit et l'accessibilité depuis Internet. Tous ces facteurs peuvent être définis au niveau du Produit dans DefectDojo.
* La conformité au contrôle A.12.6.1 de l'[ISO 27001/27002](https://www.iso.org/standard/27001) exige la gestion des vulnérabilités techniques avec une Priorité basée sur l'évaluation du risque.
* L'[article 32 du RGPD](https://gdpr-info.eu/art-32-gdpr/) exige des mesures de sécurité basées sur le risque - les enregistrements utilisateurs et les indicateurs d'audience externe au niveau du Produit peuvent aider à prioriser les systèmes de votre organisation qui traitent des données personnelles.
* La conformité [FISMA/FedRAMP](https://help.fedramp.gov/hc/en-us) exige une surveillance continue et une remédiation des vulnérabilités basée sur le risque.

Les calculs de Priorité et de Risque de DefectDojo Pro peuvent être ajustés, ce qui vous permet d'adapter DefectDojo Pro à vos normes internes de Priorité et de Risque des Constatations.

## Moteurs de priorisation

À l'instar des configurations SLA, les Moteurs de priorisation vous permettent de définir les règles régissant le calcul de la Priorité et du Risque.

![image](images/priority_default.png)

DefectDojo est livré avec un Moteur de priorisation intégré, appliqué à tous les Produits.  Vous pouvez toutefois modifier ce Moteur de priorisation pour changer la pondération des multiplicateurs **Constatation** et **Produit**, ce qui ajustera la façon dont la Priorité et le Risque des Constatations sont attribués.

### Multiplicateurs de Constatation

Huit facteurs contextuels influencent le Score de Priorité d'une Constatation.  Trois d'entre eux sont propres à la Constatation, et les cinq autres sont attribués en fonction du Produit qui contient la Constatation.

Vous pouvez ajuster votre Moteur de priorisation en modifiant la façon dont ces facteurs sont appliqués au calcul final.

![image](images/priority_sliders.png)

Sélectionnez un facteur en cliquant sur le bouton, puis ce curseur vous permet de contrôler le pourcentage d'application d'un facteur donné.  Au fur et à mesure que vous ajustez le curseur, vous verrez les seuils de Risque changer en conséquence.

#### Multiplicateurs au niveau Constatation

* **Sévérité** - le niveau de Sévérité d'une Constatation
* **Exploitabilité** - le score KEV et/ou EPSS d'une Constatation
* **Points de terminaison** - le nombre de Points de terminaison associés à une Constatation

#### Multiplicateurs au niveau Produit

* **Criticité métier** - la Criticité métier du Produit associé (Aucune, Très faible, Faible, Moyenne, Élevée ou Très
élevée)
* **Enregistrements utilisateurs** - le nombre d'Enregistrements utilisateurs du Produit associé
* **Revenu** - le revenu du Produit associé, relatif au revenu total du Type de Produit
* **Audience externe** - si le Produit associé possède ou non une audience externe
* **Accessible depuis Internet** - si le Produit associé est accessible depuis Internet ou non

### Seuils de Risque

En fonction du réglage du Moteur de priorisation, DefectDojo recommandera automatiquement des Seuils de Risque.  Ces seuils peuvent toutefois également être ajustés et définis selon les valeurs que vous jugez appropriées.

![image](images/risk_threshold.png)

## Créer de nouveaux Moteurs de priorisation

Vous pouvez utiliser plusieurs Moteurs de priorisation, chacun pouvant être attribué à différents Produits.

![image](images/priority_engine_new.png)

La création d'un nouveau Moteur de priorisation ouvrira le formulaire du Moteur de priorisation.  Une fois ce formulaire soumis, un nouveau Moteur de priorisation sera ajouté au tableau.

## Attribuer des Moteurs de priorisation aux Produits

Chaque Produit peut avoir un Moteur de priorisation actuellement utilisé, via le formulaire **Modifier le Produit** pour un Produit donné.

![image](images/priority_chooseengine.png)

Notez que lorsque le Moteur de priorisation d'un Produit est modifié, ou qu'un Moteur de priorisation est mis à jour, le Moteur de priorisation du Produit ou le Moteur de priorisation lui-même sera « Verrouillé » jusqu'à ce que le calcul de priorisation soit terminé.

Chaque Produit de DefectDojo peut avoir sa propre configuration d'Accord de niveau de service (SLA), qui représente le nombre de jours dont dispose votre organisation pour remédier ou autrement gérer une Constatation.

Le SLA peut être défini en fonction de la **[Sévérité de la Constatation](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** ou du **[Risque de la Constatation](/asset_modelling/pro_hierarchy/priority_sla/)** (dans DefectDojo Pro).

![image](images/sla_multiple.png)

Les SLA appliquent un compte à rebours de jours à une Constatation, à partir du jour où la Constatation a été créée dans DefectDojo.  Si une Constatation n'est pas Fermée avant la fin du compte à rebours, la Constatation sera étiquetée comme étant en violation du SLA.

## Travailler avec les SLA

Vous pouvez utiliser les SLA pour représenter les politiques de remédiation de votre organisation.  Vous pouvez également les utiliser pour prioriser les Constatations les plus critiques et actives depuis le plus longtemps dans votre instance DefectDojo.

* Vous pouvez trier ou filtrer les tableaux de Constatations par jours de SLA.
* Les violations de SLA peuvent être configurées pour déclencher des [Notifications](/admin/notifications/about_notifications/) aux utilisateurs DefectDojo affectés au Produit concerné.
* Dans **DefectDojo Pro**, la performance du SLA est également suivie sur les Tableaux de bord Métriques [Informations exécutives et remédiation](/metrics_reports/pro_metrics/pro__overview/).
* La conformité au SLA peut également être affichée sur un [tableau de bord](/metrics_reports/dashboards/custom-dashboards/) personnalisé dans **DefectDojo Pro** — par exemple avec un widget SLA Burndown ou un widget de Comptage filtré.

### Statut Atténué dans les délais du SLA

Si une Constatation est Atténuée avec succès avant l'échéance du SLA, la Constatation affichera une coche verte ✅ dans la colonne Atténué dans les délais du SLA.

![image](images/sla_mitigated_within.png)

Si une Constatation a été Atténuée, mais pas avant que le SLA ne soit violé, la Constatation affichera un X rouge ❌ dans la colonne Atténué dans les délais du SLA.

### Violation des SLA

Lorsqu'un SLA pour une Constatation donnée est violé (la Constatation n'est pas Fermée dans les délais du SLA) la coche verte ✅ se transformera en X rouge ❌.  Le SLA continuera d'être suivi avec un nombre négatif, représentant le nombre de jours de dépassement du SLA.

![image](images/sla_breached.png)

## Gérer les configurations SLA (Pro)

Dans DefectDojo Pro, une ou plusieurs configurations SLA sont gérées dans la section **Configuration > Accords de niveau de service** de la barre latérale.  Vous pouvez créer un **Nouvel Accord de niveau de service** ou gérer les configurations SLA existantes depuis la page **Tous les Accords de niveau de service**.

![image](images/pro_sla_risk.png)

Les configurations SLA ne peuvent être modifiées que par les Superutilisateurs ou par un utilisateur disposant de la [Permission de Configuration](/admin/user_management/user_permission_chart/#configuration-permission-chart) correspondante.

### Configurer le SLA

Les configurations SLA contiennent le nombre de jours attribué à chaque valeur de **Sévérité** ou de **Risque** dans DefectDojo.

![image](images/pro_new_sla.png)

Chaque Accord de niveau de service peut avoir un nom unique, ainsi qu'une description facultative.

**Redémarrer le SLA lors de la réactivation d'une Constatation** : si cette option est activée, elle relancera le SLA à zéro lorsqu'une Constatation est Rouverte.  Sinon, le SLA sera basé sur la date de création de la Constatation.

Lors de la modification d'un SLA, vous pouvez choisir si ce SLA utilisera la **Sévérité** ou le **Risque** comme référence pour attribuer le nombre de jours pour remédier.  Cela se fait en sélectionnant l'option correspondante dans la section **Type de configuration du niveau de service** du formulaire.

À partir de là, vous pouvez définir le nombre de jours autorisés pour chaque niveau de **Sévérité** ou de **Risque**.  Vous pouvez également appliquer les SLA de manière sélective ; en décochant **Appliquer les jours de Constatation ___**, vous pouvez ignorer le calcul du SLA pour ces niveaux de Sévérité ou de Risque.

## Appliquer une configuration SLA à un Produit (Pro)

Les Produits nouvellement créés dans DefectDojo appliqueront toujours la **Configuration SLA par défaut**, qui peut être définie avec des valeurs différentes si vous le souhaitez.

Si vous disposez de configurations SLA, vous pouvez choisir laquelle appliquer à votre Produit depuis le formulaire **Modifier le Produit**.

![image](images/pro_sla_product.png)

### Recalcul du SLA

Une fois qu'un nouveau SLA a été sélectionné pour un Produit, le SLA de toutes les Constatations associées devra être recalculé par DefectDojo.  Pendant l'exécution de ce processus, le SLA d'un Produit ne peut pas être modifié.

## Remarques sur les SLA

* Les SLA peuvent être facultativement redémarrés une fois qu'une Constatation en [Risque accepté](/triage_findings/findings_workflows/pro__risk_acceptance/) est réactivée.  Cela se configure lors de la création de l'Acceptation du risque en activant le champ **Redémarrer si le SLA a expiré**.
* La réimportation d'une Constatation ne redémarre pas le SLA - les SLA sont toujours calculés à partir de la première détection d'une Constatation, sauf si **Redémarrer le SLA lors de la réactivation d'une Constatation** est activé.
* L'expiration de l'Acceptation du risque ou la réactivation d'une Constatation Fermée sont les seuls moyens de réinitialiser ou de recalculer un SLA pour une Constatation une fois celle-ci créée (sans modifier la configuration SLA du Produit).
