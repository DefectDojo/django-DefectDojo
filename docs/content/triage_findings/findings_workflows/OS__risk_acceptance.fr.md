---
title: Acceptations du risque
description: Tirer parti des acceptations du risque dans DefectDojo OS
audience: opensource
weight: 2
---

**Les acceptations du risque** sont un statut spécial qui peut être appliqué aux Constatations pour documenter formellement et opérationnaliser la décision de les reconnaître sans les corriger immédiatement.

Contrairement à DefectDojo Pro, les acceptations du risque dans DefectDojo OS ne sont pas des objets indépendants. Elles sont uniquement liées aux Engagements. Ainsi, elles ne peuvent contenir que des Constatations provenant de l'Engagement auquel elles appartiennent. Si 3 occurrences d'une même Constatation apparaissent dans un Test au sein de 3 Engagements différents, 3 acceptations du risque distinctes seront nécessaires pour accepter entièrement ces Constatations.

### Accéder aux acceptations du risque 

Les acceptations du risque incluent des Constatations propres au(x) Test(s) de chaque Engagement. Elles sont donc accessibles depuis l'Engagement qui contient le Test dont proviennent ces Constatations. 

![image](images/OS_RA_image1.png)

Une liste complète des Constatations ayant fait l'objet d'une acceptation du risque individuelle est consultable dans le sous-menu **Risk Accepted Findings** de la section **Findings** de la barre latérale.

![image](images/OS_RA_image2.png)

## Créer des acceptations du risque 

Lorsqu'une Constatation fait l'objet d'une acceptation du risque, les événements suivants se produisent : 
- Le statut de la Constatation ne sera plus « Actif », mais elle restera interrogeable, incluse dans les rapports et auditable.
- Le statut de la Constatation sera changé en « Risque accepté ».
- La Constatation ne sera plus comptabilisée dans les métriques, mais continuera d'apparaître dans le Test dont elle provient.

Le risque associé à une Constatation peut être accepté de deux façons : soit en l'ajoutant manuellement à une **acceptation du risque complète**, soit en utilisant le workflow d'**acceptation du risque simple**.

### Acceptations du risque complètes

Une acceptation du risque complète permet aux Utilisateurs d'accepter le risque de plusieurs Constatations au sein d'un Engagement et de les regrouper en une seule unité. Si la politique de l'organisation exige des acceptations du risque formelles et documentées, ou si les Utilisateurs souhaitent déclencher certaines actions à l'expiration d'une acceptation du risque, les acceptations du risque complètes sont le meilleur choix, car elles retracent le processus de décision interne et peuvent servir de source de référence.

Chaque acceptation du risque complète ajoute un contexte supplémentaire, tel que :
- Le nom de l'acceptation du risque.
- Le propriétaire de l'acceptation du risque.
- La recommandation de sécurité et la décision concernant le traitement de la ou des Constatations.
- Toute preuve associée à la recommandation ou à la décision.
- Les détails relatifs à la recommandation ou à la décision.
- L'Utilisateur qui accepte le risque associé à la décision.
- La date d'expiration.
    - Si le statut de la Constatation redeviendra « Actif » à l'expiration.
    - Si le SLA redémarrera à l'expiration.

L'expiration est propre aux acceptations du risque complètes et permet de réexaminer, au moment approprié, les Constatations dont le risque a été accepté. Une fois qu'une acceptation du risque complète expire, les Constatations concernées repassent à l'état Actif. Si vous ne précisez pas de date, la date Default Risk Acceptance / Default Risk Acceptance Expiration définie sur la page System Settings sera utilisée.

Important : les acceptations du risque complètes étant limitées à un Engagement donné, il n'existe pas de section unique permettant de visualiser l'ensemble des acceptations du risque complètes. Elles ne sont consultables que dans l'Engagement respectif qui contient les Constatations qu'elles couvrent.

#### Comment créer une acceptation du risque complète

Pour créer une acceptation du risque complète, accédez à la vue Engagement et cliquez sur le symbole **+** dans l'encadré Risk Acceptance. 

![image](images/OS_RA_image3.png)

Renseignez ensuite les détails de l'acceptation du risque complète et sélectionnez les Constatations à inclure. **Accepted Findings** propose une liste déroulante de toutes les Constatations disponibles pouvant être ajoutées à l'acceptation du risque. Les Constatations de l'Engagement s'affichent par ordre décroissant de sévérité (les Constatations Critiques en haut, les Constatations Faibles en bas). Une Constatation ayant déjà fait l'objet d'une acceptation du risque n'apparaît pas dans la liste déroulante. 

Une fois terminée, l'acceptation du risque complète apparaît dans l'encadré Risk Acceptance de la vue Engagement. 

Une acceptation du risque peut également être créée en cliquant sur le bouton **Add Risk Acceptance** dans le menu kebab ⋮ d'une Constatation individuelle. 

![image](images/OS_RA_image7.png)

#### Interagir avec les acceptations du risque complètes

Une fois créée, une acceptation du risque complète peut être ouverte pour consulter les Constatations qui y ont été ajoutées ainsi que les détails saisis lors de sa création (par exemple la date, le propriétaire, la décision, l'expiration, etc.).

Pour retirer une Constatation d'une acceptation du risque complète, cliquez sur le bouton **Remove** dans le tableau Findings Accepted. 

![image](images/OS_RA_image8.png)

La vue de l'acceptation du risque complète comprend également, en bas de page, un tableau listant toutes les autres Constatations des Tests de cet Engagement. Vous pouvez y sélectionner des Constatations supplémentaires et les ajouter à cette acceptation du risque complète. 

De plus, une fonction Notes permet aux Utilisateurs d'ajouter du contexte supplémentaire à l'acceptation du risque complète. Toutes les notes publiques apparaissent dans les Rapports générés pour l'acceptation du risque complète. Les notes marquées comme **Privée** ne sont visibles que par leur auteur et par les superutilisateurs, et sont exclues des rapports. 

Important : si une acceptation du risque complète est entièrement supprimée, le statut des Constatations qu'elle contenait repasse automatiquement à « Actif ».

### Acceptations du risque simples

Alors que l'acceptation du risque complète est activée par défaut, l'acceptation du risque simple doit être activée manuellement, soit à la création d'un Asset, soit dans les paramètres de l'Asset.

![image](images/OS_RA_image4.png)

Une acceptation du risque simple peut être réalisée de deux façons : 
1. Depuis une vue Test, à l'aide du menu Bulk Edits qui apparaît après avoir sélectionné une ou plusieurs Constatations dans le tableau des Constatations. 

![image](images/OS_RA_image5.png)

2. En cliquant sur **Accept Risk** dans le menu kebab ⋮ d'une Constatation individuelle. 

![image](images/OS_RA_image6.png)

Une fois qu'une Constatation a fait l'objet d'une acceptation du risque simple, elle continue d'apparaître dans le tableau des Constatations du Test, mais son statut passe à **Inactive, Risk Accepted.** Une liste complète des Constatations ayant fait l'objet d'une acceptation du risque individuelle est consultable dans le sous-menu **Risk Accepted Findings** de la section **Findings** de la barre latérale.

Si vous effectuez une acceptation du risque simple sur une Constatation et que vous souhaitez ensuite l'ajouter à une acceptation du risque complète, le risque doit d'abord être désaccepté avant de pouvoir l'ajouter à l'acceptation du risque complète.

## Lorsque la date d'expiration d'une acceptation du risque est modifiée

La date d'expiration d'une acceptation du risque complète peut être modifiée à tout moment après sa création.  Le comportement de DefectDojo dépend du fait que l'acceptation du risque soit actuellement active ou déjà expirée.

### Modifier la date d'une acceptation du risque active

Si une acceptation du risque n'a pas encore expiré — sa date d'expiration est dans le futur, ou vient de passer mais la tâche périodique d'expiration ne l'a pas encore traitée — la modification de la date est simple :

- La nouvelle date est enregistrée telle quelle.
- Les Constatations liées restent au statut Risque accepté.
- L'objet acceptation du risque reste actif.

### Reporter la date d'une acceptation du risque déjà expirée

Si l'acceptation du risque a **déjà expiré** — c'est-à-dire que la tâche périodique d'expiration a traité son expiration et que les Constatations liées ont été remises à Actif — modifier la date d'expiration vers une valeur future déclenche un workflow de **réactivation** :

- L'acceptation du risque est réactivée et n'est plus à l'état expiré.
- Chaque Constatation liée à l'acceptation du risque actuellement à l'état Actif fait l'objet d'une nouvelle acceptation (elle repasse à Risque accepté / Inactive).
- Un commentaire consignant la réactivation est publié sur tout ticket Jira lié.

La date que vous saisissez est celle qui est enregistrée.  Le paramètre système **Risk Acceptance Form Default Days** (valeur par défaut : 180) n'est utilisé que lorsque vous n'avez pas demandé de date précise — par exemple lorsque vous utilisez l'action **Reinstate**, qui réactive l'acceptation du risque sans modifier sa date d'expiration, et la définit donc sur aujourd'hui + N jours.

### Avancer la date ou la placer dans le passé

Avancer la date d'expiration à une date antérieure mais toujours future n'entraîne aucun comportement particulier — l'acceptation du risque reste active et la nouvelle date est enregistrée.

Placer la date dans le passé ne fait pas expirer immédiatement l'acceptation du risque depuis le formulaire d'édition ; la prochaine tâche périodique d'expiration la prendra en charge et appliquera le comportement d'expiration standard.  Cela vaut aussi pour une acceptation du risque **déjà expirée** : une date passée reste la date que vous avez choisie, elle est donc enregistrée telle quelle, et la prochaine exécution de la tâche d'expiration fera de nouveau expirer l'acceptation du risque.

### Ce que l'API expose

Les consommateurs de l'API peuvent observer l'état d'expiration de l'objet acceptation du risque via les champs `expiration_date`, `expiration_date_handled` et `expiration_date_warned`.  Une acceptation du risque est « expirée » précisément lorsque `expiration_date_handled` n'est pas nul.  Lors d'une réactivation, `expiration_date_handled` et `expiration_date_warned` sont tous deux réinitialisés à `null`, et `expiration_date` contient la date que vous avez envoyée — ou aujourd'hui + N jours si aucune date n'a été demandée.

L'expiration et la réactivation sont également disponibles directement, sans avoir à passer par la modification de `expiration_date` :

- `POST /api/v2/risk_acceptance/{id}/expire/` la fait expirer immédiatement.  Renvoie `400` si elle a déjà expiré.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` réactive une acceptation du risque expirée, en acceptant de nouveau les Constatations qu'elle couvre.  Renvoie `400` si elle n'a pas expiré.  Envoyez `expiration_date` pour choisir la durée ; omettez ce champ pour utiliser aujourd'hui + N jours.

Les deux acceptent un champ `reason` optionnel, qui est enregistré comme note sur l'acceptation du risque avec l'identité de la personne ayant effectué l'action.  Les deux nécessitent la même permission que celle requise pour modifier l'acceptation du risque.

## Bonnes pratiques pour les acceptations du risque 

En règle générale, il est préférable d'utiliser exclusivement soit les acceptations du risque complètes, soit les acceptations du risque simples, plutôt que de recourir aux deux.

Par exemple, si les acceptations du risque complètes constituent l'approche par défaut, le fait qu'une Constatation fasse l'objet d'une acceptation du risque simple peut créer de la confusion en l'absence d'acceptation du risque complète associée contenant cette Constatation. De même, si les Constatations font habituellement l'objet d'acceptations du risque simples, ajouter certaines Constatations à une acceptation du risque complète alors qu'aucun autre objet de ce type n'existe pour la plupart des autres Constatations peut également créer de la confusion. 
