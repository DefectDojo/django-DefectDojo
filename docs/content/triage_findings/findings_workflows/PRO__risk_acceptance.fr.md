---
title: Acceptations du risque
description: Tirer parti des acceptations du risque dans DefectDojo Pro
audience: pro
weight: 2
aliases:
- /fr/en/working_with_findings/findings_workflows/risk_acceptances/
---

**Les acceptations du risque** sont un statut spécial qui peut être appliqué aux constatations à l’aide d’objets **Acceptation du risque complète** ou du workflow **Acceptation du risque simple**. Les acceptations du risque permettent de documenter formellement et d’opérationnaliser la décision d’accepter une constatation vulnérable sans la corriger immédiatement.

DefectDojo Pro inclut des fonctionnalités d’acceptation du risque avancées pour faire évoluer les décisions de gestion des risques, notamment :
- **Acceptations du risque inter-produits** : une seule acceptation du risque peut être appliquée à plusieurs produits, ce qui permet de regrouper toutes les occurrences d’une même constatation ou de constatations similaires à travers l’ensemble de votre portefeuille d’actifs en un seul objet Acceptation du risque.
- **Gestion en masse des acceptations du risque** : filtrez et recherchez des constatations spécifiques ou des identifiants de vulnérabilité, puis appliquez l’acceptation du risque à tous les résultats simultanément, quel que soit l’actif auquel ils appartiennent.

### Accéder aux constatations à risque accepté

La barre latérale comporte une section Acceptations du risque qui inclut trois sous-sections dans son menu déroulant :
- **Constatations à risque accepté**
    - Cette section comprend un tableau de toutes les constatations dont le risque a été accepté, que ce soit dans le cadre d’un objet Acceptation du risque complète ou via le workflow Acceptation du risque simple.
- **Toutes les acceptations du risque**
    - Cette section comprend un tableau de tous les objets Acceptation du risque complète, classés par ordre chronologique.
- **Nouvelle acceptation du risque**
    - Cliquer sur cette option dans la barre latérale démarre le workflow de création d’un objet Acceptation du risque complète.

![Risk acceptance sidebar](images/RA_image1.png)

## Créer des acceptations du risque

Lorsqu’une constatation est mise en risque accepté, ce qui suit se produit :

- Le statut de la constatation ne sera plus « Actif ».
- Le statut de la constatation sera changé en « Risque accepté ».
- La constatation ne sera plus comptabilisée dans les métriques, mais continuera d’apparaître dans le Test dont elle est issue.

Les constatations peuvent être mises en risque accepté de deux façons : elles peuvent être ajoutées à des objets Acceptation du risque complète, ou via le workflow Acceptation du risque simple.

### Acceptations du risque complètes

Une acceptation du risque complète permet aux utilisateurs d’accepter le risque de plusieurs constatations en les regroupant au sein d’un seul objet, quels que soient l’actif, l’engagement ou le test dont elles sont issues.

Si la politique de l’organisation exige des acceptations du risque formelles et documentées, ou si les utilisateurs souhaitent que les acceptations du risque expirent automatiquement après une certaine date, l’acceptation du risque complète est le meilleur choix, car elle capture le processus de décision interne et peut servir de source de vérité.

Chaque acceptation du risque complète ajoute un contexte supplémentaire à l’acceptation du risque, tel que :
- Le nom de l’objet Acceptation du risque.
- Le propriétaire de l’objet Acceptation du risque.
- La recommandation de sécurité et la décision quant à la manière de traiter la ou les constatations.
- Toute preuve associée à la recommandation ou à la décision.
- Les détails concernant la recommandation ou la décision.
- L’utilisateur qui accepte le risque associé à la décision.
- La date d’expiration.
    - Si le statut de la constatation redeviendra « Actif » à l’expiration.
    - Si le SLA redémarrera à l’expiration.

L’expiration est propre aux objets Acceptation du risque complète et permet de réexaminer, au moment approprié, les constatations dont le risque a été accepté. Une fois qu’une acceptation du risque a expiré, les constatations repassent au statut Actif.

Si vous ne spécifiez pas de date, les valeurs Acceptation du risque par défaut / Jours d’expiration par défaut de l’acceptation du risque définies dans la page Paramètres système seront utilisées.

#### Comment créer une acceptation du risque complète

Un objet Acceptation du risque complète peut être créé de trois manières différentes :
- En utilisant le bouton **Nouvelle acceptation du risque** dans la barre latérale.
- En utilisant le bouton **Ajouter une acceptation du risque** sur une constatation individuelle.
- En cliquant sur le bouton **Actions d’acceptation du risque** qui apparaît après avoir sélectionné une ou plusieurs constatations dans un tableau.

##### Nouvelle acceptation du risque (barre latérale)

Cliquer sur Nouvelle acceptation du risque dans la barre latérale ouvre une page dans laquelle l’utilisateur peut renseigner les données et les détails associés à un nouvel objet Acceptation du risque complète. La deuxième page permet à l’utilisateur de filtrer et de sélectionner les constatations à ajouter à cet objet.

##### Ajouter une acceptation du risque (individuelle)

Après avoir ouvert une constatation individuelle, cliquez sur l’icône en forme d’engrenage dans le coin supérieur droit de la vue et sélectionnez **Ajouter une acceptation du risque**. Vous pourrez alors soit ajouter la constatation à un objet Acceptation du risque complète existant, soit en créer un nouveau.

![Risk Acceptance in Finding Submenu](images/RA_image2.png)

##### Actions d’acceptation du risque (tableau)

Après avoir sélectionné une ou plusieurs constatations dans un tableau, cliquez sur le bouton **Actions d’acceptation du risque** qui apparaît en haut, puis sélectionnez **Ajouter à un nouvel objet d’acceptation du risque** ou **Ajouter à un objet d’acceptation du risque existant**, et remplissez les champs requis.

Les constatations ne peuvent être ajoutées qu’à une seule acceptation du risque à la fois. Si le bouton Actions d’acceptation du risque n’est pas cliquable, c’est probablement parce que l’une des constatations sélectionnées a déjà été ajoutée à un objet Acceptation du risque complète.

![Risk Acceptance Actions button](images/RA_image5.png)

##### Modifier les acceptations du risque complètes

Une fois qu’un objet Acceptation du risque complète a été créé, vous pouvez modifier les détails de l’objet, téléverser un fichier apportant la preuve de l’acceptation du risque, ou supprimer entièrement l’objet en cliquant sur l’icône en forme d’engrenage dans le coin supérieur droit de la vue de l’objet.

Des constatations peuvent également être ajoutées à l’objet ou en être retirées à l’aide de ce même menu. Autrement, une constatation peut être retirée de l’objet en cliquant sur le menu ⋮ à côté d’une constatation individuelle, en cliquant sur **Actions de mise à jour groupée**, puis en sélectionnant **Annuler l’acceptation du risque** dans le menu déroulant Statut d’acceptation du risque simple.

Enfin, si vous ajoutez des constatations à un objet Acceptation du risque complète puis que vous supprimez cet objet par la suite, le statut des constatations qu’il contenait repassera automatiquement à « Actif ».

### Acceptations du risque simples

Les acceptations du risque simples ne comportent aucune métadonnée ni date d’expiration associées. Elles conviennent le mieux lorsque le suivi des constatations à risque accepté reste nécessaire à des fins de conformité, mais sans qu’il soit besoin d’un objet pour suivre ou modifier le statut des constatations concernées.

L’acceptation du risque simple n’est pas activée par défaut, mais elle peut être activée dans la section Champs facultatifs des paramètres de l’actif, après avoir cliqué sur l’icône en forme d’engrenage dans le coin supérieur droit de la vue de l’actif.

![Enabling simple risk acceptance](images/RA_image3.png)

Une fois activée, l’acceptation du risque simple peut être exécutée depuis le tableau des constatations dans une vue de test.

#### Comment effectuer une acceptation du risque simple

Vous pouvez effectuer le workflow d’acceptation du risque simple soit depuis le tableau Toutes les constatations (accessible depuis la barre latérale), soit depuis le tableau des constatations d’un test spécifique. Le workflow est identique dans les deux cas.

Sélectionnez les constatations dont vous souhaitez accepter le risque, puis cliquez sur le bouton **Actions de mise à jour groupée** qui apparaît en haut du tableau. Sélectionnez ensuite **Accepter le risque** dans le menu déroulant Statut d’acceptation du risque simple. Étant donné que les constatations ont fait l’objet d’une acceptation du risque simple, aucun objet Acceptation du risque complète n’y est associé. Les constatations dont le risque a été accepté sont accessibles depuis le menu **Constatations à risque accepté** dans la barre latérale.

![Risk Acceptance Actions in Table](images/RA_image4.png)

À l’inverse, si vous souhaitez annuler l’acceptation du risque pour des constatations dont le risque avait été précédemment accepté, sélectionnez **Annuler l’acceptation du risque**. Si une constatation a fait l’objet d’une acceptation du risque simple, le risque doit être annulé avant de pouvoir l’ajouter à un objet Acceptation du risque complète.

## Autorisations et visibilité de l’acceptation du risque

La visibilité d’une acceptation du risque **est soumise à un niveau d’autorisation minimal distinct de celui de la visibilité des constatations**. Un utilisateur pouvant consulter une constatation ne dispose pas automatiquement de l’autorisation de consulter une acceptation du risque contenant cette constatation.

### Rôle minimal pour les actions d’acceptation du risque

| Action | Rôle minimal sur l’actif (produit) parent |
| --- | --- |
| Consulter une acceptation du risque | Writer |
| Ajouter ou modifier une acceptation du risque | Writer |

Pour le tableau complet des rôles et autorisations répertoriant les autorisations d’acceptation du risque aux côtés des autres actions au niveau de l’actif, consultez [Action permission charts](/admin/user_management/user_permission_chart/#role-permission-chart).

## Faire expirer et rétablir une acceptation du risque

Une acceptation du risque expirée est étiquetée **Expirée** à côté de sa date d’expiration dans le tableau des acceptations du risque, ce qui permet de repérer en un coup d’œil celles qui ne suppriment plus leurs constatations.

Le menu en forme d’engrenage d’une acceptation du risque — dans le tableau ou sur sa page de détail — propose l’option applicable parmi les suivantes :

- **Faire expirer l’acceptation du risque**, sur une acceptation encore active. Elle expire immédiatement plutôt que d’attendre sa date d’expiration, et ses constatations sont réactivées selon ses paramètres **Reactivate Expired Findings** et **Restart SLA Expired**.
- **Rétablir l’acceptation du risque**, sur une acceptation qui a expiré. Ses constatations sont de nouveau acceptées, et elle expire après le nombre de jours défini dans le paramètre **Risk Acceptance Form Default Days**.

Les deux actions nécessitent la même autorisation que la modification de l’acceptation du risque, et toutes deux demandent une confirmation au préalable. Pour rétablir l’acceptation pour une durée spécifique plutôt que la fenêtre par défaut, modifiez la date d’expiration plutôt que d’utiliser l’action Rétablir — voir ci-dessous.

## Lorsque la date d’expiration d’une acceptation du risque est modifiée

La date d’expiration d’une acceptation du risque peut être modifiée à tout moment après sa création. Le comportement de DefectDojo dépend de l’état actuel de l’acceptation du risque : active ou déjà expirée.

### Modifier la date sur une acceptation du risque active

Si une acceptation du risque n’a pas encore expiré — sa date d’expiration est dans le futur, ou vient tout juste de passer mais la tâche périodique d’expiration ne l’a pas encore traitée — la modification de la date est simple :

- La nouvelle date est enregistrée telle quelle. Si l’utilisateur choisit `2027-01-15`, l’acceptation du risque enregistre `2027-01-15`.
- Les constatations liées restent en Risque accepté.
- L’objet Acceptation du risque reste actif.

### Repousser la date sur une acceptation du risque déjà expirée

Si l’acceptation du risque a **déjà expiré** — c’est-à-dire que la tâche périodique a traité son expiration, que les constatations liées ont été remises au statut Actif selon les paramètres d’expiration de l’acceptation du risque, et que l’acceptation du risque est dans l’état expiré — modifier la date d’expiration vers une valeur future déclenche un workflow de **rétablissement** :

- L’acceptation du risque est rétablie et n’est plus dans l’état expiré.
- Chaque constatation qui était liée à l’acceptation du risque et qui est actuellement Actif est de nouveau acceptée (remise en Risque accepté / Inactif).
- Les statuts des points de terminaison de ces constatations sont mis à jour pour refléter la nouvelle acceptation.
- Un commentaire est publié sur les tickets Jira liés pour consigner le rétablissement.

La date que vous saisissez est celle qui est enregistrée. Le paramètre système **Risk Acceptance Form Default Days** (par défaut : 180) n’est utilisé que lorsque vous n’avez pas demandé de date particulière — par exemple lorsque vous utilisez l’action **Rétablir**, qui rétablit l’acceptation du risque sans modifier sa date d’expiration, et la définit donc à aujourd’hui + N jours.

### Reculer la date ou la fixer à une date déjà passée

Déplacer la date d’expiration vers une date antérieure mais toujours future n’entraîne aucun comportement particulier — l’acceptation du risque reste active et la nouvelle date est enregistrée.

Déplacer la date vers une date passée ne fait pas expirer immédiatement l’acceptation du risque depuis le formulaire de modification ; la prochaine tâche périodique d’expiration la prendra en compte et appliquera le comportement d’expiration standard (constatations réactivées selon le paramètre **Reactivate Expired Findings** de l’acceptation du risque, redémarrage du SLA appliqué si **Restart SLA Expired** est activé).

### Ce que l’API expose

Les consommateurs de l’API peuvent observer l’état d’expiration de l’objet Acceptation du risque via les champs `expiration_date`, `expiration_date_handled` et `expiration_date_warned` :

- `expiration_date` est la date configurée.
- `expiration_date_handled` vaut `null` tant que l’acceptation du risque est active, et est défini sur un horodatage lorsque la tâche périodique a traité l’expiration. Une acceptation du risque est « expirée » précisément lorsque `expiration_date_handled` est non nul.
- `expiration_date_warned` est défini lorsque le système a envoyé la notification d’avertissement d’expiration.

Lorsqu’un rétablissement a lieu, `expiration_date_handled` et `expiration_date_warned` sont tous deux remis à `null`, et `expiration_date` contient la date que vous avez envoyée — ou aujourd’hui + N jours lorsque le rétablissement a été déclenché sans nouvelle date. Les outils qui surveillent les changements d’état des acceptations du risque peuvent utiliser le champ `expiration_date_handled` comme indicateur canonique de la question « cette acceptation du risque est-elle actuellement expirée ? ».

L’expiration et le rétablissement sont également disponibles directement, sans avoir à passer par la modification de `expiration_date` :

- `POST /api/v2/risk_acceptance/{id}/expire/` la fait expirer immédiatement. Renvoie `400` si elle a déjà expiré.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` rétablit une acceptation expirée, en acceptant de nouveau les constatations qu’elle couvre. Renvoie `400` si elle n’a pas expiré. Envoyez `expiration_date` pour choisir la durée ; omettez-le pour utiliser aujourd’hui + N jours.

Les deux acceptent un paramètre `reason` facultatif, qui est enregistré comme note sur l’acceptation du risque avec l’identité de l’auteur de l’action. Les deux nécessitent la même autorisation que la modification de l’acceptation du risque.

## Bonnes pratiques d’acceptation du risque

Bien qu’il soit possible d’agir sur les constatations d’objets Acceptation du risque complète à l’aide des workflows d’acceptation du risque simple (et inversement), il est généralement préférable d’adopter par défaut l’un ou l’autre processus de manière exclusive plutôt que d’activer les deux simultanément.

Par exemple, si les objets Acceptation du risque complète constituent l’approche par défaut, le fait qu’une constatation fasse l’objet d’une acceptation du risque simple peut créer de la confusion en l’absence d’objet associé contenant la constatation concernée. De même, si les constatations font habituellement l’objet d’une acceptation du risque simple, ajouter certaines constatations à un objet Acceptation du risque complète alors qu’il n’existe pas de tels objets pour la plupart des autres constatations peut créer une confusion similaire.
