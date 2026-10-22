---
title: Jira (historique)
description: Travailler avec l'intégration Jira
weight: 1
audience: pro
aliases:
- /fr/issue_tracking/jira/pro__jira_guide/
- /fr/en/share_your_findings/jira_guide
---

> **Cette page documente l'intégration Jira historique.** L'intégration Jira par produit décrite ici a été remplacée par le **[Connecteur Downstream Jira](/connectors/downstream/about/)**, qui est disponible en version généralement disponible sur toutes les instances DefectDojo Pro et constitue la méthode recommandée pour transmettre les Constatations à Jira. Dans la barre latérale Pro, **Connect > Jira** porte pour cette raison un badge `LEGACY` — voir [Badges de menu](/navigation/pro__menu_badges/).
>
> **Si vous configurez Jira pour la première fois, commencez par le [Connecteur Downstream](/connectors/downstream/about/) plutôt que par ce guide.**
>
> **Vous utilisez déjà l'intégration historique ?** DefectDojo Pro inclut une migration intégrée qui transfère votre configuration Jira classique existante vers les Connecteurs Downstream, y compris les tickets déjà transmis — voir [Migrer vers le connecteur Downstream Jira](#migrating-to-the-jira-downstream-connector) ci-dessous.
>
> L'intégration historique continue de fonctionner, et ce guide reste valable pour celle-ci.

L'intégration Jira de DefectDojo permet de transmettre les données de Constatations à un ou plusieurs espaces Jira. Cela vous permet d'intégrer DefectDojo à votre flux de développement standard. Voici quelques exemples de fonctionnement possible :

* L'équipe AppSec peut transmettre sélectivement des Constatations à un espace Jira utilisé par les développeurs, afin que la résolution des tickets puisse être hiérarchisée de manière appropriée aux côtés du développement habituel. Les développeurs présents sur ce tableau n'ont pas besoin d'accéder à DefectDojo : ils peuvent conserver tout leur travail au même endroit.
* DefectDojo peut transmettre TOUTES les Constatations à un espace Jira bidirectionnel utilisé par l'équipe AppSec, ce qui lui permet de répartir la validation des tickets. Ce tableau reste synchronisé avec DefectDojo et permet des flux de résolution complexes.
* DefectDojo peut transmettre sélectivement des Constatations provenant de Produits et/ou d'Engagements distincts vers des espaces Jira distincts, afin de conserver chaque élément dans son contexte propre.

## Migration vers le connecteur Downstream Jira

DefectDojo Pro peut convertir pour vous une configuration Jira classique existante en configuration de Connecteur Downstream, plutôt que de vous obliger à la reconstruire manuellement.

**Où le trouver :** accédez à **Connect \> Downstream** pour ouvrir la page **Downstream Connectors**, puis utilisez la carte **Classic Jira Migration**. Cliquez sur **Migrate from classic Jira**, puis confirmez.

La carte n'apparaît que s'il existe une configuration Jira classique à migrer, ou une exécution précédente à signaler — une instance n'ayant jamais utilisé Jira classique ne la verra donc pas. Une fois que tout a été migré, la carte reste visible mais le bouton est désactivé, car il n'y a plus rien à faire.

L'exécution de la migration nécessite des **permissions globales de niveau Maintainer** (plus précisément, la permission de modifier les intégrations), et elle doit être lancée depuis une session de navigateur connectée — elle ne peut pas être déclenchée via un jeton API.

### Que deviennent les tickets déjà transmis

**Vos tickets Jira existants sont conservés et reliés à nouveau — ils ne se retrouvent pas orphelins, et le connecteur n'ouvre pas de doublons.** Chaque Constatation déjà transmise par Jira classique conserve son ticket, et le connecteur prend le relais pour mettre à jour ce même ticket en place. Les liens sur les groupes de Constatations sont conservés de la même manière.

La seule exception concerne les **epics d'Engagement**. Le Connecteur Downstream n'a pas de notion d'epic ; les tickets epic sont donc signalés dans les avertissements de la migration et laissés tels quels.

### Ce qui est migré

* Votre connexion d'**instance** Jira — URL et identifiants — devient une instance d'intégration de Connecteur Downstream, en conservant son nom.
* Les **mappages de sévérité** et les **mappages de statut** (vos clés de transition d'ouverture et de fermeture) sont transférés.
* Chaque configuration de **Jira Project** devient un mappage de suivi de tickets, en conservant sa clé de projet et son type de ticket, et reste associée au même Produit ou Engagement.
* **Push All Issues** est conservé : les projets qui l'avaient activé continuent de transmettre automatiquement.
* Les **champs personnalisés**, les **champs de transition de fermeture/réouverture**, le **composant**, l'**assigné par défaut** et les **étiquettes** sont convertis en mappages de champs. Si vous utilisiez *Add Vulnerability Id as a Jira label*, cela devient également un mappage d'étiquette.
* Un répertoire de **modèle de ticket personnalisé** devient un modèle de ticket. Les modèles standard ne sont pas copiés, car le connecteur fournit déjà des équivalents.

### Ce qui n'est pas transféré

Ces éléments sont signalés sous forme d'avertissements lors de l'exécution de la migration — ils ne l'interrompent pas. Recherchez la liste *"things the connector cannot carry over"* dans les résultats.

* **La synchronisation inverse Jira → DefectDojo.** C'est le point le plus important. Le Connecteur Downstream ne synchronise pas les changements *en provenance* de Jira, si bien que les mappages de résolution qui appliquent le statut Risque accepté ou Faux positif à partir d'une résolution Jira ne sont pas migrés. **Si vous dépendez de la synchronisation inverse, laissez l'instance Jira classique configurée** — la migration ne la supprime pas.
* **Engagement Epic Mapping** — le connecteur n'a pas de notion d'epic.
* **Push Notes**, les **commentaires de notification SLA** et les **commentaires d'expiration d'acceptation du risque** — le connecteur ne les publie pas dans Jira.
* Les champs personnalisés nommés `summary`, `description`, `project`, `issuetype` ou `status` — ils sont réservés par le connecteur, et tout mappage de champ qui en utilise un est ignoré.
* Les valeurs de champ personnalisé de plus de 512 caractères — ignorées plutôt que tronquées.
* Un Jira Project qui n'est rattaché ni à un Produit ni à un Engagement ne produit aucune association.

### Que devient l'intégration classique par la suite

**Rien n'est transmis deux fois.** Pour chaque projet qu'elle migre, la migration désactive le projet Jira classique, de sorte que seul le connecteur transmet des données à partir de ce moment. Vous n'avez rien à désactiver manuellement.

Votre configuration classique est **conservée, et non supprimée** — l'instance, le projet et les enregistrements de tickets restent tous en place, seuls les paramètres de transmission sont désactivés. Ceci est délibéré : c'est ce qui rend le changement réversible, et ce qui permet à la synchronisation inverse de continuer à fonctionner si vous en dépendez.

**Pour revenir en arrière**, réactivez les paramètres du projet Jira classique et supprimez la configuration de connecteur créée par la migration. Il n'existe pas d'annulation en un clic.

**Relancer la migration est sans risque.** Elle enregistre ce qu'elle a déjà converti et l'ignore lors d'une seconde exécution, de sorte que rien n'est dupliqué. Si un projet ou une instance échoue, le reste de la migration se poursuit — un projet en échec reste actif sur l'intégration classique plutôt que d'être désactivé, afin de continuer à fonctionner pendant que vous investiguez.

### Pendant l'exécution

La migration s'exécute en arrière-plan et signale sa progression au fur et à mesure. À la fin, vous obtenez un résumé — le nombre de connecteurs, de mappages, d'associations, de modèles et de liens de tickets créés, le nombre de projets classiques désactivés, et tout ce qui a été ignoré — accompagné des avertissements décrits ci-dessus. Une seule migration s'exécute à la fois.

# Configuration de Jira

La configuration de Jira nécessite les étapes suivantes :
1. Activez l'intégration Jira dans les Paramètres système. Tant que ce n'est pas fait, le reste des paramètres Jira reste masqué dans DefectDojo.
2. Connectez une instance Jira, avec un nom d'utilisateur / mot de passe ou un jeton API. Plusieurs instances peuvent être liées.
3. Ajoutez cette instance Jira à un ou plusieurs Produits ou Engagements dans DefectDojo.
4. Si vous souhaitez utiliser la synchronisation bidirectionnelle, créez un Webhook Jira qui enverra les mises à jour à DefectDojo.

## Étape 1 : activer l'intégration Jira dans les paramètres système

L'intégration Jira est désactivée par défaut, et tant qu'elle l'est, DefectDojo masque tous les autres contrôles Jira de l'interface. C'est la première chose à configurer : aucune des étapes ci-dessous n'est disponible tant qu'elle n'est pas activée.

Tant que l'intégration est désactivée, il n'y a pas d'entrée **Jira Instances** dans la barre latérale, il n'y a donc aucun endroit où ajouter une instance Jira :

![image](images/jira-menu-hidden-pro.png)

### Activer l'intégration

1. Accédez à **Settings \> System \> System Settings** depuis la barre latérale de DefectDojo. Sur les instances utilisant encore l'ancienne disposition de menu, cela se trouve sous un groupe nommé d'après votre offre de licence — **Pro Settings** ou **Enterprise Settings**. Voir [Le menu Paramètres](/navigation/pro__settings_menu/).
​
2. Dans la section **Jira Integration Settings**, cochez **Enable Jira Integration**.
​
3. Cliquez sur **Submit**. **Jira Instances** apparaît immédiatement dans la barre latérale, sans recharger la page :

![image](images/jira-enable-system-settings-pro.png)

### Ce que contrôle ce paramètre

Activer **Enable Jira Integration** est ce qui fait apparaître le reste de l'interface Jira. Une fois activé, vous obtenez :

* le menu **Jira Instances**, où les instances Jira sont ajoutées et modifiées
* la page **Jira Project Settings** dans le menu ⚙️ de l'Asset, et les paramètres Jira sur les Engagements
* les actions **Push to Jira** sur les Constatations et les groupes de Constatations, les champs Jira sur les formulaires de Constatation et d'édition en masse, et les colonnes Jira sur les listes Asset, Engagement, Constatation et Groupe de Constatations (y compris les exports CSV)

Ce paramètre contrôle également l'intégration en dehors de l'interface utilisateur : tant qu'il est désactivé, DefectDojo ne transmet pas les Constatations à Jira (y compris les requêtes `push_to_jira` envoyées via l'API), et les webhooks Jira entrants sont ignorés.

Les champs Jira restants dans **Jira Integration Settings** (**Add Vulnerability ID as Jira Label**, **Enable Jira Web Hook**, **Disable Jira Web Hook Secret**, **Jira Web Hook Secret**, **Jira Minimum Severity**) restent visibles que l'intégration soit activée ou non, mais ils n'ont aucun effet tant qu'elle n'est pas activée.

## Étape 2 : connecter une instance Jira

Une fois l'intégration activée, la connexion d'une instance Jira est l'étape suivante de la configuration de l'intégration Jira de DefectDojo. Notez que Jira Service Management n'est actuellement pas pris en charge.

#### Informations requises depuis Jira

Atlassian utilise des méthodes d'authentification différentes entre Jira Cloud et Jira Data Center.

pour **Jira Cloud**, vous aurez besoin de :
* une URL Jira, par ex. https://yourcompany.atlassian.net/
* un compte disposant des permissions nécessaires pour créer et mettre à jour des tickets dans votre instance Jira. Cela peut être :
    * Une combinaison standard **nom d'utilisateur / mot de passe**
    * Une combinaison **nom d'utilisateur / jeton API**

pour **Jira Data Center (ou Server)**, vous aurez besoin de :
* une URL Jira, par ex. https://jira.yourcompany.com
* un compte disposant des permissions nécessaires pour créer et mettre à jour des tickets dans votre instance Jira. Cela peut être :
    * Une combinaison standard **nom d'utilisateur / mot de passe**
    * Une combinaison **adresse e-mail / jeton d'accès personnel**

Vous pouvez éventuellement mapper :
* Les transitions Jira pour déclencher la réouverture et la fermeture des Constatations
* Les résolutions Jira pouvant appliquer les statuts Risque accepté et Faux positif aux Constatations (optionnel)

Une seule connexion d'instance Jira peut gérer plusieurs espaces Jira, tant que le compte / jeton Jira utilisé par DefectDojo dispose de la permission de créer des tickets dans l'espace Jira associé.

### Ajouter une instance Jira

1. Assurez-vous que **Enable Jira Integration** est coché dans les Paramètres système, comme décrit à l'[Étape 1](#step-1-enable-the-jira-integration-in-system-settings). Le menu **Jira Instances** n'apparaît dans la barre latérale que lorsque c'est le cas.

2. Accédez à la page **Enterprise Settings \> Jira Instances \> + New Jira Instance** depuis la barre latérale de DefectDojo.

![image](images/jira-instance-beta.png)

3. Sélectionnez un **Configuration Name** pour cette instance Jira à utiliser dans DefectDojo. Ce nom est simplement une étiquette pour la connexion d'instance dans DefectDojo, et n'a pas besoin d'être lié à des données Jira.

4. Sélectionnez l'URL de l'instance Jira de votre entreprise \- probablement similaire à `https://**yourcompany**.atlassian.net` si vous utilisez une installation Jira Cloud.

5. Saisissez une méthode d'authentification appropriée dans les champs Nom d'utilisateur / Mot de passe pour Jira :
    * Pour une **authentification Jira standard par nom d'utilisateur / mot de passe**, saisissez un nom d'utilisateur Jira et le mot de passe correspondant dans ces champs.
    * Pour une authentification avec le **jeton API d'un utilisateur (Jira Cloud)**, saisissez le nom d'utilisateur avec le **jeton API** correspondant dans le champ mot de passe.
    * Pour une authentification avec un **jeton d'accès personnel Jira (PAT, utilisé uniquement avec Jira Data Center et Jira Server)**, saisissez le PAT dans le champ mot de passe. Le nom d'utilisateur n'est pas utilisé pour l'authentification avec un PAT Jira, mais le champ reste obligatoire dans ce formulaire ; vous pouvez donc y saisir une valeur de substitution pour identifier votre PAT.

Notez que l'utilisateur associé à cette connexion doit disposer de la permission de créer des tickets et d'accéder aux données de votre instance Jira.

6. Vous devrez fournir des valeurs pour Epic Name ID, Re-open Transition ID et Close Transition ID. Ces valeurs peuvent être modifiées ultérieurement. Une fois connecté à Jira, vous pouvez récupérer ces valeurs à partir des URL suivantes :
- **Epic Name ID** : accédez à `https://<YOUR JIRA URL>/rest/api/2/field` et recherchez Epic Name. Copiez le nombre présent dans `number` et collez-le ici. Si vous n'avez pas d'Epic Name ID associé à votre espace dans Jira (par exemple parce que vous utilisez un espace géré par l'équipe), saisissez 0 dans ce champ.
- **Re-open Transition ID** : accédez à `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` pour trouver l'ID correspondant à votre instance Jira. Collez-le dans le champ Reopen Transition ID.
- **Close Transition ID** : accédez à `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` pour trouver l'ID correspondant à votre instance Jira. Collez-le dans le champ Close Transition ID.

7. Sélectionnez le type de ticket par défaut que vous souhaitez utiliser pour créer des tickets dans Jira. Les options disponibles sont **Bug, Task, Story** et **Epic** (types de ticket Jira standard), ainsi que **Spike** et **Security**, qui sont des types de ticket personnalisés. Si vous souhaitez utiliser un type de ticket différent, contactez [support@defectdojo.com](mailto:support@defectdojo.com) pour obtenir de l'aide.

8. Sélectionnez votre modèle de ticket (Issue Template), qui déterminera la description du ticket lors de la création des tickets dans Jira.

Les deux types sont :
- **Jira\_full**, qui inclut toutes les informations de la Constatation dans les tickets Jira
- **Jira\_limited**, qui inclut une quantité réduite d'informations et de métadonnées de la Constatation.

Si vous laissez ce champ vide, la valeur par défaut sera **Jira\_full.** Si vous avez besoin d'un autre type de modèle, contactez [support@defectdojo.com](mailto:support@defectdojo.com).

9. Si vous le souhaitez, saisissez le nom d'une résolution Jira qui changera le statut d'une Constatation en Risque accepté ou en Faux positif (lorsque la résolution est déclenchée sur le ticket).

Le formulaire peut être soumis à partir d'ici. Si vous le souhaitez, vous pouvez personnaliser davantage votre intégration Jira dans Optional Fields. Cliquer sur ce bouton vous permettra d'appliquer du texte générique aux tickets Jira ou de modifier le mappage des Jira Severity Mappings.

## Étape 3 : connecter un Produit ou un Engagement à Jira

Chaque Produit ou Engagement dans DefectDojo dispose de ses propres paramètres qui déterminent comment les Constatations sont converties en tickets JIRA. Depuis cet écran, vous pouvez choisir l'espace Jira associé et définir le comportement par défaut pour la création des tickets, des epics, des étiquettes et d'autres métadonnées JIRA.

### Ajouter Jira à un Produit

Vous pouvez trouver cette page en cliquant sur le menu ⚙️ (Gear) d'un Produit et en ouvrant la page **Jira Project Settings**.

![image](images/jira-project-settings.png)

#### Instance Jira

Si vous avez configuré plusieurs instances de Jira, pour des produits ou des équipes distincts au sein de votre organisation, vous pouvez indiquer dans quel espace Jira vous souhaitez que DefectDojo crée des tickets. Sélectionnez un espace dans le menu déroulant.

Si ce menu ne liste aucune instance Jira, vérifiez que ces espaces sont connectés dans votre configuration Jira globale pour DefectDojo \- yourcompany.defectdojo.com/jira.

#### Clé de projet

Il s'agit de la clé de l'espace que vous souhaitez utiliser avec DefectDojo. La Space Key d'un espace donné se trouve dans l'URL. (Ceci était auparavant appelé **Jira Project Key**, mais depuis septembre 2025, Jira l'appelle désormais **Space Key**).

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Nom du type de ticket Epic

Le nom du type de ticket Epic dans Jira. La valeur par défaut est "Epic", mais elle peut être modifiée si votre instance Jira utilise un nom différent.

#### Modèle de ticket

Vous pouvez ici déterminer la quantité de métadonnées DefectDojo que vous souhaitez envoyer à Jira. Sélectionnez l'une des deux options :

* **jira\_full** : les tickets suivront tous les paramètres de DefectDojo \- une Description complète, le CVE, la Sévérité, etc. Utile si vous avez besoin du contexte complet de la Constatation dans Jira (par exemple, si une personne travaillant sur ce ticket n'a pas accès à DefectDojo).

Voici un exemple de ticket **jira\_full** :
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited :** les tickets ne suivront que le lien DefectDojo, les liens Produit/Engagement/Test, ainsi que les champs Reporter et Environment. Tous les autres champs sont suivis uniquement dans DefectDojo. Utile si vous n'avez pas besoin du contexte complet de la Constatation dans Jira (par exemple, si une personne travaillant sur ce ticket travaille principalement dans DefectDojo et n'a pas besoin d'avoir également la vue complète dans JIRA.)

​Voici un exemple de ticket **jira\_limited** :

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Composant

Si vous gérez votre espace Jira à l'aide de Components, vous pouvez lui attribuer ici le Component approprié pour DefectDojo. Pour attribuer plusieurs Components, saisissez une liste séparée par des virgules (par exemple, `Security, DevSecOps`) ; chaque valeur est envoyée à Jira comme un composant distinct.

#### Champs personnalisés

Si vous n'avez pas besoin d'utiliser de champs personnalisés avec les tickets DefectDojo, vous pouvez laisser ce champ à 'null'.

Cependant, si les paramètres de votre espace Jira **vous obligent** à utiliser des champs personnalisés sur les nouveaux tickets, vous devrez coder ces mappages en dur.

Notez que DefectDojo ne peut pas envoyer de métadonnées spécifiques à un ticket en tant que champs personnalisés, seulement une valeur par défaut. Cette section ne doit être configurée que si votre espace Jira **exige que ces champs personnalisés existent** dans chaque ticket de votre espace.

Suivez **[ce guide](#custom-fields-in-jira)** pour commencer à travailler avec les champs personnalisés.

#### Champs de transition de fermeture / réouverture

Certains workflows Jira **exigent** que certains champs soient renseignés dans le cadre d'une transition — par exemple, un workflow qui refuse de fermer un ticket tant qu'un champ Resolution et un champ Justification ne sont pas renseignés sur l'écran de fermeture. Le paramètre Champs personnalisés ci-dessus ne s'applique que lors de la *création* d'un ticket, il ne peut donc pas satisfaire ces workflows.

Sans ces paramètres, DefectDojo envoie les transitions de fermeture / réouverture sans aucun champ. Un workflow qui exige des champs rejettera cette transition, et la Constatation et le ticket Jira se désynchronisent : la Constatation apparaît comme Atténuée dans DefectDojo alors que le ticket reste ouvert dans Jira.

Les paramètres **Close Transition fields** et **Reopen Transition fields** acceptent un objet JSON envoyé comme charge utile `fields` de l'appel de transition de fermeture / réouverture. Par exemple, pour fermer des tickets avec une Resolution *Won't Fix* et une valeur de justification :

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

Laissez ces paramètres à 'null' si votre workflow Jira n'exige pas de champs sur les transitions.

**De quels champs avez-vous besoin ?**

* Demandez à votre administrateur Jira quels champs figurent sur les **écrans de transition** de fermeture / réouverture, et lesquels sont imposés par un validateur. Le JSON configuré doit satisfaire **tous** les champs requis : si un champ requis est absent de la charge utile, Jira rejette l'intégralité de la transition et ne définit rien — fournir seulement une partie des champs requis ne suffit pas.
* À l'inverse, les champs doivent être présents **sur l'écran de transition** pour pouvoir être envoyés : Jira rejette les transitions qui tentent de définir des champs absents de l'écran de cette transition.
* Sur les workflows créés avec l'éditeur de workflow actuel de Jira Cloud, Jira renseigne automatiquement la Resolution par défaut du site lorsqu'un ticket passe à un statut de catégorie "terminé". Ainsi, une Resolution requise ne bloquera pas à elle seule une transition simple dans ce cas, et l'utilité pratique de `"resolution"` dans cette charge utile est de choisir une valeur *significative* (par exemple *False Positive*) plutôt que la valeur par défaut du site. Les workflows créés avec l'éditeur classique, ou avec des applications de validation du marketplace, peuvent quant à eux exiger la Resolution de manière stricte.
* Les transitions de réouverture réinitialisent généralement la Resolution via le workflow lui-même, donc **Reopen Transition fields** n'a en général besoin que des champs personnalisés exigés par votre workflow.

**Notes :**

* Le même JSON est envoyé pour *chaque* transition de fermeture (ou de réouverture) du Produit ou de l'Engagement — les valeurs sont statiques et ne varient pas selon la Constatation. Si vous avez besoin de champs différents selon la disposition (par exemple, une Resolution différente pour les Constatations Faux positif que pour les Constatations corrigées), utilisez le DefectDojo Pro Jira Integrator, qui prend en charge des mappages de champs de transition par statut.
* Les valeurs utilisent le même format que l'API REST de Jira : des chaînes pour les champs texte, `{"name": ...}` pour les résolutions, `[{"name": ...}]` pour les champs à sélection multiple, etc.
* Si des transitions ont été rejetées alors que ces paramètres étaient absents ou incomplets, corriger les paramètres répare la dérive : la prochaine transmission de statut pour la Constatation retente la transition avec les champs configurés.
* Ces deux paramètres sont également disponibles sur le point de terminaison REST `/api/v2/jira_projects/` (`close_transition_fields` / `reopen_transition_fields`), et peuvent donc être gérés via l'API.
* Ces champs sont également appliqués lorsque DefectDojo ferme un ticket parce que sa Constatation a été **supprimée** — les valeurs sont capturées au moment où la fermeture est mise en file d'attente.

#### Étiquettes Jira

Sélectionnez les étiquettes pertinentes avec lesquelles vous souhaitez que le ticket soit créé dans Jira, par ex. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Assigné par défaut

Le nom de l'assigné par défaut dans Jira. Si ce champ est laissé vide, DefectDojo suivra le comportement par défaut de votre espace Jira lors de la création des tickets.

### Jira Project Settings

#### Enabled

Ce bouton bascule contrôle si DefectDojo transmet les Constatations à Jira pour ce Produit. Le désactiver ne supprimera ni ne modifiera les tickets Jira existants créés par DefectDojo, mais empêchera toute mise à jour supplémentaire ou création de nouveau ticket.

Les intégrations Jira ne peuvent être supprimées de votre instance que si aucun ticket associé n'a été créé. Si des tickets ont été créés, il n'existe aucun moyen de supprimer complètement une instance Jira de DefectDojo.

#### Add Vulnerability Id as a Jira label

Cela vous permet d'ajouter automatiquement l'ID de vulnérabilité comme étiquette Jira. Les ID de vulnérabilité sont ajoutés aux Constatations par les outils de sécurité individuels \- il peut s'agir d'ID CVE (Common Vulnerabilities and Exposures) ou d'un format différent, propre à l'outil ayant signalé la Constatation.

#### Push All Issues

Si cette case est cochée, DefectDojo transmettra automatiquement à Jira, sous forme de tickets, toutes les Constatations Actives et Vérifiées. Si elle est décochée, toutes les Constatations devront être transmises manuellement à Jira (individuellement ou via une transmission en masse).

Lorsque ce paramètre est activé, les tickets Jira continuent de se synchroniser avec DefectDojo même si le statut de la Constatation change.

#### Enable Engagement Epic Mapping

Dans DefectDojo, les Engagements représentent un ensemble de travaux. Chaque Engagement contient un ou plusieurs Tests, qui contiennent une ou plusieurs Constatations à corriger. Les epics dans Jira fonctionnent de manière similaire, et cette case à cocher vous permet de transmettre les Engagements à Jira sous forme d'epics.

* Un Engagement dans DefectDojo \- notez les trois constatations listées en bas.
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Comment le même Engagement devient un Epic une fois transmis à JIRA \- les Constatations de l'Engagement sont également transmises et apparaissent à l'intérieur de l'Engagement en tant que tickets enfants (Child Issues).

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push Notes

Si cette option est activée, les commentaires Jira apparaîtront sur la Constatation associée dans DefectDojo, sous Notes, et inversement ; les Notes sur les Constatations seront ajoutées au ticket Jira associé sous forme de commentaires.

#### Send SLA Notifications As Comments

Si cette option est activée, tout ticket qui enfreint les règles de l'accord de niveau de service (SLA) de DefectDojo recevra des commentaires sur le ticket Jira l'indiquant. Ces commentaires seront publiés quotidiennement jusqu'à ce que le ticket soit résolu.

Les accords de niveau de service peuvent être configurés sous **Configuration \> SLA Configuration** dans DefectDojo et affectés à chaque Produit.

#### Send Risk Acceptance Expiration Notifications As Comment

Si cette option est activée, tout ticket dont l'Acceptation du risque DefectDojo associée expire recevra un commentaire sur le ticket Jira l'indiquant. Ces commentaires seront publiés quotidiennement jusqu'à ce que le ticket soit résolu.

### Paramètres Jira au niveau de l'Engagement

Par défaut, les Engagements **héritent des paramètres Jira de leur Produit**. Vous pouvez toutefois remplacer les paramètres Jira pour des Engagements individuels.

Pour accéder aux paramètres Jira au niveau de l'Engagement, cliquez sur le menu ⚙️ (Gear) d'un Engagement et ouvrez la page **Jira Project Settings**.

Depuis cet écran, vous pouvez décocher **Inherit from Product** et fournir des valeurs spécifiques à l'Engagement pour : **Project Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee**, ainsi que d'autres paramètres.

Notez qu'une fois qu'un Engagement dispose de son propre projet Jira assigné, il ne peut plus hériter du Produit.

![image](images/Creating_Issues_in_Jira_5.png)

## Étape 4 : Configurer la synchronisation bidirectionnelle : Webhook Jira

L'intégration Jira permet une synchronisation bidirectionnelle via webhook. DefectDojo reçoit les notifications Jira à une adresse unique, ce qui permet de recevoir des commentaires Jira sur les Constatations, ou de résoudre des Constatations via Jira selon votre configuration.

### Localiser votre URL de webhook Jira

Votre webhook Jira se trouve sur le formulaire des paramètres système, sous **Jira Integration Settings** : **Enterprise Settings \> System Settings** depuis la barre latérale.

Vous devez également cocher **Enable Jira Web Hook** sur la même page pour que DefectDojo traite les notifications Jira entrantes. Les webhooks entrants sont ignorés si cette case ou **Enable Jira Integration** (voir [Étape 1](#step-1-enable-the-jira-integration-in-system-settings)) n'est pas cochée.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Créer le webhook Jira

1. Rendez-vous sur `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Cliquez sur « Create a Webhook ».
3. Dans le champ intitulé « URL », saisissez : `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. Le secret du webhook figure sous Jira Integration Settings comme indiqué ci-dessus.
4. Sous « Comments », activez « Created ». Sous « Issue », activez « Updated ».
5. Assurez-vous que votre instance JIRA fait confiance au certificat SSL utilisé par votre instance DefectDojo. Pour JIRA Cloud, DefectDojo doit utiliser [un certificat SSL/TLS valide, signé par une autorité de certification mondialement reconnue](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Notez que vous n'avez pas besoin de créer un secret dans Jira pour utiliser ce webhook. Le secret est intégré à l'URL de DefectDojo ; il suffit donc d'ajouter l'URL complète au formulaire de webhook Jira.

Les requêtes de webhook entrantes sont authentifiées par le secret contenu dans cette URL : traitez donc l'URL complète comme une donnée d'identification et gardez-la confidentielle.

#### Tester le webhook

Une fois que vous avez une ou plusieurs Issues créées à partir de Constatations DefectDojo, vous pouvez tester le webhook en ajoutant une note à l'une de ces Constatations. La note devrait être reçue par le webhook Jira sous forme de commentaire.

Si cela ne fonctionne pas correctement, cela peut être dû à un problème de pare-feu sur votre instance Jira bloquant le webhook.

* Les règles de pare-feu de DefectDojo incluent une case à cocher pour **Jira Cloud**, qui doit être activée pour que DefectDojo puisse recevoir les messages de webhook provenant de Jira.

### Alternative : utiliser Jira Automation (Send web request)

Certaines instances Jira n'autorisent pas les webhooks système sous `/plugins/servlet/webhooks` — par exemple lorsque cette zone d'administration est restreinte et que seules les règles **Jira Automation** sont autorisées. Dans ce cas, vous pouvez piloter la même synchronisation bidirectionnelle à l'aide de l'action **Send web request** d'Automation, qui envoie une requête vers le même point de terminaison webhook DefectDojo.

Le point de terminaison webhook de DefectDojo accepte toute requête HTTP `POST` avec `Content-Type: application/json` et un secret valide dans le chemin de l'URL. Il n'exige **pas** que la requête provienne du mécanisme de webhook système de Jira ; l'action « Send web request » d'Automation fonctionne donc comme une alternative directe.

#### Prérequis

Les mêmes prérequis que pour le webhook système s'appliquent :

* **Enable JIRA integration** et **Enable JIRA web hook** sont tous deux cochés sur la page ⚙️ **Configuration \> System Settings**.
* Un **Jira webhook secret** non vide est défini sur cette page. Le secret ne peut contenir que les caractères `A-Z`, `a-z`, `0-9`, `_` et `-`.
* La Constatation (ou le Groupe de constatations) est déjà liée à l'Issue Jira. Si l'issue n'est pas liée à une Constatation DefectDojo, la requête est tout de même acceptée (HTTP `200`) mais aucune action n'est effectuée.

#### Comment DefectDojo traite la requête

* DefectDojo se base sur un champ de premier niveau `webhookEvent`. Seuls `"jira:issue_updated"` et `"comment_created"` sont traités ; toute autre valeur est acceptée mais ignorée. Automation n'ajoute pas ce champ de lui-même, vous devez donc l'inclure vous-même dans le corps de la requête.
* Pour cette raison, réglez le **Body** de la requête sur **Custom data** et fournissez le JSON ci-dessous. Les options de corps **Empty** et **Jira issue data** n'incluent pas le champ `webhookEvent` requis, DefectDojo les ignorera donc.
* Le point de terminaison renvoie toujours HTTP `200`, qu'une mise à jour ait été appliquée ou non. La réussite ou l'échec n'est visible que dans le corps de la réponse et dans les journaux DefectDojo — un `200` dans le journal d'audit d'Automation ne confirme pas à lui seul que la mise à jour a bien atteint une Constatation.

#### Règle 1 — Issue mise à jour

Créez une règle Automation avec :

* **Déclencheur (Trigger) :** *Issue transitioned* (ou tout autre déclencheur qui se déclenche lorsque les champs que vous synchronisez changent, par exemple *Field value changed* sur Status).
* **Action :** *Send web request*
  * **Web request URL :** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **Méthode HTTP :** `POST`
  * **Web request body :** *Custom data*
  * **En-têtes (Headers) :** `Content-Type: application/json`
  * **Custom data :**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

Contraintes pour les mises à jour d'issue :

* `issue.id` doit être l'**ID interne numérique de l'issue Jira** (`{{issue.id}}`), et non la clé de l'issue (par ex. `PROJ-123`). DefectDojo fait correspondre la mise à jour à une Constatation à l'aide de cet ID numérique.
* Les champs `resolution` et `updated` doivent toujours être présents. `resolution` peut être `null`, mais si l'un des deux champs est absent, la requête est acceptée (`200`) mais n'est pas traitée, silencieusement.
* La synchronisation de statut et l'atténuation automatique sont pilotées par `status.statusCategory.key`, dont les valeurs Jira sont `new` (To Do), `indeterminate` (In Progress) et `done` (Done). Une Constatation n'est atténuée que lorsque l'issue est réellement fermée, et non simplement parce qu'une valeur de résolution est présente.

#### Règle 2 — Issue commentée

Créez une seconde règle Automation avec :

* **Déclencheur (Trigger) :** *Issue commented*
* **Action :** *Send web request* — même URL, méthode, en-tête et option de corps *Custom data* que pour la Règle 1, avec ce corps :

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

Contraintes pour les commentaires :

* `body` et `updateAuthor` doivent tous deux être présents.
* DefectDojo détermine l'issue cible à partir de l'URL `comment.self` — plus précisément le `<id>` dans le segment `.../issue/<id>/comment/...` — `{{issue.id}}` (l'ID numérique) doit donc y figurer.
* **Prévention des boucles :** si l'auteur du commentaire correspond au compte Jira que DefectDojo utilise pour publier ses propres commentaires, DefectDojo ignore le commentaire afin d'éviter une boucle d'écho. Si vous souhaitez que *tous* les commentaires soient ingérés, exécutez la règle Automation avec un utilisateur Jira **différent** de celui configuré dans l'instance Jira de DefectDojo.

#### Remarque sur les smart values

Les smart values indiquées ci-dessus (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, etc.) sont les noms standard de Jira Cloud, mais ils peuvent varier d'une instance à l'autre. Avant la mise en production, utilisez l'aperçu de charge utile (payload preview) d'Automation pour vérifier que chaque smart value se résout comme attendu.

## Tester l'intégration Jira

#### Test 1 : les Constatations sont-elles bien envoyées vers Jira ?

Pour vérifier que l'intégration Jira fonctionne correctement, vous pouvez ajouter une nouvelle Constatation vierge au Produit associé à Jira dans DefectDojo. **Produit \> Findings \> Add New Finding.**

Ajoutez le titre, la sévérité et la description de votre choix, puis cliquez sur « Finished ». La Constatation doit apparaître comme une Issue dans Jira avec toutes les métadonnées pertinentes.

Si les Issues Jira ne sont pas créées correctement, vérifiez vos notifications pour les codes d'erreur.

* Vérifiez que l'utilisateur Jira associé à la configuration Jira de DefectDojo dispose des permissions nécessaires pour créer et mettre à jour des issues sur cet espace Jira en particulier.

#### Test 2 : les webhooks Jira sont bien envoyés vers DefectDojo

Pour tester les webhooks Jira, ajoutez une note à une Constatation qui existe également dans JIRA en tant qu'Issue (par exemple, l'issue de test de la section précédente).

Si les webhooks sont configurés correctement, vous devriez voir la note apparaître dans Jira sous forme de commentaire sur l'issue.

Si cela ne fonctionne pas correctement, cela peut être dû à un problème de pare-feu sur votre instance Jira bloquant le webhook.

* Les règles de pare-feu de DefectDojo incluent une case à cocher pour **Jira Cloud**, qui doit être activée pour que DefectDojo puisse recevoir les messages de webhook provenant de Jira.

## Se déconnecter de Jira

Les intégrations Jira ne peuvent être supprimées de votre instance que si aucune Issue associée n'a été créée. Si des Issues ont été créées, il n'existe aucun moyen de supprimer complètement une instance Jira de DefectDojo.

Toutefois, vous pouvez désactiver votre intégration Jira en la désactivant au niveau du Produit. Depuis la page **Jira Project Settings** (accessible via le menu ⚙️ Gear sur un Produit), décochez le bouton **Enabled**. Cela ne supprimera ni ne modifiera aucun ticket Jira existant créé par DefectDojo, mais désactivera toute mise à jour ultérieure.

# Pousser des Constatations vers Jira

Un Produit disposant d'un mapping JIRA peut pousser des Constatations vers Jira en tant qu'Issues via plusieurs méthodes. Vous pouvez pousser les Constatations individuellement, en masse, en tant que Groupes de constatations, ou automatiquement.

## Pousser une Constatation unique

1. Ouvrez la Constatation que vous souhaitez pousser.
2. Cliquez sur le **☰ Finding Menu** et sélectionnez **Push to Jira**.
3. Confirmez l'envoi lorsque vous y êtes invité. DefectDojo créera une Issue Jira et la liera à la Constatation.

Une fois l'Issue créée, DefectDojo affichera un lien vers l'Issue Jira sur la page de la Constatation.

![image](images/Creating_Issues_in_Jira_2.png)

Vous pouvez également cocher la case **Push to Jira** lors de la modification d'une Constatation via le formulaire **Edit Finding**. Lorsque la Constatation est enregistrée, elle sera poussée vers Jira.

### Mettre à jour une Issue Jira liée

Si une Constatation a déjà une Issue Jira liée, sélectionner à nouveau **Push to Jira** mettra à jour l'Issue Jira existante avec les modifications apportées dans DefectDojo. Si **Push All Issues** est activé sur le Produit, cette synchronisation se fait automatiquement.

### Délier une Constatation de Jira

Pour supprimer l'association entre une Constatation et son Issue Jira, cliquez sur le **☰ Finding Menu** et sélectionnez **Unlink From Jira**. Cela supprime le lien dans DefectDojo mais ne supprime pas l'Issue Jira elle-même.

## Pousser des Constatations en masse

Vous pouvez pousser plusieurs Constatations vers Jira en une seule fois à l'aide du formulaire Bulk Update :

1. Depuis une liste de Constatations, sélectionnez les Constatations que vous souhaitez pousser à l'aide des cases à cocher.
2. Ouvrez le formulaire **Bulk Update**.
3. Sous **Jira Settings**, cochez la case **Push to Jira**.
4. Cliquez sur **Submit**.

Les Constatations sélectionnées seront placées dans la file d'attente pour être poussées vers Jira. DefectDojo affichera un message de confirmation indiquant le nombre de Constatations mises en file d'attente.

## Pousser des Engagements en tant qu'Épics

Si **Enable Engagement Epic Mapping** est activé dans vos Jira Project Settings, vous pouvez pousser un Engagement vers Jira en tant qu'Épic. Les Constatations de l'Engagement seront poussées en tant qu'Issues enfants au sein de cet Épic.

Pour pousser un Engagement en tant qu'Épic :

1. Ouvrez l'Engagement que vous souhaitez pousser.
2. Cliquez sur le **☰ Engagement Menu** et sélectionnez **Push to Jira**.
3. Éventuellement, indiquez un **Epic Name** (par défaut, le nom de l'Engagement si laissé vide) et une **Epic Priority**.
4. Cochez **Push to Jira (Create Epic)** et validez le formulaire.

## Pousser des Groupes de constatations en tant qu'Issues Jira

Si les Groupes de constatations sont activés, vous pouvez pousser un Groupe de constatations vers Jira en tant qu'Issue unique plutôt que des Issues séparées pour chaque Constatation.

Pour pousser un Groupe de constatations :

1. Ouvrez le Groupe de constatations.
2. Cliquez sur le **☰ Finding Group Menu** et sélectionnez **Push to Jira**, ou cochez la case **Push to Jira** lors de la modification du Groupe de constatations.

L'Issue Jira associée à un Groupe de constatations doit être supprimée directement depuis l'instance Jira si une suppression est nécessaire.

### Créer et pousser automatiquement des Groupes de constatations

Avec **Push All Issues** activé sur le Produit, et une option **Group By** sélectionnée lors de l'import :

Tant que les Groupes de constatations sont créés avec succès, c'est le Groupe de constatations qui sera automatiquement poussé vers Jira en tant qu'Issue, et non les Constatations individuelles.

![image](images/Creating_Issues_in_Jira_4.png)

## Comportement de l'envoi automatique

DefectDojo peut automatiquement pousser des Constatations et des mises à jour vers Jira dans plusieurs scénarios :

### Push All Issues

Lorsque le paramètre **Push All Issues** est activé dans les Jira Project Settings d'un Produit, DefectDojo créera automatiquement des Issues Jira pour toutes les Constatations Actives et Vérifiées. Cela inclut les Constatations créées via un import de scan. Une fois qu'une Issue Jira est créée, elle continuera à se synchroniser avec DefectDojo même si le statut de la Constatation change.

### Synchronisation automatique lors des changements de statut

Lorsque **Push All Issues** ou le paramètre système **Finding Jira Sync** est activé, DefectDojo mettra automatiquement à jour les Issues Jira liées lorsque certaines actions sont effectuées sur les Constatations :

* **Request Review** \- Un commentaire est ajouté à l'Issue Jira liée (ou à l'Issue Jira du Groupe de constatations si la Constatation appartient à un groupe).
* **Clear Review** \- Un commentaire est ajouté à l'Issue Jira liée.
* **Close Finding** \- L'Issue Jira liée est mise à jour pour refléter la fermeture. Si **Push Notes** est activé, un commentaire est également ajouté.

## Commentaires et notes Jira

Lorsque **Push Notes** est activé dans les Jira Project Settings :

* Si un commentaire est ajouté à une Issue Jira, le même commentaire sera ajouté à la Constatation, sous la section **Notes**.
* De même, si une note est ajoutée à une Constatation, la note sera ajoutée à l'issue Jira en tant que commentaire.

## Changements de statut Jira

La configuration de l'instance Jira comporte des entrées pour deux transitions Jira qui déclenchent un changement de statut sur une Constatation.

* Lorsque la **transition « Close »** est effectuée sur Jira, la Constatation associée se ferme également et devient marquée comme **Inactive** et **Atténué** dans DefectDojo. DefectDojo enregistrera ce changement sur la page de la Constatation, sous l'en-tête **Mitigated By**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Lorsque la **transition « Reopen »** est effectuée sur l'Issue Jira, la Constatation associée sera définie comme **Actif** dans DefectDojo, et perdra son statut **Atténué**.

## Mapper les résolutions Jira vers Risque accepté / Faux positif

La configuration de l'instance Jira comporte deux champs optionnels qui vous permettent de mapper une **Resolution** Jira à un statut de Constatation DefectDojo :

* **Risk Accepted Finding Mapping Resolution** — lorsqu'une issue Jira est fermée avec cette Resolution, la Constatation liée devient Risque accepté dans DefectDojo.
* **False Positive Finding Mapping Resolution** — lorsqu'une issue Jira est fermée avec cette Resolution, la Constatation liée devient Faux positif dans DefectDojo.

### Statut contre Résolution : une source de confusion fréquente

Ces champs mappent la **Resolution** Jira, et non le **Status** Jira. Status et Resolution sont deux concepts Jira indépendants : le Status décrit où en est l'issue dans le workflow (Open, In Progress, Done), tandis que la Resolution décrit comment elle a été résolue (Fixed, Won't Do, Duplicate, False Positive, etc.).

### Prérequis : une post-fonction « Set issue resolution » sur la transition de workflow Jira

Le moteur de workflow de Jira ne remplit pas automatiquement le champ Resolution. Chaque transition qui doit fermer une issue avec une Resolution spécifique nécessite une post-fonction **Set issue resolution** configurée sur la transition elle-même. Sans cette post-fonction, l'issue passe au nouveau Status mais la Resolution reste vide, et le mapping de DefectDojo n'a rien à quoi se comparer.

Un administrateur Jira peut ajouter cette post-fonction depuis **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

# Champs personnalisés dans Jira

<span style="background: rgba(243, 122, 78,0.5">DefectDojo ne prend actuellement pas en charge le passage d'informations spécifiques à une Issue dans ces champs personnalisés \- ces champs devront être mis à jour manuellement dans Jira après la création de l'issue. Chaque champ personnalisé ne sera créé par DefectDojo qu'avec une valeur par défaut.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud vous permet désormais de créer une valeur par défaut de champ personnalisé directement dans l'application. [Consultez la documentation d'Atlassian sur les champs personnalisés](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) pour en savoir plus sur la configuration de cette fonctionnalité.</span>

Les types d'Issue Jira intégrés à DefectDojo (**Bug, Task, Story** et **Epic)** sont configurés pour fonctionner « prêts à l'emploi ». Les champs de données de DefectDojo se mapperont automatiquement aux champs correspondants dans Jira. Par défaut, DefectDojo attribuera une Priority, des Labels et un Reporter à toute nouvelle Issue qu'il crée.

Certaines configurations Jira nécessitent la prise en compte de champs personnalisés supplémentaires avant qu'une issue puisse être créée. Ce processus vous permettra de prendre en compte ces champs personnalisés dans votre intégration DefectDojo \-\> Jira, garantissant que les issues sont créées avec succès. Ces champs personnalisés seront ajoutés à tous les appels API envoyés depuis DefectDojo vers une instance Jira liée.

Si vous n'utilisez pas déjà de champs personnalisés dans Jira, il n'est pas nécessaire de suivre ce processus.

1. Enregistrer les noms de vos champs personnalisés dans Jira (**interface Jira**)
2. Déterminer les valeurs de clé (Key) des nouveaux champs personnalisés (point de terminaison Jira Field Spec)
3. Localiser les données acceptables pour chaque champ personnalisé, en utilisant les valeurs de clé comme référence (point de terminaison Jira Issue)
4. Créer un bloc JSON de référence de champs pour suivre toutes les clés de champs personnalisés et les données acceptables (point de terminaison Jira Issue)
5. Stocker le bloc JSON dans le Produit DefectDojo associé, pour permettre la création des champs personnalisés depuis Jira (interface DefectDojo)
6. Tester votre travail et vous assurer que toutes les données requises circulent correctement depuis Jira

#### Étape 1 : Enregistrer les noms de vos champs personnalisés dans Jira

Jira prend en charge une variété de Context Fields différents, notamment des sélecteurs de date, des labels personnalisés, des boutons radio. Chacun de ces Context Fields aura une valeur de clé différente, que l'on peut trouver dans l'API Jira.

Notez les noms de chaque champ personnalisé requis, car vous devrez parcourir l'API Jira pour les retrouver à l'étape suivante.

**Exemple de liste de champs personnalisés (les noms de vos champs personnalisés seront différents) :**

* DefectDojo Custom URL Field
* Un autre exemple de champ personnalisé
* ...

#### Étape 2 : Trouver les valeurs de clé de vos champs personnalisés Jira

Commencez ce processus en accédant à l'URL Field Spec de l'ensemble de votre instance Jira.

Voici un exemple d'URL Field Spec :

`https://yourcompany-example.atlassian.net/rest/api/2/field`

L'API renverra une longue chaîne JSON, qu'il conviendra de formater en texte lisible (à l'aide d'un éditeur de code, d'une extension de navigateur ou de <https://jsonformatter.org/>).

Le JSON renvoyé par cette URL contiendra tous vos champs personnalisés Jira, dont la plupart ne concernent pas DefectDojo et ont des valeurs `"Null"`. Chaque objet de cette réponse d'API correspond à un champ différent dans Jira. Vous devrez rechercher les objets dont les attributs `"name"` correspondent aux noms de chaque champ personnalisé que vous avez créé dans l'interface Jira, puis noter la valeur de leur attribut « key ».

![image](images/Using_Custom_Fields.png)

Une fois que vous avez trouvé l'objet correspondant dans la sortie JSON, vous pouvez déterminer la valeur « key » \- dans ce cas, il s'agit de `customfield_10050`.

Jira génère des valeurs de clé différentes pour chaque champ personnalisé, mais ces valeurs de clé ne changent pas une fois créées. Si vous créez un autre champ personnalisé à l'avenir, il aura une nouvelle valeur de clé.

**Extension de notre liste de champs personnalisés :**

* « DefectDojo Custom URL Field » \= customfield\_10050
* « Un autre exemple de champ personnalisé » \= customfield\_12345
* ...

#### Étape 3 \- Trouver les champs personnalisés sur une Issue Jira

Localisez une Issue dans Jira qui contient les champs personnalisés que vous avez enregistrés à l'étape 2\. Copiez la clé de l'issue depuis le titre (elle devrait ressembler à « `EXAMPLE-123` ») et accédez à l'URL suivante :

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Cela renverra une autre chaîne JSON.

Comme précédemment, la sortie de l'API contiendra de nombreux paramètres d'objet `customfield_##` avec des valeurs `null` \- ce sont des champs personnalisés que Jira ajoute par défaut, qui ne concernent pas cette issue. Elle contiendra également des valeurs `customfield_##` qui correspondent aux valeurs de clé de champ personnalisé que vous avez trouvées à l'étape précédente. Contrairement à la sortie Field Spec, vous ne verrez pas de noms identifiant ces champs personnalisés, c'est pourquoi vous deviez enregistrer les valeurs de clé à l'étape 2\.

![image](images/Using_Custom_Fields_2.png)

**Exemple :**
Nous savons que `customfield_10050` représente le DefectDojo Custom URL Field car nous l'avons noté à l'étape 2\. Nous pouvons maintenant voir que `customfield_10050` contient une valeur de `"https://google.com"` dans l'issue `EXAMPLE-123`.

#### Étape 4 \- Créer une référence de champs JSON à partir de chaque clé de champ personnalisé Jira

Vous devrez maintenant prendre la valeur de chacun des champs personnalisés de votre liste et les stocker dans un objet JSON (à utiliser comme référence). Vous pouvez ignorer tout champ personnalisé qui ne correspond pas à votre liste.

Cet objet JSON contiendra toutes les valeurs par défaut pour les nouvelles Issues Jira. Nous recommandons d'utiliser des noms faciles à reconnaître par votre équipe comme des valeurs « par défaut » à modifier : « `change-me.com` », « `Change this paragraph.` », etc.

**Exemple :**

À partir de l'étape 3, nous savons maintenant que Jira attend une chaîne d'URL pour « `customfield_10050` ». Nous pouvons utiliser cela pour construire notre exemple d'objet JSON.

Supposons que nous ayons également localisé un champ de texte court lié à DefectDojo, identifié comme « `customfield_67890` ». Nous examinerions ce champ dans notre seconde sortie d'API, regarderions la valeur associée, et référencerions la valeur stockée dans notre exemple d'objet JSON également.
​
Votre objet JSON commencera à ressembler à ceci à mesure que vous y ajoutez d'autres champs personnalisés.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Répétez ce processus jusqu'à ce que tous les champs personnalisés pertinents pour DefectDojo issus de Jira aient été ajoutés à votre référence de champs JSON.

#### Types de données \& syntaxe Jira

Certains champs, tels que les champs de date, peuvent concerner plusieurs champs personnalisés dans Jira. Si c'est le cas, vous devrez ajouter les deux champs à votre référence de champs JSON.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

D'autres champs, comme le champ Label, peuvent être suivis sous forme d'une liste de chaînes \- assurez-vous que votre référence de champs JSON utilise un format correspondant à la sortie d'API de Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

D'autres champs personnalisés peuvent contenir des informations contextuelles supplémentaires qui doivent être retirées de la référence de champs. Par exemple, le champ Custom Multichoice contient un bloc supplémentaire dans la sortie de l'API, que vous devrez retirer, car ce bloc stocke la valeur actuelle du champ.

* vous devez retirer l'objet supplémentaire de ce champ :

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* vous pouvez plutôt le raccourcir comme suit et ignorer la seconde partie :

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Exemple de référence de champs complète

Voici une référence de champs JSON complète, avec des commentaires en ligne expliquant à quoi correspond chaque champ personnalisé. Ceci est un exemple englobant l'ensemble des cas. Votre JSON contiendra des valeurs de clé et des données différentes selon les valeurs personnalisées que vous souhaitez utiliser lors de la création d'issue.

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### Étape 5 \- Ajouter les champs personnalisés à un Produit DefectDojo

Vous pouvez maintenant ajouter ces champs personnalisés au Produit DefectDojo associé, sur la page Jira Project Settings (accessible via le menu ⚙️ Gear sur le Produit). Collez la référence de champs JSON en texte brut dans la zone **Custom Fields** et enregistrez.

#### Étape 6 \- Tester vos champs personnalisés Jira à partir d'une nouvelle Constatation :

Désormais, lorsque vous créez une nouvelle Constatation dans le Produit associé à Jira, Jira créera automatiquement tous ces champs personnalisés dans Jira selon le bloc JSON qu'il contient. Ces champs personnalisés seront créés avec les valeurs par défaut (« change\-me\-please », etc.).

Au sein du Produit sur DefectDojo, accédez à la page Findings \> Add New Finding. Assurez-vous que la Constatation est à la fois Active et Vérifiée pour garantir qu'elle sera poussée vers Jira, puis vérifiez côté Jira que les champs personnalisés ont été créés avec succès et sans incohérence.
