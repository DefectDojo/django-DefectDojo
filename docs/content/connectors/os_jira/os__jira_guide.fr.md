---
title: Jira
description: Travailler avec l'intégration Jira
weight: 2
audience: opensource
aliases:
- /fr/issue_tracking/jira/os__jira_guide/
---

L'intégration Jira de DefectDojo permet de transmettre les données de Constatations à un ou plusieurs espaces Jira. Cela vous permet d'intégrer DefectDojo à votre flux de développement standard. Voici quelques exemples de fonctionnement possible :

* L'équipe AppSec peut transmettre sélectivement des Constatations à un espace Jira utilisé par les développeurs, afin que la résolution des tickets puisse être hiérarchisée de manière appropriée aux côtés du développement habituel. Les développeurs présents sur ce tableau n'ont pas besoin d'accéder à DefectDojo : ils peuvent conserver tout leur travail au même endroit.
* DefectDojo peut transmettre TOUTES les Constatations à un espace Jira bidirectionnel utilisé par l'équipe AppSec, ce qui lui permet de répartir la validation des tickets. Ce tableau reste synchronisé avec DefectDojo et permet des flux de résolution complexes.
* DefectDojo peut transmettre sélectivement des Constatations provenant de Produits et/ou d'Engagements distincts vers des espaces Jira distincts, afin de conserver chaque élément dans son contexte propre.

# Configuration de Jira

La configuration de Jira nécessite les étapes suivantes :
1. Activez l'intégration Jira dans les Paramètres système. Tant que ce n'est pas fait, le reste des paramètres Jira reste masqué dans DefectDojo.
2. Connectez une instance Jira, avec un nom d'utilisateur / mot de passe ou un jeton API. Plusieurs instances peuvent être liées.
3. Ajoutez cette instance Jira à un ou plusieurs Produits ou Engagements dans DefectDojo.
4. Si vous souhaitez utiliser la synchronisation bidirectionnelle, créez un Webhook Jira qui enverra les mises à jour à DefectDojo.

## Étape 1 : activer l'intégration Jira dans les paramètres système

L'intégration Jira est désactivée par défaut, et tant qu'elle l'est, DefectDojo masque tous les autres contrôles Jira de l'interface. C'est la première chose à configurer : aucune des étapes ci-dessous n'est disponible tant qu'elle n'est pas activée.

Tant que l'intégration est désactivée, l'entrée ⚙️ **Configuration \> JIRA** n'est pas présente dans la barre latérale, il n'y a donc aucun endroit où ajouter une instance Jira :

![image](images/jira-config-menu-hidden-os.png)

### Activer l'intégration

1. Accédez à ⚙️ **Configuration \> System Settings** depuis la barre latérale de DefectDojo.
​
2. Cochez **Enable JIRA integration**.
​
3. Un **Jira webhook secret** est requis dès que l'intégration est activée. Cliquez sur l'icône 🔄 à côté du champ pour en générer un. Si vous soumettez le formulaire sans secret, il est rejeté avec le message *"This field is required when enable Jira Integration is True"* :

![image](images/jira-webhook-secret-required-os.png)

Le secret fait partie de l'URL du webhook sur laquelle Jira publie (`https://<YOUR DOJO DOMAIN>/jira/webhook/<SECRET>`), traitez donc la valeur générée comme un identifiant sensible. Vous ne devez le transmettre à Jira que si vous configurez la synchronisation bidirectionnelle à l'[Étape 4](#step-4-configure-bidirectional-sync-jira-webhook) ; le générer dès maintenant suffit simplement à satisfaire le formulaire.

4. Cliquez sur **Submit**. ⚙️ **Configuration \> JIRA** apparaît désormais dans la barre latérale :

![image](images/jira-enable-system-settings-os.png)

### Ce que contrôle ce paramètre

Activer **Enable JIRA integration** est ce qui fait apparaître le reste de l'interface Jira. Une fois activé, vous obtenez :

* la page ⚙️ **Configuration \> JIRA**, où les instances Jira sont ajoutées et modifiées
* la section **JIRA** sur les formulaires Edit Product (Asset) et Edit Engagement, utilisée pour lier un Produit ou un Engagement à un espace Jira
* les contrôles **Push to Jira** sur les Constatations, les groupes de Constatations et les formulaires d'édition en masse, ainsi que les colonnes et filtres Jira sur les listes de Constatations, d'Engagements et de Produits

Par exemple, la section **JIRA** n'apparaît qu'en bas du formulaire Edit Product une fois l'intégration activée :

![image](images/jira-asset-settings-visible-os.png)

Ce paramètre contrôle également l'intégration en dehors de l'interface utilisateur : tant qu'il est désactivé, DefectDojo ne transmettra pas les Constatations à Jira (y compris les requêtes `push_to_jira` envoyées via l'API), et les webhooks Jira entrants sont ignorés.

Les autres champs Jira de la page System Settings (**Enable JIRA web hook**, **Jira minimum severity**, **Jira labels**, **Add vulnerability Id as a JIRA label**) restent visibles que l'intégration soit activée ou non, mais ils n'ont aucun effet tant qu'elle n'est pas activée.

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

Vous pouvez éventuellement mapper :
* Les transitions Jira pour déclencher la réouverture et la fermeture des Constatations
* Les résolutions Jira pouvant appliquer les statuts Risque accepté et Faux positif aux Constatations (optionnel)

Une seule connexion d'instance Jira peut gérer plusieurs espaces Jira, tant que le compte / jeton Jira utilisé par DefectDojo dispose de la permission de créer des tickets dans l'espace Jira associé.

### Ajouter une instance Jira

1. Assurez-vous que **Enable JIRA integration** est coché dans les Paramètres système, comme décrit à l'[Étape 1](#step-1-enable-the-jira-integration-in-system-settings). L'option ⚙️ **Configuration \> JIRA** n'apparaît dans la barre latérale que lorsque c'est le cas.
​
2. Accédez à la page ⚙️ **Configuration \> JIRA** depuis la barre latérale de DefectDojo.
​
![image](images/Connect_DefectDojo_to_Jira.png)

3. Vous verrez une liste de tous les espaces Jira actuellement configurés qui sont liés à DefectDojo. Pour ajouter une nouvelle configuration de projet, cliquez sur l'icône de clé à molette et choisissez l'une des options **Add Jira Configuration (Express)** ou **Add Jira Configuration**.

#### Add Jira Configuration (Express)

La méthode Express permet de lier un espace plus rapidement. Utilisez la méthode Express si vous souhaitez simplement connecter rapidement un espace Jira, sans avoir affaire à un workflow Jira complexe.

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. Choisissez un nom pour cette configuration Jira à utiliser dans DefectDojo. Ce nom est simplement une étiquette pour la connexion d'instance dans DefectDojo, et n'a pas besoin d'être lié à des données Jira.
​
2. Sélectionnez l'URL de l'instance Jira de votre entreprise \- probablement similaire à `https://**yourcompany**.atlassian.net` si vous utilisez une installation Jira Cloud.
​
3. Saisissez une méthode d'authentification appropriée dans les champs Nom d'utilisateur / Mot de passe pour Jira :
    * Pour une **authentification Jira standard par nom d'utilisateur / mot de passe**, saisissez un nom d'utilisateur Jira et le mot de passe correspondant dans ces champs.
    * Pour une authentification avec le **jeton API d'un utilisateur (Jira Cloud)**, saisissez le nom d'utilisateur avec le **jeton API** correspondant dans le champ mot de passe.
​
4. Sélectionnez le type de ticket par défaut que vous souhaitez utiliser pour créer des tickets dans Jira. Les options disponibles sont **Bug, Task, Story** et **Epic** (types de ticket Jira standard), ainsi que **Spike** et **Security**, qui sont des types de ticket personnalisés. Si vous avez besoin d'un autre type de ticket, contactez [support@defectdojo.com](mailto:support@defectdojo.com) pour obtenir de l'aide.
​
5. Sélectionnez votre modèle de ticket (Issue Template), qui déterminera la description du ticket lors de la création des tickets dans Jira.

Les deux types sont :
- **Jira\_full**, qui inclut toutes les informations de la Constatation dans les tickets Jira
- **Jira\_limited**, qui inclut une quantité réduite d'informations et de métadonnées de la Constatation.

Si vous laissez ce champ vide, la valeur par défaut sera **Jira\_full.**

6. Sélectionnez un ou plusieurs types de résolution Jira qui changeront le statut d'une Constatation en Risque accepté (lorsque la résolution est déclenchée sur le ticket). Si vous ne souhaitez pas utiliser cette automatisation, vous pouvez laisser le champ vide.
​
7. Sélectionnez un ou plusieurs types de résolution Jira qui changeront le statut d'une Constatation en Faux positif (lorsque la résolution est déclenchée sur le ticket). Si vous ne souhaitez pas utiliser cette automatisation, vous pouvez laisser le champ vide.
​
8. Décidez si vous souhaitez envoyer les notifications SLA sous forme de commentaire sur un ticket Jira.
​
9. Décidez si vous souhaitez synchroniser automatiquement les Constatations avec Jira. Si cette option est activée, les tickets Jira resteront automatiquement synchronisés avec les Constatations associées. Si elle n'est pas activée, vous devrez transmettre manuellement toute modification apportée à une Constatation après la création du ticket dans Jira.
​
10. Sélectionnez votre clé de ticket (Issue key). Dans Jira, il s'agit de la chaîne associée à un ticket (par ex. le mot **'EXAMPLE'** dans un ticket appelé **EXAMPLE\-123**). Si vous ne connaissez pas votre clé de ticket, créez un nouveau ticket dans l'espace Jira. Dans la capture d'écran ci-dessous, on voit que la clé de ticket de notre espace Jira est **DEF**.
​
![image](images/Connect_DefectDojo_to_Jira_3.png)
​
11. Cliquez sur **Submit.** DefectDojo recherchera automatiquement les mappages appropriés dans Jira et les ajoutera à la configuration. Vous êtes maintenant prêt à lier cette configuration à un ou plusieurs Produits dans DefectDojo.

#### Add Jira Configuration (Standard)

La configuration Jira standard ajoute quelques étapes supplémentaires pour permettre un contrôle plus précis des mappages et interactions Jira. Ceci peut être modifié après l'ajout d'une configuration Jira, même si elle a été créée avec la méthode Express.
​
### Options de formulaire supplémentaires

* **Epic Name ID :** si vous avez plusieurs types d'Epic dans Jira, vous pouvez spécifier celui que vous souhaitez utiliser en trouvant son ID dans la spécification des champs Jira.
​
Pour obtenir l'« Epic name id », accédez à `https://<YOUR JIRA URL>/rest/api/2/field` et recherchez Epic Name. Copiez le nombre présent dans `number` et collez-le ici.
​  ​
* **Reopen Transition ID :** si vous souhaitez qu'une transition Jira spécifique rouvre un ticket, vous pouvez indiquer ici l'ID de la transition. Si vous utilisez la configuration Jira Express, DefectDojo trouvera automatiquement une transition appropriée et créera le mappage.
​
Accédez à `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` pour trouver l'ID correspondant à votre instance Jira. Collez-le dans le champ Reopen Transition ID.
​
* **Close Transition ID :** si vous souhaitez qu'une transition Jira spécifique ferme un ticket, vous pouvez indiquer ici l'ID de la transition. Si vous utilisez la **configuration Jira Express**, DefectDojo trouvera automatiquement une transition appropriée et créera le mappage.
​
Accédez à `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` pour trouver l'ID correspondant à votre instance Jira. Collez-le dans le champ Close Transition ID.
​
* **Mapping Severity Fields :** chaque ticket Jira dispose d'une Priorité associée, que DefectDojo attribue automatiquement en fonction de la Sévérité d'une Constatation. Saisissez le nom de chaque Priorité à laquelle vous souhaitez mapper les Sévérités Info, Faible, Moyenne, Élevée et Critique.

* **Finding Text** \- si vous souhaitez ajouter du texte standardisé supplémentaire à chaque ticket créé, vous pouvez le saisir ici. Il ne s'agit pas d'un texte associé à un champ Jira, mais d'un texte supplémentaire ajouté à la description du ticket. « **Created by DefectDojo** » par exemple.

Les commentaires (dans Jira) et les Notes (dans DefectDojo) peuvent être synchronisés. Ce paramètre peut être activé une fois la configuration Jira ajoutée à un Produit, via le formulaire **Edit Product**.

## Étape 3 : connecter un Produit ou un Engagement à Jira

Chaque Produit ou Engagement dans DefectDojo dispose de ses propres paramètres qui déterminent comment les Constatations sont converties en tickets JIRA. Depuis cet écran, vous pouvez choisir l'espace Jira associé et définir le comportement par défaut pour la création des tickets, des Epics, des étiquettes et d'autres métadonnées JIRA.

### Ajouter Jira à un Produit ou à un Engagement

Dans l'interface Classic, vous trouverez les paramètres Jira en ouvrant le formulaire Edit Product ou Edit Engagement. Bouton « **📝 Edit** » sous **Settings** sur la page :

![image](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### Liste des paramètres Jira

Les paramètres Jira se trouvent près du bas de la page Product Settings.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Instance Jira

Si vous avez configuré plusieurs instances de Jira, pour des produits ou des équipes distincts au sein de votre organisation, vous pouvez indiquer dans quel espace Jira vous souhaitez que DefectDojo crée des tickets. Sélectionnez un projet dans le menu déroulant.

Si ce menu ne liste aucune instance Jira, vérifiez que ces projets sont connectés dans votre configuration Jira globale pour DefectDojo \- yourcompany.defectdojo.com/jira.

#### Clé de projet

Il s'agit de la clé de l'espace que vous souhaitez utiliser avec DefectDojo. La Space Key d'un projet donné se trouve dans l'URL, ou sous « Space key » dans les paramètres de l'espace (Space Settings).

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Modèle de ticket

Vous pouvez ici déterminer la quantité de métadonnées DefectDojo que vous souhaitez envoyer à Jira. Sélectionnez l'une des deux options :

* **jira\_full** : les tickets suivront tous les paramètres de DefectDojo \- une Description complète, le CVE, la Sévérité, etc. Utile si vous avez besoin du contexte complet de la Constatation dans Jira (par exemple, si une personne travaillant sur ce ticket n'a pas accès à DefectDojo).

Voici un exemple de ticket **jira\_full** :
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited :** les tickets ne suivront que le lien DefectDojo, les liens Produit/Engagement/Test, ainsi que les champs Reporter et Environment. Tous les autres champs sont suivis uniquement dans DefectDojo. Utile si vous n'avez pas besoin du contexte complet de la Constatation dans Jira (par exemple, si une personne travaillant sur ce ticket travaille principalement dans DefectDojo et n'a pas besoin d'avoir également la vue complète dans JIRA.)

​Voici un exemple de ticket **jira\_limited** :​

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Composant

Si vous gérez votre espace Jira à l'aide de Components, vous pouvez lui attribuer ici le Component approprié pour DefectDojo. Pour attribuer plusieurs Components, saisissez une liste séparée par des virgules (par exemple, `Security, DevSecOps`) ; chaque valeur est envoyée à Jira comme un composant distinct.

**Champs personnalisés**

Si vous n'avez pas besoin d'utiliser de champs personnalisés avec les tickets DefectDojo, vous pouvez laisser ce champ à 'null'.

Cependant, si les paramètres de votre espace Jira **vous obligent** à utiliser des champs personnalisés sur les nouveaux tickets, vous devrez coder ces mappages en dur.

**Jira Cloud vous permet désormais de créer une valeur de champ personnalisé par défaut directement dans l'application. [Consultez la documentation d'Atlassian sur les champs personnalisés](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) pour en savoir plus sur la configuration.**

Notez que DefectDojo ne peut pas envoyer de métadonnées spécifiques à un ticket en tant que champs personnalisés, seulement une valeur par défaut. Cette section ne doit être configurée que si votre espace Jira **exige que ces champs personnalisés existent** dans chaque ticket de votre espace.

Suivez **[ce guide](#custom-fields-in-jira)** pour commencer à travailler avec les champs personnalisés.

**Étiquettes Jira**

Sélectionnez les étiquettes pertinentes avec lesquelles vous souhaitez que le ticket soit créé dans Jira, par ex. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Assigné par défaut

Le nom de l'assigné par défaut dans Jira. Si ce champ est laissé vide, DefectDojo suivra le comportement par défaut de votre espace Jira lors de la création des tickets.

### Options de formulaire supplémentaires

#### Enable Connection With Jira Space

Les intégrations Jira ne peuvent être supprimées de votre instance que si aucun ticket associé n'a été créé. Si des tickets ont été créés, il n'existe aucun moyen de supprimer complètement une instance Jira de DefectDojo.

Toutefois, vous pouvez désactiver votre intégration Jira en la désactivant au niveau du Produit. Cela ne supprimera ni ne modifiera les tickets Jira existants créés par DefectDojo, mais désactivera toute mise à jour ultérieure.

#### Add Vulnerability Id as a Jira label

Cela vous permet d'ajouter automatiquement l'ID de vulnérabilité comme étiquette Jira. Les ID de vulnérabilité sont ajoutés aux Constatations par les outils de sécurité individuels \- il peut s'agir d'ID CVE (Common Vulnerabilities and Exposures) ou d'un format différent, propre à l'outil ayant signalé la Constatation.

#### Enable Engagement Epic Mapping (For Products)

Dans DefectDojo, les Engagements représentent un ensemble de travaux. Chaque Engagement contient un ou plusieurs Tests, qui contiennent une ou plusieurs Constatations à corriger. Les Epics dans Jira fonctionnent de manière similaire, et cette case à cocher vous permet de transmettre les Engagements à Jira sous forme d'Epics.

* Un Engagement dans DefectDojo \- notez les trois constatations listées en bas.
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* Comment le même Engagement devient un Epic une fois transmis à JIRA \- les Constatations de l'Engagement sont également transmises et apparaissent à l'intérieur de l'Engagement en tant que tickets enfants (Child Issues).

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push All Issues

Si cette case est cochée, DefectDojo transmettra automatiquement à Jira, sous forme de tickets, toutes les Constatations Actives et Vérifiées. Si elle est décochée, toutes les Constatations devront être transmises manuellement à Jira.

#### Push Notes

Si cette option est activée, les commentaires Jira apparaîtront sur la Constatation associée dans DefectDojo, sous Notes sur le ticket (capture d'écran), et inversement ; les Notes sur les Constatations seront ajoutées au ticket Jira associé sous forme de commentaires.

#### Send SLA Notifications As Comments

Si cette option est activée, tout ticket qui enfreint les règles de l'accord de niveau de service (SLA) de DefectDojo recevra des commentaires sur le ticket Jira l'indiquant. Ces commentaires seront publiés quotidiennement jusqu'à ce que le ticket soit résolu.

Les accords de niveau de service peuvent être configurés sous **Configuration \> SLA Configuration** dans DefectDojo et affectés à chaque Produit.

#### Send Risk Acceptance Expiration Notifications As Comment?

Si cette option est activée, tout ticket dont l'Acceptation du risque DefectDojo associée expire recevra un commentaire sur le ticket Jira l'indiquant. Ces commentaires seront publiés quotidiennement jusqu'à ce que le ticket soit résolu.

### Paramètres Jira au niveau de l'Engagement

Des Engagements différents au sein d'un même Produit peuvent ainsi avoir des paramètres Jira sous-jacents différents. Par défaut, les Engagements « **héritent des paramètres Jira du Produit** », ce qui signifie qu'ils partagent les mêmes paramètres Jira que le Produit sous lequel ils sont imbriqués.

Toutefois, vous pouvez modifier la **Product Key**, l'**Issue Template**, les **Custom Fields**, les **Jira Labels** et le **Default Assignee** d'un Engagement pour qu'ils diffèrent des paramètres par défaut du Produit.

Vous pouvez accéder à cette page depuis la page **Edit Engagement** : **your\-instance.defectdojo.com/engagement/\[id]/edit**.

La page Edit Engagement se trouve depuis la page de l'Engagement, en cliquant sur le menu ☰ à côté de la Description de l'engagement.

![image](images/Creating_Issues_in_Jira_5.png)

## Étape 4 : configurer la synchronisation bidirectionnelle : webhook Jira

L'intégration Jira permet une synchronisation bidirectionnelle via webhook. DefectDojo reçoit les notifications Jira à une adresse unique, ce qui permet de recevoir des commentaires Jira sur les Constatations, ou de résoudre des Constatations via Jira selon votre configuration.

### Localiser l'URL de votre webhook Jira

Votre webhook Jira est composé de votre URL DefectDojo et du **Jira webhook secret** que vous avez généré à l'[Étape 1](#step-1-enable-the-jira-integration-in-system-settings). Les deux sont affichés sur la page ⚙️ **Configuration \> System Settings**, à côté du champ **Jira webhook secret** (voir la capture d'écran de l'Étape 1).

Vous devez également cocher **Enable JIRA web hook** sur la même page pour que DefectDojo traite les notifications Jira entrantes. Les webhooks entrants sont ignorés si cette case ou **Enable JIRA integration** n'est pas cochée.

### Créer le webhook Jira

1. Accédez à `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Cliquez sur « Create a Webhook ».
3. Dans le champ intitulé « URL », saisissez : `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. Le Web Hook Secret est indiqué à côté du champ **Jira webhook secret** comme mentionné ci-dessus.
4. Sous « Comments », activez « Created ». Sous Issue, activez « Updated ».
5. Assurez-vous que votre instance JIRA fait confiance au certificat SSL utilisé par votre instance DefectDojo. Pour JIRA Cloud, DefectDojo doit utiliser [un certificat SSL/TLS valide, signé par une autorité de certification mondialement reconnue](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Notez que vous n'avez pas besoin de créer un Secret dans Jira pour utiliser ce webhook. Le Secret est intégré à l'URL de DefectDojo, il suffit donc d'ajouter l'URL complète au formulaire de Webhook Jira.

Les requêtes de webhook entrantes sont authentifiées par le secret présent dans cette URL ; traitez donc l'URL complète comme un identifiant sensible et gardez-la confidentielle.

#### Tester le webhook

Une fois que vous avez un ou plusieurs tickets créés à partir de Constatations DefectDojo, vous pouvez tester le webhook en ajoutant un commentaire à l'une de ces Constatations. Le commentaire devrait être reçu par le webhook Jira sous forme de note.

Si cela ne fonctionne pas correctement, cela peut être dû à un problème de pare-feu sur votre instance Jira bloquant le webhook.

* Les règles de pare-feu de DefectDojo comprennent une case à cocher pour **Jira Cloud**, qui doit être activée avant que DefectDojo puisse recevoir les messages de webhook de Jira.

### Alternative : utiliser Jira Automation (Send web request)

Certaines instances Jira n'autorisent pas les webhooks système sous `/plugins/servlet/webhooks` — par exemple, lorsque cette zone d'administration est restreinte et que seules les règles **Jira Automation** sont autorisées. Dans ce cas, vous pouvez piloter la même synchronisation bidirectionnelle à l'aide de l'action **Send web request** d'Automation, qui envoie une requête vers le même point de terminaison webhook de DefectDojo.

Le point de terminaison webhook de DefectDojo accepte toute requête HTTP `POST` avec `Content-Type: application/json` et un secret valide dans le chemin de l'URL. Il n'exige **pas** que la requête provienne du mécanisme de webhook système de Jira, l'action « Send web request » d'Automation fonctionne donc comme une alternative directe.

#### Prérequis

Les mêmes prérequis que pour le webhook système s'appliquent :

* **Enable JIRA integration** et **Enable JIRA web hook** sont tous deux cochés sur la page ⚙️ **Configuration \> System Settings**.
* Un **Jira webhook secret** non vide est défini sur cette page. Le secret ne peut contenir que les caractères `A-Z`, `a-z`, `0-9`, `_` et `-`.
* La Constatation (ou le groupe de Constatations) est déjà liée au ticket Jira. Si le ticket n'est pas lié à une Constatation DefectDojo, la requête est tout de même acceptée (HTTP `200`) mais aucune action n'est effectuée.

#### Comment DefectDojo traite la requête

* DefectDojo se base sur un champ `webhookEvent` de premier niveau. Seuls `"jira:issue_updated"` et `"comment_created"` sont traités ; toute autre valeur est acceptée mais ignorée. Automation n'ajoute pas ce champ automatiquement, vous devez donc l'inclure vous-même dans le corps de la requête.
* Pour cette raison, définissez le **Body** de la requête sur **Custom data** et fournissez le JSON ci-dessous. Les options de corps **Empty** et **Jira issue data** n'incluent pas le champ `webhookEvent` requis, DefectDojo les ignorera donc.
* Le point de terminaison renvoie toujours HTTP `200`, qu'une mise à jour ait été appliquée ou non. Le succès ou l'échec n'est visible que dans le corps de la réponse et dans les journaux de DefectDojo — un `200` dans le journal d'audit d'Automation ne confirme pas à lui seul que la mise à jour a atteint une Constatation.

#### Règle 1 — Ticket mis à jour

Créez une règle Automation avec :

* **Trigger :** *Issue transitioned* (ou un autre déclencheur qui se déclenche lorsque les champs que vous synchronisez changent, par ex. *Field value changed* sur Status).
* **Action :** *Send web request*
  * **Web request URL :** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method :** `POST`
  * **Web request body :** *Custom data*
  * **Headers :** `Content-Type: application/json`
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

Contraintes pour les mises à jour de ticket :

* `issue.id` doit être l'**ID numérique interne du ticket Jira** (`{{issue.id}}`), et non la clé du ticket (par ex. `PROJ-123`). DefectDojo associe la mise à jour à une Constatation à partir de cet ID numérique.
* Les champs `resolution` et `updated` doivent toujours être présents. `resolution` peut être `null`, mais si l'un des deux champs est absent, la requête est acceptée (`200`) et n'est silencieusement pas traitée.
* La synchronisation du statut et l'auto-atténuation sont pilotées par `status.statusCategory.key`, dont les valeurs Jira sont `new` (To Do), `indeterminate` (In Progress) et `done` (Done). Une Constatation n'est atténuée que lorsque le ticket est réellement fermé, et non simplement parce qu'une valeur de résolution est présente.

#### Règle 2 — Ticket commenté

Créez une deuxième règle Automation avec :

* **Trigger :** *Issue commented*
* **Action :** *Send web request* — même URL, méthode, en-tête et option de corps *Custom data* que la Règle 1, avec ce corps :

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
* DefectDojo déduit le ticket cible à partir de l'URL `comment.self` — plus précisément le `<id>` dans le segment `.../issue/<id>/comment/...` — `{{issue.id}}` (l'ID numérique) doit donc y apparaître.
* **Prévention des boucles :** si l'auteur du commentaire correspond au compte Jira que DefectDojo utilise pour publier ses propres commentaires, DefectDojo ignore le commentaire pour éviter une boucle d'écho. Si vous souhaitez que *tous* les commentaires soient ingérés, exécutez la règle Automation avec un utilisateur Jira **différent** de celui configuré dans l'instance Jira de DefectDojo.

#### Remarque sur les valeurs intelligentes (smart values)

Les valeurs intelligentes présentées ci-dessus (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, etc.) sont les noms standard de Jira Cloud, mais elles peuvent varier d'une instance à l'autre. Avant la mise en production, utilisez l'aperçu de charge utile d'Automation pour vérifier que chaque valeur intelligente se résout comme prévu.

## Tester l'intégration Jira

#### Test 1 : les Constatations sont-elles correctement poussées vers Jira ?

Pour vérifier que l'intégration Jira fonctionne correctement, vous pouvez ajouter une nouvelle Constatation vierge au Produit associé à Jira dans DefectDojo. **Produit \> Constatations \> Ajouter une nouvelle Constatation.**

Ajoutez le titre, la sévérité et la description de votre choix, puis cliquez sur « Finished ». La Constatation doit apparaître comme une Issue dans Jira avec toutes les métadonnées pertinentes.

Si les Issues Jira ne sont pas créées correctement, consultez vos notifications pour connaître les codes d'erreur.

* Vérifiez que l'utilisateur Jira associé à la configuration Jira de DefectDojo dispose des autorisations nécessaires pour créer et mettre à jour des issues dans cet espace Jira particulier.

#### Test 2 : les webhooks Jira envoient des données à DefectDojo

Pour tester les webhooks Jira, ajoutez une Note à une Constatation qui existe également dans Jira sous forme d'Issue (par exemple l'issue de test de la section précédente).

Si les webhooks sont configurés correctement, vous devriez voir la Note apparaître dans Jira sous forme de commentaire sur l'issue.

Si cela ne fonctionne pas correctement, cela peut être dû à un problème de pare-feu sur votre instance Jira qui bloque le webhook.

* Les règles de pare-feu de DefectDojo incluent une case à cocher pour **Jira Cloud,** qui doit être activée avant que DefectDojo puisse recevoir les messages webhook de Jira.

## Déconnexion de Jira

Les intégrations Jira ne peuvent être supprimées de votre instance que si aucune Issue associée n'a été créée.  Si des Issues ont été créées, il n'existe aucun moyen de supprimer complètement une instance Jira de DefectDojo.

Vous pouvez toutefois désactiver votre intégration Jira en la désactivant au niveau du Produit.  Depuis le formulaire **Modifier le Produit**, vous pouvez décocher l'option « Enable Connection With Jira Space ».  Cela ne supprimera ni ne modifiera les tickets Jira existants créés par DefectDojo, mais désactivera toute mise à jour ultérieure.

# Pousser des Constatations vers Jira

## Pousser des Constatations vers Jira
Un Produit disposant d'une association Jira peut pousser des Constatations vers Jira sous forme d'Issues. Cela peut être géré de deux manières différentes :

* Les Constatations peuvent être créées manuellement en tant qu'Issues, Constatation par\-Constatation.
* Les Constatations peuvent être poussées automatiquement si le paramètre « **Push All Issues** » est activé sur un Produit. (Cela s'applique uniquement aux Constatations qui sont **Actif** et **Vérifié**).

De plus, vous avez la possibilité de pousser des Groupes de Constatations vers Jira au lieu de Constatations individuelles. Cela créera une seule Issue contenant plusieurs Constatations DefectDojo associées.

### Pousser une Constatation manuellement

1. Depuis la page d'une Constatation dans DefectDojo, accédez à la rubrique **JIRA**. Si la Constatation n'existe pas encore dans Jira sous forme d'Issue, l'en-tête JIRA affichera la valeur « **None** ».
​
2. Cliquer sur la flèche à côté de la valeur **None** créera une nouvelle issue Jira. L'état dans lequel l'issue est créée dépend du workflow de votre équipe et de la configuration Jira avec DefectDojo. Si la Constatation n'apparaît pas, actualisez la page.
​
![image](images/Creating_Issues_in_Jira.png)

3. Une fois l'Issue créée, DefectDojo crée un lien vers l'issue composé de la clé Jira et de l'ID de l'issue. Ce lien est également accompagné d'une icône de corbeille rouge permettant de supprimer l'Issue depuis Jira.
​
![image](images/Creating_Issues_in_Jira_2.png)

4. Cliquer à nouveau sur la flèche poussera toutes les modifications apportées à une issue vers Jira et mettra à jour l'Issue Jira en conséquence. Si le paramètre « **Push All Issues** » est activé sur le Produit associé à la Constatation, ce processus se produit automatiquement.

### Commentaires Jira

* Si un commentaire est ajouté à une Issue Jira, le même commentaire est ajouté à la Constatation, dans la section **Notes**.
* De même, si une Note est ajoutée à une Constatation, elle est ajoutée à l'issue Jira sous forme de commentaire.

### Changements de statut Jira

La configuration Jira sur DefectDojo comporte des entrées pour deux transitions Jira qui déclenchent un changement de statut sur une Constatation.

* Lorsque la **transition « Close »** est effectuée dans Jira, la Constatation associée se ferme également et est marquée comme **Inactif** et **Atténué** dans DefectDojo. DefectDojo enregistre ce changement sur la page de la Constatation, dans la rubrique **Mitigated By**.
​
![image](images/Creating_Issues_in_Jira_3.png)

* Lorsque la **transition « Reopen »** est effectuée sur l'Issue Jira, la Constatation associée est définie comme **Actif** dans DefectDojo et perd son statut **Atténué**.

### Associer les résolutions Jira à Risque accepté / Faux positif

Outre les transitions Close / Reopen, la configuration Jira comprend des champs optionnels permettant d'associer une **Resolution** Jira à un statut de Constatation DefectDojo.  Ces champs sont définis pendant le workflow **Add Jira Configuration (Express)** (étapes 6 et 7), et peuvent être modifiés ultérieurement dans la configuration Jira :

* **Risk Accepted Finding Mapping Resolution** — lorsqu'une issue Jira est clôturée avec cette Resolution, la Constatation associée passe à Risque accepté dans DefectDojo.
* **False Positive Finding Mapping Resolution** — lorsqu'une issue Jira est clôturée avec cette Resolution, la Constatation associée passe à Faux positif dans DefectDojo.

#### Status vs Resolution : une source de confusion fréquente

Ces champs associent la **Resolution** Jira, et non le **Status** Jira.  Status et Resolution sont deux concepts Jira indépendants : le Status décrit l'étape du workflow où se trouve l'issue (Open, In Progress, Done), tandis que la Resolution décrit la manière dont elle a été résolue (Fixed, Won't Do, Duplicate, False Positive, etc.).

Une source fréquente de confusion est qu'une transition de workflow Jira peut faire passer le Status à "Done" *sans* définir de Resolution.  Dans ce cas, l'association de résolution de DefectDojo ne se déclenche jamais — la Constatation est plutôt marquée **Atténué** par le comportement standard de la **transition « Close »** décrit ci-dessus, et non Risque accepté ou Faux positif.

#### Prérequis : une post-fonction "Set issue resolution" sur la transition du workflow Jira

Le moteur de workflow de Jira ne renseigne pas automatiquement le champ Resolution.  Chaque transition censée clôturer une issue avec une Resolution spécifique nécessite une post-fonction **Set issue resolution** configurée directement sur la transition.  Sans cette post-fonction, l'issue passe au nouveau Status mais la Resolution reste vide, et l'association de DefectDojo n'a alors rien à quoi se rattacher.

Un administrateur Jira peut ajouter cette post-fonction depuis **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

## Pousser des Groupes de Constatations en tant qu'Issues Jira

Si les Groupes de Constatations sont activés, vous pouvez pousser un Groupe de Constatations vers Jira sous forme d'une seule Issue plutôt que d'Issues distinctes pour chaque Constatation.

L'Issue Jira associée à un Groupe de Constatations ne peut toutefois pas être manipulée ni supprimée depuis DefectDojo. Elle doit être supprimée directement depuis l'instance Jira.

### Créer et pousser automatiquement des Groupes de Constatations

Avec l'option Auto\-Push To Jira activée et une option Group By sélectionnée lors de l'import :

Tant que les Groupes de Constatations sont créés avec succès, c'est le Groupe de Constatations qui sera automatiquement poussé vers Jira sous forme d'Issue, et non les Constatations individuelles.

![image](images/Creating_Issues_in_Jira_4.png)

## Champs personnalisés dans Jira
<span style="background: rgba(243, 122, 78,0.5">DefectDojo ne prend actuellement pas en charge la transmission d'informations spécifiques à une Issue dans ces champs personnalisés \- ces champs devront être mis à jour manuellement dans Jira après la création de l'issue. Chaque champ personnalisé sera créé depuis DefectDojo uniquement avec une valeur par défaut.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud vous permet désormais de créer une valeur par défaut pour un champ personnalisé directement dans l'application. [Consultez la documentation d'Atlassian sur les champs personnalisés](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) pour savoir comment configurer cela.</span>

Les types d'issue Jira intégrés à DefectDojo (**Bug, Task, Story** et **Epic)** sont configurés pour fonctionner « prêts à l'emploi ». Les champs de données de DefectDojo sont automatiquement associés aux champs correspondants dans Jira. Par défaut, DefectDojo attribue une Priority, des Labels et un Reporter à chaque nouvelle Issue qu'il crée.

Certaines configurations Jira nécessitent la prise en compte de champs personnalisés supplémentaires avant qu'une issue puisse être créée. Cette procédure vous permet de prendre en compte ces champs personnalisés dans votre intégration DefectDojo \-\> Jira, afin de garantir la création réussie des issues. Ces champs personnalisés seront ajoutés à tous les appels API envoyés depuis DefectDojo vers une instance Jira liée.

Si vous n'utilisez pas déjà de champs personnalisés dans Jira, il n'est pas nécessaire de suivre cette procédure.

1. Noter les noms de vos champs personnalisés dans Jira (**interface Jira**)
2. Déterminer les valeurs de clé (Key) des nouveaux champs personnalisés (endpoint Jira Field Spec)
3. Repérer les données acceptables pour chaque champ personnalisé, en utilisant les valeurs de clé comme référence (endpoint Jira Issue)
4. Créer un bloc JSON de référence des champs pour suivre toutes les clés de champs personnalisés et leurs données acceptables (endpoint Jira Issue)
5. Stocker le bloc JSON dans le Produit DefectDojo associé, pour permettre la création des champs personnalisés depuis Jira (interface DefectDojo)
6. Tester votre travail et vérifier que toutes les données requises circulent correctement depuis Jira

#### Étape 1 : noter les noms de vos champs personnalisés dans Jira

Jira prend en charge divers types de champs contextuels, notamment les sélecteurs de date (Date Pickers), les libellés personnalisés (Custom Labels) et les boutons radio (Radio Buttons). Chacun de ces champs contextuels possède une valeur de clé différente, que l'on retrouve dans l'API Jira.

Notez le nom de chaque champ personnalisé requis, car vous devrez les rechercher dans l'API Jira à l'étape suivante.

**Exemple de liste de champs personnalisés (les noms de vos champs personnalisés seront différents) :**

* DefectDojo Custom URL Field
* Un autre exemple de champ personnalisé
* ...

#### Étape 2 : trouver les valeurs de clé de vos champs personnalisés Jira

Commencez cette procédure en accédant à l'URL Field Spec de l'ensemble de votre instance Jira.

Voici un exemple d'URL Field Spec :

`https://yourcompany-example.atlassian.net/rest/api/2/field`

L'API renvoie une longue chaîne JSON, qu'il convient de mettre en forme pour la rendre lisible (à l'aide d'un éditeur de code, d'une extension de navigateur ou de <https://jsonformatter.org/>).

Le JSON renvoyé par cette URL contient tous vos champs personnalisés Jira, dont la plupart ne concernent pas DefectDojo et ont pour valeur `"Null"`. Chaque objet de cette réponse API correspond à un champ différent dans Jira. Vous devrez rechercher les objets dont l'attribut `"name"` correspond au nom de chaque champ personnalisé que vous avez créé dans l'interface Jira, puis noter la valeur de leur attribut "key".

![image](images/Using_Custom_Fields.png)

Une fois que vous avez trouvé l'objet correspondant dans la sortie JSON, vous pouvez déterminer la valeur "key" \- dans cet exemple, il s'agit de `customfield_10050`.

Jira génère une valeur de clé différente pour chaque champ personnalisé, mais ces valeurs ne changent pas une fois créées. Si vous créez un autre champ personnalisé ultérieurement, il aura une nouvelle valeur de clé.

**Complétons notre liste de champs personnalisés :**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Un autre exemple de champ personnalisé" \= customfield\_12345
* ...

#### Étape 3 \- trouver les champs personnalisés sur une issue Jira

Repérez une issue dans Jira contenant les champs personnalisés que vous avez notés à l'étape 2\. Copiez la clé de l'issue (Issue Key) du titre (qui doit ressembler à "`EXAMPLE-123`") et accédez à l'URL suivante :

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

Cela renvoie une nouvelle chaîne JSON.

Comme précédemment, la sortie de l'API contient de nombreux paramètres d'objet `customfield_##` avec des valeurs `null` \- il s'agit de champs personnalisés ajoutés par défaut par Jira, qui ne concernent pas cette issue. Elle contient également des valeurs `customfield_##` correspondant aux valeurs de clé des champs personnalisés que vous avez trouvées à l'étape précédente. Contrairement à la sortie de Field Spec, vous ne verrez aucun nom identifiant ces champs personnalisés, c'est pourquoi vous deviez noter les valeurs de clé à l'étape 2\.

![image](images/Using_Custom_Fields_2.png)

**Exemple :**
Nous savons que `customfield_10050` représente le champ DefectDojo Custom URL Field, car nous l'avons noté à l'étape 2\. Nous pouvons maintenant voir que `customfield_10050` contient une valeur de `"https://google.com"` dans l'issue `EXAMPLE-123`.

#### Étape 4 \- créer une référence JSON des champs à partir de chaque clé de champ personnalisé Jira

Vous devez maintenant reprendre la valeur de chaque champ personnalisé de votre liste et les stocker dans un objet JSON (à utiliser comme référence). Vous pouvez ignorer tout champ personnalisé qui ne correspond pas à votre liste.

Cet objet JSON contiendra toutes les valeurs par défaut des nouvelles Issues Jira. Nous vous recommandons d'utiliser des valeurs que votre équipe reconnaîtra facilement comme des valeurs "par défaut" à modifier : '`change-me.com`', '`Change this paragraph.`' etc.

**Exemple :**

D'après l'étape 3, nous savons maintenant que Jira attend une chaîne d'URL pour "`customfield_10050`". Nous pouvons utiliser cela pour construire notre exemple d'objet JSON.

Supposons que nous ayons également repéré un champ de texte court lié à DefectDojo, identifié comme "`customfield_67890`". Nous examinerions ce champ dans notre seconde sortie API, relèverions la valeur associée, et référencerions également cette valeur dans notre exemple d'objet JSON.
​
Votre objet JSON commencera à ressembler à ceci au fur et à mesure que vous y ajoutez des champs personnalisés.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Répétez cette procédure jusqu'à ce que tous les champs personnalisés Jira pertinents pour DefectDojo aient été ajoutés à votre référence JSON des champs.

#### Types de données \& syntaxe Jira

Certains champs, comme les champs de date, peuvent correspondre à plusieurs champs personnalisés dans Jira. Le cas échéant, vous devrez ajouter les deux champs à votre référence JSON des champs.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

D'autres champs, comme le champ Label, peuvent être suivis sous forme de liste de chaînes de caractères \- veillez à ce que votre référence JSON des champs utilise un format correspondant à la sortie de l'API Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

D'autres champs personnalisés peuvent contenir des informations contextuelles supplémentaires qu'il convient de retirer de la référence des champs. Par exemple, le champ Custom Multichoice contient un bloc supplémentaire dans la sortie de l'API, qu'il faut supprimer, car ce bloc stocke la valeur actuelle du champ.

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
* vous pouvez à la place le réduire comme suit, en ignorant la seconde partie :

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Exemple de référence des champs complète

Voici une référence JSON des champs complète, avec des commentaires en ligne expliquant à quoi correspond chaque champ personnalisé. Il s'agit d'un exemple exhaustif. Votre JSON contiendra des valeurs de clé et des données différentes selon les valeurs personnalisées que vous souhaitez utiliser lors de la création des issues.

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

#### Étape 5 \- ajouter les champs personnalisés à un Produit DefectDojo

Vous pouvez maintenant ajouter ces champs personnalisés au Produit DefectDojo associé, dans la section Custom Fields. Là encore,

* Accédez à Edit Product \- defectdojo.com/product/ID/edit .
* Accédez à Custom fields et collez la référence JSON des champs sous forme de texte brut dans le champ Custom Fields.
* Cliquez sur 'Submit'.

#### Étape 6 \- tester vos champs personnalisés Jira à partir d'une nouvelle Constatation :

Désormais, lorsque vous créez une nouvelle Constatation dans le Produit associé à Jira, Jira crée automatiquement tous ces champs personnalisés conformément au bloc JSON qu'il contient. Ces champs personnalisés seront créés avec les valeurs par défaut ("change\-me\-please", etc.).

Dans le Produit sur DefectDojo, accédez à la page Constatations \> Ajouter une nouvelle Constatation. Assurez-vous que la Constatation est à la fois Actif et Vérifié afin qu'elle soit poussée vers Jira, puis confirmez côté Jira que les champs personnalisés ont bien été créés sans incohérence.
