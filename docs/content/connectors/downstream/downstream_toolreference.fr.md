---
title: Référence des outils de connecteurs descendants
description: Guides de configuration détaillés pour les connecteurs descendants
weight: 1
audience: pro
aliases:
- /fr/en/share_your_findings/integrations_toolreference
- /fr/issue_tracking/pro_integration/integrations_toolreference/
---

## Azure DevOps Boards

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur votre URL Azure - par exemple `https://dev.azure.com/{your organization}`
- **Token** doit être défini sur un jeton d'accès personnel Azure.

L'authentification avec Azure DevOps nécessite un [jeton d'accès personnel](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
dont les autorisations sont définies sur « Read, Write and Manage » pour les « Work Items » du projet Azure avec lequel vous souhaitez travailler.

### Mappage du suivi des tickets

Ces informations déterminent la façon dont DefectDojo associe les attributs d'une Constatation ou d'un Groupe de constatations à un projet donné dans Azure DevOps :

#### Détails du mappage du suivi des tickets

Le champ `Project ID` correspond au nom ou à l'ID du projet dans Azure.

#### Détails du mappage de la sévérité

Les attributs du formulaire sont fournis par défaut et sont les suivants :

- **Severity Field Name** : `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping** : `4`
- **Low Mapping** : `4`
- **Medium Mapping** : `3`
- **High Mapping** : `2`
- **Critical Mapping** : `1`

#### Détails du mappage du statut

Les attributs du formulaire sont fournis par défaut et sont les suivants :

- **Status Field Name** : `/fields/System.State`
- **Active Mapping** : `To Do`
- **Closed Mapping** : `Done`
- **False Positive Mapping** : `Done`
- **Risk Accepted Mapping** : `Done`

## Bitbucket

L'intégration Bitbucket vous permet de transmettre des tickets vers le [suivi des tickets](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) d'un dépôt Bitbucket Cloud.

Le suivi des tickets est optionnel dans Bitbucket et doit être activé sur le dépôt avant que DefectDojo puisse y créer des tickets. Pour l'activer, ouvrez le dépôt dans Bitbucket, sélectionnez **Repository settings**, puis activez le suivi des tickets sous **Features**.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://bitbucket.org`.
- **Email** doit être l'adresse e-mail du compte Atlassian auquel appartient le jeton API.
- **API Token** doit être défini sur un jeton API Atlassian à portée limitée.

Les mots de passe d'application Bitbucket sont dépréciés par Atlassian et ne fonctionneront pas avec cette intégration. Pour créer un jeton API :

1. Ouvrez les [paramètres du compte Atlassian](https://id.atlassian.com/manage-profile/security/api-tokens) et choisissez **Security**, puis **Create and manage API tokens**.
2. Choisissez **Create API token with scopes**, nommez le jeton et définissez une date d'expiration.
3. Sélectionnez **Bitbucket** comme application.
4. Accordez au jeton l'autorisation de lire les dépôts, ainsi que de lire et écrire des tickets.

### Mappage du suivi des tickets

- **Workspace** doit correspondre au slug de l'espace de travail contenant le dépôt, tel qu'il apparaît dans les URL de bitbucket.org.
- **Repository Slug** doit correspondre au slug du dépôt dans lequel vous souhaitez créer des tickets.

### Détails du mappage de la sévérité

Ceci correspond au champ Priority des tickets Bitbucket. Les attributs du formulaire sont fournis par défaut, et chaque valeur doit être l'une des priorités de Bitbucket : `trivial`, `minor`, `major`, `critical` ou `blocker`.

- **Severity Field Name** : `priority`
- **Info Mapping** : `trivial`
- **Low Mapping** : `minor`
- **Medium Mapping** : `major`
- **High Mapping** : `critical`
- **Critical Mapping** : `blocker`

### Détails du mappage du statut

Ceci correspond au champ State des tickets Bitbucket. Chaque valeur doit être l'un des états de ticket de Bitbucket : `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix` ou `closed`.

- **Status Field Name** : `state`
- **Active Mapping** : `new`
- **Closed Mapping** : `resolved`
- **False Positive Mapping** : `invalid`
- **Risk Accepted Mapping** : `wontfix`

## GitHub

L'intégration GitHub vous permet d'ajouter des tickets à un [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects), ce qui ouvre également des tickets dans un dépôt (Repo) associé. Ces dépôts/projets peuvent être associés soit à une organisation GitHub, soit à un compte GitHub personnel.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre utilisateur ou organisation GitHub, selon l'endroit où vous souhaitez créer des tickets, par exemple `https://github.com/{your-organization}`
- **Token** doit être défini sur un jeton d'accès personnel GitHub.

Les jetons d'accès personnels pour GitHub peuvent être créés à l'adresse https://github.com/settings/tokens.  Le jeton doit disposer des portées Repo et Project.

### Mappage du suivi des tickets

- **Issue Tracker Mapping Label** doit être défini pour identifier le projet ou le dépôt dans lequel vous souhaitez créer des tickets.
- **Project Number** doit correspondre à l'ID du projet GitHub vers lequel vous souhaitez envoyer les éléments.  Vous pouvez l'obtenir depuis l'URL affichée lorsque vous consultez un projet, par exemple `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** doit correspondre au nom d'un dépôt associé à votre organisation (ou utilisateur) vers lequel vous souhaitez transmettre des tickets.


### Détails du mappage de la sévérité

**Pour configurer l'intégration, le projet DOIT disposer d'un champ personnalisé créé pour représenter la priorité des tickets ; sinon, la sévérité ne sera pas correctement mappée et les tickets ne seront pas transmis à GitHub.**

Suivez ce guide pour créer un [champ personnalisé](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority).
Chaque sévérité doit disposer d'une option à sélection unique correspondante.  Par exemple, par défaut, DefectDojo propose P0, P1, P2, P3, P4 comme valeurs possibles de priorité, et chacune d'elles doit être ajoutée au champ personnalisé Priority.

- **Severity Field Name** : `Priority`
- **Info Mapping** : `P0`
- **Low Mapping** : `P1`
- **Medium Mapping** : `P2`
- **High Mapping** : `P3`
- **Critical Mapping** : `P4`

### Détails du mappage du statut

Par défaut, les nouveaux projets GitHub disposent des statuts « In Progress » et « Done » pour les tickets.  Des statuts supplémentaires peuvent être ajoutés au projet pour suivre les statuts Faux positif ou Risque accepté si vous le souhaitez.  L'une des façons d'y parvenir consiste à ajouter une nouvelle colonne de statut au tableau du projet.

- **Status Field Name** : `Status`
- **Active Mapping** : `In Progress`
- **Closed Mapping** : `Done`
- **False Positive Mapping** : `Done`
- **Risk Accepted Mapping** : `Done`

## GitLab

L'intégration GitLab vous permet d'ajouter des tickets à un [projet GitLab](https://docs.gitlab.com/ee/user/project/).

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur le lien de votre serveur GitLab, par exemple `https://gitlab.com/`.
- **Token** doit être défini sur un jeton d'accès personnel GitLab. Le jeton doit disposer des portées API. Consultez le [guide GitLab pour créer un jeton d'accès personnel](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Mappage du suivi des tickets

- **Project Name** : le nom du projet dans GitLab vers lequel vous souhaitez envoyer les tickets.

### Détails du mappage de la sévérité

Ceci correspond au champ Priority de GitLab.
- **Severity Field Name** : `Priority`
- **Info Mapping** : `1`
- **Low Mapping** : `2`
- **Medium Mapping** : `3`
- **High Mapping** : `4`
- **Critical Mapping** : `5`

### Détails du mappage du statut

Par défaut, GitLab dispose des statuts « opened » et « closed ».  Des étiquettes de statut supplémentaires peuvent être ajoutées si vous souhaitez suivre les statuts Faux positif ou Risque accepté.  Consultez la [documentation GitLab](https://docs.gitlab.com/user/work_items/status/) pour plus de détails.

- **Status Field Name** : `Status`
- **Active Mapping** : `opened`
- **Closed Mapping** : `closed`
- **False Positive Mapping** : `closed`
- **Risk Accepted Mapping** : `closed`

## Jira

L'intégration Jira transmet les Constatations et Groupes de constatations de DefectDojo vers un projet Jira sous forme de tickets, maintient le statut de chaque ticket synchronisé avec la Constatation, et relie la Constatation au ticket créé. Jira **Cloud** et **Data Center / Server** sont tous deux pris en charge. Jira Service Management n'est pas pris en charge.

### Choisir une méthode d'authentification

Définissez d'abord **Jira Deployment**, puis choisissez une **Authentication Method** :

**Jira Cloud**
- **API Token (email + token)** — authentification HTTP Basic utilisant l'e-mail d'un compte Atlassian et un [jeton API](https://id.atlassian.com/manage-profile/security/api-tokens). Les appels sont envoyés directement à l'URL de votre site.
- **OAuth 2.0 (recommended)** — un consentement navigateur unique ; DefectDojo obtient et actualise les jetons pour vous.
- **Service Account Token** — un jeton API à portée limitée créé pour un [compte de service](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/) Atlassian.

**Jira Data Center / Server**
- **Personal Access Token (recommended)**
- **Username + Password**

> **Comment l'authentification Cloud atteint Jira :** OAuth 2.0 et Service Account s'authentifient tous deux via un jeton Bearer auprès de la passerelle Atlassian — `https://api.atlassian.com/ex/jira/{cloudId}` — qui est un *hôte différent* de l'URL de votre site `https://your-site.atlassian.net`. DefectDojo utilise la passerelle pour chaque appel API, mais construit toujours le lien du ticket affiché sur une Constatation à partir de l'**URL de votre site**, de sorte que le lien sur lequel un utilisateur clique est un lien normal et navigable de type `.../browse/{ISSUE-KEY}`. (L'authentification API Token et Data Center appelle directement l'URL du site, il n'y a donc pas de séparation.)

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'**URL de votre site** Jira, par exemple `https://your-organization.atlassian.net`. Elle est utilisée pour les liens de tickets navigables et — pour l'authentification API Token et Data Center — comme URL de base de l'API.
- Les champs restants dépendent de la méthode choisie ci-dessus (e-mail + jeton API, identifiants client OAuth, jeton de compte de service, PAT, ou nom d'utilisateur + mot de passe).

### Configuration OAuth 2.0 (Cloud)

Créez une application dédiée dans la [console développeur Atlassian](https://developer.atlassian.com/console/myapps/), puis connectez-vous depuis DefectDojo.

1. Choisissez **Create → OAuth 2.0 integration**. Il doit s'agir d'une *intégration OAuth 2.0* — une application Connect ou Forge ne peut pas utiliser le flux d'autorisation par code 3LO (vous obtiendriez `grant_type is not enabled for client`).
2. Lorsque l'on vous demande le **Access type**, choisissez **Resource-level**. Cela limite le jeton au seul site Jira que l'utilisateur autorise, ce qui correspond exactement à ce que cible une connexion DefectDojo. (**Account-level** accorde l'accès à tous les sites du compte Atlassian — une portée plus large que nécessaire.)
3. Dans **Permissions**, ajoutez la **Jira platform REST API** et accordez les portées listées ci-dessous. Remarque : `offline_access` n'est *pas* listée ici — il s'agit d'une portée OAuth standard que DefectDojo demande dans l'URL d'autorisation, et non d'un élément à ajouter sur cet écran.
4. Dans **Authorization**, à côté de **OAuth 2.0 (3LO)**, cliquez sur **Configure** et définissez la **Callback URL** sur `https://<your-defectdojo-host>/integrators/jira/oauth/callback` — elle doit correspondre exactement à l'URL de votre site DefectDojo. C'est cette activation qui active le flux d'autorisation par code et les jetons de rafraîchissement ; l'omettre provoque les erreurs `grant_type is not enabled` / `Client is not allowed to use offline_access`.
5. Copiez le **Client ID** et le **Client Secret** dans le formulaire DefectDojo, puis cliquez sur **Submit** pour enregistrer la connexion.
6. Cliquez sur **Connect with Jira** et approuvez l'écran de consentement. Atlassian redirige ensuite vers DefectDojo, qui stocke les jetons et résout automatiquement votre `cloudId`. Un indicateur « Connected » apparaît en cas de succès.

> L'hôte de rappel est votre `SITE_URL` DefectDojo. Atlassian doit pouvoir y rediriger le navigateur, et la valeur doit correspondre exactement à ce que DefectDojo envoie — utilisez donc le nom d'hôte réel par lequel vos utilisateurs accèdent à DefectDojo, et non une valeur accessible uniquement depuis l'intérieur du réseau.

#### Portées OAuth minimales

DefectDojo demande ces quatre portées classiques par défaut, qui constituent également le **minimum absolu** requis — chacune sous-tend un comportement spécifique :

| Scope | Required for |
|-------|--------------|
| `read:jira-work` | Lire le projet, les tickets et les transitions disponibles (validation de la connexion et synchronisation du statut). |
| `write:jira-work` | Créer et modifier des tickets, et exécuter des transitions de statut. |
| `read:jira-user` | La vérification d'identité de la connexion — DefectDojo appelle `/myself` lors de la validation de l'accès. |
| `offline_access` | Émettre un **jeton de rafraîchissement**. Sans cela, le jeton d'accès expire (~1 heure après la connexion) et la connexion cesse de fonctionner, car DefectDojo ne peut plus le rafraîchir. |

Atlassian recommande les portées classiques plutôt que les portées granulaires ; les quatre ci-dessus limitent l'empreinte de l'application au minimum et suffisent pour tout ce que fait l'intégration.

##### Alternative avec portées granulaires

Si votre organisation exige des portées **granulaires** plutôt que classiques, l'ensemble minimal équivalent est le suivant :

| Granular scope | Required for |
|----------------|--------------|
| `read:user:jira` | La vérification d'identité `/myself`. |
| `read:project:jira` | Valider que le projet cible existe. |
| `read:issue:jira` | Lire le statut actuel d'un ticket pendant la synchronisation. |
| `write:issue:jira` | Créer et modifier des tickets **et exécuter des transitions de statut** — il n'existe pas de portée d'écriture distincte pour les transitions ; une transition est une écriture sur le ticket. |
| `read:issue.transition:jira` | Lister les transitions disponibles sur un ticket. |
| `offline_access` | Le jeton de rafraîchissement (identique aux portées classiques). |

Selon la configuration des champs de votre site, un endpoint peut également nécessiter des portées de lecture complémentaires pour développer les champs — le plus souvent `read:status:jira` et `read:field:jira` (ainsi que `read:issue-meta:jira` pour la création). Si une transmission échoue avec une erreur `403` « scope does not match », ajoutez la portée exacte mentionnée dans l'erreur. C'est précisément cette prolifération de portées complémentaires qui justifie la recommandation des portées classiques.

Pour la méthode **Service Account Token**, accordez au jeton `read:jira-work` et `write:jira-work` (ainsi que `read:jira-user`) — ou les équivalents granulaires ci-dessus sans `offline_access`. `offline_access` ne s'applique pas — un jeton de compte de service est longue durée et n'est pas rafraîchi par DefectDojo.

### Mappage du suivi des tickets

- **Project Key** : la clé du projet Jira dans lequel créer des tickets, par exemple `SEC`.
- **Issue Type** : le type de ticket à créer, par exemple `Bug` ou `Task`. La valeur par défaut est `Bug`.

### Détails du mappage de la sévérité

Les valeurs par défaut correspondent au schéma de priorité par défaut de Jira. Modifiez-les pour correspondre aux noms de priorité de votre projet :

- **Severity Field Name** : `priority`
- **Info Mapping** : `Lowest`
- **Low Mapping** : `Low`
- **Medium Mapping** : `Medium`
- **High Mapping** : `High`
- **Critical Mapping** : `Highest`

### Détails du mappage du statut

Les statuts varient selon le workflow de chaque projet ; ces valeurs par défaut sont donc destinées à être modifiées pour correspondre aux noms de statut de **votre** workflow :

- **Status Field Name** : `status`
- **Active Mapping** : `To Do`
- **Closed Mapping** : `Done`
- **False Positive Mapping** : `Done`
- **Risk Accepted Mapping** : `Done`

### Champs personnalisés (facultatif)

Vous pouvez mapper des champs Jira supplémentaires — par exemple un `resolution` requis à la fermeture, ou des `labels` — dans l'étape **Custom Fields** du mappage. Chaque mappage de champ personnalisé comporte quatre parties :

- **Source** — d'où provient la valeur : un attribut de la **Constatation**, du **Test**, de l'**Engagement**, ou de l'**Asset** transmis, ou une **valeur statique**.
- **Value** — pour une source de type objet, l'attribut spécifique à lire, choisi dans une liste des champs de cet objet avec des libellés lisibles (par exemple *Severity*, *CVE*, *Mitigation*). Pour une source **valeur statique**, il s'agit d'une zone de texte libre dans laquelle vous saisissez la valeur littérale.
- **Vendor Field** — le champ Jira dans lequel écrire. Comme DefectDojo peut lire le catalogue de champs de Jira, il s'agit d'un sélecteur avec recherche qui liste chaque champ par son **nom d'affichage** et le résout pour vous en identifiant interne — vous sélectionnez donc *DD Close Justification* et DefectDojo stocke `customfield_10255`. Le sélecteur est alimenté à partir de la connexion ; il fonctionne donc une fois la connexion enregistrée et validée.
- **Application point** — *quand* envoyer le champ : à la **création du ticket**, à **chaque mise à jour**, ou dans le cadre d'une **transition** de statut spécifique (Actif / Fermé / Faux positif / Risque accepté). Un champ associé à une transition est envoyé dans le cadre de la modification de cette transition — c'est ainsi que vous fournissez une valeur que Jira n'accepte que sur un écran de transition, le plus souvent un `resolution` que votre workflow exige à la résolution d'un ticket.

### Modèles de tickets (facultatif)

Par défaut, les tickets Jira utilisent le titre et le corps intégrés de DefectDojo. Pour les personnaliser, associez un **Ticket Template** au mappage dans son étape **Ticket Template**. Un modèle définit quatre éléments indépendamment facultatifs — le résumé et la description de la **Constatation**, ainsi que le résumé et la description du **Groupe de constatations**. Tout élément laissé vide revient à la valeur par défaut intégrée, ce qui vous permet de ne remplacer que le titre, que le corps, ou les quatre. Utilisez **Test render** dans l'éditeur de modèle pour prévisualiser le rendu à partir de données d'exemple — ce qui permet de détecter des erreurs telles que des espaces réservés inconnus ou des valeurs dépassant la limite de longueur d'un champ — avant d'enregistrer. Si un modèle est ensuite supprimé, les mappages qui l'utilisaient reviennent automatiquement aux valeurs par défaut intégrées.

### Fonctionnement

- **Create / Update / Delete :** la création transmet un nouveau ticket et enregistre le lien sur la Constatation ; la mise à jour modifie le ticket existant ; la suppression d'une Constatation force la fermeture de son ticket (rien n'est supprimé dans Jira). Les transmissions peuvent être manuelles (« Push to Integrator ») ou automatiques selon l'Issue Tracker Assignment.
- **Réconciliation du statut :** après la création (et à chaque mise à jour), DefectDojo lit le statut actuel du ticket et, s'il diffère de la cible mappée, recherche une transition de workflow unique permettant de l'atteindre et l'applique. Si aucune transition de ce type n'existe, le mappage enregistre une erreur plutôt que d'échouer silencieusement. Tout champ personnalisé associé à une transition est envoyé avec cette transition.
- **Lien du ticket :** le lien affiché sur la Constatation est `https://your-site.atlassian.net/browse/{ISSUE-KEY}` — toujours l'URL publique de votre site, jamais la passerelle interne.
- **Cycle de vie du jeton (OAuth) :** DefectDojo gère l'intégralité du flux — il effectue l'échange du code d'autorisation, stocke les jetons d'accès et de rafraîchissement, et les rafraîchit à la demande avant chaque transmission, en persistant le nouveau jeton de rafraîchissement à chaque fois (Atlassian le fait pivoter à chaque rafraîchissement).
- **Stockage des identifiants :** tous les identifiants de connexion (mots de passe, jetons, secrets client, jetons OAuth) sont chiffrés au repos et ne sont jamais renvoyés par l'API — la modification d'une connexion affiche un texte indicatif « leave blank to keep » pour les secrets stockés.

## Linear

L'intégration Linear vous permet de transmettre les Constatations de DefectDojo sous forme de tickets [Linear](https://linear.app/). Les tickets sont créés dans une équipe (Team) de votre espace de travail Linear.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.linear.app/graphql`.
- **API Key** doit être définie sur une clé API personnelle Linear. Les clés peuvent être générées dans Linear sous Settings, puis Security & access, puis [API](https://linear.app/settings/account/security). La clé est envoyée à l'API GraphQL de Linear dans l'en-tête `Authorization`.

### Mappage du suivi des tickets

- **Team (Group) ID** doit être défini sur l'ID de l'équipe Linear pour laquelle les tickets seront créés. Vous pouvez lister vos équipes et leurs ID en appelant l'API GraphQL de Linear :

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Détails du mappage de la sévérité

Un ticket Linear porte une **priority** numérique plutôt qu'un champ de sévérité. Chaque sévérité DefectDojo est mappée à une priorité Linear, où `1` correspond à Urgent et `4` à Low :

- **Severity Field Name** : `Priority`
- **Info Mapping** : `4`
- **Low Mapping** : `4`
- **Medium Mapping** : `3`
- **High Mapping** : `2`
- **Critical Mapping** : `1`

### Détails du mappage du statut

Chaque valeur de statut doit être définie sur l'ID d'un Workflow State de votre équipe Linear. Les ID de Workflow State sont propres à chaque espace de travail ; il n'existe donc pas de valeurs par défaut. Vous pouvez lister les Workflow States et leurs ID en appelant l'API GraphQL de Linear :

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Status Field Name** : `Workflow State ID`
- **Active Mapping** : l'ID d'un état démarré ou non démarré, par exemple `Todo` ou `In Progress`.
- **Closed Mapping** : l'ID d'un état terminé, par exemple `Done`. Lorsqu'une Constatation est supprimée dans DefectDojo, son ticket est déplacé vers cet état.

## Opsgenie

L'intégration Opsgenie vous permet de transmettre les Constatations et Groupes de constatations de DefectDojo sous forme d'alertes Opsgenie, éventuellement routées vers une équipe Opsgenie en tant que répondant.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.opsgenie.com`.  Si votre compte Opsgenie est hébergé dans la région de service UE, utilisez plutôt `https://api.eu.opsgenie.com`.  Si vos alertes se trouvent dans Jira Service Management Operations (Atlassian intègre progressivement Opsgenie à JSM), utilisez `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** doit être définie sur une clé d'**intégration API** Opsgenie.  Un administrateur de compte peut en créer une dans l'application web Opsgenie, sous **Settings > Integrations** : ajoutez une intégration de type **API** et accordez-lui *Create and Update Access* (ainsi que *Read Access* afin que DefectDojo puisse vérifier la connexion).  Notez qu'il s'agit d'une clé d'intégration, et non d'une clé API personnelle - DefectDojo s'authentifie avec l'autorisation `GenieKey`, que seules les clés d'intégration prennent en charge.

### Mappage du suivi des tickets

- **Team Name** *(facultatif)* doit correspondre au nom de l'équipe Opsgenie à ajouter comme répondant sur les alertes créées.  Vous pouvez le laisser vide : si la clé d'intégration API est limitée à une équipe, les alertes sont routées automatiquement vers celle-ci, et sinon ce sont les règles de routage propres à votre compte qui déterminent les répondants.

### Détails du mappage de la sévérité

Les sévérités correspondent au champ **Priority** des alertes Opsgenie, qui utilise l'échelle fixe d'Opsgenie allant de `P1` (critique) à `P5` (informatif) :

- **Severity Field Name** : `Priority`
- **Info Mapping** : `P5`
- **Low Mapping** : `P4`
- **Medium Mapping** : `P3`
- **High Mapping** : `P2`
- **Critical Mapping** : `P1`

Si une sévérité est mappée à une valeur non reconnue, la priorité est omise et Opsgenie applique sa propre valeur par défaut (`P3`).

### Détails du mappage du statut

Les alertes Opsgenie sont `open` ou `closed`, et une alerte ouverte peut en outre être `acknowledged` :

- **Status Field Name** : `Status`
- **Active Mapping** : `open`
- **Closed Mapping** : `closed`
- **False Positive Mapping** : `closed`
- **Risk Accepted Mapping** : `acknowledged`

Notez que `closed` est un statut final dans Opsgenie - une alerte fermée ne peut pas être rouverte, et son alias est libéré.  Contrairement à certains autres outils, Opsgenie autorise les modifications de contenu après création ; ainsi, la transmission d'une Constatation mise à jour synchronise son message, sa description et sa priorité en plus du statut.

DefectDojo définit l'**alias** de chaque alerte sur une clé stable dérivée de la Constatation ou du Groupe de constatations, et Opsgenie dé-duplique les alertes ouvertes par alias - ainsi, retransmettre la même Constatation met à jour l'alerte ouverte existante au lieu d'en créer une nouvelle.

## PagerDuty

L'intégration PagerDuty vous permet de transmettre les Constatations et Groupes de constatations de DefectDojo sous forme d'incidents PagerDuty, ouverts sur un service PagerDuty de votre choix.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.pagerduty.com`.  Si votre compte PagerDuty est hébergé dans la région de service UE, utilisez plutôt `https://api.eu.pagerduty.com`.
- **API Token** doit être défini sur une clé API REST PagerDuty.  Un administrateur de compte peut en créer une dans l'application web PagerDuty, sous **Integrations > API Access Keys > Create New API Key**.  Laissez « Read-only » décoché - DefectDojo doit pouvoir créer et mettre à jour des incidents.
- **From Email** doit correspondre à l'adresse e-mail d'un utilisateur valide de votre compte PagerDuty.  PagerDuty exige cette adresse lors de la création ou de la mise à jour d'incidents, et elle sera affichée comme demandeur de l'incident.

### Mappage du suivi des tickets

- **Service ID** doit correspondre à l'ID du service PagerDuty sur lequel les incidents seront ouverts.  Vous pouvez le trouver à la fin de l'URL lorsque vous consultez le service dans PagerDuty, par exemple `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Détails du mappage de la sévérité

Par défaut, ceci correspond au champ **Urgency** des incidents PagerDuty, qui n'accepte que `high` ou `low` :

- **Severity Field Name** : `Urgency`
- **Info Mapping** : `low`
- **Low Mapping** : `low`
- **Medium Mapping** : `low`
- **High Mapping** : `high`
- **Critical Mapping** : `high`

Alternativement, si votre compte PagerDuty a activé les [Priorities](https://support.pagerduty.com/main/docs/incident-priority), vous pouvez mapper les sévérités aux noms de priorité à la place.  Définissez le **Severity Field Name** sur `Priority` et utilisez les noms de priorité de votre compte (par exemple de `P1` à `P5`) comme valeurs de mappage.  Lors du mappage vers Priority, l'urgence de l'incident est laissée aux propres règles d'urgence de votre service.

### Détails du mappage du statut

Les incidents PagerDuty ont trois statuts : `triggered`, `acknowledged` et `resolved`.

- **Status Field Name** : `Status`
- **Active Mapping** : `triggered`
- **Closed Mapping** : `resolved`
- **False Positive Mapping** : `resolved`
- **Risk Accepted Mapping** : `acknowledged`

Notez que `resolved` est un statut final dans PagerDuty - un incident résolu ne peut pas être rouvert.  Notez également que PagerDuty ne permet pas de modifier le titre ou la description d'un incident après sa création ; ainsi, la transmission d'une Constatation mise à jour synchronisera son statut, son urgence et sa priorité, mais pas les modifications de contenu.

## ServiceNow

L'intégration ServiceNow vous permet de pousser les Constatations DefectDojo sous forme d'Incidents ServiceNow.

### Configuration de l'instance

DefectDojo s'authentifie auprès de ServiceNow via OAuth 2.0. La façon dont vous créez les identifiants OAuth dépend de votre version de ServiceNow — les versions récentes (Zurich et ultérieures) utilisent un octroi Client Credentials, tandis que les versions antérieures utilisent un jeton d'actualisation (refresh token).

#### ServiceNow Zurich et versions ultérieures (client credentials)

Les versions récentes de ServiceNow ont déprécié l'option classique « Create an OAuth API endpoint for external clients » au profit de la **New Inbound Integration Experience**, qui délivre un octroi OAuth **Client Credentials** lié à un compte de service :

1. Dans la barre de navigation de gauche, recherchez « Application Registry » et sélectionnez-le.
2. Cliquez sur **New**, puis choisissez **New Inbound Integration Experience**.
3. Sélectionnez **New Integration → OAuth - Client credentials grant**.
4. Définissez **OAuth Application User** sur le compte de service qui créera les Incidents. Les rôles de ce compte déterminent ce que DefectDojo est autorisé à écrire.
5. Enregistrez l'inscription. ServiceNow génère automatiquement le **Client ID** et le **Client Secret** (laissez ces champs vides lors de la création de l'inscription).

Ensuite, dans DefectDojo :

- **Instance Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre serveur ServiceNow, par exemple `https://your-organization.service-now.com/`.
- **Client ID** doit être le Client ID provenant de l'inscription OAuth.
- **Client Secret** doit être le Client Secret provenant de l'inscription OAuth.

Laissez vides les champs Refresh Token, Username et Password — DefectDojo demande un nouveau jeton client-credentials à chaque synchronisation.

#### Versions antérieures de ServiceNow (jeton d'actualisation)

Sur les versions qui proposent encore l'inscription classique, obtenez un Refresh Token associé au compte Utilisateur ou de Service qui poussera les Incidents vers ServiceNow :

1. Dans la barre de navigation de gauche, recherchez « Application Registry » et sélectionnez-le.
2. Cliquez sur « New ».
3. Choisissez « Create an OAuth API endpoint for external clients ».
4. Renseignez les champs requis :
    * Name : indiquez un nom explicite pour votre application (par exemple, Vulnerability Integration Client).
    * (Facultatif) Ajustez la durée de vie du jeton :
    * Access Token Lifespan : la valeur par défaut est 1800 secondes (30 minutes).
    * Refresh Token Lifespan : la valeur par défaut est 8640000 secondes (environ 100 jours).
5. Cliquez sur Submit pour créer l'enregistrement de l'application.
6. Après l'envoi, sélectionnez l'application dans la liste et notez les champs **Client ID and Client Secret**.

Vous devrez ensuite utiliser cette inscription pour obtenir un Refresh Token, qui ne peut être obtenu que via l'API ServiceNow.  Ouvrez une fenêtre de terminal et collez ce qui suit (en remplaçant les variables entourées de `{{}}` par les informations réelles de votre utilisateur)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

Si vos identifiants ServiceNow sont corrects et permettent un accès de niveau administrateur à ServiceNow, vous devriez recevoir une réponse contenant un RefreshToken.  Vous aurez besoin de ce jeton pour terminer l'intégration avec DefectDojo.

- **Instance Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre serveur ServiceNow, par exemple `https://your-organization.service-now.com/`.
- **Refresh Token** est l'endroit où le Refresh Token doit être saisi.
- **Client ID** doit être le Client ID défini dans l'OAuth App Registration.
- **Client Secret** doit être le Client Secret défini dans l'OAuth App Registration.

### Détails de la correspondance des sévérités

Ceci correspond au champ Impact de ServiceNow.
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `3`

### Détails de la correspondance des statuts

- **Status Field Name**: `State`
- **Active Mapping**: `New`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Resolved`
- **Risk Accepted Mapping**: `Resolved`

Chaque correspondance accepte une étiquette d'état standard (`New`, `In Progress`, `On Hold`, `Resolved`, `Closed`, `Cancelled`) ou une valeur d'état numérique. Sur les instances dont les états d'Incident sont personnalisés — ou lorsque vous ciblez une table autre que `incident` — utilisez la **valeur d'état** numérique de la liste de choix de votre instance ; une valeur numérique en dehors de l'ensemble standard est envoyée à ServiceNow telle quelle. La valeur par défaut intégrée du code de résolution n'accompagne que les états résolu/fermé standard ; associez donc les valeurs d'état personnalisées aux correspondances de champs de clôture et de résolution ci-dessous.

### Champs de clôture et de résolution

Certaines instances ServiceNow appliquent une Data Policy qui rend obligatoires des champs tels que le **Resolution code** (`close_code`) dès qu'un Incident passe à un état résolu ou fermé. Si DefectDojo ferme un Incident sans ces champs, ServiceNow rejette l'écriture avec une erreur HTTP 403 *« Data Policy Exception »*, et la raison est enregistrée dans la vue Errors de l'intégration.

Associez les champs requis au changement d'état avec **Custom Field Mappings**, en définissant **Apply On** sur la disposition qui doit les porter :

- **Transition to Closed** — envoyé lorsqu'une Constatation est atténuée / fermée.
- **Transition to False Positive** — envoyé lorsqu'une Constatation est marquée comme faux positif.
- **Transition to Risk Accepted** — envoyé lorsqu'une Constatation fait l'objet d'une acceptation du risque.

Par exemple, pour satisfaire un Resolution code obligatoire :

| Source | Field Name | Value | Apply On |
|---|---|---|---|
| Static | `close_code` | `Resolved by DefectDojo` | Transition to Closed |
| Static | `close_notes` | `Reviewed by the security team` | Transition to Closed |
| Static | `close_code` | `Not a defect` | Transition to False Positive |

Remarques :

- Field Name est le nom de colonne ServiceNow — `close_code`, `close_notes`, ou un champ personnalisé `u_...`.
- Les correspondances de transition se déclenchent lorsque l'état de l'enregistrement change réellement : une Constatation déjà fermée lors de son premier envoi, une mise à jour qui ferme ou rouvre l'enregistrement, et la fermeture forcée lorsqu'un lien de ticket est supprimé. Elles ne sont pas renvoyées lors de mises à jour de routine d'un enregistrement inchangé ; les champs de journal tels que `work_notes` reçoivent donc une seule entrée par transition.
- Les champs de référence tels que `assignment_group` et `assigned_to` attendent un **sys_id**, et non un nom d'affichage.
- Les valeurs qui s'analysent comme du JSON sont envoyées typées : `true`, `42`, `[...]`, `{...}` — et `null`, qui efface le champ. Pour envoyer un tel texte comme chaîne littérale, entourez-le de guillemets doubles (par exemple `"null"`).
- `short_description`, `description`, `state`, `impact`, `urgency` et `priority` sont gérés par le modèle de description et par les correspondances de sévérité/statut ; ils ne peuvent donc pas être définis via une correspondance de champ personnalisée.
- Sur les tables autres que `incident`, les valeurs d'état qui correspondent à l'ensemble Incident standard (`1`, `2`, `3`, `6`, `7`, `8`) sont tout de même interprétées avec la sémantique Incident — y compris la valeur par défaut automatique du Resolution code sur `6`/`7`/`8`. Privilégiez des valeurs d'état en dehors de cette plage sur les tables personnalisées, ou fournissez explicitement les champs de clôture comme ci-dessus.

## ServiceNow SecOps

L'intégration ServiceNow SecOps (aussi appelée **ServiceNow SecOps / Vulnerability Response**) pousse les Constatations et Groupes de constatations DefectDojo vers une table de sécurité ServiceNow — un **Security Incident** (`sn_si_incident`) ou un **Vulnerable Item** (`sn_vul_vulnerable_item`) — et la maintient synchronisée à mesure que la Constatation évolue (création, mise à jour et résolution/fermeture). C'est l'équivalent côté opérations de sécurité de l'intégration ServiceNow de suivi des tickets ci-dessus ; utilisez ServiceNow SecOps lorsque vous exploitez les applications Security Incident Response (SIR) ou Vulnerability Response (VR).

### Configuration de l'instance

- **Instance Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre serveur ServiceNow, par exemple `https://your-organization.service-now.com/`.

ServiceNow SecOps prend en charge trois méthodes d'authentification ; fournissez-en **une seule** :

- **OAuth 2.0** — saisissez un **Client ID**, un **Client Secret** et un **Refresh Token**. Obtenez-les exactement comme décrit dans la section [ServiceNow](#servicenow) ci-dessus (créez un point de terminaison API OAuth dans l'Application Registry, puis échangez vos identifiants sur `/oauth_token.do` contre un jeton d'actualisation). Vous pouvez aussi fournir le **Client ID** et le **Client Secret** avec un **Username** et un **Password** pour utiliser l'octroi OAuth par mot de passe au lieu d'un jeton d'actualisation.
- **API Key** — saisissez une **API Key**, envoyée dans l'en-tête `x-sn-apikey`. La clé n'authentifie rien tant qu'un Inbound Authentication Profile et une REST API Access Policy ne lui sont pas associés sur l'instance.
- **HTTP Basic** — saisissez le **Username** et le **Password** du compte de service.

Le compte de service (ou le client OAuth) doit disposer d'un accès en écriture à la table cible.

### Correspondance du suivi des tickets

- **Target Table** sélectionne la table ServiceNow dans laquelle les enregistrements sont écrits : **Security Incident** (`sn_si_incident`, valeur par défaut) ou **Vulnerable Item** (`sn_vul_vulnerable_item`).

### Détails de la correspondance des sévérités

Pour un Security Incident, ceci correspond au champ **Impact** ; ServiceNow dérive la Priority de l'incident à partir de l'Impact et de l'Urgency, si bien que l'Urgency reflète l'Impact mappé à moins que vous ne la mappiez vous-même. Pour un Vulnerable Item, associez la sévérité au champ de risque utilisé par votre instance. Les valeurs par défaut ci-dessous correspondent à l'échelle Impact SIR standard (`1` High, `2` Medium, `3` Low) et sont modifiables.

- **Severity Field Name**: `impact`
- **Info Mapping**: `3`
- **Low Mapping**: `3`
- **Medium Mapping**: `2`
- **High Mapping**: `1`
- **Critical Mapping**: `1`

### Détails de la correspondance des statuts

Ceci correspond au champ **State** de l'enregistrement. Les valeurs d'état sont des codes numériques qui diffèrent entre les tables Security Incident et Vulnerable Item et peuvent être personnalisées par instance ; vérifiez-les donc par rapport à votre propre configuration. Les valeurs par défaut ci-dessous utilisent les codes d'état SIR standard (`16` Analysis, `3` Closed).

- **Status Field Name**: `state`
- **Active Mapping**: `16`
- **Closed Mapping**: `3`
- **False Positive Mapping**: `3`
- **Risk Accepted Mapping**: `3`

Lorsqu'un enregistrement est fermé, DefectDojo définit également le **Close Code** et les **Close Notes** ServiceNow (`Resolved` pour les Constatations fermées, `False positive` et `Risk accepted` pour les états correspondants).

### Comportements spécifiques à ServiceNow SecOps

- **Deduplication** — chaque enregistrement est marqué avec l'identifiant DefectDojo de la Constatation ou du Groupe de constatations dans son `correlation_id`. Avant de créer un enregistrement, DefectDojo en recherche un par `correlation_id` ; une correspondance est reprise et mise à jour plutôt que dupliquée, ce qui rend les resynchronisations idempotentes.
- **Updates** sont publiées dans le journal **Work notes** de l'enregistrement (interne), jamais dans les Comments visibles par le client.
- **Resolve on delete** — la suppression d'une Constatation dans DefectDojo résout/ferme l'enregistrement ServiceNow (State + Close Code) plutôt que de le supprimer ; les enregistrements ne sont jamais supprimés définitivement.
- **Reference fields** — les valeurs facultatives `cmdb_ci`, `assignment_group` et `assigned_to` peuvent être fournies sous forme de noms d'affichage ; DefectDojo résout chacune vers son `sys_id`. Un nom qui ne se résout pas est ignoré avec un avertissement plutôt que de faire échouer l'envoi.

## Shortcut

L'intégration Shortcut vous permet de pousser les Constatations DefectDojo sous forme de Stories [Shortcut](https://www.shortcut.com/). Les Stories sont créées avec le type Bug et affectées à une Team de votre espace de travail Shortcut.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.app.shortcut.com`.
- **API Token** doit être un jeton API Shortcut. Les jetons peuvent être générés dans Shortcut sous Settings, puis Your Account, puis [API Tokens](https://app.shortcut.com/settings/account/api-tokens).

### Correspondance du suivi des tickets

- **Team (Group) ID** doit être défini sur l'UUID de la Team Shortcut pour laquelle les Stories seront créées. Vous pouvez trouver cet UUID en ouvrant la page Team dans Shortcut et en copiant l'identifiant depuis l'URL, ou en appelant l'API Shortcut :

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Détails de la correspondance des sévérités

Chaque valeur de sévérité est appliquée à la Story sous forme de label. Les labels sont créés automatiquement dans Shortcut s'ils n'existent pas déjà ; les valeurs par défaut ci-dessous peuvent donc être utilisées telles quelles, ou remplacées par des noms de label de votre choix. Lorsque la sévérité d'une Constatation change, l'ancien label de sévérité est retiré de la Story et le nouveau est ajouté.

- **Severity Field Name**: `Label`
- **Info Mapping**: `sev-info`
- **Low Mapping**: `sev-low`
- **Medium Mapping**: `sev-medium`
- **High Mapping**: `sev-high`
- **Critical Mapping**: `sev-critical`

### Détails de la correspondance des statuts

Chaque valeur de statut doit être définie sur l'ID numérique d'un Workflow State dans votre espace de travail Shortcut. Les ID de Workflow State sont propres à chaque espace de travail ; il n'y a donc pas de valeurs par défaut. Vous pouvez lister les Workflow States et leurs ID en appelant l'API Shortcut :

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping** : l'ID de l'état pour le travail ouvert, par exemple un état Backlog ou To Do.
- **Closed Mapping** : l'ID d'un état de type Done. Lorsqu'une Constatation est supprimée dans DefectDojo, sa Story est déplacée vers cet état.
- **False Positive Mapping** : l'ID de l'état à utiliser pour les Constatations Faux positif.
- **Risk Accepted Mapping** : l'ID de l'état à utiliser pour les Constatations Risque accepté.

## Freshservice

L'intégration Freshservice vous permet de pousser les Constatations et Groupes de constatations DefectDojo sous forme de tickets Freshservice, affectés à un Group d'agents de votre choix.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur votre URL Freshservice : `https://yourcompany.freshservice.com`.
- **API Key** doit être une clé API Freshservice.  Trouvez-la en cliquant sur votre photo de profil (en haut à droite) > **Profile settings** - la clé apparaît à droite, sous la section **Delegate Approvals**, une fois le captcha complété.  Si aucune clé n'y est affichée, l'accès API est peut-être désactivé au niveau du compte et un administrateur doit d'abord l'activer.
- **Requester Email** doit être l'adresse e-mail au nom de laquelle les tickets sont demandés.  Freshservice exige un requester sur chaque ticket ; DefectDojo crée donc les tickets avec cette adresse comme requester.

### Correspondance du suivi des tickets

- **Group ID** doit être l'ID numérique du groupe d'agents Freshservice auquel les tickets seront affectés.  Trouvez-le dans l'URL en consultant le groupe sous **Admin > Agent Groups**.
- **Workspace ID** (facultatif) achemine les tickets vers un espace de travail spécifique sur les comptes multi-espaces.  Laissez-le vide pour utiliser l'espace de travail principal.

### Détails de la correspondance des sévérités

Ceci correspond au champ **Priority** du ticket Freshservice, qui utilise des codes numériques (`1` Low, `2` Medium, `3` High, `4` Urgent).  Les noms de priorité sont également acceptés :

- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `4`

### Détails de la correspondance des statuts

Ceci correspond au champ **Status** du ticket, qui utilise des codes numériques (`2` Open, `3` Pending, `4` Resolved, `5` Closed).  Les noms de statut sont également acceptés :

- **Status Field Name**: `Status`
- **Active Mapping**: `2`
- **Closed Mapping**: `5`
- **False Positive Mapping**: `5`
- **Risk Accepted Mapping**: `3`

Quelques comportements spécifiques à Freshservice à connaître :

- Les mises à jour synchronisent l'intégralité du contenu du ticket - Freshservice permet de modifier l'objet et la description après la création.
- Les tickets sont fermés plutôt que supprimés lorsqu'une Constatation est retirée ; les tickets déjà Resolved ou Closed restent inchangés.  Une note de résolution est jointe automatiquement à la fermeture, de sorte que les comptes qui en exigent une (une règle métier courante) acceptent la fermeture.
- Certains comptes calculent la priorité d'un ticket à partir d'une matrice Impact/Urgency ou d'une règle métier, et ignorent la priorité envoyée à la création.  DefectDojo détecte ce cas et réapplique la priorité mappée via une mise à jour de suivi, de sorte que la correspondance finit tout de même par s'appliquer.

## ServiceDesk Plus

L'intégration ManageEngine ServiceDesk Plus vous permet de pousser les Constatations et Groupes de constatations DefectDojo sous forme de requests ServiceDesk Plus, affectées à un Group de support de votre choix.  Les éditions **cloud** (ServiceDesk Plus OnDemand) et **on-premises** sont toutes deux prises en charge par la même intégration - les identifiants que vous fournissez déterminent le mode utilisé.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur votre URL ServiceDesk Plus : `https://sdpondemand.manageengine.com` pour l'édition cloud (ou son équivalent régional), ou l'adresse de votre serveur pour les installations on-premises.

Fournissez ensuite **un seul** des deux jeux d'identifiants :

#### On-premises : Technician Key

- **Technician Key** doit être une clé API générée pour un technicien sur votre serveur, sous **Admin > General Settings > API**.  Laissez vides les champs Zoho OAuth.

#### Cloud : Zoho OAuth

L'édition cloud s'authentifie via Zoho Accounts OAuth :

1. Ouvrez la [Zoho API Console](https://api-console.zoho.com/) et créez un **Self Client**.
2. Notez le **Client ID** et le **Client Secret**.
3. Dans l'onglet « Generate Code » du Self Client, saisissez le scope `SDPOnDemand.requests.ALL`, choisissez une durée, puis générez le code.
4. Échangez le code contre un jeton d'actualisation :

```
curl --request POST \
 --url 'https://accounts.zoho.com/oauth/v2/token' \
 --data 'grant_type=authorization_code' \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'code={{GENERATED_CODE}}'
```

5. Saisissez le **Client ID**, le **Client Secret** et le **Refresh Token** renvoyé dans le formulaire de l'instance.  Si votre compte est hébergé en dehors du centre de données US, définissez **Token URL** sur le point de terminaison Zoho Accounts régional (par exemple `https://accounts.zoho.eu/oauth/v2/token`).

### Correspondance du suivi des tickets

- **Group Name** doit être le nom du groupe de support ServiceDesk Plus auquel les requests seront affectées, exactement comme il apparaît sous **Admin > Users > Support Groups**.

### Détails de la correspondance des sévérités

Ceci correspond, par nom, au champ **Priority** de la request ServiceDesk Plus, en utilisant les noms de priorité de votre compte :

- **Severity Field Name**: `Priority`
- **Info Mapping**: `Low`
- **Low Mapping**: `Normal`
- **Medium Mapping**: `Medium`
- **High Mapping**: `High`
- **Critical Mapping**: `High`

### Détails de la correspondance des statuts

Ceci correspond, par nom, au champ **Status** de la request.  Les valeurs par défaut utilisent les statuts intégrés :

- **Status Field Name**: `Status`
- **Active Mapping**: `Open`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Closed`
- **Risk Accepted Mapping**: `On Hold`

Quelques comportements spécifiques à ServiceDesk Plus à connaître :

- Les mises à jour synchronisent l'intégralité du contenu de la request - contrairement à la plupart des outils de suivi, ServiceDesk Plus permet de modifier l'objet et la description après la création.
- Les requests sont fermées plutôt que supprimées lorsqu'une Constatation est retirée ; les requests déjà Closed ou Resolved restent inchangées.
- Si votre compte rend certains champs obligatoires à la clôture (par exemple une résolution), une fermeture envoyée depuis DefectDojo peut être rejetée par ces règles et apparaîtra dans la table Integration errors.

## Zendesk

L'intégration Zendesk vous permet de pousser les Constatations et Groupes de constatations DefectDojo sous forme de tickets Zendesk, affectés à un Group Zendesk de votre choix.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre compte Zendesk, par exemple `https://your-subdomain.zendesk.com`.
- **Email** doit être l'adresse e-mail de l'agent Zendesk auquel appartient le jeton API.
- **API Token** doit être un jeton API Zendesk.  Un administrateur peut en créer un dans le Zendesk Admin Center sous **Apps and integrations > APIs > Zendesk API** (l'accès par jeton doit être activé).

### Correspondance du suivi des tickets

- **Group ID** doit être l'ID numérique du Group Zendesk auquel les tickets seront affectés.  Vous pouvez le trouver dans l'Admin Center sous **People > Team > Groups**, ou dans l'URL en consultant le groupe.

### Détails de la correspondance des sévérités

Ceci correspond au champ **Priority** du ticket Zendesk, qui accepte `low`, `normal`, `high` et `urgent` :

- **Severity Field Name**: `Priority`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `normal`
- **High Mapping**: `high`
- **Critical Mapping**: `urgent`

### Détails de la correspondance des statuts

Les tickets Zendesk prennent en charge les statuts `new`, `open`, `pending`, `hold`, `solved` et `closed`.  Notez que `hold` doit être activé sur votre compte avant de pouvoir être utilisé.

- **Status Field Name**: `Status`
- **Active Mapping**: `new`
- **Closed Mapping**: `solved`
- **False Positive Mapping**: `solved`
- **Risk Accepted Mapping**: `pending`

Quelques comportements spécifiques à Zendesk à connaître :

- La description du ticket est le premier commentaire dans Zendesk et ne peut pas être modifiée après la création ; l'envoi d'une Constatation mise à jour synchronisera donc l'objet, la priorité et le statut du ticket, mais pas les modifications de la description.
- Les tickets sont marqués `solved` plutôt que supprimés lorsqu'une Constatation est retirée ; Zendesk ferme automatiquement les tickets solved au bout d'un certain temps.
- `closed` est un statut final - les tickets closed ne peuvent plus du tout être mis à jour, et l'envoi d'une Constatation dont le ticket est fermé génèrera une erreur.
