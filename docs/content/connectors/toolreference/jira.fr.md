---
title: "Jira"
description: "Comment configurer le Connecteur Downstream Jira pour DefectDojo"
weight: 82
audience: pro
---
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
