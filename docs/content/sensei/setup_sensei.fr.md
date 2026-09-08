---
title: Configurer Sensei
description: Connectez GitHub, GitLab, Bitbucket ou Azure DevOps, puis intégrez un
  dépôt pour l'analyse hébergée
draft: false
audience: pro
weight: 2
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note : Sensei est une fonctionnalité réservée à DefectDojo Pro et se trouve actuellement en BÊTA.</span>

Configurer Sensei comporte deux parties : **connecter un fournisseur de contrôle de code source**, puis **intégrer les dépôts** que vous souhaitez analyser. Vous devez disposer d'un rôle global **Mainteneur** ou **Propriétaire** pour cela. Sensei prend en charge :

- **GitHub** : une GitHub App (github.com ou **GitHub Enterprise Server**).
- **GitLab** : un jeton d'accès (gitlab.com ou auto-hébergé).
- **Bitbucket** : Cloud ou Server/Data Center, via OAuth (recommandé), un jeton d'API Atlassian, ou un jeton d'accès.
- **Azure DevOps** : un Personal Access Token.

L'intégration, la configuration, l'analyse et la correction sont identiques pour chaque fournisseur ; seule la connexion initiale diffère. Cette page couvre [la connexion d'une GitHub App](#connect-a-github-app), [GitHub Enterprise Server](#connect-github-enterprise-server), [GitLab](#connect-gitlab), [Bitbucket](#connect-bitbucket) et [Azure DevOps](#connect-azure-devops) ; l'étape [Sélectionner les dépôts](#select-repositories) et les suivantes sont communes.

**Add Repositories** sur le hub Sensei est le point d'entrée pour les deux. Cela ouvre un menu listant chaque connexion par son nom : choisissez-en une pour sélectionner des dépôts à partir de celle-ci, ou choisissez **Connect a new source** pour configurer un fournisseur que vous n'avez pas encore connecté. S'il n'y a aucune connexion, cela va directement au flux de connexion.

![Le menu Add Repositories](images/add_repositories_menu.png)

## Connexions

Une **connexion** est une identité de contrôle de code source configurée : un enregistrement de GitHub App, un jeton GitLab, un workspace Bitbucket, ou une organisation Azure DevOps. Vous intégrez des dépôts à partir d'une connexion, et vous la gérez ou la déconnectez, depuis la page **Connections** (le bouton **Connections** sur le hub Sensei).

![Connexions Sensei](images/connections.png)

Le tableau liste le libellé, l'identité, le nombre de dépôts intégrés, la date de création et le fournisseur de chaque connexion. Utilisez les actions de ligne (le menu à gauche de chaque ligne) pour gérer la connexion sur son fournisseur, ajouter des dépôts depuis cette connexion, l'ouvrir pour modification (**Update credentials**, ou **Manage App & installations** pour GitHub), ou la déconnecter.

![Actions de ligne de connexion](images/connection_row_menu.png) **Add a connection** n'affiche jamais les détails d'une connexion existante. Tout ce qui concerne une connexion que vous avez déjà se trouve sur son propre écran, accessible depuis sa ligne.

### Plusieurs organisations par fournisseur

Une instance peut contenir **autant de connexions que nécessaire, pour chaque fournisseur**, une par organisation, groupe ou workspace :

- **GitHub :** installez l'App sur chaque organisation ou compte utilisateur (**Install on another account**). Un seul enregistrement d'App les couvre tous. Pour conserver des enregistrements séparés, par exemple un hôte GitHub Enterprise Server en plus de github.com, utilisez **Register another GitHub App**. L'état propre d'une App (ses installations, les approbations de permissions, **Install on another account**, et **Disconnect this App**) se trouve sur l'écran de cette connexion, ouvert avec **Manage App & installations** sur sa ligne. Avec plusieurs enregistrements, un sélecteur y permet de basculer entre eux.
- **GitLab :** une connexion par jeton de groupe ou de projet, y compris plusieurs sur le même hôte (`gitlab.com` en plus d'une instance auto-hébergée).
- **Bitbucket :** une connexion par workspace.
- **Azure DevOps :** une connexion par organisation, car un PAT est propre à une organisation.

Chaque passage par **Connect** sur la page Connections **ajoute** une connexion, donc connecter un deuxième groupe ou workspace ne remplace jamais le premier. Donnez à chacune un **Connection Label** pour les distinguer dans le tableau. Chaque dépôt enregistre la connexion via laquelle il a été intégré, et ses analyses, pull requests et corrections utilisent l'identifiant de cette connexion. Lorsqu'il existe plusieurs connexions pour un fournisseur, l'intégration vous demande laquelle utiliser au lieu de choisir à votre place.

Pour renouveler un jeton, un PAT ou un mot de passe d'application, utilisez **Update credentials** sur la ligne de cette connexion. L'écran qui s'ouvre concerne une seule connexion : il est intitulé **Edit connection: \<label\>** et l'enregistrement met à jour cette connexion au lieu d'en ajouter une autre. Y accéder depuis **Connect** l'intitule à la place **Add a connection**. (Les identifiants de GitHub App sont gérés sur GitHub.)

L'**URL de webhook d'un fournisseur est partagée par toutes ses connexions**, et chaque connexion vérifie son propre secret, vous n'avez donc pas besoin d'une URL différente par groupe, workspace ou organisation.

> **⚠️ La déconnexion est destructrice :** déconnecter une connexion la supprime **ainsi que tous les dépôts intégrés via elle**. Cette action est irréversible.

## Choisir un fournisseur de contrôle de code source

Depuis le hub Sensei, choisissez **Add Repositories → Connect a new source** (ou **Connect** sur la page Connections) pour ouvrir **Add a connection**, puis choisissez votre fournisseur de contrôle de code source : **GitHub** (y compris GitHub Enterprise Server), **GitLab**, **Bitbucket**, ou **Azure DevOps**. Le flux de connexion de chaque fournisseur est décrit ci-dessous.

![Add a connection, avec le fournisseur de contrôle de code source choisi ici](images/setup_providers.png)

## Connecter une GitHub App

Sensei fonctionne entièrement via une GitHub App. Installez-la sur votre organisation/compte et DefectDojo utilise des jetons de courte durée pour ouvrir des PR, analyser et appliquer des corrections. Rien à coller, rien à renouveler.

Depuis le hub Sensei, choisissez **Add Repositories → Connect a new source** (ou **Connect** sur la page Connections) pour ouvrir **Add a connection**.

### Étape 1 : créer l'App

Saisissez l'**organisation** propriétaire des dépôts que vous souhaitez analyser (laissez vide pour créer l'App sur votre compte personnel), puis cliquez sur **Create GitHub App**. GitHub pré-remplit le nom de l'app, les URL et les permissions ; vérifiez-les et confirmez.

![Créer la GitHub App](images/setup_create_app.png)

GitHub ouvre une page de confirmation. Cliquez sur **Create GitHub App for `<org>`** pour enregistrer l'app sous cette organisation.

![Confirmer la création de l'app sur GitHub](images/github_create_app.png)

> **🔑 Astuce :** créez l'App sur la même organisation qui possède les dépôts que vous prévoyez d'analyser. Le propriétaire de l'App est défini à la création.

### Étape 2 : installer l'App

De retour dans DefectDojo, l'app apparaît comme *configured*. Cliquez sur **Install on GitHub** pour l'installer sur votre organisation.

![L'écran propre à la connexion, où l'App est installée et gérée](images/setup_install_app.png)

Sur GitHub, confirmez l'emplacement d'installation (votre organisation), choisissez **All repositories** ou **Only select repositories**, et passez en revue les permissions demandées. Sensei a besoin d'un accès en lecture aux actions, aux issues et aux métadonnées, et d'un accès en lecture/écriture aux checks, au code, aux pull requests, aux secrets et aux workflows, afin de pouvoir analyser et ouvrir des PR de correction. Cliquez sur **Install**.

![Installer l'App sur votre organisation](images/github_install_app.png)

## Connecter GitLab

Sensei prend également en charge **GitLab**, aussi bien **gitlab.com** que les instances **auto-hébergées**. Au lieu d'une GitHub App, GitLab se connecte avec un **jeton d'accès de projet ou de groupe** plus un webhook ; Sensei utilise ce jeton pour analyser, ouvrir des merge requests et appliquer des corrections.

Depuis le hub Sensei, choisissez **Add Repositories → Connect a new source** (ou **Connect** sur la page Connections) pour ouvrir **Add a connection**, puis sélectionnez **GitLab** comme fournisseur de contrôle de code source.

### Étape 1 : créer un jeton d'accès

Dans GitLab, ouvrez le projet (ou le groupe) que vous souhaitez analyser et allez dans **Settings → Access tokens → Add new token** :

- **Role :** **Developer**, suffisant pour pousser des branches de correction et ouvrir des merge requests. Choisissez **Maintainer** si les règles de push du projet l'exigent.
- **Scopes :** **`api`** et **`write_repository`**.

Créez le jeton et copiez la valeur générée `glpat-…` (GitLab ne l'affiche qu'une seule fois).

> **🔑 Astuce :** un jeton d'accès de **groupe** intègre n'importe quel projet de ce groupe ; un jeton d'accès de **projet** est limité à ce seul projet.

### Étape 2 : se connecter

De retour dans **Add a connection** avec **GitLab** sélectionné, renseignez :

- **GitLab Base URL :** `https://gitlab.com`, ou l'URL de votre instance auto-hébergée (par exemple `https://gitlab.example.com`).
- **Access Token :** le jeton `glpat-…` de l'étape 1.
- **Webhook Secret :** laissez vide pour une génération automatique (recommandé). Vous ajouterez ce secret au webhook à l'étape suivante.

Cliquez sur **Add GitLab connection**. DefectDojo valide le jeton, le stocke chiffré, et peut ensuite lister les projets, ouvrir des merge requests et lancer des analyses.

### Étape 3 : ajouter le webhook

Pour que DefectDojo reçoive les événements de push, de merge request et de commentaire, ajoutez un webhook à **chaque** projet GitLab que vous prévoyez d'intégrer (**Settings → Webhooks → Add new webhook**) :

- **URL :** l'URL de webhook affichée sur l'écran de connexion (`https://<your-defectdojo-host>/sensei/gitlab/webhooks`).
- **Secret token :** le secret de webhook de l'étape 2.
- **Trigger events :** activez **Push events**, **Merge request events**, et **Comments**.

Laissez la vérification SSL activée, cliquez sur **Add webhook**, puis utilisez **Test → Push events** pour confirmer que DefectDojo répond avec **HTTP 200**.

Une fois la connexion établie, cliquez sur **Choose Projects** et poursuivez avec [Sélectionner les dépôts](#select-repositories) ; l'intégration, la configuration et l'analyse fonctionnent comme pour GitHub.

> **Équivalents GitLab :** là où ce guide dit *pull request*, GitLab utilise une **merge request** ; le **status check** de la pull request est publié comme un **commit status** GitLab sur le commit de tête de la merge request.

## Connecter GitHub Enterprise Server

Sensei fonctionne avec **GitHub Enterprise Server (GHES)** en utilisant le même modèle de GitHub App que sur github.com. Seul l'hôte diffère. Comme le flux de création automatique par manifeste d'App est réservé à github.com, sur GHES vous **créez l'App manuellement** sur votre hôte d'entreprise, puis saisissez ses identifiants ainsi que l'hôte dans DefectDojo.

### Étape 1 : créer l'App sur votre hôte GHES

Sur votre instance GitHub Enterprise Server, allez dans **Settings → Developer settings → GitHub Apps → New GitHub App** et créez une App avec les mêmes permissions que Sensei utilise sur github.com : lecture pour les actions, les issues et les métadonnées, et lecture/écriture pour les checks, le code, les pull requests, les secrets et les workflows. Pointez son webhook vers `https://<your-defectdojo-host>/sensei/webhooks`. Générez et téléchargez une **clé privée**, et notez l'**App ID** (ainsi que le **Client ID/Secret** OAuth si vous les avez définis).

### Étape 2 : se connecter manuellement

Sur l'écran de connexion avec **GitHub** sélectionné, cliquez sur **Set up manually instead** et renseignez :

- **App ID** et **Private Key (PEM)** de l'étape 1 (ainsi que Client ID/Secret et Webhook Secret si configurés).
- **GitHub Enterprise host :** l'hôte de votre instance, par exemple `https://github.example.com`. DefectDojo en déduit l'API (`/api/v3`) et les origines web. Laissez vide pour github.com.

Cliquez sur **Save App credentials**. DefectDojo les valide auprès de votre hôte d'entreprise, puis installez l'App et poursuivez avec [Sélectionner les dépôts](#select-repositories).

> **🔑 Astuce :** l'hôte doit être joignable depuis DefectDojo (et DefectDojo joignable depuis GHES pour les webhooks). Les hôtes internes uniquement conviennent tant que les deux peuvent se joindre sur votre réseau.

## Connecter Bitbucket

Sensei prend en charge **Bitbucket Cloud** (`bitbucket.org`) et **Bitbucket Server / Data Center** (auto-hébergé). Trois méthodes d'authentification non obsolètes sont proposées ; **OAuth est recommandé**.

Depuis le hub Sensei, choisissez **Add Repositories → Connect a new source** (ou **Connect** sur la page Connections), puis sélectionnez **Bitbucket** ainsi que votre **deployment** (Cloud ou Server/Data Center) et votre type d'**authentication**.

### Étape 1 : créer l'identifiant

**OAuth (recommandé) :** dans Bitbucket, ouvrez **Workspace settings → OAuth consumers → Add consumer** :

- **Callback URL :** celle affichée sur l'écran de connexion (`https://<your-defectdojo-host>/sensei/bitbucket/oauth/callback`).
- **Permissions :** **Account: Read**, **Repositories: Read + Write**, **Pull requests: Read + Write** (ajoutez **Webhooks: Read + Write** si vous gérez les webhooks via l'API).

Enregistrez, puis copiez la **Key** (Client ID) et le **Secret** du consumer.

**Jeton d'API** : créez un **jeton d'API** Atlassian sur `id.atlassian.com` (Account settings → Security → API tokens). Utilisez-le avec votre **adresse e-mail de compte Atlassian**.

**Jeton d'accès** : créez un **Access Token** de dépôt ou de workspace dans Bitbucket et utilisez-le comme identifiant bearer.

### Étape 2 : se connecter

De retour sur l'écran de connexion avec **Bitbucket** sélectionné :

- **OAuth :** collez le **Client ID** et le **Client Secret**, puis cliquez sur **Connect with Bitbucket**. Approuvez l'écran de consentement ; DefectDojo stocke les jetons obtenus chiffrés et les renouvelle automatiquement.
- **Jeton d'API / jeton d'accès :** saisissez votre **Workspace** (Cloud), votre **email** (authentification par jeton d'API uniquement), et le **token**. Pour Server/Data Center, saisissez l'**URL de base** de votre hôte.

DefectDojo valide l'identifiant et peut ensuite lister les dépôts, ouvrir des pull requests et lancer des analyses.

### Étape 3 : ajouter le webhook

Ajoutez un webhook à **chaque** dépôt Bitbucket (**Repository settings → Webhooks → Add webhook**) :

- **URL :** l'URL de webhook affichée sur l'écran de connexion (`https://<your-defectdojo-host>/sensei/bitbucket/webhooks`).
- **Secret :** le secret de webhook affiché sur la page (utilisé pour la vérification HMAC-SHA256 `X-Hub-Signature`).
- **Triggers :** **Repository push**, **Pull request** (created, updated, merged, declined), et **Pull request comment created** (pour les commentaires `/fix`).

Une fois la connexion établie, cliquez sur **Choose Repositories** et poursuivez avec [Sélectionner les dépôts](#select-repositories).

> **Spécificités Bitbucket :** les dépôts sont désignés sous la forme `workspace/repo` (Cloud) ou `PROJECTKEY/repo` (Server). Le **status check** de la pull request est publié comme un **build status** Bitbucket sur le commit de tête. OAuth est la méthode recommandée car elle est liée au contexte utilisateur (pas de particularités de workspace/nom d'utilisateur) et se renouvelle automatiquement ; les mots de passe d'application sont obsolètes et ne sont pas pris en charge.

## Connecter Azure DevOps

Sensei prend en charge **Azure DevOps Repos** via un **Personal Access Token (PAT)**. Les dépôts vivent dans une hiérarchie **organisation → projet → dépôt**.

Depuis le hub Sensei, choisissez **Add Repositories → Connect a new source** (ou **Connect** sur la page Connections), puis sélectionnez **Azure DevOps**.

### Étape 1 : créer un PAT

Dans Azure DevOps, ouvrez **User settings → Personal access tokens → New Token** :

- **Organization :** l'organisation dont vous souhaitez analyser les dépôts.
- **Scopes :** **Code (Read, Write, & Manage)**, ce qui couvre le clonage, le push des branches de correction et l'ouverture de pull requests.

Créez le jeton et copiez-le (Azure DevOps ne l'affiche qu'une seule fois).

### Étape 2 : se connecter

De retour sur l'écran de connexion avec **Azure DevOps** sélectionné, renseignez :

- **Base URL :** `https://dev.azure.com`, ou l'URL de collection de votre **Server** Azure DevOps.
- **Organization :** le nom de votre organisation.
- **Personal Access Token :** le jeton de l'étape 1.

Cliquez sur **Connect**. DefectDojo valide le PAT auprès de `…/_apis/projects`, le stocke chiffré, et peut ensuite lister les dépôts, ouvrir des pull requests et lancer des analyses.

### Étape 3 : ajouter le service hook

Azure DevOps authentifie ses **Service Hooks** avec HTTP Basic, et utilise **un abonnement par type d'événement**. Dans **Project settings → Service hooks → Create subscription → Web Hooks**, créez un abonnement pour chacun de **Code pushed**, **Pull request created**, **Pull request updated**, et **Pull request merged**, tous avec :

- **URL :** l'URL de webhook affichée sur l'écran de connexion (`https://<your-defectdojo-host>/sensei/azure/webhooks`).
- **Basic authentication username / password :** les valeurs affichées sur la page.

Une fois la connexion établie, cliquez sur **Choose Repositories** et poursuivez avec [Sélectionner les dépôts](#select-repositories).

> **Spécificités Azure DevOps :** les dépôts sont désignés sous la forme `project/repo` (l'organisation est stockée sur la connexion). Le **status check** de la pull request est publié comme un **commit status** Git sur le commit de tête.

## Sélectionner les dépôts

Une fois l'App installée, DefectDojo affiche les dépôts auxquels il peut accéder. Seuls les dépôts pour lesquels Sensei dispose d'un **accès en push** sont listés ; la remédiation fonctionne en poussant une branche et en ouvrant une pull request, donc les dépôts sans accès en push sont masqués. Une pull request est ouverte contre la **branche par défaut** de chaque dépôt.

![Sélectionner les dépôts à intégrer](images/setup_repo_picker.png)

Utilisez **Add** pour sélectionner un ou plusieurs dépôts, puis cliquez sur **Configure N repo(s)**. Les dépôts déjà intégrés sont marqués **Configured** et ne peuvent pas être ajoutés deux fois.

### Un dépôt n'apparaît pas dans la liste

Le sélecteur n'affiche que les dépôts auxquels la connexion a été autorisée. Un dépôt auquel vous n'avez jamais donné accès à Sensei n'apparaîtra pas. Si la connexion ne couvre qu'un seul dépôt déjà intégré, la liste semble vide. Élargissez ce que la connexion peut voir, puis revenez à cette étape :

- **GitHub :** utilisez **Manage repository access for \<account\>** pour ouvrir la page de cette installation sur GitHub, où vous pouvez ajouter des dépôts à l'installation. Utilisez **Install on another account** pour installer l'App sur une deuxième organisation ou un deuxième compte utilisateur.
- **GitLab, Bitbucket, Azure DevOps :** la liste est limitée par l'identifiant que vous avez connecté. Accordez au jeton, au mot de passe d'application ou au PAT l'accès au projet (un jeton de **groupe** GitLab couvre tous les projets du groupe), ou ajoutez une deuxième connexion pour un autre groupe, workspace ou organisation.

## Configurer un dépôt

Le formulaire **Configure Repository** contrôle la façon dont Sensei analyse le dépôt et en rend compte.

![Configurer un dépôt](images/repo_config.png)

- **Scanning Mode (DefectDojo-hosted) :** les analyses s'exécutent dans DefectDojo. Rien n'est ajouté à votre dépôt ; déclenchez les analyses à la demande ou automatiquement via la GitHub App.
- **PR Reporting :** choisissez ce que Sensei publie sur les pull requests :
  - Publier un status check sur la pull request.
  - Faire échouer le check lorsque de nouvelles constatations nettes sont introduites.
  - Publier un commentaire récapitulatif des résultats sur chaque commit.
  - Créer automatiquement la référence (baseline) de la branche de base lors de la première PR.
- **Automated Fixes :** activez *Stage matching findings for one-click auto-fix after each scan* pour que Sensei mette automatiquement des candidats en attente (voir ci-dessous).

### Critères de correction automatisée

Lorsque les corrections automatisées sont activées, les constatations répondant à vos critères sont mises en attente en tant que **candidats** sur la page Sensei après chaque analyse. Rien ne s'exécute (et aucun coût de LLM n'est engagé) tant que vous n'approuvez pas, sauf si vous activez la remédiation automatique.

![Critères de correction automatisée et options avancées](images/repo_config_advanced.png)

- **Severity threshold :** les constatations à ce niveau de sévérité ou au-dessus sont éligibles (choisissez *Any* pour ne filtrer que sur le risque).
- **Risk threshold :** les constatations à ce niveau de risque ou au-dessus sont également éligibles (combiné à la sévérité avec un OU).
- **Open fix PRs against branch :** la branche ciblée par les pull requests de correction automatique ; modifiable pour chaque correction lorsque vous approuvez individuellement.
- **Exclude findings tagged :** ignorer les constatations portant les étiquettes que vous listez (par exemple `no-fix`).
- **Automatically remediate candidates :** lorsque cette option est activée, une vérification en arrière-plan (environ toutes les 5 minutes) ouvre des pull requests de correction pour les candidats en attente de ce dépôt sans attendre d'approbation, jusqu'à ce que votre quota de corrections soit atteint. Laissez désactivé pour examiner et approuver chaque candidat vous-même.

Sous **Advanced options**, vous pouvez lier le dépôt à un produit/asset existant ou en créer un nouveau, définir l'organisation, et définir une sévérité minimale en dessous de laquelle les constatations ne sont ni signalées ni utilisées dans la porte de fusion (merge gate).

## Intégrer

Cliquez sur **Onboard for hosted scanning**. Le dépôt apparaît sur le hub Sensei avec un statut **Active**, prêt à être analysé. À partir de là, poursuivez avec [Corriger les constatations avec Sensei](/sensei/fixing_findings/).
