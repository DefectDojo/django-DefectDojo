---
title: Référence Sensei
description: Statuts, actions de ligne, quotas et dépannage
draft: false
audience: pro
weight: 5
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Sensei est une fonctionnalité réservée à DefectDojo Pro et est actuellement en BÊTA.</span>

Une référence rapide des statuts, actions et limites que vous rencontrerez en utilisant Sensei.

## Statuts des dépôts

Le statut affiché pour un dépôt intégré sur le hub Sensei :

| Status | Meaning |
|--------|---------|
| **Active** | Intégré et prêt à être analysé. |
| **Pull Request Open** | Sensei a une pull request ouverte sur le dépôt. |
| **Pull Request Closed** | Une pull request Sensei a été fermée. |
| **Error** | La dernière opération a échoué : consultez Scan Activity pour en connaître la cause. |
| **Not Configured** | Le dépôt est connecté mais pas encore configuré. |

## Statuts des candidats et des corrections

Les candidats de correction automatique et les enregistrements de correction passent par ces états :

| Status | Meaning |
|--------|---------|
| **Candidate** | Mis en attente par les critères de correction automatique d'une analyse. Rien ne s'exécute tant que vous n'approuvez pas. |
| **In Progress** | Approuvé : Sensei génère la correction et va ouvrir une pull request. |
| **PR Open** | Une pull request de correction est ouverte ; le badge y renvoie. |
| **Failed** | La correction n'a pas pu être terminée ; elle reste listée pour ne pas disparaître silencieusement. |

## Actions de ligne des dépôts

Chaque dépôt intégré dispose d'un menu d'actions de ligne sur le hub Sensei :

![Actions de ligne du dépôt](images/repo_row_menu.png)

- **Scan now :** démarrer une analyse à la demande (ouvre le sélecteur de branche).
- **Scan history :** consulter les analyses passées de ce dépôt.
- **Configure :** rouvrir le formulaire de configuration (signalement des PR, corrections automatisées, association au produit).
- **Re-stage candidates :** réévaluer les constatations du dépôt par rapport aux critères de correction automatique et mettre en attente de nouveaux candidats.
- **Delete :** retirer le dépôt de Sensei. Cela arrête son analyse ; cela ne supprime pas l'actif ou les constatations sous-jacents.

## Quotas et mesure d'utilisation

Sensei est mesuré par rapport à votre licence DefectDojo Pro, sous forme de compteurs en haut du hub :

- **Fixes :** corrections appliquées par rapport à votre limite prépayée. Approuver un candidat ou déclencher une correction consomme ce quota ; une fois épuisé, les corrections suivantes sont bloquées (une bannière d'avertissement apparaît) jusqu'à ce que la limite soit relevée.
- **Onboarded Repositories :** dépôts intégrés par rapport à votre limite de dépôts. Une fois atteinte, l'intégration de nouveaux dépôts est bloquée.

Pour relever une limite, contactez votre équipe de compte DefectDojo.

## Spécificités GitLab

GitLab est pris en charge aux côtés de GitHub (gitlab.com et instances auto-hébergées). Le comportement de scan-and-fix est identique ; voici les détails spécifiques à GitLab :

- **Connexion :** un **jeton d'accès de projet ou de groupe** (rôle **Developer**, ou **Maintainer** si les règles de push l'exigent) avec les scopes **`api`** et **`write_repository`**, et non une GitHub App. Voir [Configurer Sensei](/sensei/setup_sensei/#connect-gitlab).
- **Webhook :** chaque projet intégré nécessite un webhook vers `…/sensei/gitlab/webhooks` (avec le secret de la connexion) abonné aux événements **Push**, **Merge request** et **Comment**. L'ajout d'un webhook nécessite le rôle **Maintainer**/**Owner** sur le projet.
- **Merge requests, pas des pull requests :** les corrections ouvrent une **merge request** sur la branche par défaut ; le commentaire `/fix` fonctionne sur les notes de merge request.
- **Contrôle par commit status :** le contrôle de statut de la PR est un **commit status** GitLab sur le commit de tête de la merge request : `running` pendant l'analyse, puis `success` ou `failed` (fail-on-new). GitLab n'a pas d'état *neutre*, donc une analyse **non bloquante** qui comporte tout de même des constatations affiche un statut **vert** ; la note de synthèse contient le détail des constatations.
- **Auto-hébergé :** pointez la **GitLab Base URL** vers votre instance ; DefectDojo clone et appelle l'API sur cet hôte.

## Spécificités Bitbucket

Bitbucket **Cloud** et **Server/Data Center** sont pris en charge. Le comportement de scan-and-fix est identique ; voici les détails spécifiques à Bitbucket :

- **Connexion :** **OAuth** (recommandé), un **jeton API** Atlassian (utilisé avec l'e-mail de votre compte), ou un **jeton d'accès** de dépôt/workspace. Voir [Configurer Sensei](/sensei/setup_sensei/#connect-bitbucket). Les mots de passe d'application sont obsolètes et ne sont pas pris en charge.
- **Portée par workspace (Cloud) :** les jetons API/d'accès sont liés à un workspace, donc un **workspace** est requis pour Cloud ; OAuth fonctionne dans le contexte utilisateur et découvre automatiquement les workspaces accessibles.
- **Webhook :** chaque dépôt intégré nécessite un webhook vers `…/sensei/bitbucket/webhooks` (avec le secret de la connexion, vérifié via HMAC-SHA256 `X-Hub-Signature`) abonné aux événements **Push**, **Pull request** (created/updated/merged/declined) et **Pull request comment**.
- **Contrôle par build status :** le contrôle de statut de la PR est publié comme un **build status** Bitbucket sur le commit de tête (`INPROGRESS` → `SUCCESSFUL`/`FAILED`). Bitbucket n'a pas d'état *neutre*, donc une analyse non bloquante correspond à `SUCCESSFUL` et le commentaire de synthèse contient le détail. Le lien du build status doit être une URL publique, il utilise donc votre hôte DefectDojo.
- **Noms de dépôt :** `workspace/repo` (Cloud) ou `PROJECTKEY/repo` (Server/Data Center).
- **Server/Data Center :** définissez la **Base URL** sur votre hôte ; DefectDojo utilise l'API REST v1.0 et les chemins git `/scm/…`.

## Spécificités Azure DevOps

Azure DevOps Repos est pris en charge via un **Personal Access Token**. Le comportement de scan-and-fix est identique ; voici les détails spécifiques à Azure :

- **Connexion :** un **PAT** avec le scope **Code (Read, Write, & Manage)**, plus l'**organisation**. Les applications OAuth Azure DevOps sont en cours de retrait, un PAT est donc l'identifiant recommandé. Voir [Configurer Sensei](/sensei/setup_sensei/#connect-azure-devops).
- **Webhook :** les **Service Hooks** Azure s'authentifient en HTTP **Basic** (pas via HMAC) et utilisent **un abonnement par événement**. Créez des abonnements vers `…/sensei/azure/webhooks` pour **Code pushed** et **Pull request created/updated/merged**, avec le nom d'utilisateur/mot de passe Basic de la connexion.
- **Contrôle par commit status :** le contrôle de statut de la PR est publié comme un **commit status** Git sur le commit de tête.
- **Noms de dépôt :** `project/repo` (l'organisation est stockée sur la connexion).
- **Azure DevOps Server :** définissez la **Base URL** sur l'URL de votre collection sur site.

## Spécificités GitHub Enterprise Server

GitHub Enterprise Server utilise le **même modèle de GitHub App** que github.com ; seul l'hôte diffère :

- **Connexion :** comme le flux de création automatique par manifeste d'App est réservé à github.com, créez l'App **manuellement** sur votre hôte GHES et saisissez ses identifiants ainsi que l'**hôte Enterprise** via **Set up manually**. Voir [Connecter GitHub Enterprise Server](/sensei/setup_sensei/#connect-github-enterprise-server). DefectDojo dérive l'API (`/api/v3`) et les origines web à partir de l'hôte.
- **Coexistence :** une connexion App github.com et une connexion App GHES peuvent être configurées sur la même instance ; chaque dépôt se résout vers la connexion via laquelle il a été intégré.
- **Accessibilité :** DefectDojo doit pouvoir atteindre l'hôte de l'API GHES, et GHES doit pouvoir atteindre le endpoint `…/sensei/webhooks` de DefectDojo (des hôtes internes conviennent si les deux parties peuvent se connecter).

## Dépannage

- **Le bouton Sensei sur une constatation affiche « Configure Product ».** Le produit de la constatation n'est pas intégré. Cliquez dessus pour intégrer un dépôt pour ce produit, puis revenez à la constatation.
- **Une correction affiche « Failed » dans Auto-fix Candidates ou Scan Activity.** Ouvrez **Scan Activity** et consultez **Root Cause** / **Details** pour cette exécution. Les corrections échouées restent listées afin de ne pas disparaître avant d'avoir produit une PR ; vous pouvez les remettre en attente et réessayer.
- **Un dépôt n'apparaît pas lors de l'intégration.** Seuls les dépôts accessibles à la connexion sont affichés. Sur **GitHub**, vérifiez que l'App est installée sur la bonne organisation et que son accès aux dépôts inclut le dépôt en question. Sur **GitLab**, vérifiez que le scope du jeton d'accès couvre le projet. Sur **Bitbucket Cloud**, vérifiez que le **workspace** est défini (les jetons sont limités à un workspace). Sur **Azure DevOps**, vérifiez que l'organisation du PAT correspond et que son scope **Code** est accordé.
- **Les analyses ou corrections ne démarrent jamais après un webhook.** Vérifiez que le webhook du dépôt pointe vers le récepteur du fournisseur (`…/sensei/{gitlab,bitbucket,azure}/webhooks`, ou `…/sensei/webhooks` pour GitHub) avec le bon secret/identifiants, et qu'il est abonné aux événements push + pull-request (+ comment). Les **livraisons récentes** du fournisseur doivent afficher `HTTP 200`. Les exécutions déclenchées par webhook ne se produisent que pour les dépôts intégrés en mode **hébergé** ; un push sur une branche non par défaut est analysé via sa pull request, pas seul.
- **Rien ne se passe après une analyse.** Vérifiez que les corrections automatisées sont activées (et que vos seuils de sévérité/risque correspondent aux constatations) dans la configuration du dépôt, et que votre quota **Fixes** n'est pas épuisé.

> **🔎 Toujours en BÊTA :** Sensei évolue rapidement. Si le comportement ne correspond pas à ce guide, consultez le [journal des modifications Pro](/releases/pro/changelog/) pour les changements récents.
