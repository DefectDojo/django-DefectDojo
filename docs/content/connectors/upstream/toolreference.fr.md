---
title: Référence des outils pour les Connecteurs Upstream
description: Notre liste des outils de Connecteur pris en charge, et comment les configurer
  avec DefectDojo
aliases:
- /fr/import_data/pro/connectors/connectors_tool_reference/
- /fr/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les Connecteurs Upstream sont une fonctionnalité réservée à DefectDojo Pro.</span>

Lors de la configuration d'un Connecteur pour un outil pris en charge, vous devez fournir à DefectDojo des informations spécifiques liées à l'API de l'outil. Au minimum, vous aurez besoin des éléments suivants :

* **Location** \- un champ qui fait généralement référence à l'URL de votre outil sur votre réseau,
* **Secret** \- généralement une clé API.

De nombreux outils exposent un seul hôte d'API fixe. Pour ceux\-là, DefectDojo remplit le champ **Location** lorsque vous ajoutez le connecteur, vous n'avez donc pas à copier l'URL depuis cette page. Conservez la valeur proposée. Ne la modifiez que si votre instance utilise un autre hôte, par exemple une installation auto\-hébergée ou une autre région.

Certains outils nécessiteront des champs supplémentaires liés à l'API, en plus de **Location** et **Secret**. Ils peuvent également nécessiter que vous effectuiez des modifications de leur côté pour prendre en charge un Connecteur entrant depuis DefectDojo.

![image](images/connectors_tool_reference.png)

Chaque outil possède une configuration d'API différente, et ce guide a pour but de vous aider à configurer l'API de l'outil afin que DefectDojo puisse s'y connecter.

Dans la mesure du possible, nous vous recommandons de créer un nouveau compte « DefectDojo Bot » au sein de votre outil de sécurité, qui sera utilisé exclusivement par le Connecteur. Cela vous aidera à mieux distinguer les actions effectuées manuellement par votre équipe des actions automatisées effectuées par le Connecteur.

# **Connecteurs d'actifs**

La plupart des Connecteurs importent des **constatations** depuis un outil de sécurité. Les **Connecteurs d'actifs** fonctionnent différemment : ils importent plutôt votre **inventaire d'actifs**. Un Connecteur d'actifs énumère les actifs qui existent sur une plateforme externe (par exemple, les dépôts d'un groupe GitLab) et crée et maintient automatiquement les **Produits** (Actifs) et **Types de produit** (Organisations) correspondants dans DefectDojo. Aucune constatation n'est importée par un Connecteur d'actifs.

* **Discover** et **Sync** réconcilient tous deux la liste des actifs. Les nouveaux actifs apparaissent comme des Enregistrements `NEW` ; une fois mappés (automatiquement, si le mappage automatique est activé), DefectDojo crée le Produit et le regroupe sous un Type de produit dérivé de l'outil — par exemple, l'espace de noms GitLab ou le projet Azure DevOps.
* Si un actif est ensuite supprimé en amont (par exemple, un dépôt est supprimé), son Enregistrement mappé est marqué `MISSING` lors de la prochaine synchronisation via **Sync**, afin que votre équipe puisse le trier. DefectDojo ne supprime jamais silencieusement un Produit.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets et ServiceNow CMDB sont des Connecteurs d'actifs. runZero est principalement un Connecteur d'actifs, mais peut également importer des vulnérabilités sous forme de constatations. Tous les autres Connecteurs listés ci-dessous importent des constatations.

# **Connecteurs pris en charge**

## **Acunetix 360**

Le connecteur Acunetix 360 importe des **constatations de vulnérabilités DAST** depuis la plateforme cloud Acunetix 360 (la plateforme Invicti). DefectDojo découvre les sites web analysés de votre compte et crée un Enregistrement pour chaque **site web** ; les constatations d'un site web proviennent de son dernier scan terminé.

**Veuillez noter :** ce connecteur est destiné à **Acunetix 360** (le produit cloud à l'adresse `online.acunetix360.com`). Il ne concerne pas le scanner Acunetix Standard/Premium sur site, qui dispose d'une API différente.

#### Prérequis

Un compte Acunetix 360 et des **identifiants API** : dans Acunetix 360, ouvrez le menu de votre compte \> **API Settings**, notez l'**API User ID** et générez un **API Token**. Le connecteur s'authentifie avec ces identifiants au format HTTP Basic ; un compte de service dédié est donc recommandé pour distinguer l'activité automatisée des actions manuelles de l'équipe.

#### Mappages du Connecteur

1. Saisissez l'URL de votre Acunetix 360 dans le champ **Location** : `https://online.acunetix360.com`.
2. Saisissez l'API User ID dans le champ **API User ID**.
3. Saisissez l'API Token dans le champ **API Token**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque site web analysé devient un Enregistrement. Les constatations proviennent du dernier scan terminé du site web ; les vulnérabilités qu'Acunetix 360 a marquées **Accepted Risk** ou **False Positive** sont tout de même importées, mais signalées comme inactives (risque accepté ou faux positif) afin que le produit DefectDojo reflète le triage effectué par l'éditeur.

## **Akamai API Security**

Le connecteur Akamai API Security utilise une clé API pour récupérer les constatations de sécurité depuis l'API Akamai. DefectDojo découvre votre environnement Akamai et crée des Enregistrements distincts pour chaque **Application** et **Host** configurés dans votre compte.

#### Prérequis

Vous aurez besoin d'une clé API ayant accès à l'API Akamai. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de bien distinguer l'activité automatisée des actions manuelles de l'équipe.

#### Mappages du Connecteur

1. Saisissez l'URL de base de votre API Akamai dans le champ **Location**. Cette URL est spécifique à votre instance Akamai : par exemple
2. Saisissez une **API Key** valide dans le champ **Secret**.

DefectDojo mappe les **Applications** et les **Hosts** sous forme d'Enregistrements distincts. Chaque Application apparaîtra sous la forme `{name} (application)` et chaque Host sous la forme `{name} (host)` dans votre liste d'Enregistrements.

## **Anchore**

Le connecteur Anchore utilise le jeton API d'un utilisateur pour récupérer des données depuis Anchore Enterprise.  Les Produits sont mappés et découverts à partir des « Applications », qui sont composées de plusieurs Images dans Anchore - voir la [documentation Anchore Enterprise](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) pour plus d'informations.

#### Mappages du Connecteur

1. L'URL d'Anchore dans le champ **Location** : il s'agit de l'URL à laquelle vous accédez à Anchore.
2. Saisissez une clé API valide dans le champ Secret. Il s'agit de la clé API associée à votre compte de service Burp.

Consultez la [documentation officielle d'Anchore](https://docs.anchore.com/current/docs/) pour plus d'informations sur la création d'un jeton pour Anchore.

## **AWS Security Hub**

Le connecteur AWS Security Hub utilise une clé d'accès AWS pour interagir avec les API de Security Hub.

#### Prérequis

Plutôt que d'utiliser la clé d'accès AWS d'un membre de l'équipe, nous recommandons de créer un utilisateur IAM dans votre compte AWS spécifiquement pour DefectDojo, avec des permissions limitées à celles nécessaires pour interagir avec Security Hub.

La politique AWS « **[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**policy » fournit le niveau d'accès requis pour un connecteur. Si vous souhaitez rédiger une politique personnalisée pour un Connecteur, vous devrez inclure les permissions suivantes :

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Un exemple de politique fonctionnelle pourrait ressembler à ceci :

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Veuillez noter :** nous pourrions avoir besoin d'utiliser des actions API supplémentaires à l'avenir afin d'offrir la meilleure expérience possible, ce qui nécessitera des mises à jour de cette politique.

Une fois que vous avez créé votre utilisateur IAM et lui avez attribué les permissions nécessaires à l'aide d'une politique/d'un rôle approprié, vous devrez générer une clé d'accès, que vous pourrez ensuite utiliser pour créer un Connecteur.

#### Mappages du Connecteur

1. Saisissez le [point de terminaison de l'API AWS correspondant à votre région](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) dans le champ **Location**\ :  par exemple, pour récupérer les résultats de la région `us-east-1`, vous fourniriez

`https://securityhub.us-east-1.amazonaws.com`
2. Saisissez une **AWS Access Key** valide dans le champ **Access Key**.
3. Saisissez la **Secret Key** correspondante dans le champ **Secret Key**.

DefectDojo peut récupérer des constatations depuis plusieurs régions grâce à la fonctionnalité d'**agrégation inter-régions** de Security Hub. Si l'[agrégation inter-régions](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) est activée, vous devez fournir le point de terminaison de l'API pour votre « **Aggregation Region** ». Pour les régions liées supplémentaires, des Enregistrements de Produit seront créés dans DefectDojo à partir de l'ID de votre compte AWS et du nom de la région.

## **Azure DevOps**

Le connecteur Azure DevOps est un **Connecteur d'actifs** : il énumère les dépôts git de chaque projet de votre organisation Azure DevOps et crée un Actif DefectDojo pour chaque dépôt, regroupé en Organisations par projet Azure DevOps. Aucune constatation n'est importée.

#### Prérequis

Vous aurez besoin d'un jeton d'accès personnel (PAT) pour l'organisation. Nous recommandons de générer ce jeton depuis un compte de service dédié. Seuls des scopes en lecture sont nécessaires :

1. Dans Azure DevOps, ouvrez **User settings \> Personal access tokens \> New Token**.
2. Cliquez sur **Show all scopes**, puis sélectionnez **Code: Read** et **Project and Team: Read**.

Seul Azure DevOps Services (dev.azure.com) est pris en charge ; Azure DevOps Server sur site n'est pas pris en charge pour le moment.

#### Mappages du Connecteur

1. Saisissez l'URL de votre organisation dans le champ **Location** : `https://dev.azure.com/{your-organization}`. Les URL héritées `https://{your-organization}.visualstudio.com` sont également acceptées, et tout segment de chemin supplémentaire (par exemple, un lien vers un projet spécifique) est ignoré.
2. Saisissez le PAT dans le champ **Secret**.

Chaque dépôt devient un Enregistrement portant le nom du dépôt, regroupé par **projet** Azure DevOps. Les dépôts désactivés sont ignorés, si bien que désactiver ou supprimer un dépôt marque son Enregistrement comme `MISSING` lors de la prochaine synchronisation.

## **Backstage**

Le connecteur Backstage est un **connecteur d'actifs** : au lieu d'importer des constatations, il récupère votre Software Catalog [Backstage](https://backstage.io) dans DefectDojo et maintient votre hiérarchie de Produits et la propriété des équipes synchronisées avec celui-ci. Il est conçu pour les organisations qui maintiennent leur inventaire de services et leur structure organisationnelle dans Backstage et souhaitent que DefectDojo reflète cette structure au lieu de la maintenir manuellement.

#### Ce qui est mappé

| Backstage | DefectDojo |
|---|---|
| **System** | Type de produit (les Components sans System sont regroupés sous un Type de produit configurable « Backstage / Uncategorized ») |
| **Component** | Produit — nommé à partir du `title` de l'entité (avec repli sur `name`), avec la description du catalogue |
| **Owning Group** (relation `ownedBy`) | Un Groupe DefectDojo lié au Produit (rôle par défaut : Maintainer, configurable) |
| **Owner email** (e-mail du profil du Groupe, ou e-mail d'un propriétaire Utilisateur) | Un Membre de produit, lorsqu'un utilisateur DefectDojo possédant cet e-mail existe déjà (aucun utilisateur n'est jamais créé) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Étiquettes de produit sous un préfixe `backstage:` |
| `metadata.annotations` | Stocké sur l'Enregistrement (avec une limite) ; certaines annotations peuvent être promues en attributs de premier niveau ou en étiquettes via **Annotation Mappings** |

Les Enregistrements sont indexés par le `metadata.uid` attribué par le serveur de l'entité ; ainsi, les renommages effectués dans Backstage mettent à jour le Produit mappé **sur place** lors de la prochaine synchronisation — sans doublons. Le nom du Produit suit toujours le catalogue : pour renommer un Produit géré par ce connecteur, renommez le Component dans Backstage (un renommage effectué côté DefectDojo, ou un nom personnalisé attribué lors du mappage manuel, est réconcilié avec le nom du catalogue lors de la prochaine synchronisation, sauf s'il entre en collision avec un autre Produit). Les changements de propriété déplacent l'affectation de groupe du Produit. Les Components qui disparaissent du catalogue (ou qui sont signalés par l'annotation `backstage.io/orphan`) sont marqués **MISSING** — DefectDojo ne supprime jamais un Produit de lui-même. La hiérarchie de Domain et de Group (équipes parentes) est uniquement enregistrée sous forme d'étiquettes/métadonnées ; elle ne crée pas de niveaux de hiérarchie supplémentaires.

#### Prérequis

Le connecteur s'authentifie à l'aide d'un **jeton d'accès externe statique** auprès du backend Backstage. Dans la configuration de votre application Backstage, définissez un jeton et (recommandé) restreignez-le au plugin catalog :

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Générez un jeton aléatoire fort (par exemple `openssl rand -hex 32`) et stockez-le dans l'environnement de votre déploiement Backstage. Consultez la [documentation Backstage sur l'authentification de service à service](https://backstage.io/docs/auth/service-to-service-auth) pour plus de détails.

#### Mappages du Connecteur

1. Saisissez l'**URL racine du backend Backstage** dans le champ **Location** : par exemple `https://backstage.example.com` (le connecteur ajoute `/api/catalog`). Il doit s'agir de l'URL du **backend**, et non de l'interface web frontend.
2. Saisissez le jeton d'accès externe statique dans le champ **Secret**.

Champs facultatifs (laissez vide pour les valeurs par défaut) :

* **Namespaces** — espaces de noms du catalogue à importer, séparés par des virgules ; vide importe tous les espaces de noms.
* **Component Types** — valeurs `spec.type` séparées par des virgules (par ex. `service,website`) ; vide importe tous les types.
* **Page Size** — taille de page pour les requêtes du catalogue (1\-500, valeur par défaut 250).
* **TLS Verification** — à définir sur `false` uniquement si Backstage sert un certificat que DefectDojo ne peut pas vérifier (AC interne) ; non recommandé.
* **Uncategorized Product Type** — le Type de produit utilisé pour les Components sans System (par défaut `Backstage / Uncategorized`).
* **Owner Group Role** — le rôle accordé à l'équipe propriétaire sur les Produits mappés (par défaut `Maintainer`).
* **Annotation Mappings** — un objet JSON associant des clés d'annotation à des noms d'attributs d'Enregistrement, ou à `"tag"` pour importer une annotation en tant qu'étiquette de Produit, par ex. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Lorsque **Auto\-Map** est activé, un seul cycle Discover \+ Sync construit l'intégralité de la structure Type de produit / Produit / propriété sans étape manuelle. Lorsque Auto\-Map est désactivé, les Components découverts apparaissent comme des Enregistrements en attente de votre décision de mappage.

#### Limitations (v1)

* **L'appartenance aux Groups Backstage n'est pas synchronisée** : le connecteur crée/associe l'équipe propriétaire en tant que Groupe DefectDojo, mais le peuplement des utilisateurs de ce groupe est laissé à votre fournisseur d'identité ou à vos administrateurs.
* Seuls les Components deviennent des Produits ; les API, Resources et Domains ne sont pas importés comme actifs (les domains apparaissent sous forme d'étiquettes).
* Les étiquettes et annotations sont normalisées et limitées pour respecter les contraintes de longueur des champs DefectDojo (les valeurs trop longues sont tronquées).

**Remarque sur le sens inverse :** afficher les constatations et les notes DefectDojo *à l'intérieur* de Backstage (sur les pages d'entité) constituerait un prolongement naturel, qui serait développé sous la forme d'un plugin frontend Backstage consommant l'API REST de DefectDojo — cela sort délibérément du périmètre de ce connecteur, qui se contente d'importer les données du catalogue dans DefectDojo.

## **Black Duck**

Le connecteur Black Duck importe des constatations d'**analyse de composition logicielle (SCA)** depuis une instance Black Duck Hub (Synopsys / Black Duck). DefectDojo découvre tous les projets de l'instance et crée un Enregistrement pour chaque **projet** ; les constatations d'un projet proviennent des composants du BOM vulnérables de sa version sélectionnée.

#### Prérequis

Un **jeton API** Black Duck pour un utilisateur pouvant voir les projets que vous souhaitez importer. Dans Black Duck, ouvrez votre menu utilisateur \> **My Access Tokens** \> **Create New Token**, accordez-lui (au moins) un accès en lecture, et copiez le jeton lorsqu'il s'affiche — il n'est affiché qu'une seule fois. Le connecteur échange ce jeton contre un jeton porteur (bearer) de courte durée à chaque synchronisation ; il n'est jamais stocké en clair en dehors du champ secret du connecteur.

#### Mappages du Connecteur

1. Saisissez l'URL de votre hub Black Duck dans le champ **Location** — par exemple `https://your-company.app.blackduck.com`.
2. Saisissez le jeton API dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque projet Black Duck devient un Enregistrement. Par défaut, le connecteur importe la version **released** du projet (avec repli sur sa première version) ; chaque composant du BOM vulnérable de cette version devient une constatation, intitulée `{vulnerability} in {component}:{version}`.

Ce connecteur est distinct des parseurs Black Duck basés sur fichiers — ses constatations utilisent le type de scan dédié **Black Duck - Connectors Import**.

## **Bitbucket**

Le connecteur Bitbucket est un **Connecteur d'actifs** : il énumère les dépôts des espaces de travail (workspaces) Bitbucket Cloud que vous indiquez et crée un Actif DefectDojo pour chaque dépôt, regroupé en Organisations par projet Bitbucket. Aucune constatation n'est importée.

#### Prérequis

Bitbucket Cloud nécessite un jeton API Atlassian **à portée définie (scoped)** — les jetons API Atlassian classiques (sans portée) sont rejetés par Bitbucket avec une erreur « API Token provided has no Bitbucket scopes ».

1. Rendez-vous sur [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) et choisissez **Create API token with scopes**.
2. Sélectionnez l'application **Bitbucket**, puis accordez les portées en lecture : `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` et `read:project:bitbucket`.

Seul Bitbucket Cloud (bitbucket.org) est pris en charge. Bitbucket Server a atteint sa fin de vie en 2024, et Bitbucket Data Center n'est pas pris en charge.

#### Mappages du Connecteur

1. Saisissez `https://bitbucket.org` dans le champ **Location**.
2. Saisissez l'e-mail du compte Atlassian auquel appartient le jeton dans le champ **Email**.
3. Saisissez le jeton API à portée définie dans le champ **Secret**.
4. Saisissez un ou plusieurs slugs d'espace de travail (séparés par des virgules) dans le champ **Workspace Slugs**. Ce champ est obligatoire : les jetons API à portée définie de Bitbucket ne peuvent pas lister automatiquement les espaces de travail, DefectDojo doit donc être informé des espaces de travail à lire.

Chaque dépôt devient un Enregistrement portant le nom du dépôt, regroupé par **projet** Bitbucket.

## **Bugcrowd**

Le connecteur Bugcrowd utilise l'API REST de Bugcrowd pour importer les soumissions de vos programmes de bug bounty et de divulgation de vulnérabilités. DefectDojo découvre les programmes auxquels votre jeton API a accès et crée un Enregistrement pour chacun d'eux, en important les soumissions de ce programme sous forme de constatations.

#### Prérequis

Vous aurez besoin d'un **jeton API** Bugcrowd ayant accès aux programmes que vous souhaitez importer. Nous recommandons de créer un compte de service dédié pour DefectDojo afin que l'activité automatisée soit facile à distinguer des actions manuelles de l'équipe. Générez le jeton dans Bugcrowd sous **Organization settings \> API credentials** ; un accès en lecture aux submissions, programs et targets est suffisant.

#### Mappages du Connecteur

1. Saisissez `https://api.bugcrowd.com` dans le champ **Location**.
2. Saisissez votre jeton API Bugcrowd dans le champ **Secret**. Il est envoyé sous forme d'en-tête `Authorization: Token`.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque **programme** Bugcrowd devient un Enregistrement, et ses soumissions sont importées comme constatations en conservant la sévérité Bugcrowd. Les soumissions en doublon sont exclues, si bien qu'une réimportation ne crée pas de constatations répétées pour le même problème.

## **Bright Security**

Le connecteur Bright Security utilise l'API [Bright](https://brightsec.com) (anciennement NeuraLegion) pour importer des **constatations DAST**. DefectDojo découvre tous les scans auxquels le jeton a accès et crée un Enregistrement pour chaque scan terminé, puis importe les issues de ce scan sous forme de constatations.

#### Prérequis

Vous aurez besoin d'une **clé API** Bright, créée dans l'application Bright sous **User settings → API keys** (une clé `Org` ou personnelle). La clé est envoyée dans l'en-tête `Authorization: Api-Key` et n'est jamais journalisée.

#### Mappages du Connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://app.brightsec.com`, ou saisissez explicitement votre hôte Bright.
2. Saisissez la clé API Bright dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo mappe chaque **scan** terminé sur un Enregistrement et chaque **issue** sur une constatation : la sévérité provient de la notation propre à Bright (Critical/High/Medium/Low), le score CVSS, le CWE et la remédiation sont repris, le point d'entrée affecté devient le point de terminaison, et les preuves de requête/réponse sont incluses dans la description. Les constatations sont enregistrées comme des constatations dynamiques et dédupliquées sur l'ID d'issue de Bright.

Consultez la [documentation de l'API Bright](https://docs.brightsec.com/) pour plus d'informations.

## **BurpSuite**

Le connecteur Burp de DefectDojo appelle l'API GraphQL de Burp pour récupérer les données. 

#### Prérequis

Avant de pouvoir configurer ce connecteur, vous aurez besoin d'une clé API provenant d'un Burp Service Account. Les comptes utilisateur Burp n'ont pas de clé API par défaut ; vous devrez donc peut-être créer un nouvel utilisateur spécifiquement à cette fin. 

Consultez la [documentation Burp](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) pour un guide sur la configuration d'un utilisateur Service Account avec une clé API.

#### Mappages du Connecteur

1. Saisissez l'URL racine de Burp dans le champ **Location** : il s'agit de l'URL à laquelle vous accédez à l'outil Burp.
2. Saisissez une clé API valide dans le champ Secret. Il s'agit de la clé API associée à votre compte Burp Service.

Consultez la [documentation officielle de Burp](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) pour plus d'informations sur l'API Burp.

## **Censys**

Le connecteur Censys lit les actifs de type host depuis la Censys Platform et importe les services exposés de chaque host sous forme de constatations. Il utilise l'API de recherche globale de la Censys Platform pour énumérer les hosts sur lesquels vous le limitez.

#### Prérequis

Vous aurez besoin d'un compte Censys **Platform** avec accès API :

* Un **Personal Access Token**, créé dans la Censys Platform Console sous Personal Access Tokens.
* Votre **Organization ID**, affiché sur la même page de paramètres sous « Current Organization ». L'accès API au point de terminaison de recherche nécessite une organisation ; un abonnement Starter ou supérieur est donc requis. Les jetons de niveau gratuit n'ont pas d'Organization ID et ne peuvent pas utiliser l'API de recherche.

Les données de CVE et de risque par host ne sont disponibles que sur les abonnements Censys Core (entreprise) ; sur les niveaux inférieurs, les constatations représentent donc des services exposés plutôt que des vulnérabilités.

Consultez la [documentation de l'API Censys Platform](https://docs.censys.com/reference/get-started) pour plus d'informations.

#### Mappages du Connecteur

1. Saisissez `https://api.platform.censys.io` dans le champ **Location**.
2. Saisissez votre Personal Access Token dans le champ **API Key**.
3. Saisissez votre **Organization ID**.
4. Saisissez une **Search Query** qui limite l'import à vos propres actifs, par exemple `host.autonomous_system.asn: <your ASN>` ou `host.ip: 203.0.113.0/24`.
5. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo crée un Enregistrement pour chaque host et importe ses services exposés sous forme de constatations.

## **Checkmarx ONE**

Le connecteur Checkmarx ONE de DefectDojo appelle l'API Checkmarx pour récupérer les données.

#### **Mappages du Connecteur**

1. Saisissez votre **Tenant Name** dans le champ **Checkmarx Tenant**. Ce nom doit être visible sur la page de connexion de Checkmarx ONE, dans le coin supérieur droit :  
" Tenant : \<**votre nom de tenant**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Saisissez une clé API valide. Vous devrez peut-être en générer une nouvelle : consultez la [documentation de l'API Checkmarx](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) pour plus de détails.
3. Saisissez l'emplacement de votre tenant dans le champ **Location**. Cette URL est formatée comme suit :  
​`https://<your-region>.ast.checkmarx.net/` . Votre région se trouve au début de votre URL Checkmarx lorsque vous utilisez l'application Checkmarx. **<https://ast.checkmarx.net>** est le serveur US principal (qui n'a pas de préfixe de région).

#### **Gestion des branches**

Par défaut, chaque synchronisation importe les constatations du **seul scan terminé le plus récent d'un projet, quelle que soit la branche**. Si votre CI analyse de nombreuses branches, la branche qui a été analysée en dernier « remporte » cette synchronisation : les constatations qui n'existent que sur d'autres branches ne sont pas importées, et la réconciliation de fermeture des anciennes constatations lors de la synchronisation peut faire osciller des constatations entre ouvert et fermé à mesure que différentes branches deviennent tour à tour le scan le plus récent.

Deux champs facultatifs contrôlent ce comportement :

- **Branch** : épingle chaque projet à un nom de branche unique — seuls les scans de cette branche sont importés. Il s'agit d'une valeur globale unique pour l'ensemble du connecteur, ce qui convient aux parcs où chaque projet utilise la même branche pérenne (par ex. `main`).
    - Un **caractère générique `*`** est pris en charge. Une valeur Branch contenant `*` sélectionne *toutes* les branches correspondantes plutôt qu'une seule — par exemple `release/*` importe chaque branche de release, et `*` correspond à toutes les branches. Combiné avec **Track Scanned Branches**, c'est le moyen de suivre une famille de branches sans toutes les suivre.
    - Si un caractère générique ne correspond à **aucune** branche dans la fenêtre de scan, cette synchronisation est **ignorée** plutôt que traitée comme « la branche n'a aucune constatation » — ainsi, un motif qui ne correspond temporairement à rien ne peut pas fermer toutes les constatations de l'actif.
- **Track Scanned Branches** : lorsque cette option est activée, chaque synchronisation recherche toutes les branches ayant un scan terminé dans l'historique récent des scans du projet et importe **le dernier scan terminé de chaque branche**, avec une réimportation par branche. Les constatations de chaque branche vivent dans leur propre engagement sur l'actif mappé, nommé « \<engagement par défaut\> \- \<branche\> », si bien que la fermeture des constatations obsolètes est limitée à chaque branche : un correctif fusionné sur une branche ne peut jamais fermer les constatations d'une autre branche. La branche principale du projet (telle que rapportée par Checkmarx) est importée en premier, de sorte que les réapparitions d'une même constatation sur d'autres branches se dédupliquent par rapport à l'originale de la branche principale.

Remarques sur **Track Scanned Branches** :

- **Vérifiez quel comportement par défaut s'applique à vous.** Le suivi des branches est **activé par défaut pour les nouvelles installations**. Les installations antérieures à ce changement conservent leur comportement précédent ; l'option reste donc désactivée pour elles tant que quelqu'un ne l'active pas.
- Lorsque les deux champs sont renseignés, seule la **Branch** épinglée est suivie — y compris lorsque cette valeur Branch est un motif générique, auquel cas toutes les branches correspondant au motif sont suivies.
- Une branche qui cesse d'être analysée (fusionnée ou supprimée) cesse de recevoir des mises à jour : son engagement reste visible avec ses dernières constatations connues, que vous pouvez examiner et fermer en masse.
- Désactiver l'option ultérieurement est sans risque : les engagements par branche cessent simplement de recevoir des imports, et l'engagement par défaut reprend lors de la prochaine synchronisation.
- Les Connecteurs réconcilient l'état selon le calendrier de synchronisation. Le suivi des branches rend chaque synchronisation complète à travers les branches ; il ne rend pas les données en temps réel entre deux synchronisations.

## **Cloudflare**

Le connecteur Cloudflare importe les **insights Security Center** — des problèmes de posture de sécurité que Cloudflare signale sur votre compte et vos zones, comme un enregistrement DMARC manquant, le DNSSEC non activé, ou un problème de certificat. DefectDojo crée un Enregistrement pour chaque zone (domaine) ayant des insights ouverts, ainsi qu'un Enregistrement au niveau du compte pour les insights qui ne sont liés à aucune zone spécifique.

#### Prérequis

Vous aurez besoin d'un **jeton API** Cloudflare (et non de l'ancienne Global API Key). Créez-en un sous **My Profile > API Tokens > Create Token** dans le tableau de bord Cloudflare. L'option la plus rapide est le modèle **« Read all resources »** ; pour un jeton à privilège minimal, accordez **Zone > Zone > Read** (toutes les zones) ainsi qu'un accès en lecture au niveau du compte pour Security Center.

#### Mappages du Connecteur

1. Saisissez `https://api.cloudflare.com/client/v4` dans le champ **Location**.
2. Saisissez le jeton API dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo découvre automatiquement les comptes et zones auxquels le jeton a accès — aucun ID de compte n'est requis. Seuls les insights ouverts (actifs, non ignorés) sont importés ; les insights que vous résolvez ou ignorez dans Cloudflare sont donc automatiquement atténués dans DefectDojo lors de la prochaine synchronisation.

## **Cobalt.io**

Le connecteur Cobalt.io utilise l'API Cobalt.io (v2) pour récupérer les résultats de pentest de votre organisation Cobalt.io. DefectDojo découvre chaque organisation à laquelle votre jeton d'API a accès et crée un enregistrement distinct pour chaque **actif** (l'unité que Cobalt teste).

#### Prérequis

Vous aurez besoin d'un **jeton d'API personnel** Cobalt.io. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de distinguer clairement l'activité automatisée des actions manuelles de l'équipe. Générez un jeton depuis **Settings \> API Tokens** dans l'interface Cobalt.io. Les jetons d'organisation sont découverts automatiquement \- vous n'avez pas besoin de les fournir.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API Cobalt.io dans le champ **Location** : `https://api.cobalt.io` (ou votre hôte régional, par exemple `https://api.us.cobalt.io`).
2. Saisissez votre **jeton d'API personnel** dans le champ **Secret**.
3. Facultativement, saisissez un **Organization Token** pour limiter la synchronisation à une seule organisation. Si ce champ est laissé vide, DefectDojo synchronise toutes les organisations auxquelles le jeton d'API personnel a accès.

DefectDojo associe chaque **actif** Cobalt.io à un enregistrement distinct. Les constatations sont importées pour chaque actif associé, leur état Cobalt.io (par exemple `valid_fix`, `wont_fix`, `invalid`) déterminant le statut de la constatation dans DefectDojo.

## **Contrast**

Le connecteur Contrast utilise l'API REST Contrast Assess pour importer les vulnérabilités des applications. DefectDojo découvre les applications de votre organisation Contrast et crée un enregistrement pour chacune d'elles.

#### Prérequis

Vous aurez besoin de quatre valeurs provenant de Contrast. Nous recommandons de créer un compte de service dédié afin que l'activité automatisée soit facile à distinguer des actions manuelles de votre équipe. Dans l'interface Contrast, sous **User Settings > Profile > Your Keys**, vous trouverez :

* Votre **API Key** d'organisation.
* Votre **Service Key** personnelle.
* Le **username** auquel appartiennent ces identifiants (l'e-mail de connexion du compte).
* Votre **Organization ID** — l'UUID de l'organisation depuis laquelle importer, également affiché sous **Organization Settings**.

#### Mappages du connecteur

1. Saisissez l'URL de base que vous utilisez pour accéder à Contrast dans le champ **Location** — pour le produit hébergé, il s'agit généralement de `https://app.contrastsecurity.com` (ou de l'URL de votre Team Server régional / auto-hébergé).
2. Saisissez l'e-mail de connexion du compte dans le champ **Username**.
3. Saisissez l'**API Key** de l'organisation dans le champ **API Key**.
4. Saisissez la **Service Key** personnelle dans le champ **Service Key**.
5. Saisissez l'**Organization ID** (UUID) dans le champ **Organization ID**.
6. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque application Contrast devient un enregistrement, et ses vulnérabilités sont importées comme constatations.

## **Coverity**

Le connecteur Coverity importe des constatations depuis un serveur **Coverity Connect**. DefectDojo crée un enregistrement pour chaque **projet** Coverity.

#### Mappages du connecteur

1. Saisissez l'URL de votre serveur Coverity Connect dans le champ **Location**.
2. Saisissez le **username** Coverity Connect dans le champ **Username**.
3. Saisissez le mot de passe ou la clé d'authentification de l'utilisateur dans le champ **Secret**.
4. Facultativement, définissez un **View Name** pour sélectionner la vue d'issues enregistrée que le connecteur doit lire. Laissez vide pour utiliser la vue par défaut, **Outstanding Issues**.
5. Facultativement, définissez **Import All Issue Kinds** sur `true` pour élargir l'import au-delà du filtre d'issues Security and Quality (`RESOURCE_LEAK`) par défaut.

## **CrowdStrike Falcon**

Le connecteur CrowdStrike Falcon importe les **vulnérabilités Spotlight** et les **détections EDR** depuis la plateforme Falcon, sous forme de deux types de constatations distincts (`CrowdStrike:Spotlight` et `CrowdStrike:Detections`). DefectDojo crée un enregistrement pour chaque **hôte** Falcon.

#### Prérequis

Un **client API** Falcon (Client ID et secret), créé dans la console Falcon sous **Support \> API Clients and Keys**. Accordez-lui les scopes correspondant aux données que vous souhaitez importer : **Hosts: Read** (requis, pour la découverte des hôtes), **Vulnerabilities (Spotlight): Read** (pour les constatations Spotlight) et **Alerts: Read** (pour les détections EDR). Les deux types de constatations sont indépendants — si le client ne dispose pas d'un scope, ce type de constatation est ignoré plutôt que de faire échouer la synchronisation ; ainsi, un client sans **Alerts: Read** importe tout de même les vulnérabilités Spotlight.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API de votre cloud Falcon dans le champ **Location**, en fonction de la région de votre console — par exemple `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1), ou `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Saisissez le Client ID du client API dans le champ **Client ID**.
3. Saisissez le secret du client API dans le champ **Client Secret**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque hôte Falcon devient un enregistrement, nommé d'après son nom d'hôte, son OS et son type. Seules les vulnérabilités Spotlight à l'état **open** et **reopened** sont importées ; une réimportation clôt donc les constatations corrigées.

## **Deepfence ThreatMapper**

Le connecteur Deepfence ThreatMapper utilise l'API REST de la console de gestion [ThreatMapper](https://github.com/deepfence/ThreatMapper) pour importer les résultats des **scans de vulnérabilités**. DefectDojo découvre chaque nœud scanné par ThreatMapper — une image de conteneur, un hôte ou un conteneur — et crée un enregistrement pour chacun, puis importe le scan complété le plus récent de ce nœud sous forme de constatations.

#### Prérequis

Vous aurez besoin d'un **jeton d'API** ThreatMapper, disponible dans la console sous **Settings → User Management** (la clé d'API de votre utilisateur). Le connecteur l'échange contre un jeton d'accès de courte durée à chaque synchronisation ; le jeton d'API n'est jamais journalisé.

#### Mappages du connecteur

1. Saisissez l'URL de votre console ThreatMapper dans le champ **Location** (par exemple `https://threatmapper.example.com`).
2. Dans le champ **Secret**, saisissez le jeton d'API ThreatMapper.
3. Si votre console utilise un certificat auto-signé, définissez **Skip TLS Verification** sur `true`.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **nœud** scanné à un enregistrement et chaque **CVE** de son dernier scan de vulnérabilités complété à une constatation. La sévérité provient de la notation propre à ThreatMapper, et le paquet affecté, le score CVSS, la version corrigée (utilisée comme atténuation), les liens de référence et un bloc de détails sont repris. Les constatations sont enregistrées comme constatations dynamiques et dédupliquées sur le nœud, le CVE, le paquet et le chemin du paquet.

Pour plus d'informations, consultez la [documentation ThreatMapper](https://community.deepfence.io/threatmapper/docs/v2.5/).

## Dependency\-Track

Ce connecteur récupère les données d'une instance Dependency\-Track sur site, via l'API REST.

​**Mappages du connecteur**

1. Saisissez l'URL de votre serveur Dependency\-Track local dans le champ **Location**.
2. Saisissez une clé d'API valide dans le champ **Secret**.

Pour générer une clé d'API Dependency\-Track :

1. **Access Management** : accédez à Administration \> Access Management \> Teams dans l'interface Dependency\-Track.
2. **Teams Setup** : vous pouvez créer une nouvelle équipe ou en sélectionner une existante. Les équipes permettent de gérer l'accès à l'API en fonction de l'appartenance à un groupe.
3. **Generate API Key** : sur la page de détails de l'équipe sélectionnée, trouvez la section « API Keys ». Cliquez sur le bouton \+ pour générer une nouvelle clé d'API.
4. **Assign Permissions** : dans la section « Permissions » de la page de l'équipe, cliquez sur le bouton \+ pour ouvrir le sélecteur de permissions. Choisissez les permissions **VIEW\_PORTFOLIO** et **VIEW\_VULNERABILITY** pour activer l'accès API aux portefeuilles de projets et aux détails des vulnérabilités.
5. Cliquez sur « **Select** » pour confirmer et enregistrer ces permissions.

Pour plus d'informations, consultez la **[documentation Dependency\-Track](https://docs.dependencytrack.org/integrations/rest-api/)**.

## **Docker Scout**

Le connecteur Docker Scout utilise l'API de l'exportateur de métriques Docker Scout pour rendre compte de la posture de vulnérabilité des images de votre organisation. DefectDojo découvre chaque flux (stream) Docker Scout (vos environnements d'exécution) et importe un résumé des vulnérabilités et de la conformité aux politiques pour chacun.

#### Prérequis

Vous aurez besoin d'un jeton d'accès personnel Docker créé par un **owner** d'une organisation Docker **inscrite à Docker Scout**. L'exportateur de métriques est une fonctionnalité au niveau de l'organisation ; un compte personnel, ou une organisation non inscrite à Docker Scout, ne renverra donc aucune donnée.

Créez le jeton depuis les paramètres de votre compte Docker, sous **Personal access tokens**, et notez votre **espace de noms d'organisation** Docker, qui vous sera également nécessaire.

#### Mappages du connecteur

1. Saisissez `https://api.scout.docker.com` dans le champ **Location**.
2. Saisissez votre jeton d'accès personnel Docker dans le champ **Secret**.
3. Saisissez votre espace de noms **Organization** Docker.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations d'une sévérité inférieure à celle sélectionnée ne seront pas importées.

DefectDojo crée un enregistrement distinct pour chaque flux Docker Scout, et importe une constatation par sévérité pour les vulnérabilités que Docker Scout comptabilise dans ce flux, ainsi qu'une constatation pour chaque image qui échoue à votre politique Docker Scout. L'API de métriques de Docker Scout renvoie des comptages agrégés plutôt que des CVE individuels ; ces constatations résument donc la posture d'un flux. Ouvrez le flux dans Docker Scout pour obtenir le détail par image et par CVE.

Pour plus d'informations, consultez la [documentation Docker Scout](https://docs.docker.com/scout/).

## **Endor Labs**

Le connecteur Endor Labs utilise l'API REST Endor Labs pour synchroniser un **espace de noms (namespace)** Endor Labs entier. DefectDojo découvre chaque **projet** Endor sous forme d'enregistrement et importe les constatations de ce projet, en reprenant le verdict d'**accessibilité (reachability)** d'Endor afin de vous permettre de prioriser les vulnérabilités dont le code affecté est réellement atteignable.

#### Prérequis

Vous aurez besoin d'une **API key** Endor Labs (un identifiant de clé accompagné de son secret) et de l'**espace de noms (namespace)** à synchroniser. Créez la clé dans la plateforme Endor Labs sous **Settings \> Access \> API Keys** ; la clé doit disposer d'un accès en lecture aux projets et constatations de cet espace de noms.

Le connecteur s'authentifie en échangeant la clé d'API et le secret contre un jeton porteur (bearer token) de courte durée — le secret n'est utilisé que pour cet échange et n'est jamais stocké en clair.

#### Mappages du connecteur

1. Saisissez `https://api.endorlabs.com` dans le champ **Location**. Si votre tenant est hébergé dans une autre région, utilisez plutôt l'URL de base de l'API de cette région.
2. Saisissez le **Namespace** Endor Labs à synchroniser (par exemple `your-org` ou `your-org.team`).
3. Saisissez l'identifiant de l'**API Key**.
4. Saisissez l'**API Secret** associé à la clé.
5. Facultativement, définissez **Traverse Child Namespaces** sur `true` pour importer également les constatations des espaces de noms enfants de l'espace de noms configuré.
6. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations d'une sévérité inférieure à celle sélectionnée ne sont pas importées.

DefectDojo crée un enregistrement pour chaque projet Endor Labs de l'espace de noms et importe ses constatations, en associant les niveaux de sévérité Endor aux sévérités DefectDojo, les identifiants CVE/GHSA et le score CVSS de chaque vulnérabilité, ainsi que les étiquettes d'accessibilité d'Endor. Le verdict d'accessibilité (par exemple *Reachable — vulnerable function is called* ou *Unreachable*) est présenté comme l'Impact de la constatation et comme une étiquette.

Pour plus d'informations, consultez la **[documentation de l'API REST Endor Labs](https://docs.endorlabs.com/rest-api/)**.

## **Edgescan**

Le connecteur Edgescan utilise l'API REST Edgescan pour importer les vulnérabilités ouvertes de l'ensemble de votre compte Edgescan. DefectDojo énumère chaque **actif** Edgescan et crée un enregistrement pour chacun, puis importe les vulnérabilités ouvertes de cet actif sous forme de constatations — il n'y a pas de configuration par actif.

#### Prérequis

Vous aurez besoin d'un jeton d'API Edgescan. Créez-en un depuis votre compte Edgescan sous **Account settings \> API tokens** : saisissez un libellé, cliquez sur **Create**, puis copiez le jeton généré (il n'est affiché qu'une seule fois). Nous recommandons un compte dédié pour le connecteur afin que l'activité automatisée soit facile à distinguer.

#### Mappages du connecteur

1. Saisissez votre URL Edgescan dans le champ **Location** — `https://live.edgescan.com` pour la plateforme hébergée standard, ou l'hôte de votre tenant si différent.
2. Saisissez votre jeton d'API Edgescan dans le champ **Secret**. Il est envoyé dans l'en-tête `X-API-TOKEN`.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque actif Edgescan devient un enregistrement, et chaque vulnérabilité ouverte sur cet actif est importée comme constatation. La sévérité est convertie de l'échelle numérique d'Edgescan (1–5) vers l'échelle Info–Critique de DefectDojo, et les références CVE, la CWE, ainsi qu'un vecteur CVSS v3 sont inclus lorsqu'Edgescan les fournit.

## **Escape**

Le connecteur Escape utilise l'API [Escape](https://escape.tech) pour importer des **constatations de sécurité API (DAST)**. DefectDojo énumère chaque organisation à laquelle le jeton a accès ainsi que chaque application qu'elle contient, crée un enregistrement pour chaque application ayant fait l'objet d'un scan, et importe les issues du dernier scan de cette application sous forme de constatations — il n'y a pas de configuration par application.

#### Prérequis

Vous aurez besoin d'une **API key** Escape, créée dans l'application Escape sous **Settings → API keys**. La clé est envoyée dans l'en-tête `Authorization: Key` et n'est jamais journalisée.

#### Mappages du connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://public.escape.tech/v2`, ou saisissez explicitement l'hôte de votre API Escape.
2. Saisissez la clé d'API Escape dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **application** à un enregistrement et chaque **issue** de scan à une constatation : la sévérité provient de la notation d'Escape (Critical/High/Medium/Low), la CWE est reprise, la catégorie OWASP et la méthode HTTP deviennent des étiquettes, l'URL affectée devient le point de terminaison, et les recommandations de remédiation sont incluses. Les constatations sont enregistrées comme constatations dynamiques et dédupliquées sur l'identifiant d'issue Escape.

Pour plus d'informations, consultez la [documentation de l'API Escape](https://docs.escape.tech/).

## **Fairwinds Insights**

Le connecteur Fairwinds Insights utilise l'API REST [Fairwinds Insights](https://insights.fairwinds.com) pour importer des **constatations de sécurité Kubernetes** sur l'ensemble de votre organisation. DefectDojo énumère chaque **cluster** actif et crée un enregistrement pour chacun, puis importe les **action items** de sécurité de ce cluster \(provenant de Polaris, Trivy, Kube\-bench, OPA et des autres rapports Insights\) sous forme de constatations — il n'y a pas de configuration par cluster.

#### Prérequis

Vous aurez besoin d'un nom d'**organisation** Fairwinds Insights et d'un **jeton d'API**. Créez le jeton dans l'application Insights sous **Organization Settings \> Tokens** ; un jeton `read_only` suffit. Le jeton est limité à l'organisation (org-scoped) et est envoyé comme jeton porteur (bearer token) ; il n'est jamais journalisé.

#### Mappages du connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://insights.fairwinds.com`, ou saisissez explicitement l'hôte de votre instance Insights.
2. Saisissez votre nom d'**Organization** Insights (le slug affiché dans l'URL de votre tableau de bord).
3. Saisissez le jeton d'API Insights dans le champ **Secret**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **cluster** actif à un enregistrement et chaque **action item** de sécurité à une constatation : la sévérité provient du score numérique de Fairwinds \(converti vers l'échelle Info–Critique de DefectDojo\), le rapport Fairwinds à l'origine de l'élément \(`polaris`, `trivy`, `kube-bench`, ...\) devient une étiquette d'outil, la ressource Kubernetes affectée et l'image de conteneur sont incluses, et les identifiants CVE éventuels sont extraits. Les constatations sont enregistrées comme constatations statiques et dédupliquées sur l'identifiant d'action item Fairwinds.

Pour plus d'informations, consultez la [documentation de l'API Fairwinds Insights](https://insights.docs.fairwinds.com/technical-details/api/).

## **Fortify**

Le connecteur Fortify importe les résultats SAST/DAST de Fortify (OpenText/Micro Focus), couvrant les deux éditions qui partagent la plateforme : **SSC** (Software Security Center, auto-hébergé) et **Fortify on Demand (FoD)** (SaaS). Il synchronise l'ensemble du compte : DefectDojo découvre chaque application (version de projet SSC / release FoD) et crée un enregistrement pour chacune, puis importe les issues de cette application sous forme de constatations.

#### Prérequis

- **SSC** : un **FortifyToken** — créez-en un dans l'interface SSC sous **Administration → Token Management** (un CIToken/UnifiedLoginToken).
- **FoD** : une **clé d'API OAuth2** — un Client ID et un Client Secret depuis **Settings → API** (avec le scope `api-tenant`).

Le jeton et le secret OAuth ne sont jamais journalisés.

#### Mappages du connecteur

1. Saisissez l'URL de base de Fortify dans le champ **Location** : pour SSC, l'hôte de votre serveur (le connecteur ajoute `/ssc/api/v1`) ; pour FoD, l'hôte de l'API de votre région, par exemple `https://api.ams.fortify.com`.
2. Définissez **Edition** sur `SSC` ou `FoD`.
3. Pour **FoD**, saisissez le **Client ID** OAuth ; laissez-le vide pour SSC.
4. Dans **Token / Client Secret**, saisissez le FortifyToken SSC ou le client secret OAuth FoD.
5. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **application** Fortify à un enregistrement et chaque **issue** à une constatation : la sévérité provient de la notation **friority** propre à Fortify (Critical/High/Medium/Low), le titre combine la catégorie de l'issue avec son fichier et sa ligne, et le chemin du fichier, la ligne, le kingdom, l'analyzer et le type de moteur sont repris. Les issues provenant des moteurs d'analyse statique (SCA) sont enregistrées comme constatations statiques et les issues WebInspect (DAST) comme constatations dynamiques ; les issues supprimées, retirées ou masquées sont ignorées, les issues auditées « Not an Issue » sont marquées Faux positif, et les issues « Exploitable » / revues sont marquées Vérifié.

Pour plus d'informations, consultez la documentation de l'API [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) et [Fortify on Demand](https://api.ams.fortify.com/swagger/ui).

## **GitGuardian**

Le connecteur GitGuardian utilise l'API REST GitGuardian pour importer des **incidents de secrets** — des identifiants exposés que GitGuardian a détectés sur l'ensemble de vos sources surveillées. DefectDojo crée un enregistrement pour chaque source surveillée (dépôt ou périmètre) ayant actuellement des incidents ouverts, et importe chaque incident ouvert sous forme de constatation.

Pour votre sécurité, le connecteur n'importe que les **métadonnées** de l'incident — le détecteur, la sévérité, la validité, le statut, et un lien de retour vers GitGuardian. La valeur du secret exposé elle-même n'est jamais récupérée ni stockée par DefectDojo ; suivez le lien dans chaque constatation pour examiner les emplacements concernés dans GitGuardian.

#### Prérequis

Vous aurez besoin d'une clé d'API GitGuardian. Nous recommandons un **jeton de compte de service (Service Account token)** (plutôt qu'un jeton d'accès personnel) afin que l'activité automatisée soit facile à distinguer. Créez-le sous **API** dans le tableau de bord GitGuardian et accordez ces scopes en lecture :

* `incidents:read`
* `sources:read`

#### Mappages du connecteur

1. Saisissez l'URL de l'API GitGuardian dans le champ **Location** : `https://api.gitguardian.com` pour la plateforme SaaS, ou l'URL de l'API de votre instance auto-hébergée.
2. Saisissez la clé d'API dans le champ **Secret**.

Seuls les incidents à l'état **open** (statut `TRIGGERED` ou `ASSIGNED`) sont importés ; les incidents que vous résolvez ou ignorez dans GitGuardian sont automatiquement atténués dans DefectDojo lors de la prochaine synchronisation. Un secret confirmé actif (validité *valid*) est importé comme une constatation vérifiée.

## **GitHub**

Le connecteur GitHub est un **connecteur d'actifs (Asset Connector)** : il énumère les dépôts auxquels votre jeton a accès et crée un actif DefectDojo pour chacun, regroupés en organisations par propriétaire GitHub (organisation ou utilisateur). Aucune constatation n'est importée.

**Remarque :** ce connecteur importe uniquement l'**inventaire** de vos dépôts. Pour importer les alertes de sécurité GitHub — code scanning, Dependabot et secret scanning — sous forme de constatations, utilisez le connecteur **GitHub Advanced Security** distinct décrit plus bas. Les deux sont indépendants et peuvent être exécutés ensemble.

#### Prérequis

Le connecteur s'authentifie avec un **jeton d'accès personnel** GitHub et ne lit que les **métadonnées** du dépôt (nom, description, URL et propriétaire) — il n'accède ni à votre code, ni à vos issues, ni à vos alertes de sécurité. Il importe chaque dépôt dont le compte du jeton est propriétaire, collaborateur, ou membre de l'organisation propriétaire ; vérifiez donc que le compte du jeton peut voir les dépôts que vous souhaitez refléter. Nous recommandons un compte de service dédié.

Le jeton n'a besoin que d'un accès en lecture seule aux métadonnées du dépôt :

- Un jeton *fine-grained* nécessite **Repository permissions → Metadata: Read-only**, accordé aux dépôts (ou à l'ensemble de l'organisation) que vous souhaitez importer.
- Un jeton *classic* nécessite le scope **`repo`** pour inclure les dépôts privés (utilisez **`public_repo`** si vous n'avez besoin que des dépôts publics), ainsi que **`read:org`** pour que les dépôts appartenant à une organisation soient résolus.

Seul GitHub.com (y compris GitHub Enterprise Cloud) est pris en charge. GitHub Enterprise **Server** n'est pas pris en charge par ce connecteur pour le moment.

#### Mappages du connecteur

1. Saisissez `https://api.github.com` dans le champ **Location**.
2. Saisissez le jeton d'accès personnel dans le champ **Secret**.

Aucune liste d'organisations ou de dépôts n'est à saisir — DefectDojo importe tous les dépôts que le jeton peut voir. Chaque dépôt devient un enregistrement nommé d'après le dépôt, regroupé par **owner** GitHub (organisation ou utilisateur). Si un dépôt est supprimé par la suite, ou si le jeton perd l'accès à celui-ci, son enregistrement associé est marqué `MISSING` lors de la prochaine synchronisation plutôt que supprimé — DefectDojo ne supprime jamais silencieusement un Produit.

## **GitHub Advanced Security**

Le connecteur GitHub Advanced Security importe les alertes **code scanning**, **Dependabot** et **secret scanning** de GitHub, sous forme de trois types de constatations distincts (`GitHub:CodeScanning`, `GitHub:Dependabot` et `GitHub:SecretScanning`). DefectDojo découvre chaque dépôt non archivé de l'organisation configurée et crée un enregistrement pour chacun.

#### Prérequis

Les fonctionnalités GitHub Advanced Security doivent être activées pour les dépôts que vous souhaitez importer. Le connecteur s'authentifie avec un **jeton d'accès personnel** GitHub :

1. Dans GitHub, ouvrez **Settings \> Developer settings \> Personal access tokens** et créez un jeton appartenant à (ou ayant accès à) l'organisation cible.
2. Accordez-lui un accès en lecture aux alertes de sécurité : un jeton *fine\-grained* nécessite un accès **Read\-only** à **Code scanning alerts**, **Dependabot alerts** et **Secret scanning alerts** sur les dépôts de l'organisation ; un jeton *classic* nécessite les scopes **`repo`** et **`security_events`**.
3. Vérifiez que le propriétaire du jeton peut voir les dépôts que vous prévoyez d'importer — le connecteur ne voit que les dépôts auxquels le jeton a accès.

#### Mappages du connecteur

1. Saisissez `https://api.github.com` dans le champ **Location**. Pour GitHub Enterprise Server, utilisez `https://<your-host>/api/v3`.
2. Saisissez le login de l'organisation dans le champ **Organization**.
3. Saisissez le jeton d'accès personnel dans le champ **Secret**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque dépôt non archivé devient un enregistrement, interrogé sur les trois familles d'alertes pour les alertes ouvertes. Une famille d'alertes non activée pour un dépôt est ignorée plutôt que signalée comme résolue, de sorte que les fonctionnalités désactivées ne provoquent pas de fermetures erronées.

## **GitLab**

Le connecteur GitLab est un **connecteur d'actifs (Asset Connector)** : il énumère chaque projet (dépôt) auquel votre jeton a accès et crée un actif DefectDojo pour chacun, regroupés en organisations par espace de noms (namespace) GitLab (groupe ou utilisateur). Aucune constatation n'est importée.

#### Prérequis

Vous aurez besoin d'un jeton d'accès personnel (Personal Access Token) avec le scope **read_api**. Nous recommandons de créer le jeton depuis un compte de service dédié ; le connecteur liste les projets dont ce compte est membre.

#### Mappages du connecteur

1. Saisissez votre URL GitLab dans le champ **Location** : `https://gitlab.com`, ou l'URL de base de votre instance auto-hébergée.
2. Saisissez le Personal Access Token dans le champ **Secret**.

Chaque projet devient un enregistrement nommé d'après le projet, regroupé par son **namespace**. Les projets en attente de suppression dans GitLab (supprimés par un utilisateur, mais pas encore purgés par la tâche de fond de GitLab) sont exclus automatiquement ; la suppression d'un projet marque donc son enregistrement comme `MISSING` lors de la prochaine synchronisation, au lieu de laisser un actif fantôme renommé.

## **Google Cloud Security Command Center**

Le connecteur Google Cloud SCC utilise l'API REST Security Command Center v2 pour importer les constatations de sécurité actives de votre organisation, dossier ou projet Google Cloud. DefectDojo crée un enregistrement pour chaque **projet** Google Cloud ayant des constatations ouvertes.

#### Prérequis

Security Command Center doit être **activé** sur votre organisation (le niveau Standard est gratuit). Vous aurez ensuite besoin d'un compte de service capable de lister les constatations, ainsi que d'une clé JSON pour celui-ci :

1. Dans Google Cloud, créez un compte de service — un compte dédié pour DefectDojo est recommandé.
2. Accordez-lui le rôle **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) au niveau (organisation, dossier ou projet) que vous souhaitez importer.
3. Créez une **clé JSON** pour le compte de service et téléchargez-la.

#### Mappages du connecteur

1. Laissez le champ **Location** à sa valeur par défaut `https://securitycenter.googleapis.com`, sauf si vous utilisez un point de terminaison non standard.
2. Dans le champ **Parent Resource**, saisissez le périmètre depuis lequel importer : `organizations/{id}`, `folders/{id}`, ou `projects/{id}`.
3. Collez le contenu complet du fichier de **clé JSON** du compte de service dans le champ **Service Account Key**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Seules les constatations à l'état `ACTIVE` et non mises en sourdine sont importées ; les constatations que vous désactivez ou mettez en sourdine dans SCC sont donc automatiquement atténuées dans DefectDojo lors de la prochaine synchronisation. Le projet GCP affecté par chaque constatation devient son enregistrement.

## **Group-IB ASM**

Le connecteur Group-IB ASM (Attack Surface Management) utilise l'API REST Group-IB ASM pour importer dans DefectDojo les **issues** (constatations) de surface d'attaque externe. DefectDojo découvre chaque **entreprise/locataire** Group-IB comme un Enregistrement distinct et importe les issues de cette entreprise de façon planifiée et incrémentale. L'actif auquel se rapporte chaque issue (un domaine, une IP ou une URL) est rattaché à la constatation résultante en tant que **Point de terminaison**.

#### Prérequis

Vous aurez besoin de votre identifiant de connexion Group-IB ASM et d'une clé API. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de pouvoir distinguer l'activité automatisée des actions manuelles de l'équipe.

Pour générer une clé API :

1. Ouvrez Group-IB Attack Surface Management, cliquez sur **Help** dans le coin inférieur gauche, puis sélectionnez **API**.
2. Cliquez sur **Generate API Key** (en haut à droite, sous votre nom d'utilisateur).
3. Saisissez votre mot de passe SSO, cliquez sur **Next**, puis cliquez sur **Copy token**.
4. Stockez la clé dans un gestionnaire de secrets et prévoyez une rotation régulière.

#### Mappages du connecteur

Group-IB ASM s'authentifie via HTTP Basic Auth, où le nom d'utilisateur est votre identifiant de connexion ASM et le mot de passe est votre clé API. **Les deux valeurs sont requises** — la clé API seule ne suffit pas.

1. Saisissez `https://asm.group-ib.com` dans le champ **Location**. Cette valeur est identique pour tous les locataires Group-IB ASM.
2. Saisissez votre identifiant de connexion ASM (généralement une adresse e-mail) dans le champ **Username**.
3. Saisissez votre clé API dans le champ **API Key** (Secret).
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne sont pas importées.

DefectDojo mappe chaque **entreprise** Group-IB comme un Enregistrement distinct, en utilisant l'identifiant de l'entreprise comme identifiant. Lors de la première synchronisation, DefectDojo réimporte l'historique récent des issues ; les synchronisations suivantes sont incrémentales et ne récupèrent que les issues modifiées depuis la dernière synchronisation (suivies via l'horodatage `lastSeen` le plus récent de chaque issue).

#### Limiter à une seule entreprise (optionnel)

Par défaut, le connecteur découvre automatiquement les entreprises accessibles avec vos identifiants API (via le point de terminaison ASM `clients`) et crée un Enregistrement par entreprise. C'est la configuration recommandée et elle ne nécessite aucune configuration supplémentaire.

Si le point de terminaison `clients` n'est pas disponible pour votre locataire — par exemple lorsqu'il est réservé aux comptes partenaires/MSP —, le connecteur peut être limité à une seule entreprise en fournissant son **identifiant d'entreprise** en tant que champ spécifique à l'outil `company_id` dans la configuration du connecteur. Lorsque `company_id` est défini, DefectDojo utilise directement cette entreprise au lieu d'énumérer les entreprises. Laissez ce champ vide pour utiliser la découverte automatique.

Consultez le manuel de l'API REST Group-IB ASM (disponible dans le produit via **Help → API**) pour plus d'informations.

## **HackerOne**

Le connecteur HackerOne utilise l'API REST HackerOne pour importer les rapports de votre programme de bug bounty ou de divulgation de vulnérabilités. DefectDojo crée un Enregistrement pour chaque programme auquel le jeton peut accéder et importe ses rapports en tant que constatations.

#### Prérequis

Le connecteur utilise l'API **customer** de HackerOne, qui nécessite un **jeton API d'organisation** — un jeton personnel provenant de vos paramètres utilisateur ne fonctionne qu'avec l'API hacker et ne permettra pas de s'authentifier ici.

1. Dans HackerOne, accédez à **Organization Settings > API Tokens**.
2. Créez un jeton et notez à la fois l'**identifiant** et la valeur du **jeton**. Un accès en lecture au programme suffit.

#### Mappages du connecteur

1. Saisissez `https://api.hackerone.com` dans le champ **Location**.
2. Saisissez l'**identifiant** du jeton dans le champ **API Token Identifier**.
3. Saisissez la valeur du jeton dans le champ **API Token**.
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

Chaque programme devient un Enregistrement, et ses rapports sont importés en tant que constatations en conservant la note de sévérité HackerOne.

## **Harbor**

Le connecteur Harbor utilise l'API REST Harbor v2.0 pour importer les vulnérabilités des images de conteneurs sur l'ensemble de votre registre. DefectDojo énumère chaque **projet** Harbor et crée un Enregistrement pour chacun, puis parcourt les dépôts et artefacts du projet et importe les vulnérabilités de chaque artefact **scanné** — en conservant l'image (dépôt + tag/digest) comme contexte de la constatation. Il n'y a pas de configuration par image.

#### Prérequis

Vous aurez besoin d'un compte Harbor (ou d'un **compte robot**) disposant d'un accès pull/lecture aux projets que vous souhaitez importer. Nous recommandons un compte robot dédié : dans Harbor, ouvrez un projet (ou **Administration > Robot Accounts** pour un robot système), créez un robot avec la permission **pull** sur les dépôts et artefacts, et copiez son nom complet et son secret. Les noms de robot commencent par `robot$` par défaut, mais le préfixe est configurable selon l'instance Harbor (certaines utilisent `robot_`) — copiez le nom exactement tel qu'affiché par Harbor. Un nom d'utilisateur/mot de passe classique fonctionne aussi.

#### Mappages du connecteur

1. Saisissez votre URL Harbor dans le champ **Location** — par exemple `https://harbor.example.com`. DefectDojo ajoute automatiquement le chemin d'API `/api/v2.0`.
2. Saisissez le nom d'utilisateur Harbor, ou un nom de compte robot exactement tel qu'affiché par Harbor (`robot$<name>` par défaut), dans le champ **Username**.
3. Saisissez le mot de passe ou le secret du compte robot dans le champ **Secret**. Il est envoyé via authentification HTTP Basic.
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

Chaque projet Harbor devient un Enregistrement. Pour chaque artefact ayant un scan terminé, ses vulnérabilités sont importées en tant que constatations ; le paquet/version affecté, une sévérité dérivée du CVSS, le CVE, le CWE et une remédiation (version corrigée) sont inclus lorsque Harbor les fournit. Seuls les artefacts scannés sont importés — déclenchez un scan dans Harbor pour les images qui n'ont pas encore été scannées.

## **Have I Been Pwned**

Le connecteur Have I Been Pwned (HIBP) utilise l'API REST HIBP pour signaler quels comptes des domaines de votre propre organisation sont apparus dans des fuites de données connues. DefectDojo découvre chaque domaine que vous avez vérifié auprès de HIBP et importe une constatation par fuite affectant ce domaine.

#### Prérequis

Vous aurez besoin d'une clé API Have I Been Pwned avec recherche par domaine, ce qui nécessite un abonnement de niveau **Core** ou supérieur. Vous pouvez obtenir une clé depuis votre [compte Have I Been Pwned](https://haveibeenpwned.com/API/Key).

Vous devez également **vérifier au moins un domaine** sur votre compte HIBP avant que des données de fuite soient disponibles. HIBP permet de vérifier un domaine par enregistrement DNS TXT, balise meta, téléversement de fichier ou e-mail, sous **Domain search** dans votre compte. Tant qu'aucun domaine n'est vérifié, le connecteur ne découvre aucun domaine et n'importe aucune constatation.

#### Mappages du connecteur

1. Saisissez `https://haveibeenpwned.com` dans le champ **Location**.
2. Saisissez votre clé API dans le champ **Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne seront pas importées.

DefectDojo crée un Enregistrement distinct pour chaque domaine que vous avez vérifié auprès de HIBP, et importe une constatation par fuite affectant les comptes de ce domaine. La sévérité de chaque constatation reflète le type de données exposées par la fuite, et sa description répertorie les comptes affectés sur votre domaine afin que votre équipe puisse agir.

Consultez la [documentation de l'API Have I Been Pwned](https://haveibeenpwned.com/API/v3) pour plus d'informations.

## **HCL AppScan**

Le connecteur HCL AppScan utilise l'API REST AppScan v4 pour importer les issues depuis **AppScan on Cloud (ASoC)** ou une instance auto-hébergée **AppScan 360°** (les deux partagent la même API). Il synchronise l'ensemble du compte : DefectDojo découvre chaque application et crée un Enregistrement pour chacune, puis importe les issues de cette application (DAST, SAST et IAST) en tant que constatations.

#### Prérequis

Vous aurez besoin d'une **clé API** AppScan — un Key ID et un Key Secret générés dans les paramètres de votre compte AppScan (API Key). Le connecteur les échange contre un jeton de session de courte durée à chaque exécution ; le Key ID, le Key Secret et le jeton ne sont jamais journalisés.

#### Mappages du connecteur

1. Saisissez l'URL de la console AppScan dans le champ **Location** : pour ASoC, utilisez `https://cloud.appscan.com` (ou `https://eu.cloud.appscan.com` pour la région UE) ; pour AppScan 360°, utilisez l'hôte de votre instance.
2. Définissez **Provider** sur `ASOC` pour AppScan on Cloud, ou `A360` pour une instance AppScan 360° auto-hébergée.
3. Saisissez l'**API Key ID** et l'**API Key Secret**.
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

DefectDojo mappe chaque **application** AppScan à un Enregistrement (VEP) et chaque **issue** à une constatation : le titre est le type d'issue avec son domaine / entité / cause-id / URL / chemin ajouté ; la sévérité mappe Informational → Info (Low/Medium/High/Critical sont conservées telles quelles) ; le CWE, une description étiquetée, la remédiation et l'avis, ainsi que le point de terminaison hôte/port sont repris. Les issues issues de l'analyse statique sont enregistrées comme constatations statiques et les issues dynamiques/interactives comme constatations dynamiques ; les issues ouvertes sont actives et les issues corrigées/passées sont atténuées.

Consultez la [documentation de l'API REST AppScan](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html) pour plus d'informations.

## **Intigriti**

Le connecteur Intigriti utilise l'API externe Intigriti pour les entreprises afin d'importer dans DefectDojo les **soumissions** de bug bounty / pentest. Il synchronise l'ensemble du compte de l'entreprise : DefectDojo découvre chaque programme auquel le jeton peut accéder et crée un Enregistrement pour chacun, puis importe les soumissions de ce programme en tant que constatations.

#### Prérequis

Vous aurez besoin d'un **jeton API d'entreprise** Intigriti. Dans le portail entreprise Intigriti, sous **Company Settings > API** (le périmètre `company_external_api`), générez un jeton d'accès avec un accès en lecture à vos programmes et soumissions. Un jeton dédié pour DefectDojo est recommandé. Le jeton est envoyé en tant que jeton Bearer et n'est jamais journalisé.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API externe Intigriti pour les entreprises dans le champ **Location** : `https://api.intigriti.com/external/company`. L'URL doit être en HTTPS.
2. Saisissez le jeton API d'entreprise dans le champ **Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

DefectDojo mappe chaque **programme** Intigriti à un Enregistrement et chaque **soumission** à une constatation, indexée par le code de la soumission. La sévérité de la constatation suit la notation Intigriti (Exceptional/Critical → Critique, puis High/Medium/Low, sinon Informational), et l'état du cycle de vie de la soumission se mappe au statut de la constatation : les soumissions ouvertes/en triage sont actives, les soumissions acceptées sont vérifiées, et les soumissions fermées deviennent atténuées, doublon, hors périmètre, faux positif ou risque accepté selon leur motif de fermeture. La description de la constatation reprend le type de vulnérabilité du rapport, l'actif affecté, la preuve de concept et les réponses du chercheur.

Consultez la [documentation de l'API Intigriti](https://kb.intigriti.com/en/articles/6117846-intigriti-api) pour plus d'informations.

## **Intruder**

Le connecteur Intruder utilise l'[API REST Intruder](https://developers.intruder.io/) pour importer dans DefectDojo la posture de l'ensemble de votre compte. Chaque **cible** Intruder est découverte comme un Enregistrement (Produit) ; chaque **occurrence** d'une issue sur une cible devient une Constatation.

#### Mappages du connecteur

1. Laissez le champ **Location** à `https://api.intruder.io/` (le serveur API Intruder par défaut).
2. Saisissez un **jeton d'accès API** Intruder dans le champ **Secret**.

Générez un jeton d'accès dans Intruder sous **My account > API Access Tokens** (vous aurez besoin du mot de passe de votre compte pour le créer, et le jeton n'est affiché qu'une seule fois). Consultez la [documentation de l'API Intruder](https://developers.intruder.io/docs/creating-an-access-token) pour plus de détails.

Les constatations sont dérivées par occurrence : la sévérité provient de la sévérité de l'issue, les CVE et le CVSS proviennent de l'occurrence, l'emplacement provient de la cible/du port, et une occurrence mise en sommeil (snoozed) est importée comme une constatation inactive (faux positif ou risque accepté).

## **IriusRisk**

Le connecteur IriusRisk utilise un jeton API pour importer les données de modélisation de menaces de votre instance IriusRisk.

#### Prérequis

Vous aurez besoin d'un jeton API provenant de votre compte IriusRisk. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de bien distinguer l'activité automatisée des actions manuelles de l'équipe.

Pour générer un jeton API dans IriusRisk :

1. Connectez-vous à votre instance IriusRisk.
2. Accédez à votre **User Profile** dans le menu en haut à droite.
3. Sélectionnez **API Token** et générez un nouveau jeton.

Consultez la [documentation de l'API IriusRisk](https://support.iriusrisk.com/hc/en-us/categories/360001148511) pour plus d'informations.

#### Mappages du connecteur

1. Saisissez l'URL de votre instance IriusRisk dans le champ **Location URL**. Pour les instances hébergées dans le cloud, il s'agit généralement de `https://{your-subdomain}.iriusrisk.com`. Pour les installations sur site, utilisez l'URL de base de votre instance.
2. Saisissez votre **jeton API** dans le champ **Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne seront pas importées.

## **JFrog Xray**

Le connecteur JFrog Xray utilise l'API REST JFrog Xray pour récupérer les données de vulnérabilité de vos dépôts Artifactory. DefectDojo découvrira tous les dépôts de votre instance JFrog et générera des rapports de vulnérabilité via Xray, en important les constatations de façon planifiée.

#### Prérequis

Vous aurez besoin d'un jeton API ayant accès aux API Artifactory et Xray. Nous recommandons de créer un compte de service dédié pour DefectDojo. Le compte nécessite :

* Un accès en lecture aux dépôts Artifactory
* La permission de générer et consulter les rapports de vulnérabilité Xray (permission `Apply on Watches` dans Xray, ou équivalent)

#### Mappages du connecteur

1. Saisissez l'URL de base de votre instance JFrog dans le champ **Location**. Il doit s'agir de l'URL racine de votre instance JFrog, par exemple `https://your-instance.jfrog.io`. N'incluez pas de chemin final — DefectDojo construira automatiquement les chemins d'API appropriés.
2. Saisissez un **Reference Token** valide dans le champ **Secret**. Les jetons peuvent être générés sous **User Management > Access Tokens** dans l'interface JFrog Platform.
Vous devrez générer un **Reference Token** et utiliser cette valeur.

Portées de jeton requises pour JFrog Xray :

- **All Services**, car DefectDojo a besoin d'accéder à la fois aux services XRay et Artifactory
- **Manage Reports + Manage Resources** au minimum.

Par défaut, DefectDojo mappe chaque **dépôt** Artifactory comme un Enregistrement distinct. Chaque synchronisation génère un rapport de vulnérabilité complet par dépôt via Xray, de sorte que les statuts des constatations dans DefectDojo reflètent toujours l'état actuel du dépôt.

#### Filtre de dépôt (optionnel)

Par défaut, le connecteur découvre **tous** les dépôts de votre instance JFrog. Sur les instances comptant un grand nombre de dépôts — dont beaucoup peuvent ne pas être pertinents pour la revue de sécurité —, la découverte peut être limitée avec le champ optionnel **Repository Filter**, sous **Import Filters** sur le formulaire du connecteur.

Le filtre est appliqué pendant la découverte, **avant que tout travail par dépôt ne soit effectué**. Un dépôt en dehors du filtre ne coûte rien : aucun rapport Xray n'est généré pour lui et, en mode artefact, aucun de ses artefacts de premier niveau n'est énuméré. C'est donc le moyen le plus efficace de réduire à la fois le temps de synchronisation et la charge que DefectDojo impose à votre instance JFrog — plus que tout paramètre appliqué plus tard dans la synchronisation. Il est particulièrement recommandé en complément des **Artifact-Level Records** sur les grandes instances.

**Syntaxe :** une liste de clés de dépôt séparées par des virgules. Chaque entrée peut utiliser des jokers `*` :

* Une entrée contenant `*` est traitée comme un motif — `releases-*` correspond à toute clé de dépôt commençant par `releases-`, et `*docker-pr-local*` correspond à toute clé contenant `docker-pr-local`. Un `*` correspond à toute suite de caractères, y compris `/`.
* Une entrée sans `*` doit correspondre **exactement** à une clé de dépôt.
* Un dépôt est découvert s'il correspond à **n'importe quelle** entrée de la liste. Les espaces autour des virgules sont ignorés.

```
releases-*, snapshots
```

L'exemple ci-dessus découvre tous les dépôts dont la clé commence par `releases-`, plus le seul dépôt nommé exactement `snapshots`.

Remarques :

* Le filtre est une **liste d'autorisation** — une correspondance sélectionne un dépôt. Il n'existe pas de syntaxe d'exclusion ou de négation, vous ne pouvez donc pas exprimer directement « tout sauf X ».
* La correspondance est **sensible à la casse**, aussi bien pour les entrées exactes que pour les jokers. `*` est le seul caractère joker ; `?` et les plages de caractères ne sont pas pris en charge.
* **Laissez-le vide pour découvrir tous les dépôts.** Une valeur composée uniquement d'espaces ou de virgules est traitée comme vide.
* Un filtre qui ne correspond à rien ne découvre simplement rien — il n'y a pas d'erreur. Si une synchronisation ne trouve inopinément aucun dépôt, vérifiez l'entrée `repository filter scoped discovery` dans le journal du connecteur, qui indique combien de dépôts sur le total ont correspondu.
* Le champ peut être modifié après la création de la connexion.

**Modifier le filtre ultérieurement :** les dépôts qu'un filtre nouvellement restreint exclut désormais ne sont plus découverts, et leurs Enregistrements existants suivent le cycle de vie normal des produits que l'outil ne signale plus — les Enregistrements **mappés** sont marqués `MISSING` lors de la synchronisation suivante, et les Enregistrements `NEW` non mappés sont supprimés. Les constatations déjà importées dans DefectDojo ne sont pas supprimées ; le filtre régit uniquement la découverte.

#### Enregistrements au niveau des artefacts

Le bouton **Artifact-Level Records** modifie la découverte pour descendre d'un niveau sous le dépôt : chaque entrée de premier niveau sous la racine d'un dépôt (pour les dépôts Docker, chaque image ; pour les dépôts génériques, chaque fichier ou dossier de premier niveau) devient son propre Enregistrement. Chaque synchronisation génère toujours un seul rapport Xray par dépôt — DefectDojo attribue chaque vulnérabilité aux artefacts qu'elle impacte, de sorte que la charge sur votre instance JFrog n'augmente pas.

> **Vérifiez dans quel mode vous vous trouvez avant votre première synchronisation.** Artifact-Level Records est **activé par défaut pour les nouvelles installations**. Les installations antérieures à cette fonctionnalité conservent leur disposition existante au niveau du dépôt, le bouton est donc désactivé pour elles jusqu'à ce que quelqu'un l'active. Dans les deux cas, le bouton peut être modifié à tout moment — voir *Basculer une connexion existante* ci-dessous.

Avec Artifact-Level Records activé :

* Les dépôts restent des Enregistrements et deviennent des **actifs parents** : ils ne portent aucune constatation eux-mêmes, mais lorsque la fonctionnalité Asset Hierarchy est activée, DefectDojo relie automatiquement chaque actif artefact à son actif dépôt avec une relation `parent`. Les actifs peuvent alors être filtrés par parent/enfant, et les constatations remontent la hiérarchie.
* Une vulnérabilité qui impacte plusieurs artefacts est importée dans l'actif de chaque artefact affecté, de sorte que chaque actif affiche l'ensemble complet des constatations qui le concernent.
* Les constatations sont limitées à la **dernière build** de chaque artefact, de sorte que les constatations d'un artefact décrivent sa build actuelle plutôt que d'accumuler les résultats de toutes les builds que Xray a jamais analysées.
* Les relations hiérarchiques créées par le connecteur n'écrasent jamais les relations que vous avez créées manuellement. Si un actif a déjà un parent que vous avez attribué, le connecteur le laisse tel quel.
* Le jeton nécessite en plus un accès en lecture à l'API de stockage Artifactory (inclus dans les portées ci-dessus).

**Basculer une connexion existante vers Artifact-Level Records :** le bouton peut être modifié à tout moment. Lors de la synchronisation suivante, de nouveaux Enregistrements d'artefacts apparaissent pour le mappage — activez **Auto Map** sur la connexion lors du basculement pour que les constatations soient transférées sans interruption. Les actifs au niveau du dépôt cessent de recevoir des constatations et leurs constatations précédemment importées sont fermées lors de leur prochaine synchronisation (les mêmes constatations sont réimportées sous les nouveaux actifs artefacts, avec un statut actualisé) ; les notes et l'historique des anciennes constatations au niveau du dépôt restent sur l'actif dépôt. Revenir en arrière inverse ce processus : les Enregistrements de dépôt recommencent à porter des constatations (les constatations précédemment fermées se rouvrent lorsqu'elles correspondent à nouveau), et les Enregistrements d'artefacts sont marqués MISSING — leurs actifs et constatations sont conservés mais cessent d'être mis à jour, afin que vous puissiez les archiver à votre convenance.

Consultez la [documentation de l'API REST JFrog Xray](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) pour plus d'informations.

## **Jira Service Management Assets**

Le connecteur JSM Assets est un **Connecteur d'actifs** : il énumère les objets de votre espace de travail Jira Service Management Assets (anciennement Insight) et crée un Actif DefectDojo pour chaque objet, regroupés en Organisations par schéma d'objet. Aucune constatation n'est importée.

#### Prérequis

* Assets nécessite un plan **Jira Service Management Premium ou Enterprise**. Sur les plans Free ou Standard, l'API Assets répond avec `403 "Access to Assets API was denied"`, même si le reste du site fonctionne.
* Le compte Atlassian utilisé doit disposer d'un **accès produit Jira Service Management** (un siège agent) sur le site — l'accès au site seul ne suffit pas.
* Créez un jeton API Atlassian classique sur [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Nous recommandons un compte de service dédié.

#### Mappages du connecteur

1. Saisissez l'URL de votre site Atlassian dans le champ **Location** : `https://{your-site}.atlassian.net`.
2. Saisissez l'e-mail du compte Atlassian auquel appartient le jeton dans le champ **Email**.
3. Saisissez le jeton API dans le champ **Secret**.

Chaque objet Assets devient un Enregistrement nommé d'après le libellé de l'objet, regroupé par son **schéma d'objet**.

## **Kubescape**

Le connecteur Kubescape lit les résultats de posture Kubernetes (mauvaises configurations) produits par l'[opérateur Kubescape](https://kubescape.io/docs/install-operator/) directement depuis l'API Kubernetes du cluster — aucun compte SaaS ARMO n'est requis. Il lit les objets `WorkloadConfigurationScan` servis par l'API agrégée de stockage in-cluster de l'opérateur (`spdx.softwarecomposition.kubescape.io/v1beta1`). Chaque **espace de noms** Kubernetes disposant de résultats de posture est mappé à un Enregistrement (Produit) ; chaque contrôle échoué sur une charge de travail devient une Constatation.

#### Prérequis

- L'opérateur Kubescape doit être installé dans le cluster cible avec l'analyse de configuration activée (voir [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Confirmez l'existence de résultats avec `kubectl get workloadconfigurationscans -A`.
- Un **kubeconfig** accordant un accès en lecture au groupe d'API `spdx.softwarecomposition.kubescape.io` (list/get sur `workloadconfigurationscans`) pour le cluster cible.

#### Mappages du connecteur

1. Saisissez l'URL du serveur API du cluster (ou un identifiant convivial du cluster) dans le champ **Location**.
2. Collez le **kubeconfig** du cluster cible dans le champ `kubeconfig`. Vous pouvez éventuellement définir `kube_context` pour sélectionner un contexte à l'intérieur de celui-ci, et `cluster_name` pour étiqueter les Produits découverts.
3. Chaque espace de noms disposant de résultats de posture est découvert comme un Enregistrement ; mappez ceux que vous souhaitez importer vers des Produits DefectDojo.

Les constatations sont dérivées par contrôle échoué : le nom du contrôle et la charge de travail identifient la Constatation, la sévérité provient du facteur de score du contrôle, l'identifiant du contrôle devient l'identifiant de vulnérabilité, et chaque Constatation renvoie vers sa référence de contrôle à l'adresse `https://hub.armosec.io/docs/`.

## **Mend**

Le connecteur Mend (anciennement **WhiteSource**) utilise l'API Mend pour importer les constatations de sécurité de votre organisation Mend. DefectDojo crée un Enregistrement pour chaque **projet** Mend.

#### Prérequis

Vous aurez besoin d'un utilisateur (de service) Mend avec une **User Key** (un jeton d'accès personnel) et de l'**Organization UUID** de votre organisation Mend. Nous recommandons un compte de service dédié afin que l'activité automatisée soit facile à distinguer des actions manuelles de l'équipe. Trouvez l'Organization UUID dans l'application Mend sous **Administration > Organization UUID**.

#### Mappages du connecteur

1. Saisissez l'URL de l'API Mend dans le champ **Location**. Cette URL est **spécifique à la région** — utilisez l'URL de base de l'API pour la région où votre organisation Mend est hébergée.
2. Saisissez l'e-mail de connexion de l'utilisateur Mend dans le champ **Email**.
3. Saisissez votre **Organization UUID** Mend dans le champ **Organization UUID**.
4. Saisissez la **User Key** Mend dans le champ **User Key**.
5. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

## **Lacework / FortiCNAPP**

Le connecteur Lacework / FortiCNAPP utilise l'API Lacework v2 pour importer les **vulnérabilités des hôtes et des conteneurs** de l'ensemble de votre compte Lacework.

#### Prérequis

Vous aurez besoin d'une **clé API** Lacework — un identifiant de clé API et un secret, créés dans la console Lacework sous **Settings → API keys**. Le connecteur les échange contre un jeton d'accès de courte durée à chaque synchronisation ; l'identifiant de clé, le secret et le jeton ne sont jamais journalisés.

#### Mappages du connecteur

1. Saisissez l'URL de votre compte Lacework dans le champ **Location** — par exemple `https://YOUR-ACCOUNT.lacework.net` (un simple nom de compte est également accepté).
2. Saisissez l'**API Key ID** et l'**API Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

DefectDojo mappe le **compte** Lacework à un Enregistrement (le périmètre de l'ensemble du compte). Chaque vulnérabilité de **conteneur** et d'**hôte** devient une constatation : la sévérité provient de la notation propre à Lacework, le paquet et la version affectés deviennent le composant, la version corrigée devient l'atténuation, et l'image/hôte affecté est enregistré sous forme d'étiquettes. Les vulnérabilités de conteneurs sont enregistrées comme constatations statiques (scans d'image) et les vulnérabilités d'hôtes comme constatations dynamiques (scans d'hôte en cours d'exécution).

Consultez la [documentation de l'API Lacework](https://docs.lacework.net/api/v2/docs) pour plus d'informations.

## **Microsoft Defender**

Le connecteur Microsoft Defender importe les constatations de vulnérabilités des appareils depuis **Microsoft Defender Vulnerability Management (MDVM)** — une constatation par combinaison appareil / version logicielle / CVE, incluant la sévérité, le score CVSS, le niveau d'exploitabilité et les mises à jour de sécurité recommandées. DefectDojo découvre vos **groupes d'appareils** Defender et crée un Record pour chacun ; les appareils qui ne sont assignés à aucun groupe d'appareils sont regroupés sous un groupe synthétique **Unassigned**.

**Remarque :** ce Connecteur est distinct du type de scan basé sur fichier **« MSDefender Parser »**, qui importe des fichiers Defender exportés manuellement. Choisissez un seul chemin d'import par Produit afin d'éviter les constatations en double.

#### Prérequis

Votre tenant Microsoft doit disposer d'une licence active incluant les API d'export de vulnérabilités Defender : **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, ou MDE P1/P2 avec l'add\-on MDVM. (Le SKU *Add\-on* MDVM seul ne suffit pas — il nécessite Defender for Endpoint Plan 2 en dessous.)

Le connecteur s'authentifie en tant qu'**app registration** Microsoft Entra ID via le flux client credentials. Pour en créer une :

1. Dans le [portail Azure](https://portal.azure.com), ouvrez **App registrations \> New registration**. Nommez\-la (par exemple `defectdojo-connector`), laissez les valeurs par défaut, puis sélectionnez **Register**.
2. Sur la page **Overview** de l'application, notez l'**Application (client) ID** et le **Directory (tenant) ID**.
3. Ouvrez **API permissions \> Add a permission \> APIs my organization uses** et recherchez **WindowsDefenderATP**. Si elle n'apparaît pas, le backend Defender de votre tenant n'a pas encore été provisionné : vérifiez que la licence est active, ouvrez une fois [security.microsoft.com](https://security.microsoft.com), puis réessayez après quelques minutes.
4. Choisissez **Application permissions** (*et non* Delegated — les permissions Delegated n'apparaissent jamais dans le jeton de service du connecteur), développez **Vulnerability**, cochez **Vulnerability.Read.All**, puis sélectionnez **Add permissions**.
5. Sélectionnez **Grant admin consent** et confirmez. La colonne Status doit afficher une coche verte — sans cette étape, chaque appel API renvoie une erreur 403.
6. Ouvrez **Certificates & secrets \> New client secret**, définissez une expiration, et copiez immédiatement la **Value** du secret (elle n'est affichée qu'une seule fois). Le Connecteur cesse de fonctionner à l'expiration du secret, notez donc la date.

#### Correspondances du connecteur

1. Saisissez `https://api.security.microsoft.com` dans le champ **Location**.
2. Saisissez le **Directory (tenant) ID** dans le champ **Tenant ID**.
3. Saisissez l'**Application (client) ID** dans le champ **Client ID**.
4. Saisissez la valeur du secret client dans le champ **Client Secret**.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque groupe d'appareils Defender devient un Record. Microsoft régénère l'instantané de vulnérabilités que lit le connecteur environ toutes les 6 heures, et les appareils nouvellement intégrés peuvent mettre jusqu'à ~24 heures à produire leurs premières données de vulnérabilité — un tenant tout juste créé effectuera légitimement un Sync avec zéro constatation tant que les appareils n'auront pas été intégrés et évalués. L'activation de la licence elle\-même peut aussi prendre ~20 minutes ou plus avant d'atteindre l'API (les erreurs « No active license found » pendant cette fenêtre se résolvent d'elles\-mêmes).

## **Microsoft Defender for Cloud**

Le connecteur Microsoft Defender for Cloud importe les constatations de vulnérabilités de **Microsoft Defender Vulnerability Management (MDVM)** telles qu'exposées par Defender for Cloud — à la fois les constatations **serveur** (CVE du système d'exploitation et des logiciels installés sur les VM Azure) et les constatations **registre de conteneurs** (CVE des images de conteneurs), incluant la sévérité, le score CVSS, le paquet ou l'image concerné, et la remédiation. DefectDojo découvre les **abonnements** Azure que votre service principal peut lire et crée un Record pour chaque abonnement activé.

**Remarque :** ce Connecteur est distinct du connecteur **Microsoft Defender**, qui importe les constatations d'appareils depuis l'API Defender for Endpoint. Defender for Cloud est un produit Azure avec une surface d'API différente (Azure Resource Manager / Resource Graph) et un modèle de permissions différent (Azure RBAC). Exécutez celui qui correspond à l'emplacement de vos constatations — ou les deux, si vous utilisez les deux produits.

#### Prérequis

Vous avez besoin d'un ou plusieurs **abonnements Azure avec Microsoft Defender for Cloud activé**, avec les plans Defender pertinents activés pour les ressources que vous souhaitez scanner (sous **Microsoft Defender for Cloud \> Environment settings**, puis sélectionnez votre abonnement) :

* **Defender for Servers (Plan 2)** — constatations CVE du système d'exploitation et des logiciels des VM Azure (scan de vulnérabilités sans agent).
* **Defender for Containers** — constatations CVE des images du registre de conteneurs.

Les constatations d'évaluation de vulnérabilités SQL et de configuration/posture ne sont intentionnellement **pas** importées — ce connecteur importe uniquement les vulnérabilités CVE.

Le connecteur s'authentifie en tant qu'**app registration** Microsoft Entra ID via le flux client credentials :

1. Dans le [portail Azure](https://portal.azure.com), ouvrez **App registrations \> New registration**. Nommez\-la (par exemple `defectdojo-connector`), laissez les valeurs par défaut, puis sélectionnez **Register**.
2. Sur la page **Overview** de l'application, notez l'**Application (client) ID** et le **Directory (tenant) ID**.
3. Ouvrez **Certificates & secrets \> New client secret**, définissez une expiration, et copiez immédiatement la **Value** du secret (elle n'est affichée qu'une seule fois). Le Connecteur cesse de fonctionner à l'expiration du secret, notez donc la date.
4. Accordez à l'application un accès en lecture à chaque abonnement que vous souhaitez importer : ouvrez **Subscriptions**, sélectionnez votre abonnement, puis **Access control (IAM) \> Add \> Add role assignment**. Sélectionnez le rôle **Security Reader** (ou **Reader**), et dans l'onglet **Members**, assignez\-le à l'application que vous avez créée — recherchez\-la par le **nom** ou l'**object ID** de l'application, car le sélecteur ne fait pas correspondre le client ID. Répétez l'opération pour chaque abonnement.

Contrairement au connecteur Microsoft Defender basé sur les appareils, aucune permission API ni consentement admin n'est requis : l'accès à Defender for Cloud est entièrement régi par l'attribution de rôle Azure RBAC ci\-dessus.

#### Correspondances du connecteur

1. Saisissez `https://management.azure.com` dans le champ **Location**. (Pour les clouds souverains, utilisez le endpoint ARM correspondant, par exemple `https://management.usgovcloudapi.net`.)
2. Saisissez le **Directory (tenant) ID** dans le champ **Tenant ID**.
3. Saisissez l'**Application (client) ID** dans le champ **Client ID**.
4. Saisissez la valeur du secret client dans le champ **Client Secret**.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque abonnement Azure activé devient un Record. Les constatations sont lues via Azure Resource Graph, elles apparaissent donc rapidement une fois que Defender for Cloud a scanné vos ressources — mais les scans eux\-mêmes s'exécutent selon le calendrier de Microsoft : les images du registre de conteneurs sont généralement scannées dans l'heure suivant leur push, tandis que le premier scan de vulnérabilités sans agent d'une VM peut prendre plusieurs heures. Un abonnement nouvellement activé effectuera légitimement un Sync avec zéro constatation tant que ses ressources n'auront pas été scannées.

## **MobSF**

Le connecteur MobSF utilise l'API REST de [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) pour importer les résultats d'analyse statique d'applications mobiles (APK/IPA). DefectDojo découvre chaque application scannée sur votre instance MobSF et crée un Record pour chacune, puis importe les constatations d'analyse statique de cette application.

#### Prérequis

Vous aurez besoin de votre **clé API REST** MobSF. Trouvez\-la sur la page d'accueil MobSF sous **API** (également indiquée dans la documentation MobSF comme la valeur `Authorization`). La clé est envoyée à chaque requête et n'est jamais journalisée.

#### Correspondances du connecteur

1. Saisissez l'URL de base de votre MobSF dans le champ **Location** (par exemple `https://mobsf.example.com`).
2. Dans le champ **Secret**, saisissez la clé API REST MobSF.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **application** scannée à un Record et importe ses constatations depuis le rapport JSON de MobSF, réparties sur plusieurs sections — permissions de l'application, analyse de code, certificat de signature, manifeste Android, utilisation de l'API Android et analyse binaire. Chaque constatation est étiquetée **CWE 919** (mobile), et sa sévérité provient de la notation propre à MobSF (high, warning, info, secure/good) — une permission *dangerous* est traitée comme High. Les constatations sont enregistrées comme des constatations statiques et dédupliquées sur le scan, la section, le titre, la sévérité et le chemin du fichier.

Consultez la [documentation de l'API REST MobSF](https://mobsf.github.io/docs/#/rest_api) pour plus d'informations.

## **NeuVector**

Le connecteur NeuVector utilise l'API REST du contrôleur [NeuVector](https://github.com/neuvector/neuvector) pour importer les **scans de vulnérabilités d'images** de conteneurs. DefectDojo découvre chaque image scannée par NeuVector et crée un Record pour chacune, puis importe le rapport de scan de cette image sous forme de constatations.

#### Prérequis

Vous aurez besoin d'un **nom d'utilisateur et d'un mot de passe** NeuVector pour un compte du contrôleur disposant de la permission de lire les résultats de scan. Le connecteur se connecte avec ces identifiants pour obtenir un jeton de session ; le mot de passe et le jeton ne sont jamais journalisés.

#### Correspondances du connecteur

1. Saisissez l'URL de votre contrôleur NeuVector dans le champ **Location**, en incluant le port de l'API REST — par exemple `https://neuvector.example.com:10443`.
2. Saisissez le **Username** et le **Password** du contrôleur.
3. Si votre contrôleur utilise un certificat auto\-signé, réglez **Skip TLS Verification** sur `true`.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **image** scannée à un Record et chaque **CVE** de son rapport de scan à une constatation. La sévérité provient de la notation propre à NeuVector, et le paquet et la version concernés, le score et le vecteur CVSSv3, la version corrigée (en tant que mitigation) et le lien de référence sont repris. Les constatations sont dédupliquées sur l'image, le CVE, le paquet, la version et la sévérité.

Consultez la [documentation de l'API NeuVector](https://open-docs.neuvector.com/automation/automation) pour plus d'informations.

## **Nuclei (ProjectDiscovery Cloud)**

Le connecteur Nuclei utilise l'API REST de la ProjectDiscovery Cloud Platform (PDCP) pour récupérer les résultats de scan [nuclei](https://github.com/projectdiscovery/nuclei) depuis votre compte PDCP. DefectDojo découvre chaque scan du compte et crée un Record distinct pour chaque **scan**.

#### Prérequis

Vous aurez besoin d'une **clé API** ProjectDiscovery Cloud. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de bien distinguer l'activité automatisée des actions manuelles de l'équipe. Générez une clé depuis **Settings \> API Key** dans l'interface ProjectDiscovery Cloud ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Les résultats parviennent à PDCP soit depuis des scans hébergés, soit depuis le CLI nuclei exécuté avec `-dashboard`.

#### Correspondances du connecteur

1. Saisissez l'URL de base de l'API PDCP dans le champ **Location** : `https://api.projectdiscovery.io`.
2. Saisissez votre **clé API** dans le champ **Secret**.
3. Optionnellement, saisissez un **Team ID** pour restreindre la synchronisation à un espace de travail d'équipe (trouvable sous **Settings \> Team**). Si laissé vide, DefectDojo synchronise votre espace de travail personnel.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **scan** PDCP à un Record distinct et importe les constatations de ce scan pour toutes les sévérités, y compris informationnelle.

## **OpenVAS / Greenbone**

Le connecteur OpenVAS / Greenbone importe les **constatations de vulnérabilités réseau** d'une instance Greenbone (Greenbone Community Edition ou Greenbone Enterprise). Il communique avec `gvmd` via **GMP (Greenbone Management Protocol)** — un protocole XML sur un socket TLS, et non HTTP — et synchronise l'instance entière : il énumère les **tâches** de scan et crée un produit DefectDojo pour chacune, en important les résultats du dernier rapport de chaque tâche.

#### Prérequis

Un **utilisateur GMP** Greenbone (nom d'utilisateur + mot de passe) et un accès réseau au port TLS GMP de gvmd (par défaut **9390**). La pile compose de Greenbone Community Edition expose gvmd via un socket unix ; pour l'atteindre depuis un connecteur en réseau, exécutez donc le connecteur là où il peut accéder au socket, ou exposez le port TLS GMP (par exemple un pont TLS `socat` vers `gvmd.sock`).

#### Correspondances du connecteur

1. Saisissez l'hôte gvmd dans le champ **Location** (hôte ou `host:port`).
2. Saisissez le **Username** et le **Password** GMP.
3. Optionnellement, définissez le **GMP Port** (par défaut 9390).
4. Pour le certificat auto\-signé par défaut de gvmd, fournissez soit un **CA Certificate (PEM)** pour la vérification, soit réglez **Skip TLS Verification** sur `true`.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque tâche Greenbone devient un Record. Les constatations proviennent du dernier rapport terminé de la tâche — une par `<result>`. La sévérité est tirée du niveau de menace du résultat (les niveaux informationnels `Log`/`Debug` de Greenbone sont associés à Info), avec le score CVSS numérique enregistré ; les références CVE deviennent des identifiants de vulnérabilité, la solution du NVT devient la mitigation, et l'hôte/port de chaque résultat devient un point de terminaison.

## Probely

Ce connecteur utilise l'API REST de Probely pour récupérer les données.

​**Correspondances du connecteur**

1. Saisissez l'adresse du serveur API appropriée dans le champ **Location**. (soit <https://api.us.probely.com/> soit <https://api.eu.probely.com/> )
2. Saisissez une clé API valide dans le champ **Secret**.

Vous pouvez trouver une clé API sous le menu User \> API Keys dans Probely.  
Consultez la [documentation Probely](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key) pour plus d'informations.

## Prowler

Le connecteur Prowler utilise l'API REST **Prowler App** pour importer les constatations de posture de sécurité cloud (CSPM) depuis une instance Prowler App auto\-hébergée. DefectDojo découvre chaque **provider** (compte cloud) Prowler comme un Record et importe les constatations **FAIL** du dernier scan terminé de ce provider.

#### Prérequis

Vous aurez besoin d'une instance **Prowler App** auto\-hébergée en cours d'exécution, et soit d'un e\-mail + mot de passe utilisateur (pour l'authentification JWT), soit d'une **clé API** Prowler App. Les constatations n'apparaissent qu'une fois qu'un compte cloud (AWS, GCP, Azure, Kubernetes, ...) a été connecté dans Prowler App et qu'un scan a été exécuté.

#### Correspondances du connecteur

1. Saisissez l'URL de votre Prowler App dans le champ **Location** (par exemple `https://prowler.your-company.com`).
2. Pour l'authentification JWT, saisissez l'**Email** et le **Password** de l'utilisateur Prowler App. Vous pouvez également laisser ces champs vides et saisir une **API Key** Prowler App. Si les deux sont fournis, l'e\-mail/mot de passe (JWT) est utilisé.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne sont pas importées.

DefectDojo crée un Record pour chaque provider Prowler et importe les constatations FAIL de son dernier scan terminé, en associant les sévérités Prowler aux sévérités DefectDojo, la ressource cloud concernée (ARN/resource id) comme composant, et la remédiation et le risque du contrôle dans la constatation. Les constatations mises en sourdine (muted) sont ignorées. Le compte cloud, la région et le service sont attachés en tant qu'étiquettes.

Pour plus d'informations, consultez la **[documentation de l'API Prowler App](https://api.prowler.com/api/v1/docs)**.

## Qualys

Le connecteur Qualys importe les **détections de vulnérabilités hôtes VMDR** — chacune jointe aux métadonnées de la base de connaissances Qualys (QID) — depuis la Qualys Cloud Platform. DefectDojo crée un Record pour chaque **hôte** Qualys de votre abonnement.

#### Prérequis

Un compte utilisateur Qualys avec **accès API VMDR**, et l'**URL du serveur API (platform)** de votre abonnement — celle\-ci diffère selon l'abonnement. Trouvez\-la dans l'interface Qualys sous **Help \> About**, ou sur la page [Platform Identification](https://www.qualys.com/platform-identification/) de Qualys (par exemple `https://qualysapi.qualys.com` pour US Platform 1, ou `https://qualysapi.qg2.apps.qualys.com` pour US Platform 2).

#### Correspondances du connecteur

1. Saisissez l'URL de votre serveur API Qualys dans le champ **Location** (par exemple `https://qualysapi.qualys.com`).
2. Saisissez le nom d'utilisateur API Qualys dans le champ **Username**.
3. Saisissez le mot de passe API Qualys dans le champ **Secret**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque hôte Qualys devient un Record. Les détections que Qualys a marquées **Fixed** sont exclues, de sorte qu'une réimportation clôt les constatations corrigées.

## **Quay**

Le connecteur Quay utilise l'API REST de Project Quay pour découvrir les dépôts de conteneurs et importer les rapports de vulnérabilités produits par le scanner **Clair** intégré à Quay. DefectDojo crée un Record pour chaque **dépôt** Quay et, à chaque Sync, lit le rapport de sécurité Clair du manifeste d'image de chaque tag actif.

#### Prérequis

Le scan de sécurité (Clair) doit être activé sur votre instance Quay, et vous aurez besoin d'un **jeton d'accès OAuth 2** Quay :

* Dans Quay, créez (ou ouvrez) une organisation, allez dans **Applications**, créez une application OAuth, puis **Generate Token** avec au minimum le scope **Read repositories**. Une application dédiée pour DefectDojo est recommandée.
* Le jeton est envoyé comme jeton Bearer à chaque requête et n'est jamais journalisé.

#### Correspondances du connecteur

1. Saisissez l'URL de base de votre Quay dans le champ **Location**, par exemple `https://quay.io` ou votre instance auto\-hébergée `https://quay.example.com`. L'URL doit être en HTTPS ; n'incluez pas de chemin d'API final — DefectDojo construit automatiquement les chemins d'API.
2. Saisissez le jeton d'accès OAuth dans le champ **Secret**.
3. Optionnellement, définissez un **Namespace** pour restreindre la découverte à une seule organisation ou un seul utilisateur Quay. Laissez vide pour découvrir tous les dépôts que le jeton peut lire.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **dépôt** Quay à un Record. Pour chaque dépôt, il liste les tags actifs, les déduplique vers leurs manifestes d'image uniques (un manifeste partagé par plusieurs tags est scanné une seule fois), et lit le rapport Clair de chaque manifeste. Les manifestes que Clair n'a pas terminé de scanner (par exemple une liste de manifestes multi\-architecture, ou une image encore en file d'attente) sont ignorés jusqu'à un Sync ultérieur. Chaque vulnérabilité Clair devient une constatation — le paquet concerné est le composant, la version corrigée devient la mitigation, et les sévérités **Negligible**/**Unknown** de Clair sont enregistrées comme **Informational**.

Consultez la [documentation de l'API Project Quay](https://docs.projectquay.io/api_quay.html) et la [documentation Clair](https://quay.github.io/clair/) pour plus d'informations.

## **Rapid7 InsightAppSec**

Le connecteur Rapid7 InsightAppSec importe les **constatations de vulnérabilités DAST** depuis la plateforme cloud InsightAppSec, enrichies avec les métadonnées de module d'attaque (par exemple *SQL Injection*), les scores CVSS, et les preuves collectées par le scan. DefectDojo crée un Record pour chaque **app** InsightAppSec.

**Remarque :** ce Connecteur est distinct du connecteur **Rapid7 InsightVM** ci\-dessous — InsightAppSec est le produit DAST cloud de Rapid7 sur la plateforme Insight, tandis que les constatations InsightVM proviennent de votre propre Security Console.

#### Prérequis

Un compte de la plateforme Insight avec InsightAppSec, et une **clé API** de plateforme : dans la [plateforme Rapid7 Insight](https://insight.rapid7.com), ouvrez le menu des paramètres (icône d'engrenage) \> **API Keys** et générez une **User Key** (n'importe quel rôle) ou une **Organization Key** (administrateurs de la plateforme). Copiez la clé lorsqu'elle s'affiche — elle n'est affichée qu'une seule fois.

Vous avez également besoin de votre **région** de plateforme, visible dans votre URL Insight (par exemple `us`, `us2`, `us3`, `eu`, `ca`, `au`, ou `ap`).

#### Correspondances du connecteur

1. Saisissez votre endpoint API régional dans le champ **Location** — par exemple `https://us.api.insight.rapid7.com` (remplacez `us` par votre région).
2. Saisissez la clé API de la plateforme Insight dans le champ **API Key**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque app InsightAppSec devient un Record. Seules les vulnérabilités **ouvertes** (Unreviewed ou Vérifié) sont importées — les constatations que Rapid7 a marquées Remediated, Faux positif, Ignored, ou Doublon sont exclues, de sorte qu'une réimportation les clôt dans DefectDojo. Les sévérités sont associées directement (`SAFE` et `INFORMATIONAL` sont importés comme Info).

## **Rapid7 InsightVM**

Le connecteur Rapid7 InsightVM importe les constatations de vulnérabilités d'actifs depuis votre **Security Console** InsightVM (API v3), enrichies avec le catalogue de vulnérabilités global de la console. DefectDojo crée un Record pour chaque **site** InsightVM.

#### Prérequis

Un accès réseau depuis DefectDojo vers votre Security Console, et un **compte utilisateur** de la console — son identifiant est utilisé pour l'authentification HTTP Basic. L'API de la console est servie par défaut sur le port **3780**.

#### Correspondances du connecteur

1. Saisissez l'URL de votre Security Console, port inclus, dans le champ **Location** — par exemple `https://console.example.com:3780`.
2. Saisissez le nom d'utilisateur de la console dans le champ **Username**.
3. Saisissez le mot de passe de la console dans le champ **Secret**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque site InsightVM devient un Record ; le connecteur parcourt les actifs du site et importe leurs constatations vulnérables.

## **runZero**

Le connecteur runZero utilise l'API Export de runZero pour synchroniser l'inventaire d'actifs de toute votre organisation dans DefectDojo. C'est principalement un connecteur d'**actifs** : DefectDojo découvre chaque actif et crée un Record pour chacun, regroupé en un Product Type par son **site** runZero. Il peut aussi, optionnellement, importer les vulnérabilités de runZero en tant que constatations.

#### Prérequis

Vous aurez besoin d'un **Export Token** d'organisation depuis runZero (Account → API), préfixé par `XT`. Le jeton est scopé à l'organisation (l'organisation est encodée dans le jeton), en lecture seule, et est envoyé comme jeton Bearer — il n'est jamais journalisé. Un niveau communautaire/starter est disponible.

#### Correspondances du connecteur

1. Saisissez l'URL de votre console runZero dans le champ **Location**, par exemple `https://console.runzero.com`. L'URL doit être en HTTPS.
2. Saisissez l'Export Token dans le champ **Secret**.
3. Optionnellement, réglez **Import Vulnerabilities** sur `true` pour aussi importer les vulnérabilités runZero en tant que constatations ; laissez vide pour ne synchroniser que les actifs.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations de vulnérabilité importées (s'applique uniquement lorsque les vulnérabilités sont importées).

DefectDojo associe chaque **actif** runZero à un Record (VEP) : le nom d'affichage provient du nom ou de l'adresse de l'actif, et son site, type, OS, adresses et étiquettes sont attachés en tant qu'attributs ; le **site** de l'actif devient son Product Type. Les actifs sont synchronisés via un export complet que DefectDojo réconcilie (ajouts/suppressions). Lorsque **Import Vulnerabilities** est activé, chaque vulnérabilité runZero devient une constatation sur son actif — en associant la sévérité, le score CVSS, le CVE, le point de terminaison du service concerné (`protocol://address:port`) et la remédiation.

Consultez la [documentation de l'API runZero](https://help.runzero.com/) pour plus d'informations.

## **Semgrep**

Ce connecteur utilise l'API REST de Semgrep pour récupérer les données.

#### Correspondances du connecteur

Saisissez `https://semgrep.dev/api/v1/` dans le champ **Location**.

1. Saisissez une clé API valide dans le champ **Secret**. Vous pouvez la trouver sur la page Tokens :   
​  
« Settings » dans la barre de navigation de gauche \> Tokens \> Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

Consultez la [documentation Semgrep](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list) pour plus d'informations.

## **ServiceNow CMDB**

Le connecteur ServiceNow CMDB est un **connecteur d'actifs** : au lieu d'importer des constatations, il lit les éléments de configuration (CI) de votre base de données de gestion de configuration ServiceNow et crée un Asset DefectDojo pour chaque CI, regroupé en Organizations par classe de CI. Aucune constatation n'est importée.

#### Prérequis

Vous aurez besoin d'une instance ServiceNow et d'un compte pouvant lire les tables CMDB via l'API Table de ServiceNow. Nous recommandons un compte de service dédié, en lecture seule, pour DefectDojo. Le compte a besoin d'un accès en lecture aux tables `cmdb_ci` que vous souhaitez importer.

#### Correspondances du connecteur

1. Saisissez l'URL de votre instance ServiceNow dans le champ **Location** : `https://{your-instance}.service-now.com`.
2. Sélectionnez ou créez une **Tool Configuration** ServiceNow contenant les identifiants de l'instance (le nom d'utilisateur et le mot de passe ServiceNow).

Chaque élément de configuration devient un Record nommé d'après le CI, regroupé par sa **classe de CI** (par exemple, application, serveur, ou service métier). La Discovery et le Sync réconcilient la liste des CI : les nouveaux CI apparaissent comme des Records `NEW`, et un CI supprimé de la CMDB est marqué `MISSING` au Sync suivant afin que votre équipe puisse le trier. DefectDojo ne supprime jamais un Produit silencieusement.

## **Shodan**

Le connecteur Shodan utilise l'API REST de Shodan pour importer les vulnérabilités (CVE) que Shodan a observées sur vos hôtes exposés sur Internet. Vous fournissez une requête de recherche Shodan qui limite l'import à vos propres actifs ; DefectDojo crée un Record pour chaque hôte correspondant et importe ses CVE en tant que constatations.

#### Prérequis

Vous aurez besoin d'une clé API Shodan, disponible sur votre page **Account** Shodan. La recherche d'hôtes avec données de vulnérabilité nécessite un abonnement Shodan ou un plan API payant — le niveau gratuit ne permet pas de parcourir les pages de résultats de recherche.

#### Correspondances du connecteur

1. Saisissez `https://api.shodan.io` dans le champ **Location**.
2. Saisissez votre clé API Shodan dans le champ **API Key**.
3. Dans le champ **Search Query**, saisissez une requête Shodan qui limite l'import aux actifs de votre organisation — par exemple `hostname:example.com`, `net:203.0.113.0/24`, ou `org:"Example Inc"`. Seuls les hôtes correspondant à cette requête sont importés ; veillez donc à la limiter à l'infrastructure que vous possédez.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque hôte correspondant devient un Record, et chaque CVE détecté par Shodan sur les services exposés de cet hôte est importé en tant que constatation — la sévérité est dérivée du score CVSS, avec le contexte EPSS et CISA KEV inclus lorsqu'il est disponible. Chaque page de résultats de recherche consomme un crédit de requête Shodan.

## SonarQube

Le connecteur SonarQube peut récupérer des données soit depuis un compte SonarCloud, soit depuis une instance SonarQube locale.

**Pour les utilisateurs de SonarCloud :**

1. Saisissez https://sonarcloud.io/ dans le champ Location.
2. Saisissez une **clé API** valide dans le champ Secret.

**Pour les utilisateurs de SonarQube (sur site) :**

1. Saisissez l'URL de base de votre instance SonarQube dans le champ Location : par exemple `https://my.sonarqube.com/`
2. Saisissez une **clé API** valide dans le champ Secret. Il devra s'agir d'un **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [type de jeton API](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

Le jeton devra avoir accès aux Projects, Vulnerabilities et Hotspots dans Sonar.

Les clés API peuvent être trouvées et générées via **My Account \-\> Security \-\> Generate Token** dans l'application SonarQube. Pour plus d'informations, [consultez la documentation SonarQube](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

## **Snyk**

Le connecteur Snyk utilise l'API REST de Snyk pour récupérer les données.

#### Correspondances du connecteur

1. Saisissez **[https://api.snyk.io/rest](https://api.snyk.io/v1)** ou **[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** (pour un déploiement régional EU) dans le champ **Location**.
2. Saisissez une clé API valide dans le champ **Secret**. Les jetons API se trouvent dans les **[paramètres du compte](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)** [utilisateur](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token) dans Snyk.

Consultez la [documentation de l'API Snyk](https://docs.snyk.io/snyk-api) pour plus d'informations.

## **Socket**

Le connecteur Socket utilise l'API [Socket.dev](https://socket.dev) pour importer des **constatations de sécurité de la chaîne d'approvisionnement logicielle** — les alertes de Socket sur vos dépendances (logiciels malveillants, typosquats, scripts d'installation, vulnérabilités connues et plus de 70 autres catégories). DefectDojo découvre chaque dépôt dans les organisations auxquelles votre jeton a accès et crée un Enregistrement pour chacun, puis importe les alertes du dernier scan complet de ce dépôt.

#### Prérequis

Vous aurez besoin d'un **jeton API** Socket — un jeton d'organisation créé dans le tableau de bord Socket sous **Settings → API Tokens** (avec les portées `repo:list` et de lecture des scans complets). Le jeton est envoyé en tant que jeton porteur (bearer) et n'est jamais journalisé.

#### Mappages du connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://api.socket.dev/v0`, ou saisissez-le explicitement.
2. Saisissez le jeton API Socket dans le champ **Secret**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **dépôt** à un Enregistrement et importe les alertes de son scan complet le plus récent. Chaque alerte devient une constatation : la sévérité provient de la propre notation de Socket (low, medium, high, critical), le paquet concerné devient le composant et un PURL, la catégorie de l'alerte (risque de chaîne d'approvisionnement, qualité, maintenance, vulnérabilité, licence) est enregistrée sous forme d'étiquettes, et les détails de l'alerte sont repris dans la description. Les constatations sont enregistrées comme des constatations statiques et dédupliquées sur la clé d'alerte de Socket.

Consultez la [documentation de l'API Socket](https://docs.socket.dev/reference) pour plus d'informations.

## **Sonatype IQ**

Le connecteur Sonatype IQ utilise l'API REST du serveur Sonatype IQ (Nexus Lifecycle) pour importer les vulnérabilités des composants open source. Il recense chaque application de votre organisation IQ et, pour chacune, importe les vulnérabilités de composants du dernier rapport de cette application à l'étape du cycle de vie que vous configurez. DefectDojo crée automatiquement un Enregistrement pour chaque application — il n'y a pas de configuration par application.

#### Prérequis

Vous aurez besoin d'un compte utilisateur Sonatype IQ disposant de la permission **View IQ Elements** sur les applications que vous souhaitez importer. Sonatype recommande de s'authentifier avec un **jeton utilisateur** (généré sous **My Profile > User Token** dans IQ Server) plutôt qu'avec un mot de passe ; les deux parties du jeton correspondent aux champs Username et User Token ci-dessous. Le connecteur fonctionne aussi bien avec un serveur IQ auto-hébergé qu'avec une instance hébergée par Sonatype (SaaS).

#### Mappages du connecteur

1. Dans le champ **Location**, saisissez l'URL de base de votre serveur IQ — pour un serveur auto-hébergé, `https://iq.example.com` ; pour une instance hébergée par Sonatype, `https://<tenant>.sonatype.app/platform`.
2. Saisissez l'utilisateur IQ (ou la partie code utilisateur de votre jeton utilisateur) dans le champ **Username**.
3. Saisissez le jeton utilisateur IQ (ou le mot de passe) dans le champ **User Token**.
4. Optionnellement, définissez un **Stage** pour choisir l'étape du cycle de vie dont le rapport est importé pour chaque application (`build`, `stage-release`, `release`, etc.). Laissez vide pour utiliser `build`.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque application devient un Enregistrement, et chaque problème de sécurité du dernier rapport de cette application pour l'étape sélectionnée est importé comme constatation. La sévérité est dérivée du score numérique du problème, et les références CVE, le CWE, le vecteur CVSS et l'URL de paquet (PURL) du composant concerné sont inclus lorsqu'ils sont disponibles.
## **Sysdig Secure**

Le connecteur Sysdig Secure importe des **constatations de vulnérabilité de conteneurs / CNAPP** depuis l'API de gestion des vulnérabilités de Sysdig Secure. Il synchronise l'intégralité du compte sur le ou les périmètres configurés et crée un produit DefectDojo pour chaque regroupement d'actifs analysé.

#### Prérequis

Un **jeton API** Sysdig Secure : dans Sysdig Secure, allez dans **Settings > Sysdig Secure API Token** et copiez le jeton. Vous avez également besoin de l'**URL de région** Sysdig (par exemple `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, ou votre hôte sur site).

#### Mappages du connecteur

1. Saisissez votre région/URL de base Sysdig dans le champ **Location**.
2. Saisissez le jeton API dans le champ **Secret**.
3. Optionnellement, définissez **Scopes** — une liste séparée par des virgules de `runtime`, `registry` et/ou `pipeline` (laissez vide pour `runtime`, le périmètre des charges de travail déployées).
4. Optionnellement, définissez **Runtime Product Grouping** — la façon dont les résultats runtime sont associés aux produits : `cluster`, `namespace`, `workload` ou `image` (laissez vide pour `namespace`). Les résultats registry et pipeline sont toujours regroupés par dépôt d'images.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque regroupement d'actifs devient un Enregistrement. Pour chaque résultat de scan, le connecteur importe chaque paquet vulnérable comme constatation. Les constatations **Runtime** (charges de travail déployées) sont enregistrées comme des constatations dynamiques et étiquetées avec leur contexte Kubernetes cluster / namespace / workload / conteneur ; les constatations **registry** et **pipeline** sont enregistrées comme des constatations statiques d'analyse d'image. La sévérité `NEGLIGIBLE` de Sysdig est associée à Info.

## Tenable

Le connecteur Tenable utilise l'API REST **Tenable.io** pour récupérer les données.  Les scans sont extraits du point de terminaison `/scans` de Tenable VM.

Les connecteurs Tenable sur site ne sont pas disponibles pour le moment.

#### **Mappages du connecteur**

1. Saisissez <https://cloud.tenable.com> dans le champ Location.
2. Saisissez une **clé API** valide dans le champ Secret.

Consultez la [documentation de l'API Tenable](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) pour plus d'informations.

## **Tenable Web App Scanning**

Le connecteur Tenable Web App Scanning importe des **constatations d'application web (DAST)** depuis Tenable Web App Scanning. Il s'agit d'un connecteur distinct de Tenable (Vulnerability Management) : les deux produits couvrent des actifs différents et se configurent indépendamment, vous pouvez donc utiliser l'un, l'autre, ou les deux.

DefectDojo crée un Enregistrement pour chaque **application web analysée**. Les applications sont découvertes à partir de vos configurations de scan Web App Scanning ; une configuration qui n'a jamais été exécutée ne produit pas d'Enregistrement tant que son premier scan n'est pas terminé. Lorsque plusieurs configurations analysent la même application, elles partagent un seul Enregistrement.

#### Prérequis

Des **clés API** Tenable (une clé d'accès et une clé secrète) pour un utilisateur disposant des permissions Web App Scanning. Dans Tenable, allez dans **My Account > API Keys** pour les générer, et vérifiez que l'utilisateur peut voir les scans que vous souhaitez importer — les clés limitées à Vulnerability Management ne peuvent pas lire les données de Web App Scanning.

Les connecteurs Tenable sur site ne sont pas disponibles pour le moment.

#### Mappages du connecteur

1. Saisissez <https://cloud.tenable.com> dans le champ **Location**.
2. Saisissez votre **Access Key** et votre **Secret Key**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Les constatations sont importées avec la sévérité que Tenable indique pour votre compte, y compris toute sévérité que votre équipe a reclassée. Chaque constatation porte l'URL concernée comme point de terminaison, le paramètre de requête et la charge utile qui l'ont déclenchée, ainsi que la preuve et la sortie de Tenable comme étapes de reproduction, avec les valeurs CWE, CVE, CVSS et EPSS lorsque le plugin de détection les fournit.

Seules les constatations actuellement ouvertes ou rouvertes sont importées. Une constatation que Tenable a marquée comme corrigée est fermée dans DefectDojo lors de la prochaine synchronisation.

## **Veracode**

Le connecteur Veracode importe les constatations d'application depuis la plateforme Veracode, réparties par type de scan en types de constatation **SAST**, **DAST**, **SCA** et **Manual**. DefectDojo crée un Enregistrement pour chaque **application** Veracode.

#### Prérequis

Générez un **identifiant API** Veracode pour un compte pouvant voir les applications que vous souhaitez importer : dans la plateforme Veracode, ouvrez le menu de votre compte > **API Credentials** et sélectionnez **Generate API Credentials** (voir [Gestion des identifiants API Veracode](https://docs.veracode.com/r/c_api_credentials3)). Copiez à la fois l'**API ID** et l'**API Secret Key** — la clé secrète n'est affichée qu'une seule fois.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API Veracode dans le champ **Location** : `https://api.veracode.com` (région commerciale), `https://api.veracode.eu` (région européenne), ou `https://api.veracode.us` (région fédérale américaine).
2. Saisissez l'API ID dans le champ **API ID**.
3. Saisissez la clé secrète API dans le champ **Secret**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque application Veracode devient un Enregistrement. Seules les constatations **open** sont importées, donc une réimportation ferme les constatations que Veracode signale comme résolues.

## **Wazuh**

Le connecteur Wazuh utilise le Wazuh Indexer (OpenSearch) pour récupérer les constatations de vulnérabilité. Wazuh 4.8 et versions ultérieures stockent les CVE détectées dans l'Indexer plutôt que dans l'API du serveur Wazuh ; ce connecteur les lit donc directement dans l'index `wazuh-states-vulnerabilities-*`.

DefectDojo crée un Enregistrement pour chaque agent Wazuh (point de terminaison) et importe les CVE détectées par cet agent comme constatations selon une planification.

#### Prérequis

Vous aurez besoin de :

* L'URL de base de votre Wazuh Indexer, port inclus (l'Indexer écoute par défaut sur le port 9200). DefectDojo se connecte directement à l'Indexer, ce point de terminaison doit donc être accessible depuis DefectDojo. Pour les déploiements auto-gérés, il s'agit de l'hôte exécutant le Wazuh Indexer. Pour Wazuh Cloud, utilisez le point de terminaison de l'Indexer indiqué dans votre console Wazuh Cloud, distinct de l'URL du tableau de bord Wazuh.
* Un utilisateur et un mot de passe Indexer disposant d'un accès en lecture à l'index `wazuh-states-vulnerabilities-*`. Nous recommandons de créer un utilisateur dédié pour DefectDojo.

La détection de vulnérabilités doit être activée dans Wazuh pour que l'index d'état des vulnérabilités soit alimenté. Consultez la [documentation de détection de vulnérabilités de Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) pour plus d'informations.

#### Mappages du connecteur

1. Saisissez l'URL de base de votre Wazuh Indexer dans le champ **Location**, avec le schéma et le port, par exemple `https://your-indexer.example.com:9200`. N'incluez pas de chemin final. DefectDojo construit automatiquement les chemins de recherche.
2. Saisissez le nom d'utilisateur de l'Indexer dans le champ **Username**.
3. Saisissez le mot de passe de l'Indexer dans le champ **Password**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne seront pas importées.

## Wiz

L'utilisation du connecteur Wiz nécessite la création d'un compte de service : consultez la [documentation Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) pour plus d'informations.  Vous aurez besoin d'un compte Wiz pour accéder à la documentation.

Le compte de service doit répondre à toutes les exigences suivantes. Un compte de service qui n'en respecte pas une peut tout de même s'authentifier avec succès mais n'importera rien :

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: au minimum `read:projects`, `read:issues`, et `read:vulnerabilities`.
* **Project visibility**: le compte de service doit être limité à chaque Wiz Project que vous souhaitez importer (ou à tous les Projects). Le connecteur découvre d'abord vos Wiz Projects, puis récupère les constatations de chaque Project — un compte qui peut lire les issues mais n'a de visibilité sur aucun Project ne découvre aucun Project, il n'y a donc rien à importer et aucune erreur n'est signalée par l'un ou l'autre des systèmes.

#### **Mappages du connecteur**

1. Saisissez votre Wiz Client ID dans le champ Client ID.
2. Saisissez le Wiz Client Secret dans le champ Secret.

## **YesWeHack**

Le connecteur YesWeHack utilise l'API REST de YesWeHack pour importer les rapports de vos programmes de bug bounty et de divulgation de vulnérabilités. DefectDojo crée un Enregistrement pour chaque programme auquel votre jeton a accès et importe ses rapports comme constatations.

#### Prérequis

Vous aurez besoin d'un **jeton d'accès personnel (PAT)** YesWeHack. Un accès en lecture à vos programmes suffit. Certains comptes exigent TOTP/MFA lors de la création d'un jeton ; une fois créé, c'est la valeur du jeton elle-même que le connecteur utilise.

1. Dans YesWeHack, ouvrez les paramètres de votre compte et allez dans **API / Personal Access Tokens**.
2. Créez un jeton et copiez sa valeur. Elle n'est affichée qu'une seule fois.

#### Mappages du connecteur

1. Saisissez `https://api.yeswehack.com/` dans le champ **Location**.
2. Saisissez votre jeton d'accès personnel dans le champ **Secret**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne seront pas importées.

DefectDojo crée un Enregistrement distinct pour chaque programme auquel votre jeton a accès, et importe chaque rapport comme constatation. La sévérité de la constatation est déterminée par la notation CVSS du rapport (avec repli sur la priorité de triage), et son statut reflète l'état de workflow du rapport — par exemple, les rapports résolus sont importés comme atténués, et les rapports marqués comme invalides ou hors périmètre sont importés comme inactifs.
