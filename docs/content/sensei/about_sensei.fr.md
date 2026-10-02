---
title: À propos de Sensei
description: Ce qu'est Sensei et comment fonctionne le scan-and-fix hébergé par DefectDojo
draft: false
audience: pro
weight: 1
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Sensei est une fonctionnalité réservée à DefectDojo Pro et est actuellement en BÊTA.</span>

**Sensei** est la fonctionnalité de **scan-and-fix** de DefectDojo basée sur l'IA pour les dépôts de code source. Connectez un dépôt (via une **GitHub App**, **GitLab**, **Bitbucket** ou **Azure DevOps**) et Sensei l'analyse, importe les résultats sous forme de constatations DefectDojo, puis utilise un grand modèle de langage pour **corriger ces constatations en ouvrant des pull/merge requests**, le tout sans quitter DefectDojo.

> **🔀 Plusieurs fournisseurs :** Sensei prend en charge **GitHub** (github.com et GitHub Enterprise Server), **GitLab** (gitlab.com et instances auto-hébergées), **Bitbucket** (Cloud et Server/Data Center), et **Azure DevOps**, tous avec le même flux de scan-and-fix. Là où ce guide indique *pull request*, GitLab utilise une **merge request** ; le *contrôle de statut* de la PR est publié comme un **commit status** GitLab/Azure ou un **build status** Bitbucket. La connexion diffère selon le fournisseur (voir [Configurer Sensei](/sensei/setup_sensei/)) ; tout ce qui suit l'intégration est identique.

- **Scan-and-fix centralisé :** les dépôts sont analysés et corrigés depuis la page Sensei et depuis vos constatations, en utilisant les mêmes données de constatations normalisées et dédupliquées que le reste de DefectDojo.
- **Aperçu avant tout :** Sensei met en attente des *candidats* de correction pour révision. Rien n'est envoyé à un LLM et aucune pull request n'est ouverte tant que vous n'avez pas approuvé, il n'y a donc ni coût surprise ni PR inattendue.
- **Identifiants à courte durée de vie :** Sensei fonctionne entièrement via une GitHub App et utilise des jetons d'installation à courte durée de vie. Il n'y a rien à coller ni à faire tourner.
- **Mesuré et soumis à licence :** Sensei est une fonctionnalité Pro avec des quotas par instance pour les corrections et les dépôts intégrés.

> **🧠 Avant même que le code existe :** Sensei génère également un modèle de menace, des chemins d'attaque et des exigences de sécurité à partir de la *conception* d'une fonctionnalité, sans qu'aucun dépôt ne soit impliqué — voir [Modélisation des menaces](/sensei/threat_modeling/).

> **🔎 BÊTA :** Sensei est en développement actif et porte la mention **BÊTA** dans toute l'interface. Le comportement et les écrans peuvent changer d'une version à l'autre.

> **📍 Où le trouver :** ouvrez **Sensei** depuis la navigation de gauche.

![Hub Sensei](images/hub_overview.png)

## Fonctionnement de l'analyse hébergée par DefectDojo

L'analyse hébergée par DefectDojo est la méthode recommandée pour exécuter Sensei. Les analyses s'exécutent **au sein de DefectDojo**, et rien n'est ajouté à votre dépôt :

1. **Connectez une GitHub App** et installez-la sur l'organisation (ou le compte) propriétaire de vos dépôts.
2. **Intégrez un dépôt** pour l'analyse hébergée et choisissez comment les constatations sont signalées et (en option) corrigées automatiquement.
3. **Sensei analyse le dépôt** (à la demande, ou automatiquement à l'ouverture d'une pull request) et importe les résultats dans un engagement nommé d'après la branche.
4. **Sensei corrige les constatations** en générant une correction et en ouvrant une pull request sur la branche par défaut du dépôt.

Chaque dépôt intégré est lié à un **actif** DefectDojo (produit), de sorte que ses constatations, engagements et corrections cohabitent avec le reste de vos données.

## Les trois façons de déclencher une correction

Sensei peut corriger une constatation de trois façons :

- **Le bouton Fix sur une constatation :** déclenchez une correction ponctuelle directement depuis le tableau des constatations ou la page de détail d'une constatation. Voir [Corriger des constatations avec Sensei](/sensei/fixing_findings/).
- **Candidats de correction automatique :** après chaque analyse, Sensei met en attente les constatations correspondant à vos critères en tant que candidats. Vous les examinez et approuvez celles à corriger (ou laissez Sensei les corriger automatiquement). Voir [Candidats de correction automatique](/sensei/fixing_findings/#auto-fix-candidate-triage).
- **Un commentaire `/fix` sur une pull request :** commentez `/fix` sur une pull request et Sensei pousse une correction vers cette PR.

## Prérequis

- Une licence **DefectDojo Pro** incluant la fonctionnalité **Sensei**.
- Un fournisseur de gestion de code source connecté (voir [Configurer Sensei](/sensei/setup_sensei/)) : une **GitHub App** (github.com ou Enterprise Server), un jeton d'accès de projet/groupe **GitLab** (gitlab.com ou auto-hébergé), une connexion **Bitbucket** (Cloud ou Server/Data Center — OAuth, jeton API ou jeton d'accès), ou un Personal Access Token **Azure DevOps**.
- Pour **configurer** Sensei (connecter des applications, intégrer des dépôts) : un rôle global **Maintainer** ou **Owner**.
- Pour **déclencher une correction** sur une constatation : au minimum un accès **Writer** au produit de cette constatation.

## Quotas

Sensei est mesuré par rapport à votre licence. Le hub Sensei affiche deux compteurs d'utilisation en haut de la page :

- **Fixes :** le nombre de corrections appliquées par rapport à votre limite prépayée. Approuver un candidat ou déclencher une correction consomme ce quota.
- **Onboarded Repositories :** le nombre de dépôts intégrés par rapport à votre limite de dépôts.

Lorsqu'un quota est atteint, Sensei bloque les corrections (ou les intégrations) suivantes jusqu'à ce qu'il soit relevé. Voir [Référence](/sensei/sensei_reference/#quotas-and-metering) pour plus de détails.
