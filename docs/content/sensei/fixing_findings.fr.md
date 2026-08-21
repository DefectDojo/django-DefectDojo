---
title: Corriger des constatations avec Sensei
description: Analyser, trier les candidats de correction automatique et ouvrir des
  pull requests de correction
draft: false
audience: pro
weight: 3
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Sensei est une fonctionnalité réservée à DefectDojo Pro et est actuellement en BÊTA.</span>

Une fois qu'un dépôt est intégré, Sensei apparaît directement sur vos constatations et sur le hub Sensei. Cette page couvre l'analyse d'un dépôt, le triage des candidats de correction automatique et la correction de constatations individuelles. Vous avez besoin d'au moins un accès **Writer** au produit d'une constatation pour déclencher une correction.

## Analyser un dépôt

Les analyses importent les constatations dans un engagement nommé d'après la branche. Vous pouvez déclencher une analyse à la demande depuis le hub Sensei : ouvrez les actions de ligne d'un dépôt et choisissez **Scan now**.

![Boîte de dialogue Scan with Sensei](images/scan_dialog.png)

Choisissez la branche à analyser (par défaut, la branche par défaut du dépôt) et cliquez sur **Start scan**. En mode hébergé par DefectDojo, les analyses s'exécutent aussi automatiquement à l'ouverture d'une pull request.

## La colonne Sensei sur les constatations

Les dépôts intégrés ajoutent une colonne **Sensei** au tableau des constatations. Chaque constatation affiche un bouton **Fix** (ou son statut de correction actuel), ce qui permet de corriger sans quitter votre vue de triage.

![Colonne Sensei dans le tableau des constatations](images/findings_sensei_column.png)

Le bouton a deux états :

- **Fix :** le produit de la constatation est intégré à Sensei. Cliquer dessus démarre une correction.
- **Configure Product :** le produit de la constatation n'est **pas encore** intégré. Cliquer dessus vous amène à Sensei pour intégrer un dépôt pour ce produit ; une fois l'intégration effectuée, le bouton devient **Fix**.

## Corriger une constatation unique

Cliquer sur **Fix** (dans le tableau des constatations ou dans l'en-tête de détail d'une constatation) ouvre la boîte de dialogue **Fix with Sensei**. Choisissez la branche de base que doit cibler la pull request de correction, puis cliquez sur **Fix**.

![Boîte de dialogue Fix with Sensei](images/fix_with_sensei_dialog.png)

Sensei génère une correction et ouvre une pull request. Le statut de correction de la constatation est affiché sous forme de badge qui passe de *in progress* → *PR open* (ou *failed*). Une fois la pull request ouverte, le badge y renvoie directement.

![Détail de la constatation avec badge de statut de correction](images/finding_detail_fix.png)

> **💡 Une correction, une PR :** chaque correction approuvée consomme une correction de votre quota et ouvre une pull request. Examinez et fusionnez la PR dans GitHub comme n'importe quelle autre.

## Triage des candidats de correction automatique

Lorsqu'un dépôt a les corrections automatisées activées, chaque analyse met en attente les constatations correspondantes en tant que **candidats** dans l'onglet **Auto-fix Candidates** du hub Sensei. C'est le modèle d'aperçu avant tout de Sensei : les constatations sont mises en attente, mais **rien ne s'exécute (aucun coût LLM) tant que vous n'approuvez pas**. Approuver ouvre des pull requests de correction et consomme des corrections.

![Triage des candidats de correction automatique](images/auto_fix_candidates.png)

Chaque candidat affiche la constatation, son statut, sa sévérité, son risque, sa priorité, le dépôt cible et la branche de la PR. Pour corriger :

- **Approuver un candidat :** cliquez sur **Approve** sur une ligne pour ouvrir le sélecteur de branche et démarrer cette correction.
- **Approuver plusieurs candidats :** sélectionnez plusieurs lignes et utilisez l'action d'approbation groupée.

Les constatations approuvées restent listées comme **In Progress** (ou **Failed**) jusqu'à ce que leur pull request soit rattachée, de sorte qu'une correction en cours ou échouée ne disparaît jamais avant d'avoir produit une PR.

> **🔎 Correction automatisée :** si vous avez activé *Automatically remediate candidates* sur le dépôt, une vérification en arrière-plan ouvre automatiquement des PR de correction pour les candidats en attente, jusqu'à votre quota de corrections, sans approbation manuelle.

## Suivre les analyses et leur impact

Deux emplacements du hub Sensei vous aident à suivre ce que Sensei a fait :

- **Scan Activity :** un registre de chaque exécution d'analyse et de correction, avec son mode (Branch Scan, PR Scan, Fix (Finding)), son déclencheur (Manual, Webhook, Auto Remediated), son statut, son temps d'exécution, et des liens vers l'engagement ou la pull request produite.

  ![Registre Scan Activity](images/scan_activity.png)

- **Fix Impact :** un résumé des corrections appliquées, avec les actifs les plus souvent corrigés, en haut du hub.

  ![Panneau Fix Impact](images/fix_impact.png)

Utilisez les actions de ligne **Scan now**, **Scan history**, **Configure** et **Re-stage candidates** pour gérer chaque dépôt intégré au fil du temps (voir [Référence](/sensei/sensei_reference/#repository-row-actions)).
