---
title: "GitHub Advanced Security"
description: "Comment configurer le Connecteur Upstream GitHub Advanced Security pour DefectDojo"
weight: 64
audience: pro
---
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
