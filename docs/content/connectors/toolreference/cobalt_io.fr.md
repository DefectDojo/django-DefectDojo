---
title: "Cobalt.io"
description: "Comment configurer le Connecteur Upstream Cobalt.io pour DefectDojo"
weight: 37
audience: pro
---
Le connecteur Cobalt.io utilise l'API Cobalt.io (v2) pour récupérer les résultats de pentest de votre organisation Cobalt.io. DefectDojo découvre chaque organisation à laquelle votre jeton d'API a accès et crée un enregistrement distinct pour chaque **actif** (l'unité que Cobalt teste).

#### Prérequis

Vous aurez besoin d'un **jeton d'API personnel** Cobalt.io. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de distinguer clairement l'activité automatisée des actions manuelles de l'équipe. Générez un jeton depuis **Settings \> API Tokens** dans l'interface Cobalt.io. Les jetons d'organisation sont découverts automatiquement \- vous n'avez pas besoin de les fournir.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API Cobalt.io dans le champ **Location** : `https://api.cobalt.io` (ou votre hôte régional, par exemple `https://api.us.cobalt.io`).
2. Saisissez votre **jeton d'API personnel** dans le champ **Secret**.
3. Facultativement, saisissez un **Organization Token** pour limiter la synchronisation à une seule organisation. Si ce champ est laissé vide, DefectDojo synchronise toutes les organisations auxquelles le jeton d'API personnel a accès.

DefectDojo associe chaque **actif** Cobalt.io à un enregistrement distinct. Les constatations sont importées pour chaque actif associé, leur état Cobalt.io (par exemple `valid_fix`, `wont_fix`, `invalid`) déterminant le statut de la constatation dans DefectDojo.
