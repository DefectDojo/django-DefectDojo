---
title: "Bugcrowd"
description: "Comment configurer le Connecteur Upstream Bugcrowd pour DefectDojo"
weight: 29
audience: pro
---
Le connecteur Bugcrowd utilise l'API REST de Bugcrowd pour importer les soumissions de vos programmes de bug bounty et de divulgation de vulnérabilités. DefectDojo découvre les programmes auxquels votre jeton API a accès et crée un Enregistrement pour chacun d'eux, en important les soumissions de ce programme sous forme de constatations.

#### Prérequis

Vous aurez besoin d'un **jeton API** Bugcrowd ayant accès aux programmes que vous souhaitez importer. Nous recommandons de créer un compte de service dédié pour DefectDojo afin que l'activité automatisée soit facile à distinguer des actions manuelles de l'équipe. Générez le jeton dans Bugcrowd sous **Organization settings \> API credentials** ; un accès en lecture aux submissions, programs et targets est suffisant.

#### Mappages du Connecteur

1. Saisissez `https://api.bugcrowd.com` dans le champ **Location**.
2. Saisissez votre jeton API Bugcrowd dans le champ **Secret**. Il est envoyé sous forme d'en-tête `Authorization: Token`.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque **programme** Bugcrowd devient un Enregistrement, et ses soumissions sont importées comme constatations en conservant la sévérité Bugcrowd. Les soumissions en doublon sont exclues, si bien qu'une réimportation ne crée pas de constatations répétées pour le même problème.
