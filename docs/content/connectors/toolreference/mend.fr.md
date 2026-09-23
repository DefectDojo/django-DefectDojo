---
title: "Mend"
description: "Comment configurer le Connecteur Upstream Mend pour DefectDojo"
weight: 88
audience: pro
---
Le connecteur Mend (anciennement **WhiteSource**) utilise l'API Mend pour importer les constatations de sécurité de votre organisation Mend. DefectDojo crée un Enregistrement pour chaque **projet** Mend.

#### Prérequis

Vous aurez besoin d'un utilisateur (de service) Mend avec une **User Key** (un jeton d'accès personnel) et de l'**Organization UUID** de votre organisation Mend. Nous recommandons un compte de service dédié afin que l'activité automatisée soit facile à distinguer des actions manuelles de l'équipe. Trouvez l'Organization UUID dans l'application Mend sous **Administration > Organization UUID**.

#### Mappages du connecteur

1. Saisissez l'URL de l'API Mend dans le champ **Location**. Cette URL est **spécifique à la région** — utilisez l'URL de base de l'API pour la région où votre organisation Mend est hébergée.
2. Saisissez l'e-mail de connexion de l'utilisateur Mend dans le champ **Email**.
3. Saisissez votre **Organization UUID** Mend dans le champ **Organization UUID**.
4. Saisissez la **User Key** Mend dans le champ **User Key**.
5. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.
