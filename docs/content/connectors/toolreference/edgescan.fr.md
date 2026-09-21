---
title: "Edgescan"
description: "Comment configurer le Connecteur Upstream Edgescan pour DefectDojo"
weight: 52
audience: pro
---
Le connecteur Edgescan utilise l'API REST Edgescan pour importer les vulnérabilités ouvertes de l'ensemble de votre compte Edgescan. DefectDojo énumère chaque **actif** Edgescan et crée un enregistrement pour chacun, puis importe les vulnérabilités ouvertes de cet actif sous forme de constatations — il n'y a pas de configuration par actif.

#### Prérequis

Vous aurez besoin d'un jeton d'API Edgescan. Créez-en un depuis votre compte Edgescan sous **Account settings \> API tokens** : saisissez un libellé, cliquez sur **Create**, puis copiez le jeton généré (il n'est affiché qu'une seule fois). Nous recommandons un compte dédié pour le connecteur afin que l'activité automatisée soit facile à distinguer.

#### Mappages du connecteur

1. Saisissez votre URL Edgescan dans le champ **Location** — `https://live.edgescan.com` pour la plateforme hébergée standard, ou l'hôte de votre tenant si différent.
2. Saisissez votre jeton d'API Edgescan dans le champ **Secret**. Il est envoyé dans l'en-tête `X-API-TOKEN`.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque actif Edgescan devient un enregistrement, et chaque vulnérabilité ouverte sur cet actif est importée comme constatation. La sévérité est convertie de l'échelle numérique d'Edgescan (1–5) vers l'échelle Info–Critique de DefectDojo, et les références CVE, la CWE, ainsi qu'un vecteur CVSS v3 sont inclus lorsqu'Edgescan les fournit.
