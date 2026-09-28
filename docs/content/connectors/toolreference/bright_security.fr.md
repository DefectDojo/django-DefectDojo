---
title: "Bright Security"
description: "Comment configurer le Connecteur Upstream Bright Security pour DefectDojo"
weight: 28
audience: pro
---
Le connecteur Bright Security utilise l'API [Bright](https://brightsec.com) (anciennement NeuraLegion) pour importer des **constatations DAST**. DefectDojo découvre tous les scans auxquels le jeton a accès et crée un Enregistrement pour chaque scan terminé, puis importe les issues de ce scan sous forme de constatations.

#### Prérequis

Vous aurez besoin d'une **clé API** Bright, créée dans l'application Bright sous **User settings → API keys** (une clé `Org` ou personnelle). La clé est envoyée dans l'en-tête `Authorization: Api-Key` et n'est jamais journalisée.

#### Mappages du Connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://app.brightsec.com`, ou saisissez explicitement votre hôte Bright.
2. Saisissez la clé API Bright dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo mappe chaque **scan** terminé sur un Enregistrement et chaque **issue** sur une constatation : la sévérité provient de la notation propre à Bright (Critical/High/Medium/Low), le score CVSS, le CWE et la remédiation sont repris, le point d'entrée affecté devient le point de terminaison, et les preuves de requête/réponse sont incluses dans la description. Les constatations sont enregistrées comme des constatations dynamiques et dédupliquées sur l'ID d'issue de Bright.

Consultez la [documentation de l'API Bright](https://docs.brightsec.com/) pour plus d'informations.
