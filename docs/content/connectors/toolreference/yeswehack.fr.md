---
title: "YesWeHack"
description: "Comment configurer le Connecteur Upstream YesWeHack pour DefectDojo"
weight: 143
audience: pro
---
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
