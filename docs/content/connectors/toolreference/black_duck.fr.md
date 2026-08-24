---
title: "Black Duck"
description: "Comment configurer le Connecteur Upstream Black Duck pour DefectDojo"
weight: 26
audience: pro
---
Le connecteur Black Duck importe des constatations d'**analyse de composition logicielle (SCA)** depuis une instance Black Duck Hub (Synopsys / Black Duck). DefectDojo découvre tous les projets de l'instance et crée un Enregistrement pour chaque **projet** ; les constatations d'un projet proviennent des composants du BOM vulnérables de sa version sélectionnée.

#### Prérequis

Un **jeton API** Black Duck pour un utilisateur pouvant voir les projets que vous souhaitez importer. Dans Black Duck, ouvrez votre menu utilisateur \> **My Access Tokens** \> **Create New Token**, accordez-lui (au moins) un accès en lecture, et copiez le jeton lorsqu'il s'affiche — il n'est affiché qu'une seule fois. Le connecteur échange ce jeton contre un jeton porteur (bearer) de courte durée à chaque synchronisation ; il n'est jamais stocké en clair en dehors du champ secret du connecteur.

#### Mappages du Connecteur

1. Saisissez l'URL de votre hub Black Duck dans le champ **Location** — par exemple `https://your-company.app.blackduck.com`.
2. Saisissez le jeton API dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque projet Black Duck devient un Enregistrement. Par défaut, le connecteur importe la version **released** du projet (avec repli sur sa première version) ; chaque composant du BOM vulnérable de cette version devient une constatation, intitulée `{vulnerability} in {component}:{version}`.

Ce connecteur est distinct des parseurs Black Duck basés sur fichiers — ses constatations utilisent le type de scan dédié **Black Duck - Connectors Import**.
