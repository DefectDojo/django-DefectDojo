---
title: "Nuclei (ProjectDiscovery Cloud)"
description: "Comment configurer le Connecteur Upstream Nuclei (ProjectDiscovery Cloud) pour DefectDojo"
weight: 97
audience: pro
---
Le connecteur Nuclei utilise l'API REST de la ProjectDiscovery Cloud Platform (PDCP) pour récupérer les résultats de scan [nuclei](https://github.com/projectdiscovery/nuclei) depuis votre compte PDCP. DefectDojo découvre chaque scan du compte et crée un Record distinct pour chaque **scan**.

#### Prérequis

Vous aurez besoin d'une **clé API** ProjectDiscovery Cloud. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de bien distinguer l'activité automatisée des actions manuelles de l'équipe. Générez une clé depuis **Settings \> API Key** dans l'interface ProjectDiscovery Cloud ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Les résultats parviennent à PDCP soit depuis des scans hébergés, soit depuis le CLI nuclei exécuté avec `-dashboard`.

#### Correspondances du connecteur

1. Saisissez l'URL de base de l'API PDCP dans le champ **Location** : `https://api.projectdiscovery.io`.
2. Saisissez votre **clé API** dans le champ **Secret**.
3. Optionnellement, saisissez un **Team ID** pour restreindre la synchronisation à un espace de travail d'équipe (trouvable sous **Settings \> Team**). Si laissé vide, DefectDojo synchronise votre espace de travail personnel.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **scan** PDCP à un Record distinct et importe les constatations de ce scan pour toutes les sévérités, y compris informationnelle.
