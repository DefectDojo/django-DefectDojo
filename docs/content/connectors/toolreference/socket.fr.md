---
title: "Socket"
description: "Comment configurer le Connecteur Upstream Socket pour DefectDojo"
weight: 126
audience: pro
---
Le connecteur Socket utilise l'API [Socket.dev](https://socket.dev) pour importer des **constatations de sécurité de la chaîne d'approvisionnement logicielle** — les alertes de Socket sur vos dépendances (logiciels malveillants, typosquats, scripts d'installation, vulnérabilités connues et plus de 70 autres catégories). DefectDojo découvre chaque dépôt dans les organisations auxquelles votre jeton a accès et crée un Enregistrement pour chacun, puis importe les alertes du dernier scan complet de ce dépôt.

#### Prérequis

Vous aurez besoin d'un **jeton API** Socket — un jeton d'organisation créé dans le tableau de bord Socket sous **Settings → API Tokens** (avec les portées `repo:list` et de lecture des scans complets). Le jeton est envoyé en tant que jeton porteur (bearer) et n'est jamais journalisé.

#### Mappages du connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://api.socket.dev/v0`, ou saisissez-le explicitement.
2. Saisissez le jeton API Socket dans le champ **Secret**.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **dépôt** à un Enregistrement et importe les alertes de son scan complet le plus récent. Chaque alerte devient une constatation : la sévérité provient de la propre notation de Socket (low, medium, high, critical), le paquet concerné devient le composant et un PURL, la catégorie de l'alerte (risque de chaîne d'approvisionnement, qualité, maintenance, vulnérabilité, licence) est enregistrée sous forme d'étiquettes, et les détails de l'alerte sont repris dans la description. Les constatations sont enregistrées comme des constatations statiques et dédupliquées sur la clé d'alerte de Socket.

Consultez la [documentation de l'API Socket](https://docs.socket.dev/reference) pour plus d'informations.
