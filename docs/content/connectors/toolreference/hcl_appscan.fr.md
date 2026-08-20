---
title: "HCL AppScan"
description: "Comment configurer le Connecteur Upstream HCL AppScan pour DefectDojo"
weight: 73
audience: pro
---
Le connecteur HCL AppScan utilise l'API REST AppScan v4 pour importer les issues depuis **AppScan on Cloud (ASoC)** ou une instance auto-hébergée **AppScan 360°** (les deux partagent la même API). Il synchronise l'ensemble du compte : DefectDojo découvre chaque application et crée un Enregistrement pour chacune, puis importe les issues de cette application (DAST, SAST et IAST) en tant que constatations.

#### Prérequis

Vous aurez besoin d'une **clé API** AppScan — un Key ID et un Key Secret générés dans les paramètres de votre compte AppScan (API Key). Le connecteur les échange contre un jeton de session de courte durée à chaque exécution ; le Key ID, le Key Secret et le jeton ne sont jamais journalisés.

#### Mappages du connecteur

1. Saisissez l'URL de la console AppScan dans le champ **Location** : pour ASoC, utilisez `https://cloud.appscan.com` (ou `https://eu.cloud.appscan.com` pour la région UE) ; pour AppScan 360°, utilisez l'hôte de votre instance.
2. Définissez **Provider** sur `ASOC` pour AppScan on Cloud, ou `A360` pour une instance AppScan 360° auto-hébergée.
3. Saisissez l'**API Key ID** et l'**API Key Secret**.
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

DefectDojo mappe chaque **application** AppScan à un Enregistrement (VEP) et chaque **issue** à une constatation : le titre est le type d'issue avec son domaine / entité / cause-id / URL / chemin ajouté ; la sévérité mappe Informational → Info (Low/Medium/High/Critical sont conservées telles quelles) ; le CWE, une description étiquetée, la remédiation et l'avis, ainsi que le point de terminaison hôte/port sont repris. Les issues issues de l'analyse statique sont enregistrées comme constatations statiques et les issues dynamiques/interactives comme constatations dynamiques ; les issues ouvertes sont actives et les issues corrigées/passées sont atténuées.

Consultez la [documentation de l'API REST AppScan](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html) pour plus d'informations.
