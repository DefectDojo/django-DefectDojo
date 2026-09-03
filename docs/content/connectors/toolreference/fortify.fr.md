---
title: "Fortify"
description: "Comment configurer le Connecteur Upstream Fortify pour DefectDojo"
weight: 59
audience: pro
---
Le connecteur Fortify importe les résultats SAST/DAST de Fortify (OpenText/Micro Focus), couvrant les deux éditions qui partagent la plateforme : **SSC** (Software Security Center, auto-hébergé) et **Fortify on Demand (FoD)** (SaaS). Il synchronise l'ensemble du compte : DefectDojo découvre chaque application (version de projet SSC / release FoD) et crée un enregistrement pour chacune, puis importe les issues de cette application sous forme de constatations.

#### Prérequis

- **SSC** : un **FortifyToken** — créez-en un dans l'interface SSC sous **Administration → Token Management** (un CIToken/UnifiedLoginToken).
- **FoD** : une **clé d'API OAuth2** — un Client ID et un Client Secret depuis **Settings → API** (avec le scope `api-tenant`).

Le jeton et le secret OAuth ne sont jamais journalisés.

#### Mappages du connecteur

1. Saisissez l'URL de base de Fortify dans le champ **Location** : pour SSC, l'hôte de votre serveur (le connecteur ajoute `/ssc/api/v1`) ; pour FoD, l'hôte de l'API de votre région, par exemple `https://api.ams.fortify.com`.
2. Définissez **Edition** sur `SSC` ou `FoD`.
3. Pour **FoD**, saisissez le **Client ID** OAuth ; laissez-le vide pour SSC.
4. Dans **Token / Client Secret**, saisissez le FortifyToken SSC ou le client secret OAuth FoD.
5. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **application** Fortify à un enregistrement et chaque **issue** à une constatation : la sévérité provient de la notation **friority** propre à Fortify (Critical/High/Medium/Low), le titre combine la catégorie de l'issue avec son fichier et sa ligne, et le chemin du fichier, la ligne, le kingdom, l'analyzer et le type de moteur sont repris. Les issues provenant des moteurs d'analyse statique (SCA) sont enregistrées comme constatations statiques et les issues WebInspect (DAST) comme constatations dynamiques ; les issues supprimées, retirées ou masquées sont ignorées, les issues auditées « Not an Issue » sont marquées Faux positif, et les issues « Exploitable » / revues sont marquées Vérifié.

Pour plus d'informations, consultez la documentation de l'API [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) et [Fortify on Demand](https://api.ams.fortify.com/swagger/ui).
