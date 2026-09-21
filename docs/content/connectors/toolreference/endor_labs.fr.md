---
title: "Endor Labs"
description: "Comment configurer le Connecteur Upstream Endor Labs pour DefectDojo"
weight: 54
audience: pro
---
Le connecteur Endor Labs utilise l'API REST Endor Labs pour synchroniser un **espace de noms (namespace)** Endor Labs entier. DefectDojo découvre chaque **projet** Endor sous forme d'enregistrement et importe les constatations de ce projet, en reprenant le verdict d'**accessibilité (reachability)** d'Endor afin de vous permettre de prioriser les vulnérabilités dont le code affecté est réellement atteignable.

#### Prérequis

Vous aurez besoin d'une **API key** Endor Labs (un identifiant de clé accompagné de son secret) et de l'**espace de noms (namespace)** à synchroniser. Créez la clé dans la plateforme Endor Labs sous **Settings \> Access \> API Keys** ; la clé doit disposer d'un accès en lecture aux projets et constatations de cet espace de noms.

Le connecteur s'authentifie en échangeant la clé d'API et le secret contre un jeton porteur (bearer token) de courte durée — le secret n'est utilisé que pour cet échange et n'est jamais stocké en clair.

#### Mappages du connecteur

1. Saisissez `https://api.endorlabs.com` dans le champ **Location**. Si votre tenant est hébergé dans une autre région, utilisez plutôt l'URL de base de l'API de cette région.
2. Saisissez le **Namespace** Endor Labs à synchroniser (par exemple `your-org` ou `your-org.team`).
3. Saisissez l'identifiant de l'**API Key**.
4. Saisissez l'**API Secret** associé à la clé.
5. Facultativement, définissez **Traverse Child Namespaces** sur `true` pour importer également les constatations des espaces de noms enfants de l'espace de noms configuré.
6. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations d'une sévérité inférieure à celle sélectionnée ne sont pas importées.

DefectDojo crée un enregistrement pour chaque projet Endor Labs de l'espace de noms et importe ses constatations, en associant les niveaux de sévérité Endor aux sévérités DefectDojo, les identifiants CVE/GHSA et le score CVSS de chaque vulnérabilité, ainsi que les étiquettes d'accessibilité d'Endor. Le verdict d'accessibilité (par exemple *Reachable — vulnerable function is called* ou *Unreachable*) est présenté comme l'Impact de la constatation et comme une étiquette.

Pour plus d'informations, consultez la **[documentation de l'API REST Endor Labs](https://docs.endorlabs.com/rest-api/)**.
