---
title: "Fairwinds Insights"
description: "Comment configurer le Connecteur Upstream Fairwinds Insights pour DefectDojo"
weight: 56
audience: pro
---
Le connecteur Fairwinds Insights utilise l'API REST [Fairwinds Insights](https://insights.fairwinds.com) pour importer des **constatations de sécurité Kubernetes** sur l'ensemble de votre organisation. DefectDojo énumère chaque **cluster** actif et crée un enregistrement pour chacun, puis importe les **action items** de sécurité de ce cluster \(provenant de Polaris, Trivy, Kube\-bench, OPA et des autres rapports Insights\) sous forme de constatations — il n'y a pas de configuration par cluster.

#### Prérequis

Vous aurez besoin d'un nom d'**organisation** Fairwinds Insights et d'un **jeton d'API**. Créez le jeton dans l'application Insights sous **Organization Settings \> Tokens** ; un jeton `read_only` suffit. Le jeton est limité à l'organisation (org-scoped) et est envoyé comme jeton porteur (bearer token) ; il n'est jamais journalisé.

#### Mappages du connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://insights.fairwinds.com`, ou saisissez explicitement l'hôte de votre instance Insights.
2. Saisissez votre nom d'**Organization** Insights (le slug affiché dans l'URL de votre tableau de bord).
3. Saisissez le jeton d'API Insights dans le champ **Secret**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **cluster** actif à un enregistrement et chaque **action item** de sécurité à une constatation : la sévérité provient du score numérique de Fairwinds \(converti vers l'échelle Info–Critique de DefectDojo\), le rapport Fairwinds à l'origine de l'élément \(`polaris`, `trivy`, `kube-bench`, ...\) devient une étiquette d'outil, la ressource Kubernetes affectée et l'image de conteneur sont incluses, et les identifiants CVE éventuels sont extraits. Les constatations sont enregistrées comme constatations statiques et dédupliquées sur l'identifiant d'action item Fairwinds.

Pour plus d'informations, consultez la [documentation de l'API Fairwinds Insights](https://insights.docs.fairwinds.com/technical-details/api/).
