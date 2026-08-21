---
title: "Contrast"
description: "Comment configurer le Connecteur Upstream Contrast pour DefectDojo"
weight: 39
audience: pro
---
Le connecteur Contrast utilise l'API REST Contrast Assess pour importer les vulnérabilités des applications. DefectDojo découvre les applications de votre organisation Contrast et crée un enregistrement pour chacune d'elles.

#### Prérequis

Vous aurez besoin de quatre valeurs provenant de Contrast. Nous recommandons de créer un compte de service dédié afin que l'activité automatisée soit facile à distinguer des actions manuelles de votre équipe. Dans l'interface Contrast, sous **User Settings > Profile > Your Keys**, vous trouverez :

* Votre **API Key** d'organisation.
* Votre **Service Key** personnelle.
* Le **username** auquel appartiennent ces identifiants (l'e-mail de connexion du compte).
* Votre **Organization ID** — l'UUID de l'organisation depuis laquelle importer, également affiché sous **Organization Settings**.

#### Mappages du connecteur

1. Saisissez l'URL de base que vous utilisez pour accéder à Contrast dans le champ **Location** — pour le produit hébergé, il s'agit généralement de `https://app.contrastsecurity.com` (ou de l'URL de votre Team Server régional / auto-hébergé).
2. Saisissez l'e-mail de connexion du compte dans le champ **Username**.
3. Saisissez l'**API Key** de l'organisation dans le champ **API Key**.
4. Saisissez la **Service Key** personnelle dans le champ **Service Key**.
5. Saisissez l'**Organization ID** (UUID) dans le champ **Organization ID**.
6. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque application Contrast devient un enregistrement, et ses vulnérabilités sont importées comme constatations.
