---
title: "Prowler"
description: "Comment configurer le Connecteur Upstream Prowler pour DefectDojo"
weight: 108
audience: pro
---
Le connecteur Prowler utilise l'API REST **Prowler App** pour importer les constatations de posture de sécurité cloud (CSPM) depuis une instance Prowler App auto\-hébergée. DefectDojo découvre chaque **provider** (compte cloud) Prowler comme un Record et importe les constatations **FAIL** du dernier scan terminé de ce provider.

#### Prérequis

Vous aurez besoin d'une instance **Prowler App** auto\-hébergée en cours d'exécution, et soit d'un e\-mail + mot de passe utilisateur (pour l'authentification JWT), soit d'une **clé API** Prowler App. Les constatations n'apparaissent qu'une fois qu'un compte cloud (AWS, GCP, Azure, Kubernetes, ...) a été connecté dans Prowler App et qu'un scan a été exécuté.

#### Correspondances du connecteur

1. Saisissez l'URL de votre Prowler App dans le champ **Location** (par exemple `https://prowler.your-company.com`).
2. Pour l'authentification JWT, saisissez l'**Email** et le **Password** de l'utilisateur Prowler App. Vous pouvez également laisser ces champs vides et saisir une **API Key** Prowler App. Si les deux sont fournis, l'e\-mail/mot de passe (JWT) est utilisé.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne sont pas importées.

DefectDojo crée un Record pour chaque provider Prowler et importe les constatations FAIL de son dernier scan terminé, en associant les sévérités Prowler aux sévérités DefectDojo, la ressource cloud concernée (ARN/resource id) comme composant, et la remédiation et le risque du contrôle dans la constatation. Les constatations mises en sourdine (muted) sont ignorées. Le compte cloud, la région et le service sont attachés en tant qu'étiquettes.

Pour plus d'informations, consultez la **[documentation de l'API Prowler App](https://api.prowler.com/api/v1/docs)**.
