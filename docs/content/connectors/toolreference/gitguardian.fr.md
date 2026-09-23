---
title: "GitGuardian"
description: "Comment configurer le Connecteur Upstream GitGuardian pour DefectDojo"
weight: 62
audience: pro
---
Le connecteur GitGuardian utilise l'API REST GitGuardian pour importer des **incidents de secrets** — des identifiants exposés que GitGuardian a détectés sur l'ensemble de vos sources surveillées. DefectDojo crée un enregistrement pour chaque source surveillée (dépôt ou périmètre) ayant actuellement des incidents ouverts, et importe chaque incident ouvert sous forme de constatation.

Pour votre sécurité, le connecteur n'importe que les **métadonnées** de l'incident — le détecteur, la sévérité, la validité, le statut, et un lien de retour vers GitGuardian. La valeur du secret exposé elle-même n'est jamais récupérée ni stockée par DefectDojo ; suivez le lien dans chaque constatation pour examiner les emplacements concernés dans GitGuardian.

#### Prérequis

Vous aurez besoin d'une clé d'API GitGuardian. Nous recommandons un **jeton de compte de service (Service Account token)** (plutôt qu'un jeton d'accès personnel) afin que l'activité automatisée soit facile à distinguer. Créez-le sous **API** dans le tableau de bord GitGuardian et accordez ces scopes en lecture :

* `incidents:read`
* `sources:read`

#### Mappages du connecteur

1. Saisissez l'URL de l'API GitGuardian dans le champ **Location** : `https://api.gitguardian.com` pour la plateforme SaaS, ou l'URL de l'API de votre instance auto-hébergée.
2. Saisissez la clé d'API dans le champ **Secret**.

Seuls les incidents à l'état **open** (statut `TRIGGERED` ou `ASSIGNED`) sont importés ; les incidents que vous résolvez ou ignorez dans GitGuardian sont automatiquement atténués dans DefectDojo lors de la prochaine synchronisation. Un secret confirmé actif (validité *valid*) est importé comme une constatation vérifiée.
