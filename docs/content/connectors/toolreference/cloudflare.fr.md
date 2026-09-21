---
title: "Cloudflare"
description: "Comment configurer le Connecteur Upstream Cloudflare pour DefectDojo"
weight: 36
audience: pro
---
Le connecteur Cloudflare importe les **insights Security Center** — des problèmes de posture de sécurité que Cloudflare signale sur votre compte et vos zones, comme un enregistrement DMARC manquant, le DNSSEC non activé, ou un problème de certificat. DefectDojo crée un Enregistrement pour chaque zone (domaine) ayant des insights ouverts, ainsi qu'un Enregistrement au niveau du compte pour les insights qui ne sont liés à aucune zone spécifique.

#### Prérequis

Vous aurez besoin d'un **jeton API** Cloudflare (et non de l'ancienne Global API Key). Créez-en un sous **My Profile > API Tokens > Create Token** dans le tableau de bord Cloudflare. L'option la plus rapide est le modèle **« Read all resources »** ; pour un jeton à privilège minimal, accordez **Zone > Zone > Read** (toutes les zones) ainsi qu'un accès en lecture au niveau du compte pour Security Center.

#### Mappages du Connecteur

1. Saisissez `https://api.cloudflare.com/client/v4` dans le champ **Location**.
2. Saisissez le jeton API dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo découvre automatiquement les comptes et zones auxquels le jeton a accès — aucun ID de compte n'est requis. Seuls les insights ouverts (actifs, non ignorés) sont importés ; les insights que vous résolvez ou ignorez dans Cloudflare sont donc automatiquement atténués dans DefectDojo lors de la prochaine synchronisation.
