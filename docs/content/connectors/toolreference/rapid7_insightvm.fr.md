---
title: "Rapid7 InsightVM"
description: "Comment configurer le Connecteur Upstream Rapid7 InsightVM pour DefectDojo"
weight: 113
audience: pro
---
Le connecteur Rapid7 InsightVM importe les constatations de vulnérabilités d'actifs depuis votre **Security Console** InsightVM (API v3), enrichies avec le catalogue de vulnérabilités global de la console. DefectDojo crée un Record pour chaque **site** InsightVM.

#### Prérequis

Un accès réseau depuis DefectDojo vers votre Security Console, et un **compte utilisateur** de la console — son identifiant est utilisé pour l'authentification HTTP Basic. L'API de la console est servie par défaut sur le port **3780**.

#### Correspondances du connecteur

1. Saisissez l'URL de votre Security Console, port inclus, dans le champ **Location** — par exemple `https://console.example.com:3780`.
2. Saisissez le nom d'utilisateur de la console dans le champ **Username**.
3. Saisissez le mot de passe de la console dans le champ **Secret**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque site InsightVM devient un Record ; le connecteur parcourt les actifs du site et importe leurs constatations vulnérables.
