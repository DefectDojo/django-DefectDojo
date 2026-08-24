---
title: "Akamai API Security"
description: "Comment configurer le Connecteur Upstream Akamai API Security pour DefectDojo"
weight: 13
audience: pro
---
Le connecteur Akamai API Security utilise une clé API pour récupérer les constatations de sécurité depuis l'API Akamai. DefectDojo découvre votre environnement Akamai et crée des Enregistrements distincts pour chaque **Application** et **Host** configurés dans votre compte.

#### Prérequis

Vous aurez besoin d'une clé API ayant accès à l'API Akamai. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de bien distinguer l'activité automatisée des actions manuelles de l'équipe.

#### Mappages du Connecteur

1. Saisissez l'URL de base de votre API Akamai dans le champ **Location**. Cette URL est spécifique à votre instance Akamai : par exemple
2. Saisissez une **API Key** valide dans le champ **Secret**.

DefectDojo mappe les **Applications** et les **Hosts** sous forme d'Enregistrements distincts. Chaque Application apparaîtra sous la forme `{name} (application)` et chaque Host sous la forme `{name} (host)` dans votre liste d'Enregistrements.
