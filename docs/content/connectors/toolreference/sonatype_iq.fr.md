---
title: "Sonatype IQ"
description: "Comment configurer le Connecteur Upstream Sonatype IQ pour DefectDojo"
weight: 128
audience: pro
---
Le connecteur Sonatype IQ utilise l'API REST du serveur Sonatype IQ (Nexus Lifecycle) pour importer les vulnérabilités des composants open source. Il recense chaque application de votre organisation IQ et, pour chacune, importe les vulnérabilités de composants du dernier rapport de cette application à l'étape du cycle de vie que vous configurez. DefectDojo crée automatiquement un Enregistrement pour chaque application — il n'y a pas de configuration par application.

#### Prérequis

Vous aurez besoin d'un compte utilisateur Sonatype IQ disposant de la permission **View IQ Elements** sur les applications que vous souhaitez importer. Sonatype recommande de s'authentifier avec un **jeton utilisateur** (généré sous **My Profile > User Token** dans IQ Server) plutôt qu'avec un mot de passe ; les deux parties du jeton correspondent aux champs Username et User Token ci-dessous. Le connecteur fonctionne aussi bien avec un serveur IQ auto-hébergé qu'avec une instance hébergée par Sonatype (SaaS).

#### Mappages du connecteur

1. Dans le champ **Location**, saisissez l'URL de base de votre serveur IQ — pour un serveur auto-hébergé, `https://iq.example.com` ; pour une instance hébergée par Sonatype, `https://<tenant>.sonatype.app/platform`.
2. Saisissez l'utilisateur IQ (ou la partie code utilisateur de votre jeton utilisateur) dans le champ **Username**.
3. Saisissez le jeton utilisateur IQ (ou le mot de passe) dans le champ **User Token**.
4. Optionnellement, définissez un **Stage** pour choisir l'étape du cycle de vie dont le rapport est importé pour chaque application (`build`, `stage-release`, `release`, etc.). Laissez vide pour utiliser `build`.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque application devient un Enregistrement, et chaque problème de sécurité du dernier rapport de cette application pour l'étape sélectionnée est importé comme constatation. La sévérité est dérivée du score numérique du problème, et les références CVE, le CWE, le vecteur CVSS et l'URL de paquet (PURL) du composant concerné sont inclus lorsqu'ils sont disponibles.
