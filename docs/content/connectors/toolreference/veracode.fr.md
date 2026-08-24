---
title: "Veracode"
description: "Comment configurer le Connecteur Upstream Veracode pour DefectDojo"
weight: 137
audience: pro
---
Le connecteur Veracode importe les constatations d'application depuis la plateforme Veracode, réparties par type de scan en types de constatation **SAST**, **DAST**, **SCA** et **Manual**. DefectDojo crée un Enregistrement pour chaque **application** Veracode.

#### Prérequis

Générez un **identifiant API** Veracode pour un compte pouvant voir les applications que vous souhaitez importer : dans la plateforme Veracode, ouvrez le menu de votre compte > **API Credentials** et sélectionnez **Generate API Credentials** (voir [Gestion des identifiants API Veracode](https://docs.veracode.com/r/c_api_credentials3)). Copiez à la fois l'**API ID** et l'**API Secret Key** — la clé secrète n'est affichée qu'une seule fois.

#### Mappages du connecteur

1. Saisissez l'URL de base de l'API Veracode dans le champ **Location** : `https://api.veracode.com` (région commerciale), `https://api.veracode.eu` (région européenne), ou `https://api.veracode.us` (région fédérale américaine).
2. Saisissez l'API ID dans le champ **API ID**.
3. Saisissez la clé secrète API dans le champ **Secret**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque application Veracode devient un Enregistrement. Seules les constatations **open** sont importées, donc une réimportation ferme les constatations que Veracode signale comme résolues.
