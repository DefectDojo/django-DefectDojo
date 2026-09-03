---
title: "Google Cloud Security Command Center"
description: "Comment configurer le Connecteur Upstream Google Cloud Security Command Center pour DefectDojo"
weight: 67
audience: pro
---
Le connecteur Google Cloud SCC utilise l'API REST Security Command Center v2 pour importer les constatations de sécurité actives de votre organisation, dossier ou projet Google Cloud. DefectDojo crée un enregistrement pour chaque **projet** Google Cloud ayant des constatations ouvertes.

#### Prérequis

Security Command Center doit être **activé** sur votre organisation (le niveau Standard est gratuit). Vous aurez ensuite besoin d'un compte de service capable de lister les constatations, ainsi que d'une clé JSON pour celui-ci :

1. Dans Google Cloud, créez un compte de service — un compte dédié pour DefectDojo est recommandé.
2. Accordez-lui le rôle **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) au niveau (organisation, dossier ou projet) que vous souhaitez importer.
3. Créez une **clé JSON** pour le compte de service et téléchargez-la.

#### Mappages du connecteur

1. Laissez le champ **Location** à sa valeur par défaut `https://securitycenter.googleapis.com`, sauf si vous utilisez un point de terminaison non standard.
2. Dans le champ **Parent Resource**, saisissez le périmètre depuis lequel importer : `organizations/{id}`, `folders/{id}`, ou `projects/{id}`.
3. Collez le contenu complet du fichier de **clé JSON** du compte de service dans le champ **Service Account Key**.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

Seules les constatations à l'état `ACTIVE` et non mises en sourdine sont importées ; les constatations que vous désactivez ou mettez en sourdine dans SCC sont donc automatiquement atténuées dans DefectDojo lors de la prochaine synchronisation. Le projet GCP affecté par chaque constatation devient son enregistrement.
