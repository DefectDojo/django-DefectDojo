---
title: "MobSF"
description: "Comment configurer le Connecteur Upstream MobSF pour DefectDojo"
weight: 91
audience: pro
---
Le connecteur MobSF utilise l'API REST de [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) pour importer les résultats d'analyse statique d'applications mobiles (APK/IPA). DefectDojo découvre chaque application scannée sur votre instance MobSF et crée un Record pour chacune, puis importe les constatations d'analyse statique de cette application.

#### Prérequis

Vous aurez besoin de votre **clé API REST** MobSF. Trouvez\-la sur la page d'accueil MobSF sous **API** (également indiquée dans la documentation MobSF comme la valeur `Authorization`). La clé est envoyée à chaque requête et n'est jamais journalisée.

#### Correspondances du connecteur

1. Saisissez l'URL de base de votre MobSF dans le champ **Location** (par exemple `https://mobsf.example.com`).
2. Dans le champ **Secret**, saisissez la clé API REST MobSF.
3. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **application** scannée à un Record et importe ses constatations depuis le rapport JSON de MobSF, réparties sur plusieurs sections — permissions de l'application, analyse de code, certificat de signature, manifeste Android, utilisation de l'API Android et analyse binaire. Chaque constatation est étiquetée **CWE 919** (mobile), et sa sévérité provient de la notation propre à MobSF (high, warning, info, secure/good) — une permission *dangerous* est traitée comme High. Les constatations sont enregistrées comme des constatations statiques et dédupliquées sur le scan, la section, le titre, la sévérité et le chemin du fichier.

Consultez la [documentation de l'API REST MobSF](https://mobsf.github.io/docs/#/rest_api) pour plus d'informations.
