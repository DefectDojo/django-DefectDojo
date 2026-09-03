---
title: "Harbor"
description: "Comment configurer le Connecteur Upstream Harbor pour DefectDojo"
weight: 71
audience: pro
---
Le connecteur Harbor utilise l'API REST Harbor v2.0 pour importer les vulnérabilités des images de conteneurs sur l'ensemble de votre registre. DefectDojo énumère chaque **projet** Harbor et crée un Enregistrement pour chacun, puis parcourt les dépôts et artefacts du projet et importe les vulnérabilités de chaque artefact **scanné** — en conservant l'image (dépôt + tag/digest) comme contexte de la constatation. Il n'y a pas de configuration par image.

#### Prérequis

Vous aurez besoin d'un compte Harbor (ou d'un **compte robot**) disposant d'un accès pull/lecture aux projets que vous souhaitez importer. Nous recommandons un compte robot dédié : dans Harbor, ouvrez un projet (ou **Administration > Robot Accounts** pour un robot système), créez un robot avec la permission **pull** sur les dépôts et artefacts, et copiez son nom complet et son secret. Les noms de robot commencent par `robot$` par défaut, mais le préfixe est configurable selon l'instance Harbor (certaines utilisent `robot_`) — copiez le nom exactement tel qu'affiché par Harbor. Un nom d'utilisateur/mot de passe classique fonctionne aussi.

#### Mappages du connecteur

1. Saisissez votre URL Harbor dans le champ **Location** — par exemple `https://harbor.example.com`. DefectDojo ajoute automatiquement le chemin d'API `/api/v2.0`.
2. Saisissez le nom d'utilisateur Harbor, ou un nom de compte robot exactement tel qu'affiché par Harbor (`robot$<name>` par défaut), dans le champ **Username**.
3. Saisissez le mot de passe ou le secret du compte robot dans le champ **Secret**. Il est envoyé via authentification HTTP Basic.
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

Chaque projet Harbor devient un Enregistrement. Pour chaque artefact ayant un scan terminé, ses vulnérabilités sont importées en tant que constatations ; le paquet/version affecté, une sévérité dérivée du CVSS, le CVE, le CWE et une remédiation (version corrigée) sont inclus lorsque Harbor les fournit. Seuls les artefacts scannés sont importés — déclenchez un scan dans Harbor pour les images qui n'ont pas encore été scannées.
