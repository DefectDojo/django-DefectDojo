---
title: "Lacework / FortiCNAPP"
description: "Comment configurer le Connecteur Upstream Lacework / FortiCNAPP pour DefectDojo"
weight: 86
audience: pro
---
Le connecteur Lacework / FortiCNAPP utilise l'API Lacework v2 pour importer les **vulnérabilités des hôtes et des conteneurs** de l'ensemble de votre compte Lacework.

#### Prérequis

Vous aurez besoin d'une **clé API** Lacework — un identifiant de clé API et un secret, créés dans la console Lacework sous **Settings → API keys**. Le connecteur les échange contre un jeton d'accès de courte durée à chaque synchronisation ; l'identifiant de clé, le secret et le jeton ne sont jamais journalisés.

#### Mappages du connecteur

1. Saisissez l'URL de votre compte Lacework dans le champ **Location** — par exemple `https://YOUR-ACCOUNT.lacework.net` (un simple nom de compte est également accepté).
2. Saisissez l'**API Key ID** et l'**API Secret**.
3. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées.

DefectDojo mappe le **compte** Lacework à un Enregistrement (le périmètre de l'ensemble du compte). Chaque vulnérabilité de **conteneur** et d'**hôte** devient une constatation : la sévérité provient de la notation propre à Lacework, le paquet et la version affectés deviennent le composant, la version corrigée devient l'atténuation, et l'image/hôte affecté est enregistré sous forme d'étiquettes. Les vulnérabilités de conteneurs sont enregistrées comme constatations statiques (scans d'image) et les vulnérabilités d'hôtes comme constatations dynamiques (scans d'hôte en cours d'exécution).

Consultez la [documentation de l'API Lacework](https://docs.lacework.net/api/v2/docs) pour plus d'informations.
