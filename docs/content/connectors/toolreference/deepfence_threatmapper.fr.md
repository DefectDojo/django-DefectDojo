---
title: "Deepfence ThreatMapper"
description: "Comment configurer le Connecteur Upstream Deepfence ThreatMapper pour DefectDojo"
weight: 46
audience: pro
---
Le connecteur Deepfence ThreatMapper utilise l'API REST de la console de gestion [ThreatMapper](https://github.com/deepfence/ThreatMapper) pour importer les résultats des **scans de vulnérabilités**. DefectDojo découvre chaque nœud scanné par ThreatMapper — une image de conteneur, un hôte ou un conteneur — et crée un enregistrement pour chacun, puis importe le scan complété le plus récent de ce nœud sous forme de constatations.

#### Prérequis

Vous aurez besoin d'un **jeton d'API** ThreatMapper, disponible dans la console sous **Settings → User Management** (la clé d'API de votre utilisateur). Le connecteur l'échange contre un jeton d'accès de courte durée à chaque synchronisation ; le jeton d'API n'est jamais journalisé.

#### Mappages du connecteur

1. Saisissez l'URL de votre console ThreatMapper dans le champ **Location** (par exemple `https://threatmapper.example.com`).
2. Dans le champ **Secret**, saisissez le jeton d'API ThreatMapper.
3. Si votre console utilise un certificat auto-signé, définissez **Skip TLS Verification** sur `true`.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **nœud** scanné à un enregistrement et chaque **CVE** de son dernier scan de vulnérabilités complété à une constatation. La sévérité provient de la notation propre à ThreatMapper, et le paquet affecté, le score CVSS, la version corrigée (utilisée comme atténuation), les liens de référence et un bloc de détails sont repris. Les constatations sont enregistrées comme constatations dynamiques et dédupliquées sur le nœud, le CVE, le paquet et le chemin du paquet.

Pour plus d'informations, consultez la [documentation ThreatMapper](https://community.deepfence.io/threatmapper/docs/v2.5/).
