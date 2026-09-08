---
title: "Escape"
description: "Comment configurer le Connecteur Upstream Escape pour DefectDojo"
weight: 55
audience: pro
---
Le connecteur Escape utilise l'API [Escape](https://escape.tech) pour importer des **constatations de sécurité API (DAST)**. DefectDojo énumère chaque organisation à laquelle le jeton a accès ainsi que chaque application qu'elle contient, crée un enregistrement pour chaque application ayant fait l'objet d'un scan, et importe les issues du dernier scan de cette application sous forme de constatations — il n'y a pas de configuration par application.

#### Prérequis

Vous aurez besoin d'une **API key** Escape, créée dans l'application Escape sous **Settings → API keys**. La clé est envoyée dans l'en-tête `Authorization: Key` et n'est jamais journalisée.

#### Mappages du connecteur

1. Conservez la valeur pré\-remplie du champ **Location**, `https://public.escape.tech/v2`, ou saisissez explicitement l'hôte de votre API Escape.
2. Saisissez la clé d'API Escape dans le champ **Secret**.
3. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **application** à un enregistrement et chaque **issue** de scan à une constatation : la sévérité provient de la notation d'Escape (Critical/High/Medium/Low), la CWE est reprise, la catégorie OWASP et la méthode HTTP deviennent des étiquettes, l'URL affectée devient le point de terminaison, et les recommandations de remédiation sont incluses. Les constatations sont enregistrées comme constatations dynamiques et dédupliquées sur l'identifiant d'issue Escape.

Pour plus d'informations, consultez la [documentation de l'API Escape](https://docs.escape.tech/).
