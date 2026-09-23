---
title: "Group-IB ASM"
description: "Comment configurer le Connecteur Upstream Group-IB ASM pour DefectDojo"
weight: 68
audience: pro
---
Le connecteur Group-IB ASM (Attack Surface Management) utilise l'API REST Group-IB ASM pour importer dans DefectDojo les **issues** (constatations) de surface d'attaque externe. DefectDojo découvre chaque **entreprise/locataire** Group-IB comme un Enregistrement distinct et importe les issues de cette entreprise de façon planifiée et incrémentale. L'actif auquel se rapporte chaque issue (un domaine, une IP ou une URL) est rattaché à la constatation résultante en tant que **Point de terminaison**.

#### Prérequis

Vous aurez besoin de votre identifiant de connexion Group-IB ASM et d'une clé API. Nous recommandons de créer un compte de service dédié pour DefectDojo afin de pouvoir distinguer l'activité automatisée des actions manuelles de l'équipe.

Pour générer une clé API :

1. Ouvrez Group-IB Attack Surface Management, cliquez sur **Help** dans le coin inférieur gauche, puis sélectionnez **API**.
2. Cliquez sur **Generate API Key** (en haut à droite, sous votre nom d'utilisateur).
3. Saisissez votre mot de passe SSO, cliquez sur **Next**, puis cliquez sur **Copy token**.
4. Stockez la clé dans un gestionnaire de secrets et prévoyez une rotation régulière.

#### Mappages du connecteur

Group-IB ASM s'authentifie via HTTP Basic Auth, où le nom d'utilisateur est votre identifiant de connexion ASM et le mot de passe est votre clé API. **Les deux valeurs sont requises** — la clé API seule ne suffit pas.

1. Saisissez `https://asm.group-ib.com` dans le champ **Location**. Cette valeur est identique pour tous les locataires Group-IB ASM.
2. Saisissez votre identifiant de connexion ASM (généralement une adresse e-mail) dans le champ **Username**.
3. Saisissez votre clé API dans le champ **API Key** (Secret).
4. Vous pouvez éventuellement définir une **Sévérité minimale** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne sont pas importées.

DefectDojo mappe chaque **entreprise** Group-IB comme un Enregistrement distinct, en utilisant l'identifiant de l'entreprise comme identifiant. Lors de la première synchronisation, DefectDojo réimporte l'historique récent des issues ; les synchronisations suivantes sont incrémentales et ne récupèrent que les issues modifiées depuis la dernière synchronisation (suivies via l'horodatage `lastSeen` le plus récent de chaque issue).

#### Limiter à une seule entreprise (optionnel)

Par défaut, le connecteur découvre automatiquement les entreprises accessibles avec vos identifiants API (via le point de terminaison ASM `clients`) et crée un Enregistrement par entreprise. C'est la configuration recommandée et elle ne nécessite aucune configuration supplémentaire.

Si le point de terminaison `clients` n'est pas disponible pour votre locataire — par exemple lorsqu'il est réservé aux comptes partenaires/MSP —, le connecteur peut être limité à une seule entreprise en fournissant son **identifiant d'entreprise** en tant que champ spécifique à l'outil `company_id` dans la configuration du connecteur. Lorsque `company_id` est défini, DefectDojo utilise directement cette entreprise au lieu d'énumérer les entreprises. Laissez ce champ vide pour utiliser la découverte automatique.

Consultez le manuel de l'API REST Group-IB ASM (disponible dans le produit via **Help → API**) pour plus d'informations.
