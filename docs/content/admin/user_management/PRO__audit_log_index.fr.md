---
title: Journalisation d'audit
description: Chaque action de création, de mise à jour et de suppression que DefectDojo
  enregistre dans son journal d'audit, ainsi que ce qui est capturé et comment configurer
  la rétention.
draft: false
weight: 4
---

DefectDojo enregistre une piste d'audit des modifications apportées à ses données.  Chaque objet suivi
enregistre automatiquement les événements de **création**, de **mise à jour** et de **suppression**, et les tables de relation
(many-to-many) enregistrent les événements d'**ajout** et de **retrait**.

## Fonctionnement

Le suivi d'audit est piloté par des déclencheurs (triggers) de base de données enregistrés par modèle. Pour chaque
objet suivi, trois types d'événements peuvent se déclencher :

| Type d'événement    | Quand il se déclenche                                                                 | Action     |
| ------------- | ----------------------------------------------------------------------------- | ---------- |
| `InsertEvent` | Un nouvel enregistrement est créé                                                        | **Création** |
| `UpdateEvent` | Un enregistrement change — uniquement lorsqu'une valeur de champ change réellement               | **Mise à jour** |
| `DeleteEvent` | Un enregistrement est supprimé                                                            | **Suppression** |

Les tables de relation many-to-many (étiquettes, réviseurs, plages IP de pare-feu) suivent
uniquement l'**ajout** (`InsertEvent`) et le **retrait** (`DeleteEvent`) — il n'existe pas
de « mise à jour » pour une ligne de relation.

### Ce qui est capturé à chaque événement

- **Who** — l'utilisateur à l'origine de l'action, tiré du contexte de la requête.
- **When** — un horodatage.
- **Source IP** — l'adresse distante, en tenant compte des chaînes de proxy `X-Forwarded-For`.
- **Before/after snapshot** — les valeurs complètes des champs de l'enregistrement.
- **Context / label** — regroupe les événements provenant de la même requête. L'étiquette
  `initial_backfill` marque les enregistrements historiques importés lors de l'activation initiale du
  suivi.

Les événements produits par des tâches de fond sont rattachés au contexte de la requête
d'origine, de sorte qu'une action effectuée de manière asynchrone est tout de même attribuée à l'utilisateur qui l'a déclenchée.

## Core (Open Source) — actions suivies

| Objet                         | Création | Mise à jour | Suppression | Remarques                                          |
| ------------------------------ | :----: | :----: | :----: | ---------------------------------------------- |
| Utilisateur                           |   ✅   |   ✅   |   ✅   | `password` exclu des instantanés             |
| Type de produit                   |   ✅   |   ✅   |   ✅   |                                                |
| Produit                        |   ✅   |   ✅   |   ✅   |                                                |
| Engagement                     |   ✅   |   ✅   |   ✅   |                                                |
| Test                           |   ✅   |   ✅   |   ✅   |                                                |
| Constatation                        |   ✅   |   ✅   |   ✅   |                                                |
| Groupe de constatations                  |   ✅   |   ✅   |   ✅   |                                                |
| Modèle de constatation               |   ✅   |   ✅   |   ✅   |                                                |
| Acceptation du risque                |   ✅   |   ✅   |   ✅   |                                                |
| Point de terminaison                       |   ✅   |   ✅   |   ✅   |                                                |
| Emplacement                       |   ✅   |   ✅   |   ✅   |                                                |
| URL                            |   ✅   |   ✅   |   ✅   |                                                |
| Webhook de notification           |   ✅   |   ✅   |   ✅   | `header_name` / `header_value` exclus (secrets) |

### Core — événements de relation (ajout / retrait)

| Relation                       | Ajout | Retrait |
| ---------------------------------- | :-: | :----: |
| Constatation → Réviseurs                | ✅  |   ✅   |
| Constatation → Étiquettes                     | ✅  |   ✅   |
| Constatation → Étiquettes héritées           | ✅  |   ✅   |
| Produit → Étiquettes                     | ✅  |   ✅   |
| Engagement → Étiquettes                  | ✅  |   ✅   |
| Engagement → Étiquettes héritées        | ✅  |   ✅   |
| Test → Étiquettes                        | ✅  |   ✅   |
| Test → Étiquettes héritées              | ✅  |   ✅   |
| Point de terminaison → Étiquettes                    | ✅  |   ✅   |
| Point de terminaison → Étiquettes héritées          | ✅  |   ✅   |
| Modèle de constatation → Étiquettes            | ✅  |   ✅   |
| Analyse d'application (Technologie) → Étiquettes   | ✅  |   ✅   |
| Objets/Produit → Étiquettes             | ✅  |   ✅   |

## Pro — actions suivies

| Objet                            | Création | Mise à jour | Suppression | Remarques                          |
| --------------------------------- | :----: | :----: | :----: | ------------------------------ |
| Constatation enrichie                  |   ✅   |   ✅   |   ✅   | Équivalent Pro de Finding       |
| Règle                              |   ✅   |   ✅   |   ✅   | Moteur de règles                   |
| Action de règle                       |   ✅   |   ✅   |   ✅   |                                |
| Condition d'action de règle             |   ✅   |   ✅   |   ✅   |                                |
| Entrée de filtre de règle                 |   ✅   |   ✅   |   ✅   |                                |
| Opération du moteur de règles            |   ✅   |   ✅   |   ✅   |                                |
| Message d'opération du moteur de règles    |   ✅   |   ✅   |   ✅   |                                |
| Tâche planifiée                    |   ✅   |   ✅   |   ✅   |                                |
| Exécution de tâche planifiée                |   ✅   |   ✅   |   ✅   |                                |
| Politique d'atténuation                 |   ✅   |   ✅   |   ✅   |                                |
| Paramètre ajustable                   |   ✅   |   ✅   |   ✅   | Modifications de configuration système   |
| État du feature flag                |   ✅   |   ✅   |   ✅   | Activation/désactivation du flag + épinglages système |
| Définition du feature flag           |   ✅   |   ✅   |   ✅   | Métadonnées / synchronisation du registre |
| Pare-feu cloud                    |   ✅   |   ✅   |   ✅   | champ `locked` exclu        |
| Masque IP de pare-feu                  |   ✅   |   ✅   |   ✅   |                                |

### Pro — RBAC / permissions

| Objet                        | Création | Mise à jour | Suppression |
| ----------------------------- | :----: | :----: | :----: |
| Groupe                         |   ✅   |   ✅   |   ✅   |
| Rôle                          |   ✅   |   ✅   |   ✅   |
| Appartenance au groupe              |   ✅   |   ✅   |   ✅   |
| Rôle global                   |   ✅   |   ✅   |   ✅   |
| Affectation de groupe à un Produit      |   ✅   |   ✅   |   ✅   |
| Affectation de groupe à un Type de produit |   ✅   |   ✅   |   ✅   |
| Membre du Produit               |   ✅   |   ✅   |   ✅   |
| Membre du Type de produit           |   ✅   |   ✅   |   ✅   |

### Pro — événements de relation (ajout / retrait)

| Relation                | Ajout | Retrait |
| --------------------------- | :-: | :----: |
| Pare-feu cloud → Plages IP  | ✅  |   ✅   |

## Configuration et rétention (contrôles on-premise)

| Paramètre              | Variable d'environnement                  | Valeur par défaut            | Effet                                                              |
| -------------------- | ------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Activer la journalisation d'audit | `DD_ENABLE_AUDITLOG`                  | `True`             | Lorsque défini sur `False`, tous les déclencheurs d'historique sont désactivés et aucun événement n'est enregistré |
| Période de rétention     | `DD_AUDITLOG_FLUSH_RETENTION_PERIOD`  | `-1` (jamais purgé) | Nombre de mois d'historique à conserver ; les événements plus anciens sont supprimés par lots par la tâche de purge  |
| Taille des lots de purge     | `DD_AUDITLOG_FLUSH_BATCH_SIZE`        | `1000`             | Lignes supprimées par lot pendant le nettoyage                              |
| Nombre maximal de lots de purge    | `DD_AUDITLOG_FLUSH_MAX_BATCHES`       | `100`              | Limite du nombre de lots par exécution de purge                        |

## Remarques et limites

- **Les secrets ne sont jamais capturés.** Les mots de passe des utilisateurs et les valeurs d'en-tête des
  webhooks de notification sont explicitement exclus des instantanés d'événements.
- **Les mises à jour ne sont enregistrées qu'en cas de changement réel.** Un enregistrement qui ne modifie aucune
  valeur de champ ne produit aucun événement de mise à jour ; les champs auto-gérés comme
  `last_updated` ne déclenchent pas d'événement à eux seuls.
- **Les événements d'authentification ne sont pas capturés ici.** Seules les
  modifications de données le sont. Les connexions, déconnexions et tentatives de connexion échouées sont gérées séparément et ne font pas partie de ce journal d'audit.
