---
title: "Zendesk"
description: "Comment configurer le Connecteur Downstream Zendesk pour DefectDojo"
weight: 144
audience: pro
---
L'intégration Zendesk vous permet de pousser les Constatations et Groupes de constatations DefectDojo sous forme de tickets Zendesk, affectés à un Group Zendesk de votre choix.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur l'URL de votre compte Zendesk, par exemple `https://your-subdomain.zendesk.com`.
- **Email** doit être l'adresse e-mail de l'agent Zendesk auquel appartient le jeton API.
- **API Token** doit être un jeton API Zendesk.  Un administrateur peut en créer un dans le Zendesk Admin Center sous **Apps and integrations > APIs > Zendesk API** (l'accès par jeton doit être activé).

### Correspondance du suivi des tickets

- **Group ID** doit être l'ID numérique du Group Zendesk auquel les tickets seront affectés.  Vous pouvez le trouver dans l'Admin Center sous **People > Team > Groups**, ou dans l'URL en consultant le groupe.

### Détails de la correspondance des sévérités

Ceci correspond au champ **Priority** du ticket Zendesk, qui accepte `low`, `normal`, `high` et `urgent` :

- **Severity Field Name**: `Priority`
- **Info Mapping**: `low`
- **Low Mapping**: `low`
- **Medium Mapping**: `normal`
- **High Mapping**: `high`
- **Critical Mapping**: `urgent`

### Détails de la correspondance des statuts

Les tickets Zendesk prennent en charge les statuts `new`, `open`, `pending`, `hold`, `solved` et `closed`.  Notez que `hold` doit être activé sur votre compte avant de pouvoir être utilisé.

- **Status Field Name**: `Status`
- **Active Mapping**: `new`
- **Closed Mapping**: `solved`
- **False Positive Mapping**: `solved`
- **Risk Accepted Mapping**: `pending`

Quelques comportements spécifiques à Zendesk à connaître :

- La description du ticket est le premier commentaire dans Zendesk et ne peut pas être modifiée après la création ; l'envoi d'une Constatation mise à jour synchronisera donc l'objet, la priorité et le statut du ticket, mais pas les modifications de la description.
- Les tickets sont marqués `solved` plutôt que supprimés lorsqu'une Constatation est retirée ; Zendesk ferme automatiquement les tickets solved au bout d'un certain temps.
- `closed` est un statut final - les tickets closed ne peuvent plus du tout être mis à jour, et l'envoi d'une Constatation dont le ticket est fermé génèrera une erreur.
