---
title: "Freshservice"
description: "Comment configurer le Connecteur Downstream Freshservice pour DefectDojo"
weight: 61
audience: pro
---
L'intégration Freshservice vous permet de pousser les Constatations et Groupes de constatations DefectDojo sous forme de tickets Freshservice, affectés à un Group d'agents de votre choix.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur votre URL Freshservice : `https://yourcompany.freshservice.com`.
- **API Key** doit être une clé API Freshservice.  Trouvez-la en cliquant sur votre photo de profil (en haut à droite) > **Profile settings** - la clé apparaît à droite, sous la section **Delegate Approvals**, une fois le captcha complété.  Si aucune clé n'y est affichée, l'accès API est peut-être désactivé au niveau du compte et un administrateur doit d'abord l'activer.
- **Requester Email** doit être l'adresse e-mail au nom de laquelle les tickets sont demandés.  Freshservice exige un requester sur chaque ticket ; DefectDojo crée donc les tickets avec cette adresse comme requester.

### Correspondance du suivi des tickets

- **Group ID** doit être l'ID numérique du groupe d'agents Freshservice auquel les tickets seront affectés.  Trouvez-le dans l'URL en consultant le groupe sous **Admin > Agent Groups**.
- **Workspace ID** (facultatif) achemine les tickets vers un espace de travail spécifique sur les comptes multi-espaces.  Laissez-le vide pour utiliser l'espace de travail principal.

### Détails de la correspondance des sévérités

Ceci correspond au champ **Priority** du ticket Freshservice, qui utilise des codes numériques (`1` Low, `2` Medium, `3` High, `4` Urgent).  Les noms de priorité sont également acceptés :

- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `4`

### Détails de la correspondance des statuts

Ceci correspond au champ **Status** du ticket, qui utilise des codes numériques (`2` Open, `3` Pending, `4` Resolved, `5` Closed).  Les noms de statut sont également acceptés :

- **Status Field Name**: `Status`
- **Active Mapping**: `2`
- **Closed Mapping**: `5`
- **False Positive Mapping**: `5`
- **Risk Accepted Mapping**: `3`

Quelques comportements spécifiques à Freshservice à connaître :

- Les mises à jour synchronisent l'intégralité du contenu du ticket - Freshservice permet de modifier l'objet et la description après la création.
- Les tickets sont fermés plutôt que supprimés lorsqu'une Constatation est retirée ; les tickets déjà Resolved ou Closed restent inchangés.  Une note de résolution est jointe automatiquement à la fermeture, de sorte que les comptes qui en exigent une (une règle métier courante) acceptent la fermeture.
- Certains comptes calculent la priorité d'un ticket à partir d'une matrice Impact/Urgency ou d'une règle métier, et ignorent la priorité envoyée à la création.  DefectDojo détecte ce cas et réapplique la priorité mappée via une mise à jour de suivi, de sorte que la correspondance finit tout de même par s'appliquer.
