---
title: "Opsgenie"
description: "Comment configurer le Connecteur Downstream Opsgenie pour DefectDojo"
weight: 99
audience: pro
---
L'intégration Opsgenie vous permet de transmettre les Constatations et Groupes de constatations de DefectDojo sous forme d'alertes Opsgenie, éventuellement routées vers une équipe Opsgenie en tant que répondant.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.opsgenie.com`.  Si votre compte Opsgenie est hébergé dans la région de service UE, utilisez plutôt `https://api.eu.opsgenie.com`.  Si vos alertes se trouvent dans Jira Service Management Operations (Atlassian intègre progressivement Opsgenie à JSM), utilisez `https://api.atlassian.com/jsm/ops/integration`.
- **API Key** doit être définie sur une clé d'**intégration API** Opsgenie.  Un administrateur de compte peut en créer une dans l'application web Opsgenie, sous **Settings > Integrations** : ajoutez une intégration de type **API** et accordez-lui *Create and Update Access* (ainsi que *Read Access* afin que DefectDojo puisse vérifier la connexion).  Notez qu'il s'agit d'une clé d'intégration, et non d'une clé API personnelle - DefectDojo s'authentifie avec l'autorisation `GenieKey`, que seules les clés d'intégration prennent en charge.

### Mappage du suivi des tickets

- **Team Name** *(facultatif)* doit correspondre au nom de l'équipe Opsgenie à ajouter comme répondant sur les alertes créées.  Vous pouvez le laisser vide : si la clé d'intégration API est limitée à une équipe, les alertes sont routées automatiquement vers celle-ci, et sinon ce sont les règles de routage propres à votre compte qui déterminent les répondants.

### Détails du mappage de la sévérité

Les sévérités correspondent au champ **Priority** des alertes Opsgenie, qui utilise l'échelle fixe d'Opsgenie allant de `P1` (critique) à `P5` (informatif) :

- **Severity Field Name** : `Priority`
- **Info Mapping** : `P5`
- **Low Mapping** : `P4`
- **Medium Mapping** : `P3`
- **High Mapping** : `P2`
- **Critical Mapping** : `P1`

Si une sévérité est mappée à une valeur non reconnue, la priorité est omise et Opsgenie applique sa propre valeur par défaut (`P3`).

### Détails du mappage du statut

Les alertes Opsgenie sont `open` ou `closed`, et une alerte ouverte peut en outre être `acknowledged` :

- **Status Field Name** : `Status`
- **Active Mapping** : `open`
- **Closed Mapping** : `closed`
- **False Positive Mapping** : `closed`
- **Risk Accepted Mapping** : `acknowledged`

Notez que `closed` est un statut final dans Opsgenie - une alerte fermée ne peut pas être rouverte, et son alias est libéré.  Contrairement à certains autres outils, Opsgenie autorise les modifications de contenu après création ; ainsi, la transmission d'une Constatation mise à jour synchronise son message, sa description et sa priorité en plus du statut.

DefectDojo définit l'**alias** de chaque alerte sur une clé stable dérivée de la Constatation ou du Groupe de constatations, et Opsgenie dé-duplique les alertes ouvertes par alias - ainsi, retransmettre la même Constatation met à jour l'alerte ouverte existante au lieu d'en créer une nouvelle.
