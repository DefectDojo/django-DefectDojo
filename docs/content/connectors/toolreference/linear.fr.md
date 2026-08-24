---
title: "Linear"
description: "Comment configurer le Connecteur Downstream Linear pour DefectDojo"
weight: 87
audience: pro
---
L'intégration Linear vous permet de transmettre les Constatations de DefectDojo sous forme de tickets [Linear](https://linear.app/). Les tickets sont créés dans une équipe (Team) de votre espace de travail Linear.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.linear.app/graphql`.
- **API Key** doit être définie sur une clé API personnelle Linear. Les clés peuvent être générées dans Linear sous Settings, puis Security & access, puis [API](https://linear.app/settings/account/security). La clé est envoyée à l'API GraphQL de Linear dans l'en-tête `Authorization`.

### Mappage du suivi des tickets

- **Team (Group) ID** doit être défini sur l'ID de l'équipe Linear pour laquelle les tickets seront créés. Vous pouvez lister vos équipes et leurs ID en appelant l'API GraphQL de Linear :

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ teams { nodes { id name key } } }"}' https://api.linear.app/graphql
```

### Détails du mappage de la sévérité

Un ticket Linear porte une **priority** numérique plutôt qu'un champ de sévérité. Chaque sévérité DefectDojo est mappée à une priorité Linear, où `1` correspond à Urgent et `4` à Low :

- **Severity Field Name** : `Priority`
- **Info Mapping** : `4`
- **Low Mapping** : `4`
- **Medium Mapping** : `3`
- **High Mapping** : `2`
- **Critical Mapping** : `1`

### Détails du mappage du statut

Chaque valeur de statut doit être définie sur l'ID d'un Workflow State de votre équipe Linear. Les ID de Workflow State sont propres à chaque espace de travail ; il n'existe donc pas de valeurs par défaut. Vous pouvez lister les Workflow States et leurs ID en appelant l'API GraphQL de Linear :

```
curl -H "Authorization: {{API_KEY}}" -H "Content-Type: application/json" \
  -d '{"query":"{ workflowStates { nodes { id name type team { key } } } }"}' https://api.linear.app/graphql
```

- **Status Field Name** : `Workflow State ID`
- **Active Mapping** : l'ID d'un état démarré ou non démarré, par exemple `Todo` ou `In Progress`.
- **Closed Mapping** : l'ID d'un état terminé, par exemple `Done`. Lorsqu'une Constatation est supprimée dans DefectDojo, son ticket est déplacé vers cet état.
