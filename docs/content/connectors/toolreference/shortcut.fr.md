---
title: "Shortcut"
description: "Comment configurer le Connecteur Downstream Shortcut pour DefectDojo"
weight: 124
audience: pro
---
L'intégration Shortcut vous permet de pousser les Constatations DefectDojo sous forme de Stories [Shortcut](https://www.shortcut.com/). Les Stories sont créées avec le type Bug et affectées à une Team de votre espace de travail Shortcut.

### Configuration de l'instance

- **Label** doit être l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.app.shortcut.com`.
- **API Token** doit être un jeton API Shortcut. Les jetons peuvent être générés dans Shortcut sous Settings, puis Your Account, puis [API Tokens](https://app.shortcut.com/settings/account/api-tokens).

### Correspondance du suivi des tickets

- **Team (Group) ID** doit être défini sur l'UUID de la Team Shortcut pour laquelle les Stories seront créées. Vous pouvez trouver cet UUID en ouvrant la page Team dans Shortcut et en copiant l'identifiant depuis l'URL, ou en appelant l'API Shortcut :

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/groups
```

### Détails de la correspondance des sévérités

Chaque valeur de sévérité est appliquée à la Story sous forme de label. Les labels sont créés automatiquement dans Shortcut s'ils n'existent pas déjà ; les valeurs par défaut ci-dessous peuvent donc être utilisées telles quelles, ou remplacées par des noms de label de votre choix. Lorsque la sévérité d'une Constatation change, l'ancien label de sévérité est retiré de la Story et le nouveau est ajouté.

- **Severity Field Name**: `Label`
- **Info Mapping**: `sev-info`
- **Low Mapping**: `sev-low`
- **Medium Mapping**: `sev-medium`
- **High Mapping**: `sev-high`
- **Critical Mapping**: `sev-critical`

### Détails de la correspondance des statuts

Chaque valeur de statut doit être définie sur l'ID numérique d'un Workflow State dans votre espace de travail Shortcut. Les ID de Workflow State sont propres à chaque espace de travail ; il n'y a donc pas de valeurs par défaut. Vous pouvez lister les Workflow States et leurs ID en appelant l'API Shortcut :

```
curl -H "Shortcut-Token: {{API_TOKEN}}" https://api.app.shortcut.com/api/v3/workflows
```

- **Status Field Name**: `Workflow State ID`
- **Active Mapping** : l'ID de l'état pour le travail ouvert, par exemple un état Backlog ou To Do.
- **Closed Mapping** : l'ID d'un état de type Done. Lorsqu'une Constatation est supprimée dans DefectDojo, sa Story est déplacée vers cet état.
- **False Positive Mapping** : l'ID de l'état à utiliser pour les Constatations Faux positif.
- **Risk Accepted Mapping** : l'ID de l'état à utiliser pour les Constatations Risque accepté.
