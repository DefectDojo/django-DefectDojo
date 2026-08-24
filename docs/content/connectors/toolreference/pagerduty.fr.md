---
title: "PagerDuty"
description: "Comment configurer le Connecteur Downstream PagerDuty pour DefectDojo"
weight: 102
audience: pro
---
L'intégration PagerDuty vous permet de transmettre les Constatations et Groupes de constatations de DefectDojo sous forme d'incidents PagerDuty, ouverts sur un service PagerDuty de votre choix.

### Configuration de l'instance

- **Label** doit correspondre à l'étiquette que vous souhaitez utiliser pour identifier cette intégration.
- **Location** doit être définie sur `https://api.pagerduty.com`.  Si votre compte PagerDuty est hébergé dans la région de service UE, utilisez plutôt `https://api.eu.pagerduty.com`.
- **API Token** doit être défini sur une clé API REST PagerDuty.  Un administrateur de compte peut en créer une dans l'application web PagerDuty, sous **Integrations > API Access Keys > Create New API Key**.  Laissez « Read-only » décoché - DefectDojo doit pouvoir créer et mettre à jour des incidents.
- **From Email** doit correspondre à l'adresse e-mail d'un utilisateur valide de votre compte PagerDuty.  PagerDuty exige cette adresse lors de la création ou de la mise à jour d'incidents, et elle sera affichée comme demandeur de l'incident.

### Mappage du suivi des tickets

- **Service ID** doit correspondre à l'ID du service PagerDuty sur lequel les incidents seront ouverts.  Vous pouvez le trouver à la fin de l'URL lorsque vous consultez le service dans PagerDuty, par exemple `https://{your-subdomain}.pagerduty.com/service-directory/{service id}`.

### Détails du mappage de la sévérité

Par défaut, ceci correspond au champ **Urgency** des incidents PagerDuty, qui n'accepte que `high` ou `low` :

- **Severity Field Name** : `Urgency`
- **Info Mapping** : `low`
- **Low Mapping** : `low`
- **Medium Mapping** : `low`
- **High Mapping** : `high`
- **Critical Mapping** : `high`

Alternativement, si votre compte PagerDuty a activé les [Priorities](https://support.pagerduty.com/main/docs/incident-priority), vous pouvez mapper les sévérités aux noms de priorité à la place.  Définissez le **Severity Field Name** sur `Priority` et utilisez les noms de priorité de votre compte (par exemple de `P1` à `P5`) comme valeurs de mappage.  Lors du mappage vers Priority, l'urgence de l'incident est laissée aux propres règles d'urgence de votre service.

### Détails du mappage du statut

Les incidents PagerDuty ont trois statuts : `triggered`, `acknowledged` et `resolved`.

- **Status Field Name** : `Status`
- **Active Mapping** : `triggered`
- **Closed Mapping** : `resolved`
- **False Positive Mapping** : `resolved`
- **Risk Accepted Mapping** : `acknowledged`

Notez que `resolved` est un statut final dans PagerDuty - un incident résolu ne peut pas être rouvert.  Notez également que PagerDuty ne permet pas de modifier le titre ou la description d'un incident après sa création ; ainsi, la transmission d'une Constatation mise à jour synchronisera son statut, son urgence et sa priorité, mais pas les modifications de contenu.
