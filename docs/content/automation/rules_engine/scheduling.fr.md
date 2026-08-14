---
title: Planification des règles
description: Exécuter automatiquement les règles du Moteur de règles selon une périodicité
  récurrente ou ponctuelle
weight: 2
audience: pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : la planification du Moteur de règles est une fonctionnalité réservée à DefectDojo Pro.</span>

Les Règles peuvent être planifiées pour s'exécuter automatiquement plutôt que d'être déclenchées manuellement à chaque fois.  Une règle planifiée s'exécute sur toutes les Constatations qui correspondent à ses conditions de filtre, à l'heure configurée.

La planification est désactivée par défaut et est activée instance par instance par DefectDojo, plutôt que depuis la page Feature Flags. Contactez le [support DefectDojo](mailto:support@defectdojo.com) pour faire activer le **Service de planification** ; l'option **Planifier la règle** apparaît une fois celui-ci activé. Voir [Feature Flags](/admin/feature_flags/pro__feature_flags/) pour savoir comment sont présentées les fonctionnalités gérées de façon centralisée par DefectDojo.

L'utilisateur qui configure la planification doit disposer de la permission de configuration **Change Scheduling Service Schedule**.

## Types de planification

### Exécution unique

Une planification de type Exécution unique exécute la règle une seule fois, à une date et une heure précises.  Une fois l'exécution terminée, la planification ne se répète pas.

### Exécution répétée

Une planification de type Exécution répétée permet de déclencher une règle de façon récurrente — par exemple, tous les jours à 9h00, ou tous les lundis à 15h00.

**Remarque :** les planifications du Moteur de règles sont limitées aux quarts d'heure.  Le champ des minutes d'une planification cron doit être l'une des valeurs suivantes : **0, 15, 30 ou 45**.  Aucune autre valeur de minute n'est autorisée.

Exemples de planifications valides :
- Toutes les heures, à l'heure pile : `0 * * * *`
- Tous les jours à 9h15 : `15 9 * * *`
- Tous les lundis à 15h00 : `0 15 * * 1`
- Toutes les 15 minutes : `0,15,30,45 * * * *`

## Créer une planification pour une règle

1. Accédez à la page **Toutes les règles** depuis le menu **Moteur de règles** de la barre latérale.
2. Repérez la règle que vous souhaitez planifier, puis ouvrez son menu d'actions (**⋮**).
3. Cliquez sur **Planifier la règle**.  Cette option n'est visible que si le Service de planification est activé et que vous disposez de la permission requise.
4. Dans la fenêtre modale **Planifier la règle**, renseignez les champs suivants :

| Field | Description |
|---|---|
| **Nom** | Un nom unique pour cette planification (obligatoire, 100 caractères maximum). |
| **Description** | Description facultative de l'objet de la planification. |
| **Type de déclenchement** | Choisissez **Exécution unique** pour une exécution ponctuelle, ou **Exécution répétée** pour une planification cron récurrente. |
| **Fréquence** | Pour une Exécution répétée : utilisez le générateur cron pour sélectionner la période (horaire, quotidienne, hebdomadaire, etc.) ainsi que les valeurs précises de minute, d'heure et de jour. Pour une Exécution unique : sélectionnez une date et une heure à l'aide du sélecteur de date. |
| **Activer la planification** | Basculez pour activer ou désactiver la planification.  Une planification désactivée ne s'exécutera pas tant qu'elle n'aura pas été réactivée. |

5. Cliquez sur **Valider** pour enregistrer la planification.  La règle s'exécutera automatiquement à la prochaine heure planifiée.


## Permissions

L'accès à la planification au sein du Moteur de règles nécessite les permissions Superutilisateur ou la permission de configuration appropriée.  Voir le [tableau des permissions utilisateur](/admin/user_management/user_permission_chart) pour plus de détails.
