---
title: Engagements
description: Comprendre les Engagements dans DefectDojo OS
audience: opensource
weight: 3
---

Organisations → Actifs → **ENGAGEMENTS** → Tests → Constatations 

## Aperçu 

Dans la hiérarchie des produits de DefectDojo, les Engagements sont des conteneurs limités dans le temps ou liés à un pipeline qui représentent des groupes de Tests associés au sein d’un Produit spécifique. Si vous avez prévu un effort de test planifié, que ce soit de façon routinière ou ponctuelle, un Engagement vous offre un endroit où stocker tous les résultats associés.

Voici des exemples d’Engagements : 
- Tests d’intrusion ponctuels
- Analyses mensuelles ou trimestrielles récurrentes
- Périodes de revue de bug bounty
- Exécutions de pipeline CI/CD (pour les équipes qui traitent chaque pipeline comme son propre Engagement)
- Cycles de publication de code (par exemple, « revue de sécurité de la version v4.2 »)

### Types d’Engagement 

DefectDojo prend en charge deux types d’Engagement : **Interactif** et **CI/CD**. Ces types déterminent la façon dont les Tests sont généralement créés et dont les résultats d’analyse sont importés.

Un Engagement Interactif est généralement mené par un ingénieur. Les Engagements Interactifs se concentrent sur le test d’une application pendant son exécution, à l’aide d’un test automatisé, d’un testeur humain, ou de toute activité « interagissant » avec les fonctionnalités de l’application. 

Un Engagement CI/CD sert à l’intégration automatisée avec un pipeline CI/CD. Les Engagements CI/CD sont destinés à importer des données sous forme d’action automatisée, déclenchée par une étape du processus de publication.

| **Catégorie**                | **Engagements Interactifs**                             | **Engagements CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Cas d’usage principal**   | Test de sécurité manuel ou ad hoc                            | Test de sécurité automatisé et récurrent au sein des pipelines             |
| **Durée**           | Limitée dans le temps et finie                                        | Durée potentiellement infinie                                      |
| **Fréquence**          | Périodique ou ponctuelle                                          | Continue ou par commit                                             |
| **Flux de travail**           | Un testeur humain exécute l’outil → importe manuellement les résultats            | Le pipeline exécute l’outil → transmet automatiquement les résultats à DefectDojo    |
| **Méthode d’import des résultats** | Import manuel via l’interface ou la CLI                                 | Import piloté par API via l’automatisation (par exemple, CLI, connecteurs, tâches cron, scripts de pipeline) |
| **Type de test typique** | Tests d’intrusion, exercices d’équipe rouge, évaluations manuelles   | Analyse statique, analyse des dépendances, analyse de conteneurs           |

### Données de l’Engagement

En tant que conteneurs organisant l’activité de test, les Engagements peuvent stocker ou suivre diverses données :

- Dates de début et de fin cibles
- Description et notes de périmètre
- Statut (en cours, planifié, terminé, etc.)
- Assigné / Responsable
- Tests associés (par exemple, analyses, tests d’intrusion, tests manuels, etc.)
- Constatations et types de Constatations (par exemple, actif, atténué, risque accepté, doublon, etc.) 
- Modèles de menace ou informations sur l’acceptation du risque
- Étiquettes
- Fichiers et notes
- Paramètres de projet Jira
- Détails sur l’environnement (par exemple, préproduction vs production)
- ID de build (si lié à un pipeline CI/CD)
- Données historiques des Tests précédents au sein de l’Engagement 

## Accéder aux Engagements 

Les Engagements sont accessibles via la barre latérale. Le sous-menu donne accès aux Engagements actifs et à tous les Engagements, ainsi qu’à l’option d’afficher les Engagements organisés par Produit, types de Test et environnements. 

![image](images/engagement_ss17.png)

Autrement, les Engagements au sein d’un Produit particulier sont accessibles depuis le sous-menu de l’option Engagements dans la barre supérieure.

![image](images/engagement_ss18.png)

### Permissions 

Les Engagements se situent en dessous des Produits et au-dessus des Tests dans la hiérarchie des objets. Ainsi, l’accès à un Produit accorde automatiquement l’accès à tous les Engagements de ce Produit. Les Engagements n’ont pas de listes de contrôle d’accès indépendantes.

## Utiliser les Engagements

### Créer des Engagements 

Il existe plusieurs façons de créer un Engagement. Chaque méthode nécessite d’abord de créer un Produit pour le contenir. 

Une fois un Produit créé, vous pouvez ajouter un nouvel Engagement Interactif ou CI/CD dans la section Engagements de la barre de navigation du Produit.

![image](images/engagement_ss4.png)

Chaque Engagement doit avoir les champs suivants définis :
- Type (Interactif ou CI/CD)
- Un nom unique 
- Dates de début et de fin cibles 
    - Cela déterminera l’apparition de l’Engagement dans la section Calendrier
- Produit
- Statut 

#### Statuts d’Engagement

Les Engagements peuvent être marqués de différents statuts lors de leur création. Le statut peut également être modifié par la suite dans les paramètres de l’Engagement. 

Un Engagement peut avoir l’un des statuts suivants : 
- Non démarré
- Bloqué
- Annulé 
- Terminé 
- En cours 
- En attente 
- Planifié 
- En attente de ressource

Changer le statut d’un Engagement en « Terminé » signifie que la plupart des opérations d’écriture (par exemple, ajouter des tests, importer des analyses) deviendront indisponibles ou masquées. Les autres statuts n’affectent pas matériellement les fonctionnalités de l’Engagement et servent surtout au filtrage ou à des fins informatives.

### Modifier des Engagements 

Les Engagements peuvent être modifiés en cliquant sur le bouton **Modifier** dans les paramètres de l’Engagement. Tous les champs modifiables qui en découlent sont également disponibles lors de la création de l’Engagement.

### Copier des Engagements 

Vous pouvez facilement dupliquer des Engagements en accédant à la liste des Engagements au sein d’un Produit et en cliquant sur le bouton **Copier** dans le menu kebab ⋮ situé à côté de l’Engagement à copier. Cela créera une copie exacte de l’Engagement d’origine au sein du Produit parent, y compris les métadonnées, les Tests et les Constatations qu’il contient.

![image](images/engagement_ss19.png)

### Fermer des Engagements 

Les Engagements peuvent être fermés en accédant à la liste des Engagements au sein d’un Produit et en cliquant sur « Fermer » dans le menu kebab ⋮ de l’Engagement choisi. 

![image](images/engagement_ss20.png)

Une fois fermé, le statut de l’Engagement passera à « Terminé ». Néanmoins, la plupart des opérations d’écriture (par exemple, ajouter des tests, importer des analyses) resteront disponibles. 

La fermeture d’un Engagement ne modifie pas le statut des Constatations au sein des Tests de l’Engagement. Les Constatations restent actives, atténuées ou à risque accepté selon leur propre cycle de vie, et restent accessibles pour consultation et création de rapports.

Si l’Engagement est lié à une Épopée (Epic) Jira (voir **[Intégration Jira : activer le mappage des Épopées d’Engagement](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**), la fermeture de l’Engagement déclenchera une tâche asynchrone qui fermera l’Épopée Jira associée dans votre Espace Jira connecté.

### Rouvrir des Engagements 

Si un Engagement est fermé, il peut être rouvert en cliquant sur **Rouvrir** dans son menu kebab ⋮ dans le tableau des Engagements fermés. Cela réactivera l’Engagement et ramènera son statut à « En cours ».

![image](images/engagement_ss21.png)

### Engagements expirés 

Un Engagement expire une fois que sa date de fin cible est dépassée.

L’expiration d’un Engagement n’a pas d’impact direct sur ses fonctionnalités et sert principalement de mécanisme de surveillance/notification.  

Une fois expiré, une notification rouge « X jours de retard » apparaîtra dans le champ « Durée » de l’Engagement, mais cela ne restreindra aucune de ses fonctionnalités. Le statut de l’Engagement continuera d’afficher « En cours ». 

Bien que cela ne soit pas activé par défaut, une option dans les paramètres système permet de fermer automatiquement un Engagement une fois qu’il a expiré depuis un certain nombre de jours. 

![image](images/engagement_ss22.png)

### Supprimer des Engagements 

La suppression d’un Engagement peut être effectuée en sélectionnant **Supprimer** dans les paramètres de l’Engagement. Cette action est irréversible. 

Supprimer un Engagement supprimera également ce qui suit : 
- Tous les Tests associés à l’Engagement 
- Toutes les Constatations au sein de ces Tests 
- Tous les mappages d’Épopées Jira liés (l’Épopée elle-même restera dans Jira, mais le lien entre DefectDojo et Jira sera supprimé)
- Toutes les notes et tous les fichiers téléchargés associés à l’Engagement 

À des fins d’audit, il est recommandé de fermer les Engagements terminés plutôt que de les supprimer. 

| **Opération** | **Résultats** | **Réversible** |
|----------|---------|------------|
| **Fermer** | Marque comme inactif ; les données restent ; peut être rouvert | Oui (réouverture) |
| **Expirer** | Avertissement visuel uniquement ; fermeture automatique optionnelle ; notifications | S/O |
| **Supprimer** | Supprime définitivement l’Engagement, les Tests, les Constatations, les notes, les fichiers et tous les mappages d’Épopées Jira (les Épopées restent dans Jira) | Non |

## Intégration Jira

Les Engagements peuvent être liés à un Espace Jira connecté, permettant aux Constatations de l’Engagement d’être transmises à Jira sous forme de Tickets. Pour un guide complet de configuration de Jira, voir **[Connecter DefectDojo à Jira](/connectors/os_jira/os__jira_guide/)**.

### Mappage des Épopées d’Engagement

Lorsque **Activer le mappage des Épopées d’Engagement** est coché dans les paramètres Jira d’un Produit, les Engagements seront transmis à Jira sous forme d’Épopées. Les Constatations au sein de l’Engagement sont transmises comme Tickets enfants sous l’Épopée, reflétant la hiérarchie Engagement → Constatations de DefectDojo dans la structure Épopée → Ticket de Jira.

Pour plus d’informations sur ce paramètre, voir **[Activer le mappage des Épopées d’Engagement](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**.

### Paramètres Jira au niveau de l’Engagement

Par défaut, les Engagements héritent de leurs paramètres Jira depuis leur Produit parent. Cependant, chaque Engagement peut redéfinir ces paramètres pour utiliser des configurations Jira différentes. Les paramètres suivants peuvent être personnalisés par Engagement :

- **Clé de projet** — router les Constatations vers un autre Espace Jira
- **Modèle de ticket** — utiliser un modèle différent pour les Tickets créés à partir de cet Engagement
- **Champs personnalisés** — appliquer des mappages de champs personnalisés différents
- **Étiquettes Jira** — étiqueter les Tickets avec des étiquettes spécifiques à l’Engagement
- **Assigné par défaut** — assigner les Tickets à un autre membre de l’équipe

Ces paramètres sont accessibles depuis la page **Modifier l’Engagement**. Pour plus de détails, voir **[Paramètres Jira au niveau de l’Engagement](/connectors/os_jira/os__jira_guide/#engagement-level-jira-settings)**.
