---
title: Engagements
description: Comprendre les Engagements dans DefectDojo Pro
audience: pro
weight: 3
---

Organisations → Actifs → **ENGAGEMENTS** → Tests → Constatations 

## Aperçu

Dans la hiérarchie des Actifs de DefectDojo, les Engagements sont des conteneurs limités dans le temps ou liés à un pipeline, qui regroupent des Tests apparentés au sein d'un Actif donné. Si vous avez prévu un effort de test, qu'il soit ponctuel ou récurrent, un Engagement vous offre un endroit où stocker tous les résultats associés.

Voici quelques exemples d'Engagements : 
- Tests d'intrusion ponctuels
- Analyses mensuelles ou trimestrielles récurrentes
- Périodes d'évaluation de bug bounty
- Exécutions de pipeline CI/CD (pour les équipes qui traitent chaque pipeline comme un Engagement à part entière)
- Cycles de publication de code (par exemple, « revue de sécurité de la version v4.2 »)

### Types d'Engagement 

DefectDojo prend en charge deux types d'Engagement : **Interactif** et **CI/CD**. Ces types déterminent la façon dont les Tests sont généralement créés et dont les résultats d'analyse sont importés.

Un Engagement Interactif est généralement mené par un ingénieur. Les Engagements Interactifs se concentrent sur le test d'une application pendant son exécution, à l'aide d'un test automatisé, d'un testeur humain, ou de toute activité « interagissant » avec les fonctionnalités de l'application. 

Un Engagement CI/CD est destiné à une intégration automatisée avec un pipeline CI/CD. Les Engagements CI/CD sont conçus pour importer des données de manière automatisée, déclenchée par une étape du processus de publication.

| **Catégorie**                | **Engagements Interactifs**                             | **Engagements CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Cas d'usage principal**   | Tests de sécurité manuels ou ponctuels                            | Tests de sécurité automatisés et récurrents au sein des pipelines             |
| **Durée**           | Limitée dans le temps et finie                                        | Durée potentiellement infinie                                      |
| **Fréquence**          | Périodique ou ponctuelle                                          | Continue ou par commit                                           |
| **Flux de travail**           | Un testeur humain exécute l'outil → importe manuellement les résultats            | Le pipeline exécute l'outil → envoie automatiquement les résultats vers DefectDojo    |
| **Méthode d'importation des résultats** | Téléversement manuel via l'interface utilisateur ou la CLI                                 | Importation pilotée par API via automatisation (par exemple, CLI, connecteurs, tâches cron, scripts de pipeline) |
| **Type de test habituel** | Tests d'intrusion, exercices red team, évaluations manuelles   | Analyse statique, analyse des dépendances, analyse de conteneurs           |

### Données de l'Engagement 

En tant que conteneurs organisant l'activité de test, les Engagements peuvent stocker ou suivre diverses données :

- Dates de début et de fin cibles
- Description et notes de périmètre
- Statut (en cours, planifié, terminé, etc.)
- Assigné / Responsable
- Tests associés (par exemple, analyses, tests d'intrusion, tests manuels, etc.)
- Constatations et types de Constatations (par exemple, actif, atténué, risque accepté, doublon, etc.) 
- Modèles de menace ou informations sur l'acceptation du risque
- Étiquettes
- Fichiers et notes
- Paramètres du projet Jira
- Détails de l'environnement (par exemple, staging ou production)
- ID de build (si lié à un pipeline CI/CD)
- Données historiques des Tests précédents au sein de l'Engagement 

## Accès aux Engagements 

Les Engagements sont accessibles depuis la barre latérale. Le sous-menu donne accès aux Engagements actifs et à tous les Engagements, ainsi qu'à l'option de création de nouveaux Engagements.

![image](images/engagement_ss13.png)

Autrement, les Engagements d'un Actif sont accessibles dans la fenêtre située en bas de la vue de l'Actif.

![image](images/engagement_ss14.png)

### Autorisations 

Les Engagements se situent sous les Actifs et au-dessus des Tests dans la hiérarchie des objets. Ainsi, l'accès à un Actif accorde automatiquement l'accès à tous les Engagements qu'il contient. Les Engagements ne disposent pas de listes de contrôle d'accès indépendantes.

## Utilisation des Engagements

### Créer des Engagements 

Avant de créer un Engagement, vous devez d'abord avoir [créé un Actif](/asset_modelling/engagements_tests/pro__assets/#create-assets) pour le contenir. 

Il existe plusieurs façons de créer un Engagement : 

- Depuis le menu déroulant Engagements de la section Gérer de la barre latérale
    - Vous devrez sélectionner l'Actif auquel attribuer l'Engagement en remplissant le formulaire Nouvel Engagement

![image](images/engagement_ss1.png)

- L'icône d'engrenage située en haut à droite de la vue d'un Actif

![image](images/engagement_ss9.png)

- Le bouton « + Nouvel Engagement » situé dans la liste des Engagements d'un Actif

![image](images/engagement_ss2.png)

- Si vous n'avez pas encore créé d'Engagement au sein d'un Actif, vous pouvez le faire lors de l'importation d'une analyse. 

![image](images/engagement_ss3.png)

Chaque Engagement doit avoir les champs suivants définis :
- Type (Interactif ou CI/CD)
- Un nom unique 
- Dates de début et de fin cibles 
    - Cela déterminera l'apparition de l'Engagement dans la section Calendrier
- Actif 
- Statut 

#### Statuts d'Engagement 

Les Engagements peuvent être associés à différents statuts lors de leur création. Le statut peut également être modifié ultérieurement dans les paramètres de l'Engagement. 

Un Engagement peut avoir l'un des statuts suivants : 
- Non démarré
- Bloqué
- Annulé 
- Terminé 
- En cours 
- En attente 
- Planifié 
- En attente de ressource 

Faire passer le statut d'un Engagement à « Terminé » entraînera l'indisponibilité ou le masquage de la plupart des opérations d'écriture (par exemple, l'ajout de tests, l'importation d'analyses). Les autres statuts n'affectent pas de manière significative le fonctionnement de l'Engagement et servent principalement à des fins de filtrage ou d'information.

### Modifier des Engagements 

Les Engagements peuvent être modifiés en cliquant sur **Modifier l'Engagement** dans le menu d'engrenage. Ce même menu est également accessible en cliquant sur le menu kebab ⋮ à gauche de l'Actif dans la vue Tous les Actifs. 

Tous les champs pouvant être modifiés par la suite sont également disponibles lors de la création de l'Engagement. 

![image](images/engagements_ss99.png)

### Copier des Engagements 

Vous pouvez facilement dupliquer des Engagements en sélectionnant « Copier l'Engagement » dans les paramètres de l'Engagement. Cela crée une copie exacte de l'Engagement d'origine au sein de l'Actif parent, y compris les métadonnées, les Tests et les Constatations qu'il contient.

### Fermer des Engagements 

Les Engagements sont fermés en sélectionnant **Fermer l'Engagement** dans les paramètres de l'Engagement. Une fois fermé, le statut de l'Engagement passera à « Terminé ». Néanmoins, la plupart des opérations d'écriture (par exemple, l'ajout de tests, l'importation d'analyses) resteront disponibles.

La fermeture d'un Engagement ne modifie pas le statut des Constatations au sein des Tests de l'Engagement. Les Constatations restent actives, atténuées ou acceptées comme risque selon leur propre cycle de vie, et demeurent accessibles pour consultation et création de rapports.

Si l'Engagement est lié à une Epic Jira (voir **[Intégration Jira : activer le mappage Engagement-Epic](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**), la fermeture de l'Engagement déclenchera une tâche asynchrone qui fermera l'Epic Jira associée dans votre Espace Jira connecté.

### Rouvrir des Engagements 

Si un Engagement est fermé, il peut être rouvert en sélectionnant **Rouvrir l'Engagement** dans ses paramètres. Cela réactivera l'Engagement et ramènera son statut à « En cours ». 

### Engagements expirés 

Un Engagement expire une fois sa date de fin cible dépassée.

Contrairement à la fermeture ou à la suppression d'un Engagement, l'expiration d'un Engagement n'a aucun impact direct sur son fonctionnement et sert principalement de mécanisme de suivi et de notification.  

Une fois expiré, une étiquette « En retard » apparaîtra à côté de l'Engagement, mais cela ne restreindra aucune de ses fonctionnalités. Le statut de l'Engagement continuera d'apparaître comme « En cours ». 

Bien que cette option ne soit pas activée par défaut, les paramètres système permettent de fermer automatiquement un Engagement une fois qu'il est expiré depuis un certain nombre de jours. 

![image](images/engagement_ss15.png)

### Supprimer des Engagements

La suppression d'un Engagement s'effectue en sélectionnant **Supprimer l'Engagement** dans les paramètres de l'Engagement. Cette action est irréversible.

La suppression d'un Engagement supprimera également les éléments suivants :
Tous les Tests associés à l'Engagement
Toutes les Constatations au sein de ces Tests
Tous les mappages d'Epic Jira liés (l'Epic elle-même restera dans Jira, mais le lien entre DefectDojo et Jira sera supprimé)
Toutes les notes et tous les fichiers téléversés associés à l'Engagement

À des fins d'audit, il est recommandé de fermer les Engagements terminés plutôt que de les supprimer.

| **Opération** | **Résultats** | **Réversible** |
|----------|---------|------------|
| **Fermer** | Marque comme inactif ; les données sont conservées ; peut être rouvert | Oui (réouverture) |
| **Expirer** | Avertissement visuel uniquement ; fermeture automatique facultative ; notifications | N/A |
| **Supprimer** | Supprime définitivement l'Engagement, les Tests, les Constatations, les notes, les fichiers et tous les mappages d'Epic Jira (les Epics restent dans Jira) | Non |

## Intégration Jira

Les Engagements peuvent être liés à un Espace Jira connecté, ce qui permet de transmettre à Jira les Constatations de l'Engagement sous forme d'Issues. Pour un guide complet de configuration de Jira, consultez **[Connexion de DefectDojo à Jira](/connectors/downstream/pro__jira_guide/)**.

### Mappage Engagement-Epic

Lorsque **Activer le mappage Engagement-Epic** est coché dans les paramètres Jira d'un Produit, les Engagements sont transmis à Jira sous forme d'Epics. Les Constatations de l'Engagement sont transmises sous forme d'Issues enfants rattachées à l'Epic, reproduisant ainsi la hiérarchie Engagement → Constatations de DefectDojo dans la structure Epic → Issue de Jira.

Pour plus d'informations sur ce paramètre, consultez **[Activer le mappage Engagement-Epic](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**.

### Paramètres Jira au niveau de l'Engagement

Par défaut, les Engagements héritent des paramètres Jira de leur Actif parent (Produit). Cependant, chaque Engagement peut individuellement remplacer ces paramètres pour utiliser des configurations Jira différentes. Les paramètres suivants peuvent être personnalisés par Engagement :

- **Clé de projet** — achemine les Constatations vers un autre Espace Jira
- **Modèle d'Issue** — utilise un modèle différent pour les Issues créées à partir de cet Engagement
- **Champs personnalisés** — applique des mappages de champs personnalisés différents
- **Étiquettes Jira** — associe aux Issues des étiquettes spécifiques à l'Engagement
- **Assigné par défaut** — attribue les Issues à un autre membre de l'équipe

Ces paramètres sont accessibles depuis la page **Modifier l'Engagement**. Pour plus de détails, consultez **[Paramètres Jira au niveau de l'Engagement](/connectors/downstream/pro__jira_guide/#engagement-level-jira-settings)**.
