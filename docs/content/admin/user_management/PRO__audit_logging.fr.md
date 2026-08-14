---
title: Journaux d'audit
description: Accéder aux journaux d'audit des objets DefectDojo
weight: 1
audience: pro
---

Les **journaux d'audit** fournissent un enregistrement chronologique des actions effectuées au sein de DefectDojo. Ils garantissent la responsabilisation et la conformité en enregistrant quel utilisateur a effectué quelle action et à quel moment.

Les journaux d'audit sont utiles pour :
- **Enquêtes de sécurité** : déterminer qui a effectué des actions sensibles.
- **Conformité** : démontrer un historique auditable pour des normes telles que SOC 2, ISO 27001, ou des exigences de gouvernance interne.
- **Dépannage** : identifier le moment où une configuration ou un objet a changé.
- **Responsabilisation** : suivre l'activité administrative et utilisateur sur l'ensemble de la plateforme.

En résumé, les journaux d'audit fournissent un enregistrement centralisé des événements importants qui aide les administrateurs à comprendre l'historique d'activité de leur instance, au-delà de l'historique d'un seul objet.

### Accéder aux journaux d'audit

Les journaux d'audit sont accessibles via la barre latérale, dans le sous-menu Configurations.

![image](images/auditlogs_ss2.png)

### Autorisations

L'accès aux journaux d'audit est déterminé par le rôle global de l'utilisateur.

Les rôles globaux API Importer, Reader et Writer ne permettent pas d'accéder aux journaux d'audit, contrairement aux rôles Maintainer et Owner. Les superutilisateurs ont également accès aux journaux d'audit, quel que soit leur rôle global.

Vous trouverez plus d'informations sur les autorisations et les rôles globaux [ici](/admin/user_management/pro_permissions_overhaul/).

## Contenu des journaux d'audit

Les journaux d'audit suivent une variété d'actions, y compris, sans s'y limiter :
- Les interactions avec les objets (par exemple, la création, la mise à jour ou la suppression d'objets).
- Les mises à jour de la priorité et du score de risque d'une Constatation.
- La création et la modification des profils Utilisateur.
- Les mises à jour du percentile EPSS.

La liste complète des modifications et actions capturées dans les journaux d'audit se trouve [ici](../pro__audit_log_index/).

## Tableau des journaux d'audit

Les journaux d'audit comprennent plusieurs colonnes contenant diverses données pour améliorer la traçabilité, notamment :
- **Horodatage** : l'heure à laquelle la modification a eu lieu.
- **Utilisateur** : l'utilisateur qui a effectué l'action.
- **Action** : l'action effectuée (par exemple, création, mise à jour, suppression).
- **Modèle** : l'aspect modifié (par exemple, Actif, Utilisateur, Constatation, Emplacement, Pare-feu, URL, etc.).
- **ID de l'objet** : l'identifiant unique de DefectDojo pour l'objet qui a été modifié.
- **Nom de l'objet** : le nom de l'objet concerné.
- **Modifications** : les champs spécifiques modifiés par l'action, y compris leurs valeurs précédentes et mises à jour.
- **Données** : un instantané exact de l'enregistrement au moment où l'action a été effectuée, incluant chaque champ, et pas seulement ceux qui ont été modifiés.
- **Contexte** : les détails environnants de la façon dont la modification s'est produite, qui l'a effectuée, d'où dans l'application elle provient, et une étiquette indiquant quelle tâche a effectué la modification (s'il s'agissait d'une tâche automatisée).
- **URL** : l'URL utilisée pour exécuter l'opération en question. Ces chemins peuvent faire référence à l'interface Vue de DefectDojo, ou à l'API REST. Le champ URL ne sera pas renseigné pour les processus back-end.
- **Adresse IP** : l'adresse réseau de l'appareil ayant effectué la modification. Ce champ ne sera pas renseigné pour les processus back-end.

### Chronologie des journaux d'audit

Par défaut, les journaux d'audit affichent les entrées des 31 derniers jours. Les entrées plus anciennes restent disponibles et peuvent être consultées en ajustant le filtre Horodatage.

![image](images/auditlogs_ss3.gif)

### Filtrer les journaux d'audit

Le tableau des journaux d'audit comprend des filtres permettant d'affiner les résultats affichés. Par exemple, si vous souhaitiez voir uniquement les actions relatives aux Actifs, vous pourriez filtrer sur les Actifs dans le tableau.

![image](images/auditlogs_ss1.png)

Les colonnes des journaux d'audit peuvent également être classées par ordre alphabétique, croissant/décroissant, ou chronologique, selon le contenu de la colonne en question. Les colonnes peuvent aussi être déplacées vers la gauche ou la droite selon l'agencement souhaité.

![image](images/auditlogs_ss4.gif)

## Historique de l'objet

L'**historique de l'objet** fournit un enregistrement chronologique des modifications apportées à un objet DefectDojo individuel (par exemple, Organisation, Actif, Engagement, Test, Constatations, Points de terminaison et Acceptations du risque). Chaque entrée inclut des détails tels que l'horodatage, l'utilisateur, l'action effectuée et les modifications associées.

Contrairement aux journaux d'audit, qui enregistrent les événements de l'ensemble d'une instance, l'historique de l'objet se rapporte strictement à l'activité d'un seul objet, ce qui facilite la compréhension de l'historique d'un objet sans avoir à filtrer des événements système non liés.

L'historique de l'objet est utile pour :
- Examiner l'évolution d'un objet au fil du temps.
- Déterminer à quel moment une modification a été effectuée.
- Identifier quel utilisateur a effectué une modification.
- Dépanner des modifications inattendues.

### Accéder à l'historique de l'objet

L'historique de l'objet est accessible via le menu en forme d'engrenage situé en haut à droite de la vue de n'importe quel objet. Seuls les utilisateurs ayant accès à l'objet en question peuvent consulter son historique.

### Journaux d'audit et historique de l'objet

Bien que les fonctions des journaux d'audit et de l'historique de l'objet se recoupent, elles opèrent à des échelles différentes. L'historique de l'objet se concentre sur les modifications apportées à des objets individuels, tandis que les journaux d'audit fournissent un enregistrement à l'échelle du système des événements significatifs survenus dans votre instance DefectDojo, offrant une vue d'ensemble plus large de l'activité.

## Points de terminaison

### Point de terminaison de l'historique de l'objet (Pro uniquement)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> les utilisateurs ont accès à un chemin d'API `/history` pour ces objets afin de consulter des données similaires.  Par exemple : `/api/v2/findings/{id}/history/`.

### Point de terminaison des journaux d'audit (Pro uniquement)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> les utilisateurs ont également accès à un point de terminaison `/audit_log` dédié pour l'ensemble de leur instance.  Ce journal ne peut être consulté que par des utilisateurs ou des jetons API disposant des autorisations de superutilisateur.

Cette API renvoie 31 jours de journaux d'audit.

* L'envoi de paramètres par défaut ou vides renverra les 31 derniers jours de journaux d'audit.

* Le paramètre `window_month`, qui prend un mois et une année au format MM-YYYY, fournit les journaux d'audit pour ce mois.
* Vous pouvez définir le paramètre `window_start` pour limiter ces journaux à une fenêtre plus courte, plutôt que de renvoyer le mois entier.

Pour plus d'informations, consultez la documentation de l'API, disponible sur votre instance : `your-instance.cloud.defectdojo.com/api/v2/oa3/swagger-ui/`
