---
title: Connecteurs en aval
weight: 1
audience: pro
aliases:
- /fr/en/share_your_findings/integrations
- /fr/issue_tracking/pro_integration/integrations/
---

**Disponibilité :** Les connecteurs en aval sont disponibles en version générale et activés pour toutes les instances DefectDojo Pro, aussi bien Cloud que sur site (On-Premise). Il n'y a rien à activer, et ils ne figurent plus sur la page Feature Flags.

Les connecteurs en aval vous permettent d'envoyer vos Constatations et groupes de Constatations vers des systèmes de suivi de tickets, afin d'intégrer facilement la remédiation de sécurité au flux de travail de développement existant de vos équipes.

Connecteurs en aval pris en charge :
- Azure Devops
- Bitbucket
- Freshservice
- GitHub
- GitLab Boards
- Jira
- Linear
- Opsgenie
- PagerDuty
- ServiceDesk Plus
- ServiceNow
- ServiceNow SecOps / Vulnerability Response
- Shortcut
- Zendesk

## Ouverture de la page Connecteurs en aval

La page Connecteurs en aval se trouve sous **Import > Connecteurs > Connecteurs en aval** dans la barre latérale.

![image](images/integrators_3.png)

## Configuration d'un connecteur en aval

Un connecteur en aval est configuré à l'aide de trois composants clés :

- **Instance d'intégration** : il s'agit de la méthode de connexion principale que DefectDojo utilisera avec un système tiers. L'instance comprend des détails tels qu'un libellé, un emplacement et des identifiants de connexion, ainsi que toute autre information pouvant être requise par l'éditeur.
- **Mappage du système de suivi des tickets (Issue Tracker Mapping)** : c'est ici que sont stockées les informations de mappage, qui définissent les détails nécessaires pour se connecter à un « projet » donné chez l'éditeur. Ces détails comprennent le nom ou l'ID du « projet », ainsi que les correspondances entre la Sévérité et le statut des Constatations DefectDojo et le champ correspondant dans le « ticket » de l'éditeur. Vous pouvez configurer plusieurs mappages si vous cherchez à envoyer des Constatations vers plusieurs emplacements de « projet ».
- **Affectation du système de suivi des tickets (Issue Tracker Assignment)** : c'est ici que les Produits et Engagements DefectDojo sont affectés à un mappage de système de suivi des tickets donné, avec des options par Produit/Engagement pour définir comment une Constatation sera envoyée vers un système de l'éditeur donné.

Ces composants sont hiérarchiques : chaque **instance** possède un ou plusieurs **mappages**, qui possèdent eux-mêmes une ou plusieurs **affectations de suivi**.

![image](images/integrators_2.png)

## Envoi des Constatations et des groupes de Constatations

Une fois ces composants configurés, les Constatations et groupes de Constatations peuvent être envoyés vers un système de suivi des tickets donné de deux façons : manuellement ou automatiquement.

- **Manuellement** : les Constatations et groupes de Constatations contenus dans un Produit/Engagement disposant d'un **mappage de système de suivi des tickets** affecté disposeront d'une option « Push to Integrator » (Envoyer vers l'intégrateur). Cela créera alors un ticket dans le système de suivi, avec les informations correspondantes de la Constatation ou du groupe de Constatations. « Push to Integrator » peut également être utilisé pour mettre à jour un ticket existant.

### Envoi automatique des Constatations

Les Constatations peuvent également être envoyées automatiquement, l'**affectation du système de suivi des tickets** déterminant la façon dont ces objets seront envoyés. Voici les quatre options disponibles :

- **Only Explicitly Publish Changes to Target** (ne publier les modifications vers la cible que de façon explicite) : cette option désactive tout comportement automatique dans le Produit ou l'Engagement affecté. La seule façon d'envoyer une Constatation ou un groupe de Constatations sera de le faire explicitement, comme indiqué ci-dessus.
- **Automatically Link New Finding to Target** (lier automatiquement les nouvelles Constatations à la cible) : lorsque de nouvelles Constatations ou groupes de Constatations sont **créés** dans le Produit ou l'Engagement affecté, DefectDojo envoie automatiquement l'objet vers le système de suivi des tickets. Une fois créés, ces Constatations ou groupes de Constatations ne seront pas mis à jour sans une action manuelle « Push to Integrator ».
- **Automatically Update Existing Link on Finding Edit** (mettre à jour automatiquement le lien existant lors de la modification d'une Constatation) : lorsque des Constatations ou groupes de Constatations sont **mis à jour** dans le Produit ou l'Engagement affecté, l'objet est automatiquement envoyé vers le système de suivi des tickets si un lien existant a déjà été créé manuellement.
- **Automatically Link New and Update Existing Link on Finding Edit** (lier automatiquement les nouvelles Constatations et mettre à jour le lien existant lors de la modification) : lorsque des Constatations ou groupes de Constatations sont créés **ou** mis à jour dans le Produit ou l'Engagement affecté, l'objet est automatiquement envoyé vers le système de suivi des tickets.

#### Filtres d'envoi

Chaque affectation de système de suivi des tickets peut, en option, restreindre les Constatations envoyées **automatiquement** :

- **Sévérité minimale** : ne crée automatiquement des tickets que pour les Constatations dont la Sévérité est égale ou supérieure au niveau sélectionné. Laissez ce champ vide pour inclure toutes les Sévérités.
- **Constatations actives uniquement** : ne crée automatiquement des tickets que pour les Constatations Actives, en ignorant celles qui sont déjà Atténuées, en Faux positif ou en Risque accepté au moment où l'affectation les détecte pour la première fois.

Ces filtres ne s'appliquent qu'à la **création** automatique. Les mises à jour d'une Constatation disposant déjà d'un ticket lié sont toujours envoyées, de sorte que les changements de statut (y compris les clôtures) continuent d'être propagés. Un envoi manuel via « Push to Integrator » ignore toujours les filtres. Laisser les deux options à leur valeur par défaut préserve le comportement d'origine, qui consiste à envoyer chaque Constatation.

#### Affecter plusieurs Produits

Une affectation de système de suivi des tickets cible un seul Produit ou Engagement. Pour couvrir plusieurs actifs, créez une affectation par Produit (ou Engagement). Si vous avez également besoin que les champs propres à l'éditeur diffèrent selon l'actif — par exemple un **groupe d'affectation** ou un **assigné** ServiceNow distinct, ou un projet Jira différent — créez un mappage de système de suivi des tickets distinct (avec ses propres mappages de champs personnalisés) pour chaque actif, et faites pointer chaque affectation vers le mappage correspondant.

## Représentation des tickets du système de suivi

Les tickets du système de suivi sont représentés par une série d'icônes sous la colonne « Integrator Tickets » lors de l'affichage et du listage des Constatations et groupes de Constatations.

Icônes de gauche à droite :

- **Type d'intégration** : le type de système de suivi des tickets auquel le ticket est associé
- **ID du ticket** : l'ID du ticket, tel que défini par le système de suivi des tickets
- **Lien du ticket** : le lien direct vers le ticket, tel que défini par le système de suivi des tickets
- **Journal des modifications** : indique à quel moment le ticket du système de suivi a été associé à une Constatation ou à un groupe de Constatations, ainsi que la dernière fois que DefectDojo a apporté une modification au ticket

![image](images/integrators_1.png)

## Exigences propres à chaque éditeur

Chaque éditeur a des exigences variables quant à la façon dont DefectDojo doit interagir avec lui. Cela peut prendre la forme d'un mécanisme d'authentification, de champs supplémentaires par « projet », ou de mappages de Sévérité/statut.

Pour la liste complète des exigences, veuillez consulter les pages spécifiques à chaque éditeur ci-dessous :

- [Azure Devops](/connectors/toolreference/azure_devops_boards/)
- [Bitbucket](/connectors/toolreference/bitbucket/#downstream-connector)
- [Freshservice](/connectors/toolreference/freshservice/)
- [GitHub](/connectors/toolreference/github/#downstream-connector)
- [GitLab Boards](/connectors/toolreference/gitlab/#downstream-connector)
- [Jira](/connectors/toolreference/jira/)
- [Linear](/connectors/toolreference/linear/)
- [Opsgenie](/connectors/toolreference/opsgenie/)
- [PagerDuty](/connectors/toolreference/pagerduty/)
- [ServiceDesk Plus](/connectors/toolreference/servicedesk_plus/)
- [ServiceNow](/connectors/toolreference/servicenow/)
- [ServiceNow SecOps / Vulnerability Response](/connectors/toolreference/servicenow_secops/)
- [Shortcut](/connectors/toolreference/shortcut/)
- [Zendesk](/connectors/toolreference/zendesk/)

## Gestion des erreurs et débogage

Les connecteurs en aval peuvent produire des erreurs pour diverses raisons telles que la connectivité, l'authentification, les permissions, etc. Pour faciliter le débogage de ces erreurs, chaque mappage de système de suivi des tickets dispose d'un tableau des erreurs indiquant le moment où l'erreur s'est produite, la raison de son apparition, et la Constatation ou le groupe de Constatations dont l'envoi a échoué.

Ces erreurs se trouvent sur la page Toutes les affectations et mappages de systèmes de suivi des tickets (All Issue Tracker Mappings & Assignments), dans la colonne ⚠️ Total des erreurs.

![image](images/integrators_4.png)

En cliquant sur l'entrée Total des erreurs, vous accédez à une page présentant des descriptions plus détaillées des erreurs associées à ce connecteur en aval.

### Voir tous les échecs au même endroit

Le tableau des erreurs par mappage couvre un seul connecteur en aval. [Diagnostics](/admin/diagnostics/pro__diagnostics/) couvre l'ensemble d'entre eux, ainsi que toutes les autres tentatives d'intégration sur l'instance — connecteurs en amont, imports, Jira, SSO et moteur de règles — avec les mêmes options de filtrage et de tri sur l'ensemble.

Utilisez-le lorsque la question dépasse le cadre d'un seul mappage :

* une tentative qui **ne s'est jamais terminée** plutôt qu'elle a échoué, ce qu'aucun tableau d'erreurs ne signale, car rien n'a généré d'erreur
* si un échec est spécifique à une seule intégration ou s'il se produit simultanément sur plusieurs intégrations
* qui ou quoi a déclenché une tentative, et par rapport à quelle configuration

Les identifiants cités dans une erreur sont supprimés avant l'enregistrement de la ligne, et le détail technique complet est réservé aux superutilisateurs.

## Disposition de la page Connecteurs en aval

Les connecteurs en aval sont listés en deux sections, **Connecteurs configurés** et **Connecteurs disponibles**, chacune triée par ordre alphabétique avec un compteur des éléments affichés à côté de son titre. Un outil peut contenir plusieurs configurations ; chacune constitue sa propre tuile, intitulée `<Tool> - <label>`, classée par libellé. La tuile **Demander un connecteur en aval** (Request Downstream Connector) sur DefectDojo Pro Cloud n'est pas comptabilisée.
