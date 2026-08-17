---
title: Introduction aux constatations
description: Le principal flux de travail et système de suivi des vulnérabilités de
  DefectDojo
weight: 1
aliases:
- /fr/en/working_with_findings/intro_to_findings
---

Les Constatations sont le principal moyen par lequel DefectDojo standardise et guide le processus de signalement et de remédiation de vos outils de sécurité. Qu'une vulnérabilité ait été signalée dans SonarQube, Acunetix, ou l'outil personnalisé de votre équipe, les Constatations vous permettent de gérer chaque vulnérabilité de la même manière.

## Que sont les Constatations ?

Les Constatations dans DefectDojo sont composées des éléments suivants :

* Les données de la vulnérabilité signalée en question
* Le « statut » de la Constatation, utilisé pour suivre la remédiation, l'acceptation du risque ou d'autres décisions prises concernant la vulnérabilité
* D'autres métadonnées liées à la Constatation. Cela peut inclure, par exemple, l'emplacement d'une Constatation dans votre réseau, les suggestions de remédiation d'un outil, ou des liens vers un CWE ou un score EPSS associé.

En plus de stocker les données de vulnérabilité et de fournir un cadre de remédiation, DefectDojo enrichit également vos Constatations des façons suivantes :

* En ajoutant automatiquement les scores EPSS associés à une Constatation pour décrire son exploitabilité
* En traduisant automatiquement la métrique de sévérité d'un outil de sécurité en un score de Sévérité pour chaque Constatation, ce qui confère un SLA à la Constatation selon la Configuration SLA de votre Produit.

Dans l'ensemble, les Constatations DefectDojo sont conçues pour fonctionner avec la Hiérarchie des Produits afin de standardiser vos efforts, et appliquer une méthode cohérente à chaque Produit.

## Une page de Constatation

La page de Constatation contient divers éléments. Chacun sera renseigné par le processus d'Import lors de la création de la Constatation.

![image](images/Introduction_to_Findings.png)

1. **Le titre de la Constatation :** Il s'agit généralement d'un raccourci descriptif qui identifie la vulnérabilité ou le problème détecté. C'est également dans cette section que s'affichent les Étiquettes créées par l'utilisateur, si elles existent.  
​
2. **Aperçu de la Constatation :** Cette section contient cinq pages distinctes d'informations pertinentes pour la Constatation : Description, Atténuation, Impact, Références et Notes. Ces champs peuvent être renseignés automatiquement à partir des données de vulnérabilité entrantes, ou être modifiés par un utilisateur DefectDojo pour fournir un contexte supplémentaire.  
​  
- ​**Description** est un résumé et une explication plus détaillés de la Constatation en question.  
- ​**Atténuation** est une méthode suggérée pour atténuer la Constatation afin qu'elle ne soit plus présente dans votre système.  
- ​**Impact** décrit l'impact de la vulnérabilité sur votre posture de sécurité. Cette page peut contenir du texte descriptif, ou peut inclure une [chaîne de vecteur CVSS](https://qualysguard.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm), qui est un moyen abrégé de communiquer l'exploitabilité globale de la vulnérabilité ainsi que les conséquences d'une exploitation pour votre organisation. L'Impact est étroitement lié au champ Sévérité d'une Constatation.  
- ​**Références** répertorie les liens ou informations supplémentaires pertinents pour cette Constatation, le cas échéant.  
- ​**Notes** est une page où vous pouvez consigner toute autre information pertinente concernant cette Constatation. Les Notes sont des métadonnées « propres à DefectDojo » et ne sont pas créées au moment de l'import. Utilisez ce champ pour suivre l'avancement de votre remédiation ou pour ajouter des détails plus précis à la Constatation.  
​
3. **Détails supplémentaires :** Cette section répertorie d'autres détails liés à cette Constatation, le cas échéant :


	* Paires Requête/Réponse associées à la vulnérabilité
	* Étapes pour reproduire la vulnérabilité
	* Justification de la sévérité, où vous pouvez consigner une explication plus détaillée de la sévérité ou de l'impact de la Constatation.  
	​  

4. **Métadonnées : Cette section contient les métadonnées filtrables liées à la Constatation :**


	* **ID :** la valeur d'ID de la Constatation dans DefectDojo
	* **Sévérité :** la valeur de Sévérité de la Constatation. Peut être Info, Faible, Moyenne, Élevée ou Critique. Les Sévérités des Constatations sont directement liées au SLA calculé de la Constatation, en fonction du Produit dans lequel elle est stockée.
	* **Statut :** le statut de la Constatation. Peut être Actif ou Inactif. En plus de ceux-ci, les Constatations peuvent également avoir un statut Doublon, Atténué, Faux positif, Hors périmètre, Risque accepté ou En révision de défaut. Ces statuts expliquent plus en détail l'état de la Constatation.
	* **Type :** ce champ décrit comment la Constatation a été trouvée, soit via une évaluation Statique (SAST) du code source, soit via une évaluation Dynamique (DAST) du Produit en cours d'exécution. Ce champ est défini par le type d'outil.
	* **Emplacement :** ce champ décrit le chemin de fichier lié à votre vulnérabilité, le cas échéant.
	* **Ligne :** ce champ décrit la ligne de code contenant la vulnérabilité, le cas échéant.
	* **Date de découverte :** ce champ indique soit la date à laquelle la Constatation a été importée dans DefectDojo, soit la date à laquelle elle a été découverte par l'Outil.
	* **Âge :** ce champ calculé indique le nombre de jours pendant lesquels la Constatation a été active.
	* **Rapporteur :** il s'agit du nom d'utilisateur du compte DefectDojo qui a créé cette Constatation.
	* **CWE :** ce champ est un lien vers la définition CWE (Common Weakness Enumeration) externe applicable à cette Constatation.
	* **ID de vulnérabilité :** s'il existe une valeur d'ID particulière pour cette vulnérabilité au sein de l'outil lui-même, elle sera suivie ici.
	* **Score EPSS / Percentile :** si les données source contiennent une valeur CWE, DefectDojo récupère automatiquement un [Score EPSS](https://www.first.org/epss/) et un Percentile (Exploit Prediction Scoring System). L'EPSS représente la probabilité qu'une vulnérabilité logicielle puisse être exploitée, sur la base de données d'exploitation réelles. Les scores EPSS sont mis à jour en continu, en utilisant les dernières données d'exploitation de First.
	* **Trouvé par :** Ceci répertorie le scanner utilisé pour trouver cette vulnérabilité.  
	​

## Notes et mentions @

La page **Notes** d'une Constatation est l'endroit où votre équipe consigne le contexte qui ne fait pas partie des données de scan importées : avancement de la remédiation, décisions de triage, ou tout autre commentaire. Les Notes sont des métadonnées propres à DefectDojo et ne sont jamais créées au moment de l'import.

Les Notes apparaissent sous forme de flux, les plus récentes en premier, et vous pouvez inverser l'ordre pour afficher les plus anciennes en premier. Chaque note indique son auteur, sa date de rédaction, son type de note, et un badge **Private** lorsque la note est privée. Une note privée n'est jamais affichée qu'à la personne qui l'a rédigée.

### Rédiger des notes en markdown

Les entrées de notes prennent en charge le markdown : vous pouvez donc utiliser des titres, du texte en **gras** et en *italique*, des listes à puces et numérotées, des citations, des tableaux, des liens et des blocs de code. L'éditeur de notes est le même que celui utilisé pour la description d'une Constatation, avec une barre d'outils pour les options de mise en forme courantes. Pour lire une note exactement telle qu'elle a été saisie plutôt que sous forme de texte formaté, utilisez le bouton bascule en haut à droite du corps de la note.

### Modification, suppression et historique

Chaque note dispose d'un menu d'actions avec **Edit**, **View History** et **Delete**, et chaque entrée n'apparaît que si vous êtes autorisé à l'utiliser :

* Vous pouvez toujours modifier, supprimer et consulter l'historique d'une note que vous avez rédigée vous-même.
* Pour gérer la note de quelqu'un d'autre, vous avez besoin de la permission de rôle correspondante sur l'objet auquel appartient la note : Note Edit, Note Delete, ou Note View History.
* L'ajout d'une note nécessite la permission Note Add, que possèdent tous les rôles au-dessus de Reader, ainsi que les Readers eux-mêmes.

Une note modifiée est étiquetée **(edited)** et enregistre qui l'a modifiée et quand. **View History** répertorie chaque révision de la note, la plus récente en premier, afin que rien ne soit perdu lorsqu'une note est réécrite. Seul le contenu de l'entrée peut être modifié : le type d'une note et son indicateur de confidentialité sont fixés dès la création de la note.

### Mentionner un utilisateur avec @

Lorsque vous ajoutez une note, vous pouvez **mentionner avec @** un autre utilisateur DefectDojo pour le notifier. Saisissez `@` immédiatement suivi de son nom d'utilisateur (par exemple `@alice`) n'importe où dans la note. Lorsque vous enregistrez la note, chaque utilisateur mentionné reçoit une notification **user-mentioned** qui renvoie vers la note.

Quelques détails à connaître :

* Le `@` doit se trouver au **début de la note ou juste après un espace**. C'est volontaire : cela empêche les adresses e-mail écrites en milieu de phrase (comme `alice@example.com`) de déclencher des mentions accidentelles.
* Le nom après le `@` doit correspondre à un nom d'utilisateur DefectDojo **existant et actif**. Les mentions d'utilisateurs inconnus ou désactivés sont ignorées.
* Un point final est ignoré, de sorte qu'une mention qui termine une phrase (`thanks @alice.`) est tout de même résolue.
* Vous pouvez mentionner plusieurs utilisateurs dans une même note.

Vous pouvez mentionner des utilisateurs avec @ depuis l'interface dans les notes sur les **Constatations**, **Tests**, **Engagements** et **Acceptations de risque**. Saisir `@` ouvre une liste d'utilisateurs correspondants ; choisir un nom dans cette liste est le moyen fiable de mentionner quelqu'un, car cela insère le nom d'utilisateur exactement comme l'attend la recherche de notification.

La mention est transmise via l'événement de notification `user_mentioned`. Consultez [Notifications](/admin/notifications/about_notifications/) pour savoir comment les notifications sont transmises et configurées. En particulier, `user_mentioned` est l'un des événements qu'un paramètre au niveau système peut continuer à transmettre même lorsqu'un utilisateur a par ailleurs mis ses notifications en sourdine (voir [Substitutions spécifiques](/admin/notifications/about_notifications/#specific-overrides)).

## Exemples de flux de travail avec les Constatations

La façon dont vous travaillez avec les Constatations dans DefectDojo dépend des responsabilités de votre équipe au sein de votre organisation. Voici quelques exemples de ces processus, et comment DefectDojo peut vous aider :

### Découvrir et signaler les vulnérabilités

Si vous êtes responsable des rapports de sécurité pour de nombreux contextes, Produits logiciels ou équipes différents, DefectDojo peut établir des rapports sur les vulnérabilités découvertes. Grâce à la Hiérarchie des Produits, vous pouvez organiser vos données de Constatations dans le contexte approprié. Par exemple :

* Chaque Produit dans DefectDojo peut avoir une configuration SLA différente, ce qui vous permet de signaler instantanément les Constatations découvertes en Production ou dans d'autres environnements hautement sensibles.
* Vous pouvez créer un rapport directement à partir d'un **Type de Produit, Produit, Engagement ou Test** pour « zoomer » sur votre contexte de sécurité. Les **Tests** contiennent les résultats d'un seul outil, les **Engagements** peuvent regrouper plusieurs Tests, les **Produits** peuvent contenir plusieurs Engagements, les **Types de Produits** peuvent contenir plusieurs Produits.

Pour plus d'informations sur la création d'un Rapport, consultez nos guides sur les **[Rapports personnalisés](/metrics_reports/reports/)**.

### Trier les vulnérabilités à l'aide du statut des Constatations

Si votre équipe doit valider les Constatations découvertes, elle peut le faire en appliquant manuellement le statut **Vérifié** aux Constatations au fur et à mesure de leur examen. Vous pouvez également appliquer d'autres statuts, tels que :

* **Faux positif :** Un outil a détecté la menace, mais celle-ci n'est pas active dans l'environnement.
* **Hors périmètre :** Active, mais non pertinente pour l'effort de test en cours.
* **Risque accepté :** Active, mais jugée non prioritaire à traiter tant que l'Acceptation du risque n'a pas expiré.
* **En révision :** peut être active ou non - votre équipe est encore en train d'enquêter.
* **Atténué :** Ce problème a été résolu depuis la création de la Constatation.

Si un outil signale une Constatation déjà triée lors d'un import ultérieur, DefectDojo se souviendra du statut précédent de la Constatation et le mettra à jour en conséquence. Les Constatations avec les statuts **Faux positif**, **Hors périmètre, Risque accepté et En révision** resteront inchangées, mais toute Constatation qui a été **Atténuée** sera **réactivée** pour vous informer qu'elle est réapparue dans l'environnement de Test.

### Garantir un consensus et une responsabilisation à l'échelle de l'équipe grâce aux Acceptations de risque

Une partie de la responsabilité d'une équipe de sécurité consiste à collaborer avec les développeurs pour prioriser et dépriorer la remédiation des problèmes de sécurité. C'est là qu'interviennent les Acceptations de risque. Ajouter une Acceptation de risque à une Constatation vous permet de :

* Stocker des enregistrements et des fichiers « artefacts » dans DefectDojo : il peut s'agir d'e-mails de collègues confirmant l'Acceptation du risque, de comptes rendus de réunion, ou simplement d'une justification écrite de l'acceptation du risque par votre propre équipe de sécurité.
* Ajouter une date d'expiration à l'Acceptation du risque, afin que la vulnérabilité puisse être réexaminée après une période donnée.

Tout membre d'une équipe AppSec comprend que la priorisation de l'atténuation des problèmes ne peut pas être laissée exclusivement aux équipes de développement ; les Acceptations de risque vous aident donc à consigner ces décisions sensibles au moment où elles sont prises.

### Surveiller les vulnérabilités actuelles à l'aide des CVE et des scores EPSS (fonctionnalité Pro)

Il arrive que l'exploitabilité et la menace posées par une vulnérabilité connue évoluent en fonction de nouvelles données. Pour que votre travail reste à jour, DefectDojo Pro s'est associé à First.org afin de maintenir une base de données des derniers scores EPSS liés aux Constatations. Toutes les Constatations dans DefectDojo Pro sont automatiquement tenues à jour selon leur EPSS, lequel est directement basé sur le CVE de la Constatation.

Si le score EPSS d'une Constatation change (c'est-à-dire que la Constatation associée devient plus ou moins exploitable), la Sévérité de la Constatation s'ajustera en conséquence.
