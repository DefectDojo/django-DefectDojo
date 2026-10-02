---
title: Constatations
description: Comprendre les Constatations dans DefectDojo OS
audience: opensource
weight: 5
---

Organisations	→ Actifs → Engagements → Tests → **CONSTATATIONS**

## Aperçu

**Les Constatations** représentent le niveau le plus bas de la hiérarchie des produits, où les vulnérabilités individuelles sont suivies et gérées, et constituent le principal moyen par lequel DefectDojo standardise et guide le processus de signalement et de remédiation de vos outils de sécurité. Qu’une vulnérabilité ait été signalée dans SonarQube, Acunetix, ou l’outil personnalisé de votre équipe, les Constatations vous permettent de gérer chaque vulnérabilité de la même manière.

Voici des exemples de Constatations : 
- Cookie non marqué comme HttpOnly
- Version obsolète (PHP)
- Évaluation de code hors bande (PHP)
- Version obsolète (MySQL)
- Code source de sauvegarde détecté
- Cross-Site Scripting aveugle

En plus de stocker les données de vulnérabilité et de fournir un cadre de remédiation, DefectDojo enrichit également vos Constatations des façons suivantes :
- Ajout automatique des scores EPSS associés à une Constatation pour décrire son exploitabilité
- Traduction automatique de la métrique de sévérité d’un outil de sécurité en un score de Sévérité pour chaque Constatation, ce qui confère un SLA à la Constatation selon la configuration SLA de votre Actif. Pour plus d’informations sur la configuration des SLA, cliquez [ici](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).

Dans l’ensemble, les Constatations sont conçues pour fonctionner avec la hiérarchie des produits afin de standardiser vos efforts et d’appliquer une méthode cohérente à chaque Actif.

## Accéder aux Constatations

Les Constatations sont accessibles via la barre latérale. Le sous-menu donne accès aux Constatations ouvertes et fermées, à toutes les Constatations (quel que soit leur statut ouvert ou fermé), aux [Constatations à risque accepté](/triage_findings/findings_workflows/os__risk_acceptance/), ainsi qu’aux Modèles de Constatation. Les Constatations individuelles sont également accessibles depuis le Test qui les contient. 

![image](images/osfindings_ss1.png)

### Permissions

Chaque Constatation appartient à un Test, ce qui permet à DefectDojo de conserver la trace de l’analyse ou de l’évaluation ayant initialement identifié la vulnérabilité.

Comme les Constatations appartiennent à des Tests, l’accès aux Constatations est déterminé par l’accès d’un Utilisateur à l’Actif qui contient le Test. Les Tests n’ont pas de listes de contrôle d’accès indépendantes.

## Vue des Constatations
Les vues de Constatation contiennent divers tableaux permettant d’interpréter le statut d’une Constatation en un coup d’œil. Cela comprend :
- **Aperçu**
    - **ID** : le numéro d’identification unique de cette Constatation. 
    - **Sévérité** : l’évaluation de sévérité de cette Constatation, appliquée automatiquement. 
        - Comme mentionné précédemment, DefectDojo traduit automatiquement la métrique de sévérité d’un outil de sécurité en un score de Sévérité pour chaque Constatation, ce qui confère un SLA à la Constatation selon la configuration SLA de votre Actif.
    - **SLA** : la date d’échéance prévue pour la résolution de la Constatation. 
    - **Statut** : le statut de la Constatation (par exemple, Actif, Vérifié, Faux positif, Doublon, Hors périmètre, et En revue de défaut).
    - **Type de Constatation** : si la Constatation est Statique (SAST) ou Dynamique (DAST).
    - **Date de découverte** : la date à laquelle la Constatation a été découverte. 
    - **CWE** : la classification CWE de la Constatation. 
    - **ID de vulnérabilité** : identifiants des vulnérabilités dans les avis de sécurité associés à la Constatation (par exemple, CVE ou autres sources).  
    - **Détecté par** : l’outil ayant révélé la Constatation. 
- **Constatations similaires** : d’autres Constatations au sein du même Actif qui ne sont pas des doublons exacts mais qui présentent des valeurs similaires pour l’ID de vulnérabilité, le CWE, le file_path, le numéro de ligne, etc.
- **Historique d’import** : liste des imports/réimports ayant créé/fermé/réactivé cette Constatation dans un Test quelconque. 
- **Points de terminaison/systèmes vulnérables** : les Points de terminaison/systèmes que la Constatation révèle comme vulnérables. 
- **Description** : la description de la Constatation (ajoutée automatiquement selon le type de Constatation, ou créée manuellement). 
- **Atténuation** : étapes suggérées pour atténuer.
- **Impact** : impact potentiel de laisser la Constatation non résolue. 
- **Étapes de reproduction** : étapes pour reproduire la Constatation. 
- **Justification de la sévérité** : description écrite expliquant pourquoi une certaine évaluation de Sévérité a été associée à la Constatation. 
- **Références** : URL permettant de recouper la description spécifique de la Constatation fournie par l’outil d’analyse tiers. Par exemple, les Références peuvent être des liens vers une entrée pertinente d’un catalogue de Constatations, ou une simple URL d’avis. 
- **Notes** : notes laissées par les Utilisateurs concernant la Constatation. Marquer une note comme Privée signifie qu’elle ne sera incluse dans aucun rapport généré comprenant la Constatation sélectionnée. 

## Données des Constatations

Les Constatations requièrent les métadonnées suivantes :
**Titre**
**Date**
**Sévérité**
**Description**

En plus des métadonnées correspondant aux tableaux dans la vue d’une Constatation, les champs de métadonnées optionnels comprennent : 
- **Groupe** : les Groupes de Constatations qui incluent la Constatation sélectionnée. 
- **Vecteur et score CVSS3/CVSS4** : le vecteur et le score CVSS3 et CVSS4 de la Constatation sélectionnée. 
- **Paires requête/réponse** : une copie du message envoyé par le client et de la réponse du serveur à la requête.
- **Points de terminaison à ajouter** : les points de terminaison vulnérables susceptibles d’être affectés par la Constatation sélectionnée et qui ne figurent pas dans la liste précédente des systèmes/points de terminaison. 
- **Score et percentile EPSS** : le score et le percentile EPSS pour le CVE. 
- **Date d’ajout au KEV** : la date à laquelle la Constatation a été ajoutée au catalogue KEV. 
- **Disponibilité et version du correctif** : indique si un correctif est disponible pour la vulnérabilité, et la version du composant affecté dans laquelle le correctif a été implémenté. 
- **Utilisateur ayant demandé une revue de défaut** : enregistre qui a demandé une revue de défaut pour la faille en question. 
- **Numéro de ligne** : numéro de ligne source du vecteur d’attaque. 
- **Chemin du fichier** : les fichiers identifiés contenant la faille. 
- **Nom et version du composant** : nom et version du composant affecté. 
- **ID unique de l’outil** : identifiant technique de la vulnérabilité provenant de l’outil source. 
- **ID de vulnérabilité de l’outil** : identifiant technique non unique provenant de l’outil source. 
- **Objet source, numéro de ligne et chemin de fichier SAST** : objet source, numéro de ligne et chemin de fichier du vecteur d’attaque. 
- **Objet destination (sink) SAST** : objet destination du vecteur d’attaque. 
- **Nombre d’occurrences** : nombre d’occurrences dans l’outil source lorsque plusieurs vulnérabilités ont été trouvées et agrégées par le scanner. 
- **Date de publication** : date à laquelle la Constatation a été publiée. 
- **Service** : les Services connectés (éléments de fonctionnalité autonomes au sein d’un Actif) affectés par la Constatation sélectionnée. Lorsqu’il est renseigné, ce champ est pris en compte dans la correspondance de déduplication (c’est-à-dire que les Constatations ayant des champs Service identiques seront dédupliquées). 
- **Date et version de remédiation planifiées** : la date à laquelle la Constatation est prévue d’être remédiée, et la version du composant affecté dans laquelle le correctif sera implémenté.
- **Effort de correction** : le niveau d’effort nécessaire pour corriger la Constatation (par exemple, Faible, Moyenne, ou Élevée). 
- **Étiquettes** : les étiquettes ajoutées à la Constatation. 

Les métadonnées exactes disponibles dépendront du parseur/scanner ayant révélé la Constatation. Certains ne fournissent que des informations de base telles que le titre et la sévérité, tandis que d’autres incluent des vecteurs CVSS, des composants vulnérables, des points de terminaison, des paires requête/réponse, et d’autres métadonnées spécifiques au scanner.
 
Ces métadonnées améliorent le filtrage, le reporting et la priorisation au sein de votre programme de sécurité, permettant un suivi à long terme et une analyse des tendances. Des détails supplémentaires et des descriptions des métadonnées sont disponibles [ici](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page). 

### Déduplication

DefectDojo intègre des fonctionnalités de déduplication qui aident à identifier et gérer les Constatations représentant la même vulnérabilité sous-jacente. Au fur et à mesure que les résultats d’analyse sont importés depuis un ou plusieurs outils, DefectDojo utilise une logique de correspondance configurable pour identifier les Constatations représentant la même vulnérabilité.

La déduplication évite qu’une même vulnérabilité n’apparaisse plusieurs fois lorsqu’elle est détectée à répétition par le même scanner ou par des scanners différents, permettant à l’historique de remédiation de rester rattaché à une seule Constatation.

Plus d’informations sur la déduplication sont disponibles [ici](/triage_findings/finding_deduplication/about_deduplication/).

### Réimport

La fonction de Réimport de DefectDojo permet de mettre à jour les Constatations à mesure que de nouveaux résultats d’analyse sont importés. Lorsqu’une analyse est réimportée, DefectDojo compare les résultats entrants aux Constatations existantes et met à jour les enregistrements correspondants au lieu d’en créer de nouveaux. Cela préserve un contexte précieux tel que les changements de statut, l’historique de remédiation, les commentaires et les informations de propriété, offrant un enregistrement continu du cycle de vie d’une Constatation à travers plusieurs cycles de test.

Plus d’informations sur la fonction de Réimport sont disponibles [ici](/import_data/import_intro/reimport/#main-content).

### Acceptations du risque 

Les Acceptations du risque constituent un statut spécial pouvant être appliqué aux Constatations pour documenter formellement et opérationnaliser la décision de les reconnaître sans les remédier immédiatement. 

Plus d’informations sur les Acceptations du risque sont disponibles [ici](/triage_findings/findings_workflows/os__risk_acceptance/).

### Statuts 

Chaque Constatation créée dans DefectDojo possède un Statut qui communique des informations pertinentes et aide votre équipe à suivre l’avancement de la résolution des problèmes.

Plus d’informations sur les Statuts sont disponibles [ici](/triage_findings/findings_workflows/finding_status_definitions/).

## Utiliser les Constatations 

### Créer des Constatations 

Bien que la plupart des Constatations soient générées automatiquement via les imports d’analyse et les intégrations, DefectDojo prend également en charge la création manuelle de Constatations. Les Constatations manuelles sont utiles pour suivre les vulnérabilités et les problèmes de sécurité identifiés lors de tests d’intrusion, de revues d’architecture, d’évaluations de conformité, de programmes de bug bounty, de missions de consultants, ou d’autres activités qui ne produisent pas de résultats de scanner. 

Pour créer une Constatation manuellement :
1. Accédez au Test dans lequel vous souhaitez ajouter manuellement la Constatation, cliquez sur le signe + Plus, puis cliquez sur **Nouvelle Constatation**.

![image](images/osfindings_ss2.png)

2. Cela ouvre le formulaire Nouvelle Constatation, que vous pouvez remplir avec toute information pertinente concernant votre Constatation.

3. Sélectionnez soit **Ajouter une autre Constatation** pour ajouter manuellement une autre Constatation, soit **Terminé** pour finaliser le processus de création manuelle de Constatation.

La Constatation apparaîtra désormais dans la liste des Constatations contenues dans le Test d’origine. 

Il est important de noter que l’ajout manuel d’une Constatation depuis la barre supérieure créera automatiquement un Engagement et un Test ad hoc pour contenir la nouvelle Constatation, plutôt que de l’ajouter au Test actuellement consulté (voir l’image ci-dessous). En effet, la barre supérieure concerne l’Actif dans son ensemble. Si vous souhaitez ajouter manuellement une Constatation à un Test spécifique déjà existant, il est préférable de le faire depuis le Test lui-même, comme décrit dans les étapes 1 à 3 ci-dessus. 

![image](images/osfindings_ss3.png)

### Modifier des Constatations

#### Menu kebab ⋮

Le menu kebab ⋮ situé à côté des Constatations contient les fonctions suivantes : 
- **Afficher** : ouvre et affiche la Constatation. 
- **Modifier** : modifie la Constatation. 
- **Copier** : crée une copie de la Constatation. La copie peut être enregistrée dans n’importe lequel des Tests contenus dans l’Engagement correspondant. 
- **Demander une revue par les pairs** : lance le processus de revue par les pairs et change le statut de la Constatation en « En revue ». Plus d’informations sur les revues par les pairs sont disponibles [ici](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Toucher la Constatation** : enregistre une interaction avec la Constatation dans son historique. 
- **Faire de la Constatation un modèle** : crée automatiquement un Modèle de Constatation basé sur la Constatation sélectionnée. 
- **Appliquer un modèle à la Constatation** : permet d’appliquer un Modèle de Constatation existant à une Constatation. 
- **Fermer la Constatation** : lance le processus de fermeture de la Constatation. 
- **Ajouter une Acceptation du risque** : lance le processus d’Acceptation du risque. Plus d’informations sont disponibles [ici](/triage_findings/findings_workflows/os__risk_acceptance/#main-content).
- **Afficher l’historique** : révèle l’historique de la Constatation sélectionnée. 
- **Supprimer** : supprime la Constatation sélectionnée. 

#### Joindre des fichiers aux Constatations 
Vous pouvez joindre des fichiers à n’importe quelle Constatation pour fournir un contexte visuel — par exemple, une capture d’écran d’une vulnérabilité en action ou une image de preuve de concept.

Les types de fichiers pris en charge comprennent : 

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Pour joindre un fichier à une Constatation :
1. Ouvrez la Constatation à laquelle vous souhaitez joindre un fichier.
2. Ouvrez le menu d’actions (le bouton ☰ en haut à droite de la Constatation) et cliquez sur Gérer les fichiers.

![image](images/OS_manage_files_menu.png)

3. Sur la page Ajouter des fichiers, saisissez un Titre pour le fichier et choisissez le fichier depuis votre ordinateur. Vous pouvez ajouter jusqu’à trois fichiers à la fois ; enregistrez et revenez pour en ajouter d’autres si nécessaire.

![image](images/OS_manage_files_form.png)

4. Cliquez sur **Enregistrer**.

Le fichier est ensuite répertorié dans le panneau **Fichiers** de la Constatation. Les fichiers image apparaissent sous forme de vignettes :

![image](images/OS_finding_files_panel.png)

#### Modifier des Constatations en masse 

Les Constatations peuvent être modifiées en masse depuis une liste de Constatations, telle que le tableau de toutes les Constatations accessible depuis la barre latérale, ou depuis le tableau des Constatations au sein d’un Test spécifique.

Plus d’informations sur la modification en masse des Constatations sont disponibles [ici](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings). 

### Fermer des Constatations 

Une fois le travail sur une Constatation terminé, vous pouvez la fermer manuellement en cliquant sur **Fermer la Constatation** dans le menu kebab ⋮ ou le menu d’actions ☰ de la Constatation. Autrement, si une analyse est réimportée dans DefectDojo sans contenir une Constatation précédemment enregistrée, cette dernière se fermera automatiquement.

Si vous ne souhaitez qu’aucune Constatation ne soit fermée, vous pouvez désactiver ce comportement lors du Réimport :

- Décochez la case Close Old Findings si vous utilisez l’interface
- Définissez close_old_findings sur False si vous utilisez l’API ​

### Supprimer des Constatations 

La suppression d’une Constatation peut être effectuée depuis le menu kebab ⋮ ou le menu d’actions ☰ de la Constatation. Cette action est irréversible. 

À des fins d’audit, il est recommandé de fermer les Constatations remédiées plutôt que de les supprimer. 

## Groupes de Constatations 

Les **Groupes de Constatations** vous permettent de traiter plusieurs Constatations liées comme une seule unité logique pour le triage, le reporting et la coordination de la remédiation.

Par exemple, une analyse peut produire 10 Constatations d’injection SQL réparties sur différents points de terminaison. Plutôt que de gérer chacune indépendamment, vous pouvez les regrouper en un seul Groupe de Constatations représentant le problème d’injection SQL dans son ensemble.

Un Groupe de Constatations ne remplace pas les Constatations individuelles. Chaque Constatation continue d’exister avec sa propre sévérité, son statut, ses métadonnées, ses commentaires et son historique de remédiation. Un Groupe de Constatations fournit simplement une couche organisationnelle supplémentaire au-dessus des Constatations qu’il contient.

### Accéder aux Groupes de Constatations 

Les Groupes de Constatations sont accessibles via la barre latérale. Le sous-menu donne accès aux Groupes de Constatations ouverts et fermés, ainsi qu’à tous les Groupes de Constatations (quel que soit leur statut d’ouverture).

![image](images/osfindings_ss1.png)

### Créer des Groupes de Constatations 


Les Groupes de Constatations peuvent être créés manuellement ou automatiquement. 

Notamment, les Groupes de Constatations ne peuvent être créés qu’à partir des Constatations contenues au sein d’un seul Test. Les Constatations provenant de Tests, d’Engagements ou de Produits différents ne peuvent pas être ajoutées au même Groupe de Constatations.

#### Groupes de Constatations manuels 

Pour effectuer manuellement des actions sur les Groupes de Constatations :
1. Accédez à une liste de Constatations au sein d’un Test. 
2. Sélectionnez la ou les Constatations que vous souhaitez ajouter à un Groupe de Constatations en cliquant sur la case à cocher correspondante. 
3. Cliquez sur la case à cocher **Groupe**. 
4. Cliquez sur l’action correspondante que vous souhaitez effectuer.
    - **Créer** : crée un Groupe de Constatations incluant les Constatations sélectionnées.
    - **Ajouter à** : ajoute les Constatations sélectionnées à un Groupe de Constatations existant.
    - **Retirer de tout groupe** : retire les Constatations sélectionnées de tout Groupe de Constatations dont elles faisaient précédemment partie. 
    - **Grouper par** : regroupe les Constatations sélectionnées selon l’option choisie (par exemple, Nom du composant, Chemin du fichier, Titre de la Constatation, etc.) 
5. Cliquez sur **Envoyer**.

![image](images/osfindings_ss4.png)

Notez que la seule action possible lors de la sélection de Constatations depuis la liste Toutes les Constatations est de retirer les Constatations sélectionnées de tout Groupe de Constatations. Cela s’explique par le fait que, comme mentionné, les Groupes de Constatations ne peuvent être créés qu’à partir des Constatations contenues au sein d’un seul Test.

#### Groupes de Constatations automatiques 

Lors de l’import d’une analyse, la fonctionnalité « Grouper par » peut créer automatiquement des Groupes de Constatations selon une méthode de regroupement choisie. Cela est utile lorsqu’un scanner produit de nombreuses Constatations liées qui devraient être gérées ensemble.

La case à cocher adjacente **Créer des Groupes de Constatations pour toutes les Constatations** remplit deux fonctions : 
- **Cochée** : crée un Groupe de Constatations pour chaque Constatation importée, même si cette Constatation est l’unique membre du groupe.
- **Décochée** : crée des Groupes de Constatations uniquement lorsqu’il y a effectivement plusieurs Constatations à regrouper.

![image](images/osfindings_ss5.png)

Si aucune option n’est sélectionnée dans le menu déroulant Grouper par lors de l’import, aucun regroupement n’aura lieu. 

Si le critère de regroupement (par exemple, nom du composant, ID de vulnérabilité, etc.) n’est pas renseigné dans la Constatation, aucun groupe ne sera créé pour elle et elle ne sera pas ajoutée à un Groupe de Constatations existant. 

Si une analyse importée révèle 10 Constatations non groupées, puis que la même analyse est réimportée avec un regroupement des Constatations, les 10 premières Constatations ne seront pas ajoutées à ce Groupe de Constatations (c’est-à-dire que le Groupe de Constatations n’inclura que les 10 Constatations du réimport, et non les 10 Constatations de l’import initial et suivant). 

## Modèles de Constatation 

Les **Modèles de Constatation** permettent aux Utilisateurs de créer des modèles réutilisables pour les vulnérabilités et problèmes de sécurité couramment signalés. Un modèle peut inclure des informations standardisées telles qu’un titre, une description, un impact, des étapes de reproduction, une atténuation, des références, et d’autres métadonnées de Constatation.

Les Modèles de Constatation sont particulièrement utiles lorsque les Utilisateurs doivent créer des Constatations manuelles de façon répétée et souhaitent éviter de ressaisir les mêmes informations à chaque fois.

### Accéder aux Modèles de Constatation 

Les Modèles de Constatation se trouvent dans le sous-menu Constatations de la barre latérale. 

![image](images/osfindings_ss6.png) 

### Créer des Modèles de Constatation 

Les Modèles de Constatation peuvent être créés en cliquant sur le bouton + Plus en haut à droite de la vue Modèles de Constatation. 

La page qui s’affiche ensuite offre un aperçu des métadonnées qui seront appliquées à une Constatation lorsqu’un Modèle de Constatation est utilisé.

Vous pouvez également utiliser une Constatation existante comme base pour un nouveau Modèle de Constatation en cliquant sur **Faire de la Constatation un modèle** dans le menu kebab ⋮ de la Constatation. 

### Appliquer des Modèles de Constatation 

Les Modèles de Constatation peuvent être appliqués aux Constatations en cliquant sur le bouton **Appliquer un modèle à la Constatation** dans le menu kebab ⋮ de la Constatation sélectionnée.

![image](images/osfindings_ss7.png)

La page qui s’affiche ensuite vous permettra de sélectionner le modèle à appliquer à la Constatation en question, puis de choisir de conserver, remplacer ou combiner les métadonnées de la Constatation avec celles du modèle. 

### Rapports 

Le générateur de rapports de DefectDojo vous permet d’assembler un rapport personnalisé à partir d’un ensemble de widgets de contenu, de l’exécuter, et d’exporter le résultat (par exemple, en l’imprimant en PDF). Les rapports personnalisés peuvent résumer les Constatations ou les Points de terminaison que vous souhaitez partager avec un public externe, et peuvent inclure des éléments de marque et du texte standard.

Plus d’informations sur le générateur de rapports de DefectDojo sont disponibles [ici](/metrics_reports/reports/using-the-report-builder/).

#### Exporter les Constatations 

Les pages affichant une liste de Constatations ou une liste d’Engagements disposent d’une option d’export CSV et Excel dans le menu déroulant en haut à droite.

Depuis n’importe quelle page de liste de Constatations, ouvrez le menu déroulant en haut à droite pour exporter les Constatations visibles au format CSV ou Excel. La liste des Engagements peut également être exportée au format CSV ou Excel en utilisant le même menu déroulant sur la page de liste des Engagements.
