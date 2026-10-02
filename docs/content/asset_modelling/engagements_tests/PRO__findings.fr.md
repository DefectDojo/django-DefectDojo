---
title: Constatations
description: Comprendre les Constatations dans DefectDojo Pro
audience: pro
weight: 5
---

Organisations	→ Actifs → Engagements → Tests → **CONSTATATIONS**

## Aperçu
**Les Constatations** représentent le niveau le plus bas de la hiérarchie des produits, où les vulnérabilités individuelles sont suivies et gérées, et constituent le principal moyen par lequel DefectDojo normalise et guide le processus de signalement et de remédiation de vos outils de sécurité. Qu'une vulnérabilité ait été signalée par SonarQube, Acunetix ou l'outil personnalisé de votre équipe, les Constatations vous permettent de gérer chaque vulnérabilité de la même manière.

Exemples de Constatations :
- **Cookie non marqué comme HttpOnly**
- **Version obsolète (PHP)**
- **Évaluation de code hors bande (PHP)**
- **Version obsolète (MySQL)**
- **Code source de sauvegarde détecté**
- **Cross-Site Scripting aveugle**

En plus de stocker les données de vulnérabilité et de fournir un cadre de remédiation, DefectDojo enrichit également vos Constatations des façons suivantes :
- Ajout automatique des scores EPSS associés à une Constatation pour décrire son exploitabilité
- Traduction automatique de la métrique de sévérité d'un outil de sécurité en un score de Sévérité pour chaque Constatation, ce qui confère un SLA à la Constatation selon la configuration SLA de votre Actif. Pour plus d'informations sur la configuration des SLA, cliquez [ici](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

Dans l'ensemble, les Constatations sont conçues pour fonctionner avec la hiérarchie des produits afin de normaliser vos efforts et d'appliquer une méthode cohérente à chaque Actif.

## Accès aux Constatations
Les Constatations sont accessibles depuis la barre latérale. Le sous-menu donne accès aux Constatations Actives et Atténuées, à Toutes les Constatations (quel que soit leur statut Ouvert ou Fermé), aux Groupes de constatations, aux Modèles de constatation, ainsi qu'au workflow de Nouvelle constatation. Les Constatations individuelles sont également accessibles depuis le Test qui les contient.

[Constatations à risque accepté] (/triage_findings/findings_workflows/os__risk_acceptance/) sont accessibles depuis la section **Acceptations du risque** de la barre latérale.

![image](images/profindings_ss1.png)

### Autorisations
Chaque Constatation appartient à un Test, ce qui permet à DefectDojo de conserver la trace du scan ou de l'évaluation ayant initialement identifié la vulnérabilité.

Comme les Constatations appartiennent à des Tests, l'accès aux Constatations est déterminé par l'accès d'un Utilisateur à l'Actif qui contient le Test. Les Tests ne disposent pas de listes de contrôle d'accès indépendantes.

## Vue des Constatations
Les vues de Constatation contiennent divers tableaux permettant d'interpréter en un coup d'œil le statut d'une Constatation.

### Aperçu de la Constatation
- **Description** : la description de la Constatation (ajoutée automatiquement selon le type de Constatation, ou créée manuellement).
- **Atténuation** : étapes suggérées pour atténuer le problème.
- **Politique d'atténuation générale** : la politique d'atténuation normalisée pour la Constatation sélectionnée.
Les politiques d'atténuation se trouvent et peuvent être modifiées dans la barre latérale, sous **Configuration** → **Politiques d'atténuation**.
- **Impact** : impact potentiel si la Constatation n'est pas résolue.
- **Références** : URL permettant de faire référence à la description spécifique de la Constatation fournie par l'outil de scan tiers. Par exemple, les Références peuvent être des liens vers une entrée pertinente d'un catalogue de Constatations, ou une URL d'avis unique.
- **Fichiers** : tout fichier ajouté pour contextualiser la Constatation.
- **Notes** : notes laissées par les Utilisateurs à propos de la Constatation. Marquer une note comme privée signifie qu'elle ne sera incluse dans aucun rapport généré comprenant la Constatation sélectionnée.

### Métadonnées
- **ID** : l'identifiant unique de la Constatation dans DefectDojo.
- **Organisation, Actif, Engagement et Test** : les objets parents de la Constatation sélectionnée.
- **Statut** : le statut de la Constatation (par exemple, Actif, Vérifié, Faux positif, Doublon, Hors périmètre et En révision de défaut).
- **Sévérité** : la note de sévérité de cette Constatation, appliquée automatiquement.
    - Comme mentionné plus haut, DefectDojo traduit automatiquement la métrique de sévérité d'un outil de sécurité en un score de Sévérité pour chaque Constatation, ce qui confère un SLA à la Constatation selon la configuration SLA de votre Actif.
- **Risque** : un système de classement à 4 niveaux qui prend en compte l'exploitabilité d'une Constatation et qui est appliqué automatiquement.
    - Vous trouverez des détails sur le calcul de la priorité, du risque et des SLA [ici](/asset_modelling/pro_hierarchy/priority_sla/#main-content). Des détails supplémentaires sur les définitions du statut et du niveau de risque des Constatations sont disponibles [ici](/triage_findings/findings_workflows/finding_status_definitions/).
- **Priorité** : un rang numérique calculé, appliqué à toutes les Constatations, qui permet de comprendre rapidement les vulnérabilités dans leur contexte.
- **Ancienneté** : l'âge de la Constatation sélectionnée.
- **SLA** : la date d'échéance à laquelle la Constatation est censée être résolue.
- **Type** : indique si la Constatation a été détectée par un outil de sécurité applicative statique ou dynamique (Statique, Dynamique ou Statique/Dynamique).
- **Emplacement et ligne** : le fichier et le numéro de ligne où la Constatation sélectionnée a été trouvée.
- **Nom et version du composant** : le nom et la version du composant dans lequel la Constatation sélectionnée a été trouvée.
- **Date de découverte** : la date à laquelle la Constatation a été découverte.
- **Date et version de remédiation prévues** : la date à laquelle la remédiation de la Constatation est prévue, et la version du composant concerné dans laquelle le correctif sera implémenté.
- **Service** : les Services connectés (éléments fonctionnels autonomes au sein d'un Actif) affectés par la Constatation sélectionnée. Lorsqu'il est renseigné, ce champ est pris en compte dans la correspondance de déduplication (c'est-à-dire que les Constatations ayant des champs Service identiques seront dédupliquées).
- **Rapporteur** : l'Utilisateur ayant révélé la Constatation.
- **CWE** : la classification de la faiblesse CWE de la Constatation. Une Constatation peut porter **plusieurs CWE** — un CWE principal, ainsi que tout CWE supplémentaire fourni par l'outil de signalement. Le CWE principal est celui utilisé pour la déduplication historique et le calcul du hash code ; l'ensemble complet des CWE peut également être utilisé pour la correspondance via les champs de hash code basés sur des ensembles de Pro (voir [Réglage de la déduplication](/triage_findings/finding_deduplication/pro__deduplication_tuning/#set-based-hash-code-fields-vulnerability-ids-and-cwes)).
    - Un CWE décrit une *classe* de faiblesse (par exemple, « Injection SQL »), et non une instance de vulnérabilité spécifique — c'est à cela que servent les Identifiants de vulnérabilité.
- **Identifiants de vulnérabilité** : identifiants de vulnérabilité publiquement reconnus associés à la Constatation, tels que CVE, GHSA ou d'autres références d'avis normalisées. Dans DefectDojo Pro, ils sont également utilisés pour effectuer des recherches EPSS et KEV.
    - Les Identifiants de vulnérabilité sont stockés comme des enregistrements de premier ordre, de sorte qu'un même CVE est suivi une seule fois et partagé par toutes les Constatations qui y font référence. Vous pouvez les consulter — ainsi que leurs valeurs EPSS et KEV — dans l'**Explorateur de vulnérabilités**. Voir [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/#viewing-kevepss-in-the-vulnerability-explorer).
- **ID unique de l'outil** : identifiant stable attribué par l'outil source à une instance spécifique de Constatation. Les ID uniques sont censés rester cohérents d'un scan à l'autre, ce qui permet à l'outil de reconnaître la même Constatation au fil du temps.
    - Contrairement aux Identifiants de vulnérabilité, cette valeur est propre à l'outil de signalement et ne constitue pas une référence publique de vulnérabilité.
        - Exemple : `finding-12345`
- **ID de vulnérabilité de l'outil** : identifiant propriétaire de vulnérabilité ou de règle attribué par l'outil source pour décrire le type de vulnérabilité détecté.
    - Contrairement à l'ID unique de l'outil, cet identifiant n'est pas propre à une Constatation individuelle et peut apparaître sur de nombreuses Constatations correspondant à la même règle de détection.
    - Contrairement aux Identifiants de vulnérabilité, ces identifiants sont spécifiques à l'outil de signalement et ne sont pas normalisés publiquement.
        - Exemple : `semgrep.rule.lang.security.sql-injection`
- **Score EPSS / Percentile** : le score EPSS et le percentile du CVE.
- **Exploitation connue** : indique s'il existe une confirmation que la vulnérabilité a été exploitée.
- **Rançongiciel utilisé** : indique si un rançongiciel a été impliqué dans l'exploitation de la vulnérabilité.
- **Date KEV** : la date à laquelle la Constatation a été ajoutée au catalogue KEV.
- **Détecté par** : le type d'outil ayant identifié la vulnérabilité.
- **Vecteur et score CVSSv3 et CVSSv4** : le vecteur et le score CVSS3 et CVSS4 de la Constatation sélectionnée.
- **Tickets d'intégrateur** : numéros de tickets de systèmes de suivi des problèmes tiers associés à la Constatation.

### Points de terminaison vulnérables
Cette section comprend un tableau des Points de terminaison affectés par la Constatation sélectionnée, ainsi que les métadonnées pertinentes.

### Détails supplémentaires
- **Paires requête/réponse** : une copie du message envoyé par le client et de la réponse du serveur à la requête.
- **Étapes de reproduction** : les étapes permettant de reproduire la Constatation.
- **Justification de la sévérité** : description écrite expliquant pourquoi une certaine note de Sévérité a été associée à la Constatation.

## Données des Constatations
Les Constatations nécessitent les métadonnées suivantes :
- **Nom**
- **Date**
- **Sévérité**
- **Description**

En plus des métadonnées correspondant aux tableaux de la vue d'une Constatation, les champs de métadonnées optionnels comprennent :
- **Étiquettes** : toutes les étiquettes ajoutées à la Constatation.
- **Propriétaires** : le groupe d'utilisateurs responsable de la Constatation sélectionnée.
- **Envoyer vers Jira** : envoie la Constatation vers Jira à des fins de gestion des tickets.
- **Envoyer vers l'intégrateur** : envoie la Constatation vers tout système de suivi des problèmes tiers intégré.
- **Paramètres de risque et de priorité** : offre la possibilité de remplacer le calcul automatique du risque et de la priorité de la Constatation effectué par DefectDojo.
- **Points de terminaison à ajouter** : points de terminaison vulnérables susceptibles d'être affectés par la Constatation sélectionnée et qui ne figurent pas dans la liste précédente des systèmes/points de terminaison.
- **Révision de défaut demandée par** : enregistre qui a demandé une révision de défaut pour la faille en question.
- **Objet source SAST, numéro de ligne et chemin du fichier** : objet source, numéro de ligne et chemin du fichier du vecteur d'attaque.
- **Objet de destination SAST** : objet de destination (sink) du vecteur d'attaque.
- **Nombre d'occurrences** : nombre d'occurrences dans l'outil source lorsque plusieurs vulnérabilités ont été trouvées et regroupées par le scanner.
- **Date de publication** : la date à laquelle la vulnérabilité a été publiée.
- **Estimation de l'effort** : le niveau d'effort requis pour corriger la Constatation (par exemple, Faible, Moyenne ou Élevée).

Les métadonnées exactement disponibles dépendent de l'analyseur/scanner ayant révélé la Constatation. Certains ne fournissent que des informations basiques telles que le titre et la sévérité, tandis que d'autres incluent des vecteurs CVSS, des composants vulnérables, des points de terminaison, des paires requête/réponse et d'autres métadonnées spécifiques au scanner.
 
Ces métadonnées améliorent le filtrage, le reporting et la priorisation au sein de votre programme de sécurité, en permettant un suivi à long terme et une analyse des tendances. Des détails supplémentaires et des descriptions des métadonnées sont disponibles [ici](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page).

### Déduplication
DefectDojo intègre des fonctionnalités de déduplication qui aident à identifier et à gérer les Constatations représentant une même vulnérabilité sous-jacente. Lorsque les résultats de scan sont importés depuis un ou plusieurs outils, DefectDojo utilise une logique de correspondance configurable pour identifier les Constatations représentant la même vulnérabilité.

La déduplication empêche qu'une même vulnérabilité n'apparaisse plusieurs fois lorsqu'elle est découverte à répétition par le même scanner ou par des scanners différents, ce qui permet à l'historique de remédiation de rester rattaché à une seule Constatation.

Vous trouverez plus d'informations sur la déduplication [ici](/triage_findings/finding_deduplication/about_deduplication/).

### Réimportation
La fonction de réimportation de DefectDojo permet de mettre à jour les Constatations à mesure que de nouveaux résultats de scan sont importés. Lorsqu'un scan est réimporté, DefectDojo compare les résultats entrants aux Constatations existantes et met à jour les enregistrements correspondants au lieu d'en créer de nouveaux. Cela préserve un contexte précieux tel que les changements de statut, l'historique de remédiation, les commentaires et les informations de propriété, offrant ainsi un enregistrement continu du cycle de vie d'une Constatation à travers plusieurs cycles de test.

Vous trouverez plus d'informations sur la fonction de réimportation [ici](/import_data/import_intro/reimport/).

### Acceptations du risque
Les Acceptations du risque sont un statut spécial pouvant être appliqué aux Constatations afin de documenter formellement et de mettre en œuvre la décision de les reconnaître sans les corriger immédiatement.

Vous trouverez plus d'informations sur les Acceptations du risque [ici](/triage_findings/findings_workflows/pro__risk_acceptance/).

### Statuts
Chaque Constatation créée dans DefectDojo possède un Statut qui communique des informations pertinentes et aide votre équipe à suivre l'avancement de la résolution des problèmes.

Vous trouverez plus d'informations sur les Statuts [ici](/triage_findings/findings_workflows/finding_status_definitions/).

## Travailler avec les Constatations

### Créer des Constatations
Bien que la plupart des Constatations soient générées automatiquement via les imports de scans et les intégrations, DefectDojo prend également en charge la création manuelle de Constatations. Les Constatations manuelles sont utiles pour suivre les vulnérabilités et les problèmes de sécurité identifiés lors de tests d'intrusion, de revues d'architecture, d'évaluations de conformité, de programmes de bug bounty, de missions de consultants, ou d'autres activités qui ne produisent pas de résultats de scanner.

Les Constatations peuvent être ajoutées manuellement en cliquant sur **Nouvelle constatation** dans la section **Constatations** de la barre latérale, ou en sélectionnant **Ajouter une constatation** dans le menu d'engrenage du Test auquel vous souhaitez ajouter la Constatation.

### Modifier des Constatations
Le menu kebab ⋮ situé à côté des Constatations contient les fonctions suivantes :
- **Modifier la constatation** : modifie la Constatation.
- **Copier la constatation** : crée une copie de la Constatation dans un autre Test. La copie peut être enregistrée dans n'importe quel Test du même Engagement pour lequel vous disposez des droits de modification. La copie est utile lorsque la même vulnérabilité doit être suivie séparément dans plusieurs contextes de Test.
- **Fermer la constatation** : lance le processus de fermeture de la Constatation.
- **Demander une révision** : lance le processus de révision par les pairs et fait passer le statut de la Constatation à « En révision ». Vous trouverez plus d'informations sur les révisions par les pairs [ici](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Ajouter une acceptation du risque** : lance le processus d'Acceptation du risque. Vous trouverez plus d'informations [ici](/triage_findings/findings_workflows/pro__risk_acceptance/).
- **Ajouter un fichier** : lance le processus d'ajout d'un fichier à la Constatation (voir la section ci-dessous).
- **Ajouter une note** : lance le processus d'ajout d'une note à la Constatation.
- **Ajouter un champ personnalisé** : ouvre une fenêtre contextuelle permettant d'ajouter et de définir un champ personnalisé à appliquer à la Constatation.
- **Envoyer vers Jira** : envoie la Constatation vers Jira à des fins de gestion des tickets.
- **Envoyer vers l'intégrateur** : envoie la Constatation vers tout système de suivi des problèmes tiers intégré.
- **Supprimer la constatation** : supprime la Constatation sélectionnée.
- **Historique de la constatation** : affiche l'historique de la Constatation sélectionnée.

#### Joindre des fichiers aux Constatations
Vous pouvez joindre des fichiers à n'importe quelle Constatation pour fournir un contexte supplémentaire — par exemple, une capture d'écran d'une vulnérabilité en action ou une image de preuve de concept.

Les types de fichiers pris en charge sont les suivants :

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Pour joindre un fichier à une Constatation, cliquez sur **Ajouter un fichier** dans le menu kebab ⋮ ou dans le menu d'engrenage de la Constatation sélectionnée. Saisissez un Titre pour le fichier, choisissez le fichier sur votre ordinateur, puis cliquez sur **Envoyer**.

Le fichier apparaîtra alors dans la section Fichiers du tableau **Aperçu du test** dans la vue de la Constatation.

#### Modifier des Constatations en masse
Les Constatations peuvent être modifiées en masse depuis une liste de Constatations, comme le tableau Toutes les Constatations accessible depuis la barre latérale, ou depuis le tableau des Constatations d'un Test spécifique.

Vous trouverez plus d'informations sur la modification en masse des Constatations [ici](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings).

### Fermer des Constatations
Une fois le travail sur une Constatation terminé, vous pouvez la fermer manuellement en cliquant sur **Fermer la constatation** dans le menu kebab ⋮ ou le menu d'engrenage de la Constatation. Autrement, si un scan est réimporté dans DefectDojo sans qu'il ne contienne une Constatation précédemment enregistrée, cette dernière se fermera automatiquement.

Si vous ne souhaitez qu'aucune Constatation ne soit fermée, vous pouvez désactiver ce comportement dans le formulaire de réimportation de scan :

- Décochez la case Fermer les anciennes constatations si vous utilisez l'interface utilisateur
- Définissez close_old_findings sur False si vous utilisez l'API ​

### Supprimer des Constatations
La suppression d'une Constatation peut être effectuée depuis le menu kebab ⋮ ou le menu d'engrenage de la Constatation. Cette action est irréversible.

À des fins d'audit, il est recommandé de fermer les Constatations corrigées plutôt que de les supprimer.

## Groupes de constatations
**Les Groupes de constatations** vous permettent de traiter plusieurs Constatations liées entre elles comme une seule unité logique pour le triage, le reporting et la coordination de la remédiation.

Par exemple, un scan peut produire 10 Constatations d'injection SQL réparties sur différents points de terminaison. Plutôt que de gérer chacune indépendamment, vous pouvez les regrouper au sein d'un seul Groupe de constatations représentant le problème d'injection SQL dans son ensemble.

Un Groupe de constatations ne remplace pas les Constatations individuelles. Chaque Constatation continue d'exister avec sa propre sévérité, son propre statut, ses propres métadonnées, commentaires et historique de remédiation. Un Groupe de constatations fournit simplement une couche organisationnelle supplémentaire au-dessus des Constatations qu'il contient.

### Accès aux Groupes de constatations
Les Groupes de constatations sont accessibles depuis la barre latérale. Le sous-menu donne accès aux Groupes de constatations Ouverts et Fermés, ainsi qu'à Tous les groupes de constatations (quel que soit leur statut Ouvert).

![image](images/profindings_ss1.png)

### Créer des Groupes de constatations
Les Groupes de constatations peuvent être créés manuellement ou automatiquement.

Il est à noter que les Groupes de constatations ne peuvent être créés qu'à partir des Constatations contenues dans un seul Test. Les Constatations provenant de Tests, d'Engagements ou de Produits différents ne peuvent pas être ajoutées au même Groupe de constatations.

#### Groupes de constatations manuels
Pour effectuer manuellement des actions de Groupe de constatations :
1. Accédez à une liste de Constatations au sein d'un Test.
2. Sélectionnez la ou les Constatations que vous souhaitez ajouter à un Groupe de constatations en cochant la case correspondante.
3. Cliquez sur le bouton **Groupe de constatations** qui apparaît en haut de la liste des Constatations.
4. Cliquez sur l'action correspondante que vous souhaitez effectuer.
    - **Ajouter à un nouveau groupe de constatations** : crée un nouveau Groupe de constatations incluant les Constatations sélectionnées.
    - **Ajouter à un groupe de constatations existant** : ajoute les Constatations sélectionnées à un Groupe de constatations préexistant.
    - **Retirer du groupe de constatations** : retire les Constatations sélectionnées de tout Groupe de constatations dont elles faisaient précédemment partie.
5. Cliquez sur **Envoyer**.

Notez que le regroupement sera désactivé à moins que chaque Constatation sélectionnée soit modifiable, non regroupée et appartienne au même Test.

Par ailleurs, notez que la seule action possible lors de la sélection de Constatations depuis la liste Toutes les Constatations consiste à retirer les Constatations sélectionnées de tout Groupe de constatations. En effet, comme mentionné, les Groupes de constatations ne peuvent être créés qu'à partir des Constatations contenues dans un seul Test.

#### Groupes de constatations automatiques
Lors de l'import d'un scan, la fonctionnalité **Regrouper par** du menu déroulant **Champs optionnels** peut créer automatiquement des Groupes de constatations selon une méthode de regroupement choisie. Cela est utile lorsqu'un scanner produit de nombreuses Constatations liées qui doivent être gérées ensemble.

La case à cocher adjacente **Créer des groupes de constatations pour toutes les constatations** remplit deux fonctions :
- **Cochée** : crée un Groupe de constatations pour chaque Constatation importée, même si cette Constatation est l'unique membre du groupe.
- **Décochée** : ne crée des Groupes de constatations que lorsqu'il y a réellement plusieurs Constatations à regrouper.

![image](images/profindings_ss2.png)

Si aucune option n'est sélectionnée dans le menu déroulant Regrouper par lors de l'import (par exemple, **Titre de la constatation** dans la capture d'écran ci-dessus, etc.), aucun regroupement n'aura lieu.

Si le critère de regroupement (par exemple, le nom du composant, l'identifiant de vulnérabilité, le titre de la Constatation, etc.) n'est pas renseigné dans la Constatation, aucun groupe ne sera créé pour elle et elle ne sera pas ajoutée à un Groupe de constatations préexistant.

Si un scan est importé et révèle 10 Constatations qui ne sont pas regroupées, puis que ce même scan est réimporté avec un regroupement des Constatations, les 10 premières Constatations ne seront pas ajoutées à ce Groupe de constatations (c'est-à-dire que le Groupe de constatations n'inclura que les 10 Constatations issues de la réimportation, et non les 10 Constatations de l'import initial).

## Modèles de constatation
**Les Modèles de constatation** permettent aux Utilisateurs de créer des modèles réutilisables pour les vulnérabilités et problèmes de sécurité fréquemment signalés. Un modèle peut inclure des informations normalisées telles qu'un titre, une description, un impact, des étapes de reproduction, une atténuation, des références et d'autres métadonnées de Constatation.

Les Modèles de constatation sont particulièrement utiles lorsque les Utilisateurs doivent créer des Constatations manuelles de manière répétée et souhaitent éviter de ressaisir les mêmes informations à chaque fois.

### Accès aux Modèles de constatation
Les Modèles de constatation se trouvent dans le sous-menu Constatations de la barre latérale.

![image](images/profindings_ss1.png)

### Créer des Modèles de constatation
Les Modèles de constatation peuvent être créés en cliquant sur le bouton **Nouveau modèle de constatation** en haut à gauche de la vue Modèles de constatation.

La page qui s'affiche présente un aperçu des métadonnées qui seront appliquées à une Constatation lors de l'utilisation d'un Modèle de constatation.

### Appliquer des Modèles de constatation
Les Modèles de constatation diffèrent entre DefectDojo OS et DefectDojo Pro. Dans Pro, les Modèles de constatation ne peuvent pas être appliqués à des Constatations préexistantes, et ils ne peuvent pas être créés à partir de Constatations préexistantes.

Cependant, vous pouvez ajouter manuellement une Constatation à un Test à partir d'un Modèle de constatation, en utilisant soit le menu kebab ⋮ situé à côté du Test dans la vue de l'Engagement parent, soit le menu d'engrenage dans la vue du Test.

![image](images/profindings_ss3.png)

![image](images/profindings_ss4.png)

## Reporting
Le générateur de rapports de DefectDojo vous permet d'assembler un rapport personnalisé à partir d'un ensemble de widgets de contenu, de l'exécuter et d'exporter le résultat (par exemple, en l'imprimant au format PDF). Les rapports personnalisés peuvent résumer les Constatations ou les Points de terminaison que vous souhaitez partager avec un public externe, et peuvent inclure une image de marque et du texte standard.

Vous trouverez plus d'informations sur le Générateur de rapports de DefectDojo [ici](/metrics_reports/reports/report-builder/).

### Exporter les Constatations
Les pages affichant une liste de Constatations ou une liste d'Engagements disposent d'une option d'export CSV et Excel en haut à gauche. Pour les Constatations, il existe également une option d'Export rapide, qui ouvre un nouvel onglet contenant des tableaux de métadonnées relatives à chaque Constatation.
