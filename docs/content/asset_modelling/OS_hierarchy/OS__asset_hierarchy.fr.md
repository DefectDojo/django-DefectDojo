---
title: 'Hiérarchie des Actifs : Aperçu'
description: Comprendre les Organisations, Actifs, Engagements, Tests et Constatations
weight: 1
audience: opensource
aliases:
- /fr/en/working_with_findings/organizing_engagements_tests/product_hierarchy
- /fr/asset_modelling/os_hierarchy/product_hierarchy/
- /fr/en/asset_modelling/os_hierarchy/product_hierarchy/
---

DefectDojo utilise cinq classes de données principales pour organiser votre travail : les **Organisations, Actifs**, **Engagements**, **Tests**, et **Constatations**.

DefectDojo est conçu pour s'adapter à votre équipe, plutôt que de forcer votre équipe à s'adapter à l'outil. Vous pourrez concevoir un espace de travail robuste et adaptable une fois que vous aurez compris comment ces classes de données peuvent être utilisées pour organiser votre travail.

### Diagramme de la hiérarchie des Actifs
![image](images/Asset_Hierarchy_Full.png)


## **Organisations**

La première catégorie de données que vous devrez configurer dans DefectDojo est une Organisation. Les Organisations sont destinées à catégoriser les Actifs d'une manière spécifique. Cela peut être :

* par domaine d'activité
* par équipe de développement
* par équipe de sécurité

![image](images/Asset_Hierarchy_Overview.png)
*Les Actifs sont regroupés et imbriqués sous leur Organisation.*

Des règles de Contrôle d'Accès Basé sur les Rôles peuvent être appliquées aux Organisations, ce qui limite la capacité des membres de l'équipe à consulter et interagir avec leurs données (y compris les Actifs sous-jacents avec les données d'Engagement, de Test et de Constatation). Pour plus d'informations sur les rôles utilisateur, consultez notre article **Introduction aux rôles**.

#### Que peut représenter une Organisation ?

* Si un projet logiciel particulier comporte de nombreux déploiements ou versions distincts, il peut être utile de créer une seule Organisation couvrant l'ensemble du périmètre du projet, chaque version existant comme un Actif individuel.
​
* Vous pourriez également envisager d'utiliser les Organisations pour représenter les étapes de votre processus de développement logiciel : une Organisation pour « En développement », une Organisation pour « En production », etc.
​
* En fin de compte, c'est à vous de décider comment organiser vos Actifs et ce que vous souhaitez que vos Organisations représentent. Votre hiérarchie DefectDojo devra peut-être évoluer pour répondre aux besoins de vos équipes de sécurité.

## **Actifs**

Un **Actif** dans DefectDojo est destiné à représenter tout projet, programme ou application que vous testez actuellement. L'Actif héberge l'ensemble du travail de sécurité et de l'historique de test relatifs à l'objectif sous-jacent.

![image](images/Asset_Hierarchy_Overview_2.png)

* un **Nom** unique
* une **Description**
* une **Organisation**
* une **Configuration SLA** assignée

Les Actifs peuvent avoir un périmètre aussi large ou aussi spécifique que vous le souhaitez. Par défaut, les Actifs sont des objets totalement distincts dans la hiérarchie, mais ils peuvent être regroupés par **Organisation**.

Les Actifs sont « cloisonnés » et n'interagissent pas avec d'autres Actifs. Les fonctionnalités intelligentes de DefectDojo, telles que la **Déduplication**, ne s'appliquent que dans le contexte d'un seul Actif.

Comme les **Organisations**, les **Actifs** peuvent avoir des règles de Contrôle d'Accès Basé sur les Rôles appliquées, ce qui limite la capacité des membres de l'équipe à les consulter et à interagir avec eux (ainsi qu'avec les données d'Engagement, de Test et de Constatation sous-jacentes). Pour plus d'informations sur les rôles utilisateur, consultez notre article **Introduction aux rôles**.

#### Que peut représenter un Actif ?

Le concept d'« Actif » de DefectDojo ne correspond pas nécessairement de façon exacte à ce que votre organisation appellerait un « Produit ». Le développement logiciel est complexe, et les besoins de sécurité peuvent varier considérablement même au sein d'un seul logiciel.

Les scénarios suivants sont de bonnes raisons d'envisager la création d'un Actif DefectDojo distinct :

* « **ExampleAsset** » possède une version Windows, une version Mac et une version Cloud
* « **ExampleAsset 1.0** » utilise des composants logiciels complètement différents de « **ExampleAsset 2.0** », et les deux versions sont activement prises en charge par votre entreprise.
* L'équipe chargée de travailler sur « **ExampleAsset version A** » est différente de l'équipe chargée de « **ExampleAsset version B** », et doit par conséquent se voir attribuer des permissions de sécurité différentes.

Ces variations au sein d'un même Actif peuvent également être gérées au niveau de l'Engagement. Notez que les Engagements ne disposent pas de contrôle d'accès de la même manière que les Actifs et les Organisations.

## **Engagements**

Une fois qu'un Actif est configuré, vous pouvez commencer à créer et planifier des Engagements. Les Engagements sont destinés à représenter des moments dans le temps où des tests ont lieu, et contiennent un ou plusieurs **Tests**.

Les Engagements ont toujours :

* un **Nom** unique
* des **dates de début et de fin** cibles
* un **Statut** (Not Started, In Progress, Cancelled, Completed...)
* un **Responsable de test** assigné
* un **Actif** associé

Il existe deux types d'Engagement : **Interactif** et **CI/CD**.

* Un **Engagement Interactif** est généralement mené par un ingénieur. Les Engagements Interactifs se concentrent sur le test de l'application pendant son exécution, à l'aide d'un test automatisé, d'un testeur humain, ou de toute activité « interagissant » avec les fonctionnalités de l'application. Voir la [définition de l'IAST par l'OWASP](https://owasp.org/www-project-devsecops-guideline/latest/02c-Interactive-Application-Security-Testing#:~:text=Interactive%20Application%20Security%20Testing,interacting%E2%80%9D%20with%20the%20application%20functionality.).
* Un **Engagement CI/CD** est destiné à l'intégration automatisée avec un pipeline CI/CD. Les Engagements CI/CD sont destinés à importer des données en tant qu'action automatisée, déclenchée par une étape du processus de mise en production.

Les Engagements peuvent être suivis à l'aide de la vue **Calendrier** de DefectDojo.

#### Que peut représenter un Engagement ?

Les Engagements sont destinés à représenter des groupes d'efforts de test liés entre eux. La manière dont vous souhaitez regrouper vos efforts de test dépend de votre approche.

Si vous avez un effort de test planifié, un Engagement vous offre un endroit pour stocker tous les résultats associés. Voici un exemple de ce type d'Engagement :

#### **Engagement :** ExampleSoftware 1.5.2 - Effort de test interactif

*Dans cet exemple, une équipe de sécurité exécute plusieurs tests le même jour dans le cadre d'une mise en production logicielle.*

* **Test :** Résultats du scan Nessus (12 mars)
* **Test :** Résultats de l'audit de scan NPM (12 mars)
* **Test :** Résultats du scan Snyk (12 mars)
​
Vous pouvez également organiser les résultats de Test CI/CD au sein d'un Engagement. Ce type d'Engagement est « Open-Ended » (à durée indéterminée), ce qui signifie qu'il n'a pas de date, et ajoutera plutôt des données supplémentaires chaque fois que les actions CI/CD associées seront exécutées.

#### Engagement : ExampleSoftware CI/CD Testing

*Dans cet exemple, plusieurs scans CI/CD sont automatiquement importés en tant que Tests à chaque création d'une nouvelle version logicielle.*

* Test : Résultats du scan 1.5.2 (12 mars)
* Test : Résultats du scan 1.5.1 (3 mars)
* Test : Résultats du scan 1.5.0 (14 février)

Les Engagements peuvent être organisés de la manière qui convient le mieux à votre équipe. Tous les Engagements imbriqués sous un Actif peuvent être consultés par l'équipe chargée de travailler sur cet Actif.

## **Tests**

Les Tests sont un regroupement d'activités menées par des ingénieurs pour tenter de découvrir des failles dans un Actif.

Les Tests ont toujours :

* un **Titre de Test** unique
* un **Type de Test** spécifique (API Test, Nessus Scan, etc)
* un **Environnement** de test associé
* un **Engagement** associé

Les Tests peuvent être créés de différentes manières. Les Tests peuvent être créés automatiquement lorsque des données de scan sont importées directement dans un Engagement, ce qui donne lieu à un nouveau Test contenant les données de scan. Les Tests peuvent également être créés en prévision de la planification d'Engagements futurs, ou pour des constatations de sécurité saisies manuellement nécessitant un suivi et une remédiation.

### **Types de Test**

DefectDojo prend en charge deux catégories de Types de Test :

1. **Types de Test basés sur un analyseur** : ils correspondent à des scanners de sécurité spécifiques produisant une sortie dans des formats tels que XML, JSON ou CSV. Lors de l'import des résultats de scan, DefectDojo utilise des analyseurs spécialisés pour convertir la sortie du scanner en Constatations.

2. **Types de Test sans analyseur** : ils sont utilisés pour les Constatations créées manuellement, non importées depuis des fichiers de scan.  Ces Types de Test utilisent la méthode [Generic Findings Import](/supported_tools/parsers/generic_findings_import/) pour afficher les Constatations et les métadonnées.

Les Types de Test suivants apparaissent dans le menu déroulant « Scan Type » lors de la création d'un nouveau test.
   * API Test
   * Static Check
   * Pen Test
   * Web Application Test
   * Security Research
   * Threat Modeling
   * Manual Code Review

Les Types de Test sans analyseur doivent être utilisés lorsque vous devez créer manuellement des constatations nécessitant une remédiation, mais qui ne proviennent pas d'une sortie de scanner automatisée.

#### **Types de Test basés sur un analyseur**

Les types de test basés sur un analyseur peuvent être catégorisés selon la façon dont le nom de leur type de test est déterminé :

- **Noms de Type de Test fixes** : le nom du type de test est prédéfini et connu avant l'import (par ex. « ZAP Scan », « Nessus Scan »).

- **Noms de Type de Test définis par le rapport** : le nom du type de test est extrait du contenu du rapport de scan au moment de l'import.

Exemples :
  - **Generic Findings Import** : crée des types de test basés sur le champ `type` dans les rapports JSON
  - **SARIF** : crée des types de test basés sur les noms d'outils dans le rapport SARIF (par ex. « Dockle Scan (SARIF) »)
  - **OpenReports** : crée des types de test distincts pour chaque source trouvée dans le rapport

**Règles de nommage des Types de Test définis par le rapport :**
- Si le champ `type` du rapport est identique au type de scan → le type de scan est utilisé directement (par ex. « Generic Findings Import »)
- Si le champ `type` du rapport diffère → un format « {type} Scan ({scan_type}) » est créé (par ex. « Tool1 Scan (Generic Findings Import) »)
- Si le champ `type` du rapport se termine déjà par le suffixe « ({scan_type}) » → il est utilisé tel quel, de sorte que le suffixe n'est jamais dupliqué (par ex. « Tool1 (Generic Findings Import) » reste « Tool1 (Generic Findings Import) »)
- Si aucun champ `type` n'est fourni → le type de scan est utilisé directement

**Points importants à considérer :**
- Les types de test définis par le rapport sont créés automatiquement lorsqu'un nouveau type est détecté lors de l'import ou du réimport.
- Pour les réimports, le nom du type de test doit correspondre exactement - toute discordance déclenchera une erreur de validation
- Les paramètres de déduplication (`HASHCODE_FIELDS_PER_SCANNER`) utilisent les noms de type de test comme clés ; les noms définis par le rapport doivent donc être configurés en conséquence si vous souhaitez un comportement de déduplication personnalisé

#### **Comment les Tests interagissent-ils entre eux ?**

Les Tests prennent vos données de test et les regroupent en Constatations. En général, les équipes de sécurité répètent le même effort de test à plusieurs reprises, et les Tests dans DefectDojo permettent de gérer ce processus de manière élégante.

**Les tests précédemment importés peuvent être réimportés** - Si vous exécutez le même type de test dans le même contexte d'Engagement, vous pouvez réimporter les résultats du test après chaque scan terminé. DefectDojo comparera les données réimportées au résultat existant, et ne créera pas de nouvelles Constatations si des doublons existent dans les données de scan.

**Les Tests peuvent être importés séparément** - Si vous exécutez le même test sur un Actif au sein d'Engagements distincts, DefectDojo comparera tout de même les données avec les Tests précédents pour trouver les Constatations en double. Cela vous permet de garder une trace des Constatations précédemment atténuées ou dont le risque a été accepté.

Si un Test est ajouté directement à un Actif sans Engagement, un Engagement générique sera créé automatiquement pour contenir le Test. Cela permet des imports de données ad hoc.

**Exemples de Tests :**

* Scan Burp du 29 oct. 2015 au 29 oct. 2015
* Scan Nessus du 31 oct. 2015 au 31 oct. 2015
* API Test du 15 oct. 2015 au 20 oct. 2015

## **Constatations**

Une fois que des données ont été téléversées dans un Test, les résultats de ces données seront répertoriés dans le Test sous forme de **Constatations** individuelles à examiner.

Une constatation représente une faille spécifique découverte lors des tests.

Les Constatations ont toujours :

* un **Nom de Constatation** unique
* la **Date** à laquelle elles ont été découvertes
* plusieurs **Statuts** associés, tels que Actif, Vérifié ou Faux positif
* un **Test** associé
* un niveau de **Sévérité** : Critique, Élevée, Moyenne, Faible, et Informationnel (Info).

Les Constatations peuvent être ajoutées via un import de données, mais elles peuvent également être ajoutées manuellement à un Test.

**Exemples de Constatations :**

* Vulnérabilité potentielle MiTM OpenSSL « ChangeCipherSpec »
* Application Web potentiellement vulnérable au Clickjacking
* Protection XSS du navigateur Web non activée

## **Points de terminaison**

Les données de scan contiennent généralement des références aux hôtes ou points de terminaison affectés par une Constatation donnée.  DefectDojo agrège automatiquement les Constatations par point de terminaison, ce qui vous permet d'utiliser la vue Point de terminaison pour consulter toutes les Constatations affectant un Point de terminaison ou un nom d'hôte donné.

Exemples :
-   https://www.example.com
-   https://www.example.com:8080/products
-   192.168.0.36
