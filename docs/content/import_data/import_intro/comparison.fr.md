---
title: Comparaison des méthodes d'importation
description: Découvrez comment importer des données manuellement, via l'API, ou via
  un connecteur
weight: 1
aliases:
- /fr/en/connecting_your_tools/import_intro
---

L'une des choses que nous comprenons chez DefectDojo, c'est que les besoins de sécurité de chaque entreprise sont complètement différents. Il n'existe pas d'approche universelle. À mesure que votre organisation évolue, il est essentiel de disposer d'une approche flexible, et DefectDojo vous permet de connecter vos outils de sécurité de manière flexible pour vous adapter à ces évolutions.

## Méthodes de téléversement des scans

Lorsque DefectDojo reçoit un rapport de vulnérabilité d'un outil de sécurité, il crée des Constatations basées sur les vulnérabilités contenues dans ce rapport. DefectDojo agit comme le référentiel central de ces Constatations, où elles peuvent être triées, corrigées, ou traitées d'une autre manière par vous et votre équipe.

Il existe deux principales façons pour DefectDojo de téléverser des rapports de Constatations.

* Via un **import** direct depuis l'interface
* Via un point de terminaison **API** (permettant une ingestion de données automatisée) : voir la [documentation de l'API](/automation/api/api-v2-docs/)

#### Méthodes DefectDojo Pro

Les utilisateurs de <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> disposent de trois méthodes supplémentaires pour traiter les rapports et les données :

* Via **Universal Importer** ou **DefectDojo CLI**, des outils en ligne de commande qui s'appuient sur l'API DefectDojo : voir les [guides Universal Importer et DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/)
* Via **Connectors** pour certains outils, une intégration de données « prête à l'emploi » : voir le [guide des Connectors](/connectors/upstream/about/)
* Via **Smart Upload** pour certains outils, un importeur conçu pour traiter les scans d'infrastructure : voir le [guide Smart Upload](/import_data/pro/specialized_import/smart_upload/)

### Comparaison des méthodes de téléversement

|  | **Import via l'interface** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Types de scan pris en charge** | Tous : voir [Outils pris en charge](/supported_tools/) | Tous : voir [Outils pris en charge](/supported_tools/) | Akamai API Security, Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, IriusRisk, JFrog Xray, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automatisation ?** | Disponible via l'API : points de terminaison `/reimport` `/import` | Déclenché depuis les [outils CLI](/import_data/pro/specialized_import/external_tools/) ou du code externe | Connectors est une fonctionnalité intrinsèquement automatisée | Disponible via l'API : point de terminaison `/smart_upload_import` |

### Hiérarchie de produits et organisation

Chacune de ces méthodes peut créer une hiérarchie de produits à la volée. La hiérarchie de produits désigne les Types de produit, Produits, Engagements ou Tests de DefectDojo : des objets dans DefectDojo qui aident à organiser vos données dans un contexte pertinent.

* **Les données de vulnérabilité peuvent être importées dans une hiérarchie de produits existante**. Les Types de produit, Produits, Engagements et Tests peuvent tous être créés à l'avance, puis les données peuvent être importées à cet emplacement dans DefectDojo.
* **La hiérarchie de produits contextuelle peut être créée au moment de l'import.** Lors de l'importation d'un rapport, vous pouvez créer un nouveau Type de produit, Produit, Engagement et/ou Test. Cela est géré par DefectDojo via l'option « auto-create context ». Dans DefectDojo OS, cette option n'est accessible que via l'API. Les imports via l'interface dans DefectDojo OS nécessiteront que la hiérarchie de produits soit créée au préalable.
