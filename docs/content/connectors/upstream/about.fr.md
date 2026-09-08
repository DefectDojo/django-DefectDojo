---
title: Connecteurs en amont
description: Connectez facilement DefectDojo à votre suite d'outils de sécurité
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 0
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
aliases:
- /fr/import_data/pro/connectors/about_connectors/
- /fr/en/connecting_your_tools/connectors/about_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les Connecteurs en amont sont une fonctionnalité réservée à DefectDojo Pro.</span>

DefectDojo permet aux utilisateurs de créer des intégrations API sophistiquées et leur donne un contrôle total sur la façon dont leurs données de vulnérabilités sont organisées. 

Mais tout le monde a besoin d'un point de départ, et c'est là qu'interviennent les Connecteurs en amont. Les Connecteurs en amont (anciennement appelés **API Connectors**) sont conçus pour connecter vos outils de sécurité et importer des données dans DefectDojo aussi rapidement que possible.

Nous prenons actuellement en charge les Connecteurs en amont pour les outils suivants, et d'autres arrivent prochainement :

* **Acunetix 360**
* **Akamai API Security**
* **Anchore**
* **AWS Security Hub**
* **Azure DevOps**
* **Backstage**
* **Bitbucket**
* **Black Duck**
* **Bright Security**
* **Bugcrowd**
* **BurpSuite**
* **Censys**
* **Checkmarx ONE**
* **Cloudflare**
* **Cobalt.io**
* **Contrast**
* **Coverity**
* **CrowdStrike Falcon**
* **Deepfence ThreatMapper**
* **Dependency-Track**
* **Docker Scout**
* **Edgescan**
* **Endor Labs**
* **Escape**
* **Fairwinds Insights**
* **Fortify**
* **GitGuardian**
* **GitHub**
* **GitHub Advanced Security**
* **GitLab**
* **Google Cloud Security Command Center**
* **Group-IB ASM**
* **HackerOne**
* **Harbor**
* **Have I Been Pwned**
* **HCL AppScan**
* **Intigriti**
* **Intruder**
* **IriusRisk**
* **JFrog Xray**
* **Jira Service Management Assets**
* **Kubescape**
* **Lacework / FortiCNAPP**
* **Mend**
* **Microsoft Defender**
* **Microsoft Defender for Cloud**
* **MobSF**
* **NeuVector**
* **Nuclei (ProjectDiscovery Cloud)**
* **OpenVAS / Greenbone**
* **Probely**
* **Prowler**
* **Qualys**
* **Quay**
* **Rapid7 InsightAppSec**
* **Rapid7 InsightVM**
* **Rapid7 InsightVM - Cloud Instance**
* **runZero**
* **Semgrep**
* **ServiceNow CMDB**
* **Shodan**
* **Snyk**
* **Socket**
* **SonarQube**
* **Sonatype IQ**
* **Sysdig Secure**
* **Tenable**
* **Tenable Web App Scanning**
* **Veracode**
* **Wazuh**
* **Wiz**
* **YesWeHack**

Pour des instructions de configuration étape par étape pour chaque outil, consultez la référence [Configuration des connecteurs par outil](../../toolreference/upstream/).

La plupart des connecteurs importent des **constatations**. Certains sont des **Connecteurs d'actifs** qui importent plutôt votre **inventaire d'actifs** — en construisant et en maintenant votre hiérarchie Produit (Actif) et Type de produit (Organisation) au lieu d'importer des constatations : **Azure DevOps**, **Backstage**, **Bitbucket**, **GitHub**, **GitLab**, **Jira Service Management Assets**, et **ServiceNow CMDB**. (**runZero** est principalement un Connecteur d'actifs, mais peut aussi, en option, importer des vulnérabilités sous forme de constatations.)

Ces connexions fournissent une intégration à la vitesse de l'API avec DefectDojo, et peuvent être utilisées pour ingérer et organiser automatiquement les données de vulnérabilités provenant de l'outil.

## Se repérer dans la page Connecteurs

Les connecteurs sont répertoriés dans deux sections, chacune affichant un nombre à côté de son titre et triée par ordre alphabétique :

* **Connecteurs configurés** — toutes les configurations de connecteur existant sur cette instance. Un outil peut apparaître plusieurs fois, une fois par configuration, et chaque tuile est intitulée `<Tool> - <label>` afin de pouvoir les distinguer. Lorsque plusieurs configurations partagent le même outil, elles sont classées selon leur label.
* **Connecteurs disponibles** — tous les outils pris en charge que vous n'avez pas encore configurés.

Le nombre affiché à côté d'un titre correspond au nombre de connecteurs actuellement affichés ; il suit donc la zone de recherche et le filtre de type **Asset / Finding** plutôt que de toujours indiquer le total. Sur DefectDojo Pro Cloud, la tuile **Request Upstream Connector** n'est pas un connecteur et n'est pas comptabilisée.

Chaque section dispose de sa propre zone de recherche, qui filtre sur le nom de l'outil.

![La page Connecteurs, avec un nombre affiché à côté du titre de chaque section](images/upstream_counts.png)

Les pages [Connecteurs en aval](/connectors/downstream/about/) et [Connecteurs d'autorisation](/admin/sso/pro__authorization_connectors/) sont organisées de la même manière.

## Démarrage rapide des Connecteurs en amont

Si vous utilisez les paramètres **Auto\-Map** de DefectDojo, vous pouvez avoir votre premier connecteur opérationnel en un rien de temps.

1. Configurez un [connecteur](../add_edit/) à partir d'un outil pris en charge.
2. [Découvrez](../manage_operations/#discover-operations) la hiérarchie de données de votre outil.
3. [Synchronisez](../manage_operations/#sync-operations) les vulnérabilités détectées par votre outil vers DefectDojo.

C'est tout, vraiment ! Et n'oubliez pas que même si vous créez votre connecteur de la manière « facile », vous pouvez facilement modifier la configuration plus tard, sans perdre aucun de vos travaux.

## Fonctionnement des Connecteurs en amont

Tant que vous disposez de la clé API de l'outil que vous essayez de connecter, un connecteur peut être ajouté en quelques minutes seulement. Une fois la connexion fonctionnelle, DefectDojo va **Discover** l'environnement de votre outil pour voir comment vous organisez vos données de scan.

Supposons que vous ayez un outil BurpSuite configuré pour analyser cinq dépôts différents à la recherche de vulnérabilités. Votre connecteur prendra note de cette structure organisationnelle et créera des **Records** pour vous aider à transposer ces dépôts distincts dans la hiérarchie Produit / Engagement / Test de DefectDojo. Si l'option **'Auto\-Map Records'** est activée, DefectDojo apprendra et reproduira automatiquement cette structure.

![image](images/_index.png)

Une fois vos mappages de **Records** configurés, DefectDojo commencera à importer régulièrement les données de scan. Vous serez tenu informé de toute nouvelle vulnérabilité détectée par l'outil, et vous pourrez commencer à travailler immédiatement avec les vulnérabilités existantes grâce au système de **Constatations** de DefectDojo.

Lorsque vous êtes prêt à ajouter d'autres outils à DefectDojo, vous pouvez facilement réorganiser vos mappages d'import. Plusieurs outils peuvent être configurés pour importer des vulnérabilités vers la même destination, et vous pouvez toujours réorganiser votre configuration pour mieux l'adapter, sans perdre aucun travail.

## Mon connecteur n'est pas pris en charge

### Demander un connecteur depuis l'interface (DefectDojo Pro Cloud)

Sur DefectDojo Pro Cloud, vous pouvez demander à notre équipe de créer un connecteur pour un outil que nous ne prenons pas encore en charge — directement depuis l'interface :

1. Allez dans **Connecteurs → Connecteurs en amont** (pour les outils qui importent des données *vers* DefectDojo). Les gestionnaires de tickets et autres intégrations sortantes peuvent être demandés de la même manière sous **Connecteurs → Connecteurs en aval**.
2. Dans la section **Connecteurs disponibles**, cliquez sur **Request a Connector**.
3. Remplissez le formulaire de demande. Les champs **Tool / Product Name**, **Tool API Base URL**, **Authentication Type** et les identifiants correspondant à ce type d'authentification sont tous obligatoires, car notre équipe a besoin d'une adresse accessible et d'un identifiant fonctionnel pour créer un connecteur et confirmer qu'il fonctionne avec votre outil. Les identifiants sont stockés de manière sécurisée. Vous pouvez éventuellement ajouter le site web de l'éditeur, un lien vers la documentation de l'API de l'outil, et une note décrivant votre cas d'usage.
4. Cliquez sur **Submit Request**. Vous verrez une confirmation indiquant que votre demande a bien été reçue. Notre équipe examine chaque demande pour évaluer la possibilité de développer le support — soumettre une demande ne garantit pas que le connecteur sera créé.

La demande d'un connecteur nécessite les permissions **global Maintainer** et n'est disponible que sur **DefectDojo Pro Cloud** — l'option n'apparaît pas sur les instances auto-hébergées (sur site).

### Import manuel

Même sans connecteur, DefectDojo peut toujours gérer l'import manuel pour un large éventail d'outils de sécurité. Consultez notre [Liste des outils pris en charge](/supported_tools), ainsi que notre guide sur l'import de données.

# **Prochaines étapes**

* Consultez la page **Connecteurs en amont** en passant à la **Pro UI** de DefectDojo et en ouvrant **Connecteurs \> Connecteurs en amont** sous l'en-tête **Import**.
* Suivez notre guide pour [créer votre premier Connecteur en amont](../add_edit/).
* Découvrez le processus d'[exécution des opérations](../manage_operations/) avec vos outils de sécurité connectés, et voyez comment ils peuvent être configurés pour importer des données.
