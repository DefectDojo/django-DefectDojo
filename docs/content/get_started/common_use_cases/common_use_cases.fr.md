---
title: Cas d'usage courants
description: Cas d'usage et exemples
draft: 'false'
weight: 2
chapter: true
aliases:
- /fr/en/about_defectdojo/examples_of_use
---

Cet article s'appuie sur la session Office Hours de DefectDojo, Inc. de février 2025 : « Tackling Common Use Cases ».
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=ilRBlfo-wvX5DPVg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Exemples de cas d'usage

DefectDojo est conçu pour gérer n'importe quelle implémentation de sécurité, quelle que soit la taille de votre équipe de sécurité, le niveau de complexité de votre IT ou le volume de vos rapports. Les scénarios suivants se veulent des points de départ pour vos propres besoins, mais ils s'appuient sur des exemples réels de notre communauté et de l'équipe DefectDojo Pro.

### Grande entreprise : RBAC et Engagements

« BigCorp » est une grande entreprise multinationale, dotée d'un Chief Information Security Officer (CISO) et d'un groupe de sécurité IT centralisé qui inclut l'AppSec.

La sécurité chez BigCorp est fortement centralisée. Certains aspects sont délégués à des Business Information Security Officers (BISO).

Les principales préoccupations de BigCorp sont les suivantes :

- Définir et maintenir une méthode de test cohérente dans toutes les unités commerciales de l'organisation
- Répondre aux exigences de conformité et éviter les problèmes réglementaires

#### Modèle de test

BigCorp gère des données de sécurité provenant de nombreuses sources :

- Des jobs CI/CD qui exécutent automatiquement des outils de scan SAST, SCA et de détection de secrets
- Des tests d'intrusion (Pen testing) tiers pour certains Produits
- Des audits de conformité PCI pour certains Produits

Chacune de ces catégories de rapports peut être gérée par un Engagement distinct, avec un Test distinct pour chaque type de scan dans DefectDojo.

![image](images/example_product_hierarchy_bigcorp.png)

- Si un Produit dispose d'un pipeline CI/CD, tous les résultats de ce pipeline peuvent être importés en continu dans un seul Engagement ouvert. Chaque outil utilisé créera un Test distinct au sein de l'Engagement CI/CD, qui peut être mis à jour en continu avec de nouvelles données.  
(Voir notre guide sur [Reimport](/import_data/import_intro/reimport/))
- Chaque effort de Pen Test peut avoir un Engagement distinct créé pour contenir tous les résultats : par exemple « Q1 Pen Test 2024 », « Q2 Pen Test 2024 », etc.
- BigCorp voudra probablement effectuer son propre audit PCI blanc afin de se préparer à l'audit réel. Les résultats de ces audits peuvent également être stockés dans un Engagement distinct.

#### Modèle RBAC

- Chaque BISO dispose d'un accès Lecteur pour chaque unité commerciale (Type de produit) dont il a la charge.
- Chaque Product Owner dispose d'un accès Rédacteur pour le Produit dont il a la charge.  Au sein de leur Produit, les Product Owners peuvent interagir avec DefectDojo en consignant des notes, en configurant des [pipelines CI/CD](/import_data/import_scan_files/api_pipeline_modelling/), en créant des Acceptations du risque et en utilisant d'autres fonctionnalités.
- Les développeurs de BigCorp n'ont aucun accès à DefectDojo, et ils n'en ont pas besoin. Le Product Owner peut envoyer directement depuis DefectDojo des tickets Jira contenant toutes les informations pertinentes sur la vulnérabilité.  Les développeurs utilisent déjà Jira, ils n'ont donc pas besoin de suivre la remédiation différemment d'une autre tâche de développement.

### Systèmes embarqués : reporting avec contrôle de version

Cyber Robotics est une entreprise qui vend du matériel de fabrication accompagné de systèmes logiciels embarqués.  Elle dispose d'un Chief Product Officer (CPO) qui supervise à la fois le produit et la cybersécurité dans son ensemble.

Bien qu'elle ait des informations de sécurité moins diversifiées à gérer que BigCorp, il reste essentiel pour elle de bien contextualiser ses informations de sécurité afin de pouvoir répondre de manière proactive à toute Constatation importante.

Principales préoccupations de Cyber Robotics :

- Elle possède une gamme de produits limitée, mais **de nombreuses** versions de chaque produit qu'elle doit cataloguer correctement.
- La maintenance de ses produits est complexe et les coûts sont élevés, il faut donc éviter tout travail superflu.

#### Modèle de test

Cyber Robotics dispose d'un processus de test standardisé pour tous ses systèmes embarqués : 

- Des tests CI/CD, SAST et SCA sont exécutés
- Des revues de contrôles de sécurité
- Des scans réseau
- Une revue de code par un tiers

Cependant, comme chaque version de leur logiciel est isolée, elles auront inévitablement beaucoup de données à organiser, dont une grande partie n'est utile que dans un seul contexte (c'est-à-dire la version particulière du logiciel qu'elles exécutent).

Cyber Robotics peut résoudre ce problème en utilisant des Types de produit pour représenter une seule gamme de produits, et des Produits individuels pour chaque version distincte.  Cela leur permettra d'approfondir l'analyse afin de déterminer quels Produits sont associés à une même vulnérabilité.

![image](images/example_product_hierarchy_robotics.png)

En associant les versions logicielles à des Produits plutôt qu'à des Engagements, Cyber Robotics peut limiter l'accès à une version logicielle particulière si nécessaire.  Les techniciens de terrain et le personnel du support peuvent se voir accorder l'accès à une seule version du logiciel sans avoir besoin d'accéder à l'ensemble de la gamme de produits.

#### Modèle RBAC

L'équipe AppSec dispose ici de Rôles globaux qui régissent son niveau d'interaction.

- Le CPO dispose d'un accès Lecteur global à DefectDojo, comme le CISO chez BigCorp.
- Les Product Owners individuels disposent d'un accès Lecteur global à n'importe quel Produit dans DefectDojo, ainsi que d'un accès Rédacteur au Produit dont ils sont propriétaires.

Du côté du support :

- Le personnel du support se voit temporairement accorder un accès Lecteur aux Produits spécifiques qu'il est chargé de maintenir, mais il n'a pas accès à l'ensemble des données de DefectDojo.

### Environnements IT dynamiques et microservices : entreprise de services cloud

Kate's Cloud Service exploite un environnement en évolution rapide qui utilise Kubernetes, des microservices et l'automatisation.  Kate's Cloud Service dispose d'un VP Cloud qui supervise les questions de sécurité du Cloud.  Elle a également un CISO qui gère le développement logiciel proposé, mais pour cet exemple, nous nous concentrerons spécifiquement sur ses préoccupations en matière de sécurité du Cloud.

Kate's Cloud Service a entièrement automatisé son reporting et ingère les données dans DefectDojo dès que les rapports sont produits.

Principales préoccupations de Kate's Cloud Service :

- Gérer la sécurité du cloud multi-tenant, en empêchant les interactions entre clients tout en permettant la fourniture de services partagés.
- Gérer les changements rapides de leur environnement cloud.

#### Étiquetage des services partagés

Comme le modèle de Kate comporte de nombreux services partagés susceptibles d'affecter d'autres Produits, l'équipe [étiquette](/asset_modelling/tags/os__tagging_objects/) ses Produits pour indiquer quelles offres cloud dépendent de ces services.  Cela permet de filtrer tout problème lié aux services partagés sur l'ensemble des Produits et de le signaler aux équipes concernées.  Chacun de ces services partagés se trouve dans un Type de produit unique qui les sépare des offres cloud principales.

![image](images/example_product_hierarchy_microservices.png)

Comme l'entreprise connaît une croissance rapide et que les tech leads changent fréquemment, Kate peut utiliser les Étiquettes pour suivre quel tech lead est actuellement responsable de chaque produit cloud, évitant ainsi d'avoir à mettre à jour manuellement et en permanence son système DefectDojo. Ces associations de tech leads sont suivies par un service externe à DefectDojo, qui peut piloter les pipelines d'import ou appeler l'API DefectDojo.

Pour en savoir plus sur l'étiquetage, consultez notre guide sur les [Étiquettes](/asset_modelling/tags/os__tagging_objects/).

#### Modèle RBAC

Du côté sécurité/conformité :

- L'équipe Product Security, propriétaire de DefectDojo, dispose d'un accès administrateur à l'ensemble du système.
- Les analystes travaillant pour le VP Cloud se voient accorder un accès en lecture seule à l'ensemble du système, ce qui leur permet de générer les rapports et métriques nécessaires pour permettre au VP d'évaluer la sécurité des différentes offres cloud.

Du côté développement :

- Les Tech Leads de chaque produit cloud spécifique (par exemple, compute, stockage, services partagés) disposent d'un **accès Mainteneur** à leur Produit assigné afin de trier les résultats de sécurité liés à leur offre de produit cloud spécifique. Ils peuvent examiner les Constatations et agir au sein de leur Produit, et peuvent également réorganiser considérablement leurs données de Constatations.
- Les développeurs travaillant sur des Produits spécifiques se voient accorder un **accès Rédacteur** au Produit sur lequel ils travaillent, ce qui leur permet de commenter les Constatations, de demander des Revues par les pairs et de créer des Acceptations du risque.

### Intégration de nouvelles acquisitions : SaaSy Software

SaaSy Software est une entreprise en croissance rapide qui acquiert fréquemment d'autres éditeurs de logiciels.  Chaque fois qu'une nouvelle entreprise est acquise, le Director of Quality Engineering et l'équipe AppSec se retrouvent soudainement en charge de nombreux nouveaux dépôts de code, développeurs et processus.  Leur modèle DefectDojo leur permet de monter en compétence le plus rapidement possible.

Principales préoccupations de SaaSy Software :

- Éviter les problèmes de sécurité publics tout en maintenant les programmes de conformité (comme SOC2).
- Pouvoir intégrer en toute confiance les outils et processus des nouveaux produits.
- Pouvoir signaler et catégoriser les vulnérabilités aussi bien sur les branches en production que sur les branches en développement.

#### Modèle de test

Les tests chez SaaSy se concentrent sur les grandes lignes plutôt que sur l'utilisation d'outils standardisés, car chaque acquisition arrive avec ses propres outils et processus AppSec.  SaaSy doit réaliser à la fois des évaluations internes (CI/CD, DAST, scans de conteneurs et modélisation des menaces) et des évaluations externes (tests d'intrusion par des tiers, audits de conformité).

Pour faciliter l'intégration de nouvelles applications, SaaSy Software applique une approche standard à son modèle de données : chaque fois que SaaSy intègre une nouvelle application, elle crée un nouveau Type de produit pour cette application, et crée des sous-produits pour les dépôts qui la composent (Front-End, API Backend, etc).

![image](images/example_product_hierarchy_saas.png)

Chacun de ces Produits est ensuite subdivisé en Engagements, un pour la branche principale et un pour chaque branche de développement.  Les Tests au sein de ces Engagements servent à catégoriser les efforts de test.  Les branches de développement disposent de Tests distincts qui stockent les résultats des scans CI/CD et SCA.  La branche principale dispose également de ces Tests, mais y ajoute des Tests qui stockent les rapports de revue de code manuelle et de modélisation des menaces.

Tous ces Tests sont ouverts et peuvent être mis à jour régulièrement via Reimport.  La [Déduplication](/triage_findings/finding_deduplication/about_deduplication/) n'est gérée qu'au niveau de l'Engagement, ce qui empêche les Constatations d'une branche de code de clôturer les Constatations d'une autre branche.

En appliquant ce modèle de manière cohérente, SaaSy dispose d'un modèle qu'elle peut appliquer à toute nouvelle acquisition logicielle, et l'équipe AppSec peut rapidement commencer à surveiller les données pour garantir la conformité.

#### Modèle RBAC

Du côté sécurité/conformité :

- L'équipe AppSec de SaaSy Software est propriétaire de DefectDojo et dispose d'un accès administrateur complet au logiciel.
- Les équipes QE et Conformité disposent d'un accès en lecture seule à l'ensemble du système, pour extraire des rapports et analyser les données si nécessaire.

Du côté développement :

- Chaque Product Owner dispose d'un accès Rédacteur au Produit dont il est propriétaire dans DefectDojo, ce qui lui permet de rédiger des Acceptations du risque et de consulter les métriques du Produit.
- Les développeurs disposent d'un accès en lecture seule à chaque Produit sur lequel ils travaillent.  Ils peuvent demander des Revues par les pairs sur les Constatations ou les problèmes qu'ils tentent de corriger.
