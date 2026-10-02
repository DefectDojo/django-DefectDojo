---
title: Tests
description: Comprendre les Tests dans DefectDojo OS
audience: opensource
weight: 4
---

Organisations → Actifs → Engagements → **TESTS** → Constatations

## Aperçu

Un Test est un conteneur pour une ou plusieurs exécutions de scan, utilisées pour découvrir des failles dans un Produit. Les Tests constituent le composant final, le plus granulaire, de la hiérarchie des produits de DefectDojo : ils servent de conteneur pour les Constatations résultant de l'exécution d'un outil de sécurité ou d'une évaluation manuelle, tout en ajoutant le contexte dans lequel ces Constatations ont été trouvées (c'est-à-dire quel outil les a signalées, quand cet outil a été exécuté pour la dernière fois, etc.).

Voici des exemples de Tests : 
- Test statique de sécurité des applications
- Test dynamique de sécurité des applications
- Analyse de la composition logicielle
- Scans de sécurité des conteneurs
- Scans d'infrastructure / réseau
- Tests d'intrusion manuels
- Scans de pipeline CI/CD

### Types de Test 

Il existe deux principales façons de créer des Tests dans DefectDojo : 
1. **Parseurs spécifiques à un éditeur** (par ex., Burp, OWASP ZAP, Acunetix, Invicti)
2. **Import générique de Constatations**

Chaque méthode peut créer de nouveaux Tests ou réimporter des Constatations dans des Tests existants, selon la configuration et la stratégie de déduplication.

Bien que chaque méthode diffère principalement dans la façon dont les données de scan sont analysées et ingérées, elles aboutissent toutes à l'association de Constatations à un Test.

#### Parseurs 

Les **Parseurs** sont des composants qui traitent des formats de sortie de scan spécifiques (par ex., XML, JSON, CSV) et les font correspondre au modèle de Constatation interne de DefectDojo. Lorsque des résultats de scan sont importés, DefectDojo utilise le parseur sélectionné pour extraire les Constatations et les rattacher à un Test nouvellement créé ou existant.

#### Import générique de Constatations 

Lorsqu'aucun parseur natif n'existe pour un outil donné, l'**Import générique de Constatations** vous permet d'importer des constatations à l'aide d'un schéma JSON ou CSV standardisé, quelle que soit la source d'origine. 

DefectDojo analyse les données fournies, crée un nouveau Test (ou importe dans un Test existant), et rattache les Constatations. Un Type de Test correspondant est également créé en fonction du champ optionnel `type` du rapport : lorsque `type` est omis (ou est égal au type de scan), le Type de Test est « Generic Findings Import » ; lorsque `type` est fourni, il devient « {type} Scan (Generic Findings Import) » (un `type` se terminant déjà par le suffixe « (Generic Findings Import) » est utilisé tel quel).

|  | **Parseurs natifs** | **Import générique de Constatations** | 
|----------|---------------|------------------------|
| **Objectif principal** | Ingérer les sorties d'outils pris en charge | Ingérer des données non prises en charge/personnalisées via un schéma fixe |
| **Format d'entrée** | Spécifique à l'outil (par ex., ZAP XML, SARIF) | Schéma JSON/CSV strict |
| **Qui gère la normalisation** | DefectDojo (parseur intégré) | Utilisateur (doit se conformer au schéma) |
| **Déclencheur de création de Test** | Téléversement manuel ou import via API | Téléversement manuel ou import via API |
| **Type de Test** | Prédéfini (par ex., « ZAP Scan ») | Type « Generic » créé automatiquement |
| **Effort de configuration** | Faible | Modéré (transformation des données requise) | 
| **Flexibilité** | Faible (uniquement les outils pris en charge) | Moyenne | 
| **Niveau d'automatisation** | Faible à modéré | Faible à modéré | 
| **Cas d'usage typique** | Scanners standards (SAST, DAST, SCA) | Scripts personnalisés, outils non pris en charge | 

Quelle que soit la méthode d'ingestion, toutes les données de scan dans DefectDojo sont finalement représentées sous forme de Constatations rattachées à un Test, qui sert d'unité d'exécution et de suivi du cycle de vie.

### Données de Test 

Les Tests stockent diverses métadonnées qui aident à documenter les différents composants de chaque effort de test, telles que : 
- Titre / nom du Test 
- Type de Test
- Description / notes du Test
- Date de début et de fin 
- L'Environnement dans lequel le Test a été exécuté (par ex., Développement, Staging, Pré-production, Production, etc.)
- Version / Branche / ID de build / Hash de commit
- Configuration de scan API 
- Fichiers supplémentaires pouvant être utilisés pour des audits ultérieurs ou des réimportations
- L'Engagement, l'Actif et l'Organisation parents 
- Historique d'import et de réimport

Chaque Test conserve un historique d'import qui enregistre tous les imports et réimports de scan associés au Test. Cela inclut des métadonnées telles que la date du scan, la version, la branche, le hash de commit et l'ID de build.

Cet historique assure la traçabilité à travers plusieurs exécutions de scan au sein d'un même Test.

### Permissions

Plusieurs Tests peuvent être stockés au sein d'un même Engagement, et les Engagements sont stockés au sein de Produits. Ainsi, l'accès à un Produit accorde automatiquement l'accès à tous les Tests (et Engagements) de ce Produit. Les Tests ne disposent pas de listes de contrôle d'accès indépendantes.

### Accéder aux Tests 

Bien que les Tests existent en tant qu'objet indépendant dans DefectDojo OS, ils ne disposent pas d'une section spécifique qui leur soit dédiée dans l'interface. Ainsi, chaque Test est principalement accessible via le Produit et/ou l'Engagement qui le contient.

### Vue Test 

La vue Test héberge divers tableaux, notamment l'Engagement parent, l'historique d'import et de réimport, une liste des Constatations contenues dans le Test ainsi que tous les Groupes de Constatations éventuels. 

Il existe également des tableaux pour les Constatations potentielles, les Fichiers et les Notes, qui peuvent tous être ajoutés manuellement. 

#### Paramètres du Test 

Les paramètres suivants sont disponibles dans chaque vue Test : 
- **Modifier le Test**
    - Permet de modifier les données du Test, telles que le titre, la planification, l'environnement et divers autres détails. 
- **Copier le Test**
    - Duplique un Test, avec toutes les métadonnées et Constatations associées, et permet de l'attribuer à un autre Engagement. 
- **Retéléverser le scan**
    - Lance le processus de réimport. Plus d'informations sur la Réimportation sont fournies plus loin dans cet article.
- **Ajouter des notes**
    - Permet à l'utilisateur d'ajouter une Note. Un tableau de Notes est également présent en bas de la page. 
        - Une Note peut être basculée en Privée, auquel cas elle ne peut pas être poussée vers Jira, les Rapports et les exports de Constatations. 
- **Rapport**
    - Lance le processus de génération d'un Rapport, dans lequel de nombreux filtres peuvent être appliqués afin de créer un rapport ne contenant que les Constatations filtrées. 
- **Ajouter au calendrier**
    - Télécharge un fichier .ics du Test choisi, qui peut être ajouté à votre application de calendrier tierce. 
- **Voir l'historique**
    - Ouvre un historique des modifications apportées au Test à des fins de suivi, de reporting et d'audit.

## Utiliser les Tests

### Créer des Tests 

Les Tests peuvent être créés automatiquement lorsque des données de scan sont importées directement dans un Engagement, ce qui donne lieu à un nouveau Test contenant les données du scan. Les Tests peuvent également être créés en prévision de la planification de futurs Engagements, ou pour des constatations de sécurité saisies manuellement nécessitant un suivi et une remédiation.

#### Flux de travail manuels 

Il existe plusieurs façons de créer un Test dans la version OS :

- Sélectionnez un Produit et cliquez sur « Import Scan Results » dans le menu Findings de la barre de navigation 
    - Cela créera un Engagement ad hoc pour contenir le Test

![image](images/tests_ss5.png)

- Sélectionnez un Engagement au sein d'un Produit, cliquez sur le menu déroulant dans la sous-section Tests, puis cliquez sur « Add Tests » ou « Import Scan Results »
    - Cela créera le Test correspondant directement au sein de l'Engagement choisi

![image](images/tests_ss6.png)

- Lors de la création d'un Engagement

![image](images/tests_ss7.png)

En utilisant la troisième méthode ci-dessus, vous pouvez effectuer les actions suivantes lors de la création d'un Engagement :

- Importer immédiatement les résultats de scan
- Créer une coquille de Test (dans laquelle vous importerez un scan ultérieurement)
- Ne faire ni l'un ni l'autre et simplement créer l'Engagement en cliquant sur « Done » 

Vous aurez la possibilité d'ajouter des métadonnées lors de l'import d'un scan ou de la création d'une coquille de Test. Toute métadonnée sera reflétée dans la section Historique d'import de la Vue Test.

#### Flux de travail automatisés 

Dans les flux de travail automatisés, les Tests peuvent être créés de manière programmatique dans le cadre du processus d'import de scan, ce qui permet aux pipelines de téléverser des résultats sans qu'un Test doive être créé manuellement au préalable.

Lors de l'utilisation de l'API pour importer des résultats de scan, un nouveau Test peut être créé automatiquement en fournissant un engagement au lieu d'un test.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Compte tenu de ce qui précède, un nouveau Test est créé sous l'Engagement spécifié, et les résultats du scan sont rattachés à ce Test.

Si un ID `test` est fourni à la place, les résultats du scan seront ajoutés à un Test existant, ce qui est courant dans les flux de travail de réimport.  

### Modifier des Tests 

Les Tests peuvent être modifiés en cliquant sur **Modifier le Test** dans le menu kebab ⋮ du tableau Tests au sein de la vue de l'Engagement parent, ou depuis le menu des paramètres dans la vue du Test. Tous les champs modifiables qui en découlent sont également disponibles lors de la création du Test.

![image](images/tests_ss24.png)

![image](images/tests_ss12.png)

#### Ajouter manuellement des Constatations à un Test

Une Constatation peut être ajoutée manuellement à un Test en cliquant sur **Ajouter une Constatation au Test** dans le menu kebab ⋮ à côté du Test dans la vue de l'Engagement parent, ou depuis les paramètres du tableau Constatations dans la vue du Test. 

![image](images/tests_ss29.png)

![image](images/tests_ss30.png)

### Supprimer des Tests 

La suppression d'un Test s'effectue en sélectionnant **Supprimer le Test** dans le menu kebab ⋮ à côté du Test dans la vue de l'Engagement parent, ou depuis le menu des paramètres dans la vue du Test. Cette action est irréversible. 

La suppression d'un Test supprimera également toutes les Constatations contenues dans ce Test.

![image](images/tests_ss25.png)

![image](images/tests_ss26.png)

## Réimport 

Réimporter des scans au sein des Tests est fondamental pour une déduplication efficace. Lorsque des résultats de scan sont réimportés dans le même Test :

- Les Constatations existantes peuvent être mises à jour
- Les Constatations en doublon peuvent être supprimées
- De nouvelles Constatations peuvent être créées si aucune correspondance n'est trouvée

Ce comportement dépend des règles de déduplication configurées et du type de scan.

Créer un nouveau Test au lieu de réimporter dans un Test existant peut entraîner la création de Constatations en doublon plutôt que leur mise à jour.

#### Réimport et import 

Le Réimport est généralement utilisé lorsque :

- Des scans récurrents sont exécutés sur la même cible
- Vous suivez l'évolution des Constatations au fil du temps
- Vous maintenez une vue continue de la posture de sécurité applicative

En revanche, l'import (création d'un nouveau Test) est plus adapté aux exécutions de scan ponctuelles ou indépendantes.

### Réimporter des résultats de scan (interface)

Afin d'ajouter de nouvelles données à un Test existant, vous pouvez soit cliquer sur **Retéléverser les résultats du scan** dans le menu kebab ⋮ à côté du Test dans la vue de l'Engagement parent, soit cliquer sur **Retéléverser le scan** dans le menu des paramètres de la vue du Test.  

![image](images/tests_ss27.png)

![image](images/tests_ss10.png)

En remplissant le formulaire Réimporter le scan, vous aurez la possibilité de mettre à jour les métadonnées du scan en cours de réimport, notamment la version, l'étiquette de branche, le hash de commit et l'ID de build. 

Ces modifications sont reflétées dans la section Historique d'import de la Vue Test, qui inclura également les mêmes métadonnées des imports de scan précédents.

Par exemple, dans la capture d'écran ci-dessous, l'étiquette de branche, l'ID de build, le hash de commit et la version ont tous été mis à jour manuellement entre l'import initial et le réimport suivant.

![image](images/tests_ss28.png)

Pour modifier les métadonnées du scan réimporté le plus récemment, suivez les instructions précédentes de la section Modifier des Tests ci-dessus et mettez à jour les métadonnées souhaitées. Seules les métadonnées de l'import le plus récent peuvent être modifiées.

### Réimporter des résultats de scan (API)

Lorsque des Tests sont créés ou mis à jour via un pipeline CI/CD, vous pouvez inclure des métadonnées de l'exécution du pipeline afin que les Tests puissent être correctement liés au code qu'ils ont scanné. Cela vous permet de :
- Associer les résultats du scan à un commit ou une branche spécifique.
- Suivre l'évolution des Constatations au fil des modifications de code.
- Améliorer la Déduplication en comprenant quand deux scans s'appliquent à la même version du code ou à des versions différentes.
- Faciliter l'auditabilité en montrant exactement quel code a été scanné et quand.

L'API de DefectDojo accepte ces valeurs lors de l'import ou du réimport afin qu'elles puissent être stockées dans le cadre de l'import du scan et reflétées dans l'historique d'import du Test. Ces métadonnées peuvent être utilisées pour identifier des hash de commit ou toute information de dépôt pertinente associée à une exécution CI/CD.

#### Champs de métadonnées pris en charge 

L'API prend en charge un ensemble défini de champs de métadonnées pouvant être inclus lors du réimport. Ceux-ci incluent :

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- indicateurs `active / verified`

Ces champs représentent le mécanisme principal permettant de rattacher des métadonnées contextuelles lors d'une opération de réimport. 

Dans les pipelines automatisés, les métadonnées les plus couramment fournies incluent :
- build_id (identifiant du job CI)
- commit_hash (référence de contrôle de source)
- branch_tag (contexte de branche ou d'environnement)
- tags (par ex., nightly, staging, production)

Ces champs assurent la traçabilité entre les scans sans nécessiter d'intervention manuelle.

Bien que les métadonnées puissent être mises à jour manuellement via le formulaire Réimporter le scan, la plupart des environnements automatisés géreront cela en appelant directement le endpoint `/api/v2/reimport-scan/`. Cette approche permet au pipeline de rattacher automatiquement les métadonnées lors du réimport.

##### Réimport via API avec métadonnées 

curl -X POST `"https://<your-instance>/api/v2/reimport-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"test=123"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"` \
  -F `"tags=nightly,api-scan"` \
  -F `"version=1.4.2"` \
  -F `"build_id=jenkins-842"` \
  -F `"branch_tag=main"` \
  -F `"commit_hash=a1b2c3d4"`

##### Métadonnées, réimport et scans planifiés 

Les scans peuvent également être planifiés pour s'exécuter à intervalles réguliers, comme ceux déclenchés par des tâches cron. Les scans planifiés ne sont pas liés à l'activité du dépôt, ce qui rend les métadonnées telles que les hash de commit ou les noms de branche non pertinentes, sauf si elles sont explicitement injectées par le script lui-même. Néanmoins, l'utilisation du réimport peut rester utile si vous préférez conserver un enregistrement continu de votre posture de sécurité au sein d'un seul Test. 
