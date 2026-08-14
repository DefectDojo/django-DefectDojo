---
title: Tests
description: Comprendre les Tests dans DefectDojo Pro
audience: pro
weight: 4
---

Organisations → Actifs → Engagements → **TESTS** → Constatations

## Aperçu

Un Test est un conteneur pour une ou plusieurs exécutions de scan, utilisées pour découvrir des failles dans un Actif. Les Tests constituent le composant final et le plus granulaire de la hiérarchie d'objets de DefectDojo : ils servent de conteneur pour les Constatations résultant de l'exécution d'un outil de sécurité ou d'une évaluation manuelle, tout en ajoutant le contexte dans lequel ces Constatations ont été trouvées (c'est-à-dire quel outil les a signalées, quand cet outil a été exécuté pour la dernière fois, etc.).

Exemples de Tests :
- Tests statiques de sécurité des applications
- Tests dynamiques de sécurité des applications
- Analyse de composition logicielle
- Analyses de sécurité des conteneurs
- Analyses d'infrastructure / réseau
- Tests d'intrusion manuels
- Analyses de pipeline CI/CD

### Types de Test

Il existe plusieurs façons de créer des Tests dans DefectDojo, notamment les **analyseurs spécifiques à un éditeur** (par ex. Burp, OWASP ZAP, Acunetix, Invicti), **Generic Findings Import**, **Universal Parser**, et **Connectors**.

Ces méthodes peuvent créer de nouveaux Tests ou réimporter des Constatations dans des Tests existants, selon la configuration et la stratégie de déduplication.

Bien que chaque méthode diffère principalement par la façon dont les données de scan sont analysées et ingérées, elles aboutissent toutes à l'association de Constatations à un Test.

#### Analyseurs

Les **analyseurs** sont des composants qui traitent des formats de sortie de scan spécifiques (par ex. XML, JSON, CSV) et les font correspondre au modèle interne de Constatation de DefectDojo. Lorsque des résultats de scan sont importés, DefectDojo utilise l'analyseur sélectionné pour extraire les Constatations et les rattacher à un Test nouvellement créé ou existant.

#### Generic Findings Import

Lorsqu'aucun analyseur natif n'existe pour un outil donné, [**Generic Findings Import**](/supported_tools/parsers/generic_findings_import) permet d'importer des constatations à l'aide d'un schéma JSON ou CSV standardisé, quelle que soit la source d'origine.

DefectDojo analyse les données fournies, crée un nouveau Test (ou importe dans un Test existant) et y rattache les Constatations. Un Type de Test correspondant est également créé en fonction du champ optionnel `type` du rapport : lorsque `type` est omis (ou égal au type de scan), le Type de Test est « Generic Findings Import » ; lorsque `type` est fourni, il devient « `{type}` Scan (Generic Findings Import) » (un `type` se terminant déjà par le suffixe « (Generic Findings Import) » est utilisé tel quel).

#### Universal Parser

[**Universal Parser**](/supported_tools/parsers/universal_parser) permet aux utilisateurs de définir comment des données d'entrée arbitraires sont associées au modèle de Constatation de DefectDojo. Après avoir configuré l'analyseur et importé les données de scan, DefectDojo applique les règles de correspondance pour extraire les Constatations, crée un Test (ou en met à jour un existant), et associe les Constatations à ce Test.

#### Connectors

Les [**Connectors**](/connectors/upstream/about/) peuvent être utilisés pour ingérer et organiser automatiquement les données de vulnérabilité provenant d'outils externes via des appels API. Une fois configuré, un Connector récupère les résultats de scan, analyse les données, et crée de nouveaux Tests ou met à jour des Tests existants selon sa configuration. Les Constatations sont ensuite rattachées au Test correspondant.

#### Comparaison des mécanismes de création de Test

| | **Analyseurs natifs** | **Generic Findings Import** | **Universal Parser (Pro)** | **Connectors** |
|----------|---------------|------------------------|------------------------|------------|
| **Objectif principal** | Ingérer les sorties d'outils pris en charge | Ingérer des données non prises en charge/personnalisées via un schéma fixe | Ingérer des formats arbitraires via des correspondances configurables | Synchroniser en continu des systèmes externes |
| **Format d'entrée** | Spécifique à l'outil (par ex. ZAP XML, SARIF) | Schéma JSON/CSV strict | Arbitraire (JSON, XML, etc.) | Réponses d'API externes |
| **Qui gère la normalisation** | DefectDojo (analyseur intégré) | Utilisateur (doit se conformer au schéma) | DefectDojo (via la configuration de l'analyseur) | Outil externe + DefectDojo |
| **Déclencheur de création de Test** | Import manuel ou via l'API | Import manuel ou via l'API | Import manuel ou via l'API | Synchronisation automatisée (planifiée ou événementielle) |
| **Type de Test** | Prédéfini (par ex. « ZAP Scan ») | Type « Generic » créé automatiquement | Dérivé de la configuration de l'analyseur | Dépend du connecteur / de l'analyseur sous-jacent |
| **Effort de configuration** | Faible | Modéré (transformation des données requise) | Élevé (configuration de l'analyseur) | Modéré à élevé (configuration de l'intégration) |
| **Flexibilité** | Faible (outils pris en charge uniquement) | Moyenne | Élevée | Moyenne à élevée |
| **Niveau d'automatisation** | Faible à modéré | Faible à modéré | Faible à modéré | Élevé |
| **Cas d'usage typique** | Scanners standards (SAST, DAST, SCA) | Scripts personnalisés, outils non pris en charge | Formats complexes/personnalisés à grande échelle | Intégrations CI/CD, SCM ou plateforme |

Quelle que soit la méthode d'ingestion, toutes les données de scan dans DefectDojo sont finalement représentées sous forme de Constatations rattachées à un Test, qui sert d'unité d'exécution et de suivi du cycle de vie.

### Données de Test

Les Tests stockent diverses métadonnées qui aident à documenter les différents composants de chaque effort de test, telles que :
- Titre / nom du Test
- Type de Test
- Description / notes du Test
- Dates de début et de fin
- L'Environnement dans lequel le Test a été exécuté (par ex. Développement, Pré-production, Production, etc.)
- Version / Branche / ID de build / Hash de commit
- Configuration de scan API
- Personnel associé au Test
- Fichiers supplémentaires pouvant être utilisés pour des audits ultérieurs ou des réimports
- L'Engagement, l'Actif et l'Organisation parents
- Historique d'import et de réimport

Chaque Test conserve un historique d'import, qui enregistre tous les imports et réimports de scan associés au Test. Chaque élément de l'historique inclut des métadonnées telles que la date du scan, la version, la branche, le hash de commit et l'ID de build.

Cet historique assure la traçabilité entre plusieurs exécutions de scan au sein d'un même Test.

### Permissions

Plusieurs Tests peuvent être stockés au sein d'un même Engagement, et les Engagements sont stockés au sein des Actifs. Ainsi, l'accès à un Actif accorde automatiquement l'accès à tous les Tests (et Engagements) de cet Actif. Les Tests n'ont pas de listes de contrôle d'accès indépendantes.

## Accéder aux Tests

Les Tests sont accessibles depuis différentes sections de l'interface DefectDojo.

- La barre latérale

![image](images/tests_ss13.png)

- Au sein d'un Engagement

![image](images/tests_ss14.png)

- La barre supérieure d'un Actif

![image](images/tests_ss15.png)

- Le tableau des métadonnées dans la vue d'une Constatation

![image](images/tests_ss16.png)

## Utilisation des Tests

### Créer des Tests

Les Tests peuvent être créés automatiquement lorsque des données de scan sont importées directement dans un Engagement, ce qui donne lieu à un nouveau Test contenant les données de scan. Les Tests peuvent également être créés en prévision d'Engagements futurs, ou pour des constatations de sécurité saisies manuellement nécessitant un suivi et une remédiation.

#### Flux de travail manuels

Pour créer un Test, un Engagement doit être créé pour le contenir, ainsi qu'un Actif pour contenir cet Engagement. Ensuite, il existe plusieurs façons de créer un Test :

- Dans la barre latérale, sous Tests dans la sous-section **Manage**
    - Vous devrez sélectionner l'Engagement préexistant auquel attribuer le Test lors de la saisie du formulaire de nouveau Test.

![image](images/tests_ss1.png)

- Le menu déroulant des paramètres en haut à droite d'une vue d'Actif
    - **Import Scan** créera automatiquement un Test une fois qu'un fichier de scan aura été ajouté au formulaire Import Scan. Vous aurez la possibilité d'attribuer le Test à un Engagement préexistant ou de créer et nommer un nouvel Engagement pour contenir le nouveau Test.
        - En remplissant le formulaire Import Scan, vous pouvez ajouter des métadonnées telles que la version, l'étiquette de branche, le hash de commit et l'ID de build. Cela se reflétera dans la section Historique d'import de la vue du Test.

![image](images/tests_ss2.png)

- Le menu déroulant des paramètres en haut à droite d'une vue d'Engagement
    - **Import Scan** suit le même flux de travail que pour les Actifs, mais placera automatiquement l'objet Test dans l'Engagement depuis lequel vous avez cliqué sur Import Scan.
    - **Add Test** crée un objet Test sans exiger qu'un scan soit importé dans le Test lui-même, ce qui est utile en prévision de Tests futurs ou pour des constatations de sécurité saisies manuellement nécessitant un suivi et une remédiation.

![image](images/tests_ss3.png)

Si vous sélectionnez Add Test et que vous souhaitez ultérieurement importer manuellement les résultats d'un scan dans un Test, vous pouvez le faire en ouvrant le Test et en cliquant sur le bouton Reimport Findings dans les paramètres du Test, ou sur le bouton Reimport Scan dans le tableau des Constatations.

![image](images/tests_ss21.png)

#### Flux de travail automatisés

Dans les flux de travail automatisés, les Tests peuvent être créés de manière programmatique dans le cadre du processus d'import de scan, ce qui permet aux pipelines de téléverser des résultats sans qu'un Test doive être créé manuellement au préalable.

Lors de l'utilisation de l'API ou de la CLI pour importer des résultats de scan, un nouveau Test peut être créé automatiquement en fournissant un `engagement` plutôt qu'un `test`.

##### API

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Dans l'exemple ci-dessus, un nouveau Test est créé sous l'Engagement spécifié, et les résultats de scan y sont rattachés.

Si un ID de `test` est fourni à la place, les résultats de scan seront ajoutés à un Test existant, ce qui est courant dans les flux de réimport.

##### CLI

En utilisant la CLI DefectDojo, ce comportement est géré automatiquement en fonction des arguments fournis.

defectdojo-cli import \
  --engagement-id 45 \
  --scan-type `"ZAP Scan"` \
GOog  --file report.xml

Dans l'exemple ci-dessus, fournir un `engagement-id` crée un nouveau Test, et fournir un `test-id` réutilise un Test existant et y réimporte les résultats de scan.

Voir [DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/#defectdojo-cli) pour plus de détails sur les indicateurs requis.

### Modifier des Tests

Les Tests peuvent être modifiés en cliquant sur **Edit Test** dans le menu à engrenage. Tous les champs modifiables qui en découlent sont également disponibles lors de la création du Test.

### Supprimer des Tests

La suppression d'un Test s'effectue en sélectionnant **Delete Test** dans les paramètres du Test. Cette action est irréversible.

La suppression d'un Test supprimera également toutes les Constatations qu'il contient.

### Réimporter les résultats de scan (UI)

Pour ajouter de nouvelles données à un Test existant, ouvrez le Test auquel vous ajoutez de nouvelles données et cliquez sur le bouton Reimport Findings dans les paramètres du Test, ou sur le bouton Reimport Scan dans le tableau des Constatations.

![image](images/tests_ss21.png)

En remplissant le formulaire Reimport Scan, vous pourrez mettre à jour les métadonnées du scan réimporté, notamment la version, l'étiquette de branche, le hash de commit et l'ID de build. Ces modifications se reflètent dans la section Historique d'import de la vue du Test, qui inclura également les mêmes métadonnées des imports précédents.

Par exemple, dans la capture d'écran ci-dessous, l'étiquette de branche, l'ID de build, le hash de commit et la version ont tous été mis à jour manuellement entre l'import initial et le réimport suivant.

![image](images/tests_ss23.png)

Pour modifier les métadonnées du scan réimporté le plus récemment, cliquez sur l'icône en forme d'engrenage située en haut à droite d'une vue d'Engagement et sélectionnez « Edit Test ». Seules les métadonnées de l'import le plus récent peuvent être modifiées.

### Réimporter les résultats de scan (API/CLI)

Lorsque des Tests sont créés ou mis à jour via un pipeline CI/CD, vous pouvez inclure des métadonnées provenant de l'exécution du pipeline afin que les Tests puissent être correctement liés au code analysé. Cela vous permet de :
- Associer les résultats de scan à un commit ou une branche spécifique.
- Suivre l'évolution des Constatations au fil des modifications du code.
- Améliorer la Déduplication en comprenant quand deux scans s'appliquent à la même version du code, ou à des versions différentes.
- Faciliter l'auditabilité en montrant précisément quel code a été analysé, et quand.

La CLI et l'API de DefectDojo acceptent ces valeurs lors de l'import ou du réimport afin qu'elles puissent être stockées dans le cadre de l'import du scan et reflétées dans l'historique d'import du Test. Ces métadonnées peuvent être utilisées pour identifier des hashs de commit ou toute information de dépôt associée à une exécution CI/CD.

#### Champs de métadonnées pris en charge

L'API et la CLI prennent en charge un ensemble défini de champs de métadonnées pouvant être inclus lors du réimport. Ceux-ci comprennent :

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- les indicateurs `active / verified`

Ces champs représentent le mécanisme principal pour rattacher des métadonnées contextuelles lors d'une opération de réimport.

Dans les pipelines automatisés, les métadonnées les plus couramment fournies sont :
- `build_id` (identifiant du job CI)
- `commit_hash` (référence de contrôle de source)
- `branch_tag` (contexte de branche ou d'environnement)
- `tags` (par ex. `nightly`, `staging`, `production`)

Ces champs assurent la traçabilité entre les scans sans nécessiter d'intervention manuelle.

Bien que les métadonnées puissent être mises à jour manuellement via le formulaire Reimport Scan, la plupart des environnements automatisés géreront cela en appelant directement le point de terminaison `/api/v2/reimport-scan/` ou en utilisant la CLI DefectDojo (`defectdojo-cli reimport`) dans le cadre du processus de build. Cette approche permet au pipeline de rattacher automatiquement les métadonnées lors du réimport.

##### Réimport via l'API avec métadonnées

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

##### Réimport via la CLI avec métadonnées

defectdojo-cli import \
  --test-id 123 \
  --scan-type "ZAP Scan" \
  --file report.xml \
  --tag nightly \
  --tag api \
  --build-id jenkins-842 \
  --branch main \
  --commit a1b2c3d4

La CLI correspond directement au même point de terminaison de l'API et prend en charge le même ensemble de champs de métadonnées.

Il existe quelques limitations à connaître lors de l'utilisation des métadonnées pendant le réimport :
- L'API/CLI ne prend en charge que des paramètres prédéfinis. Des métadonnées personnalisées sous forme de clé-valeur ne peuvent pas être ajoutées lors du réimport
- Des métadonnées supplémentaires peuvent être extraites du fichier de scan lui-même, selon le type de scan et l'analyseur.
- Les métadonnées fournies lors du réimport ne se comportent pas comme une mise à jour directe de l'objet Test, contrairement aux modifications manuelles effectuées dans l'interface.

##### Métadonnées, réimport et scans planifiés

Les scans peuvent également être planifiés pour s'exécuter à intervalles réguliers, par exemple déclenchés par des tâches cron. Les scans planifiés ne sont pas liés à l'activité du dépôt, ce qui rend des métadonnées comme les hashs de commit ou les noms de branche non pertinentes, sauf si elles sont explicitement injectées par le script lui-même. Néanmoins, l'utilisation du réimport peut rester utile si vous préférez conserver un historique glissant de votre posture de sécurité au sein d'un même Test.

## Réimport et déduplication

Le réimport des scans au sein des Tests est fondamental pour une déduplication efficace. Lorsque des résultats de scan sont réimportés dans le même Test :

- Des Constatations existantes peuvent être mises à jour
- Des Constatations en double peuvent être supprimées
- De nouvelles Constatations peuvent être créées si aucune correspondance n'est trouvée

Ce comportement dépend des règles de déduplication configurées et du type de scan.

Créer un nouveau Test au lieu de réimporter dans un Test existant peut entraîner la création de Constatations en double plutôt que leur mise à jour.

### Réimport vs. Import

Le réimport est généralement utilisé lorsque :

- Des scans récurrents sont exécutés contre la même cible
- Vous suivez l'évolution des Constatations dans le temps
- Vous maintenez une vue continue de la posture de sécurité de l'application

En revanche, l'import (création d'un nouveau Test) est plus approprié pour des exécutions de scan ponctuelles ou indépendantes.
