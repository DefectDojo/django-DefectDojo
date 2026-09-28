---
title: Universal Importer & DefectDojo-CLI
description: Importez des fichiers dans DefectDojo depuis la ligne de commande
draft: false
weight: 2
audience: pro
aliases:
- /fr/en/connecting_your_tools/external_tools
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les outils externes suivants sont des fonctionnalités réservées à DefectDojo Pro. Ces binaires ne fonctionneront pas s'ils ne sont pas connectés à une instance disposant d'une licence DefectDojo Pro.</span>

## À propos des outils externes

`defectdojo-cli` et `universal-importer` sont des outils en ligne de commande conçus pour simplifier les processus d'importation et de réimportation des Constatations et des objets associés, ce qui les rend idéaux pour les utilisateurs souhaitant configurer rapidement ces interactions avec l'API DefectDojo.

DefectDojo-CLI offre les mêmes fonctionnalités qu'Universal Importer, mais permet également d'exporter les Constatations de DefectDojo au format JSON ou CSV.

## Installation

1. Repérez « Outils externes » dans le menu de votre profil utilisateur :

2. Téléchargez le binaire approprié pour votre système d'exploitation depuis la plateforme.

![image](images/external-tools.png)

3. Extrayez l'archive téléchargée dans le répertoire de votre choix. Vous pouvez éventuellement ajouter le répertoire contenant le binaire extrait à la variable $PATH de votre système pour un accès répété.

**Notez que les utilisateurs de Macintosh peuvent être empêchés d'exécuter DefectDojo-CLI ou Universal Importer, car il s'agit d'applications provenant d'un développeur non identifié. Consultez le [Support Apple](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac) pour savoir comment contourner ce blocage d'Apple.**  

**Utilisateurs Windows : si vous recevez l'erreur « Couldn't download - virus detected », la désactivation de Smartscreen peut résoudre le problème. Sinon, utilisez un autre navigateur pour télécharger l'outil depuis le portail Cloud.**

## Configuration

Universal Importer et DefectDojo-CLI peuvent être configurés à l'aide d'indicateurs, de variables d'environnement ou d'un fichier de configuration. La configuration la plus importante est le jeton API, qui doit être défini en tant que variable d'environnement :

1. Ajoutez votre clé API à vos variables d'environnement. 
Vous pouvez récupérer votre clé API à partir de : `https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

ou 

Via l'interface utilisateur de DefectDojo 
dans le menu déroulant utilisateur situé en haut à droite :

![image](images/api-token.png)

2. Définissez votre variable d'environnement pour le jeton API.

**Pour DefectDojo-CLI :**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**Pour Universal Importer :**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

Remarque : sous Windows, utilisez `set` au lieu de `export`.

### Windows : utilisation de PowerShell

1. Ouvrez PowerShell (touche Windows, puis recherchez « PowerShell »).
2. Définissez les variables d'environnement :
   - **Temporaire :**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente :**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. Redémarrez votre session PowerShell.
4. Vérifiez le paramètre :
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows : utilisation de l'invite de commandes (comptes administrateurs)
1. Ouvrez l'invite de commandes (touche Windows, puis recherchez « Command Prompt »).
2. Définissez les variables d'environnement :
   - **Temporaire :**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **Permanente :**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### Utilisation des paramètres Windows (comptes non administrateurs)
1. Appuyez sur `Win + I` pour ouvrir la boîte de dialogue des paramètres système.
2. Dans le champ de recherche, saisissez « environment ».
3. Choisissez « Edit Environment variables for your account ».
4. Sous « User variables for [username] », cliquez sur le bouton « New… ».
5. Définissez la variable :
   - **Nom de la variable :** `DD_IMPORTER_DOJO_API_TOKEN`
   - **Valeur de la variable :** `[VALUE_FROM_DEFECTDOJO_API]`
6. Cliquez sur « OK ».
7. Répétez les étapes 4 à 6 pour la variable DD_IMPORTER_DEFECTDOJO_URL
8. Redémarrez toutes les fenêtres de commande ouvertes.
9. Vérifiez les paramètres :
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli` intègre de façon transparente les résultats de scan à DefectDojo, en simplifiant les processus d'importation et de réimportation des Constatations et des objets associés. Conçu pour être facile à utiliser, l'outil prend en charge divers points de terminaison, adaptés aussi bien aux importations initiales qu'aux réimportations ultérieures — idéal pour les utilisateurs ayant besoin d'une interaction robuste et flexible avec l'API DefectDojo. DefectDojo-CLI peut effectuer les mêmes fonctions que `universal-importer`, et ajoute une fonctionnalité d'exportation pour les Constatations.

### Commandes

- [`import`](./#import)       Importe les constatations dans DefectDojo.
- [`reimport`](./#reimport)     Réimporte les constatations dans DefectDojo.
- [`export`](./#export)	Exporte les constatations depuis DefectDojo.
- [`interactive`](./#interactive)   Démarre un mode interactif permettant de configurer le processus d'importation et de réimportation, étape par 

### Options globales

`--help, -h`     
* afficher l'aide

`--version, -v`
* afficher la version

#### Formatage de la CLI

`--no-color`
* Désactive la sortie en couleur. (par défaut : false) `[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* Désactive les emojis dans la sortie. (par défaut : false) `[$DD_CLI_NO_EMOJIS]`

* `--verbose`
Active la sortie détaillée. (par défaut : false) `[$DD_CLI_VERBOSE]`

### Import

Utilisez la commande import pour importer de nouvelles constatations dans DefectDojo.

#### Utilisation

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

`import` peut importer des Constatations de deux façons :

**Par ID :**
* Créez un Produit (ou utilisez un produit existant)
* Créez un Engagement dans le produit
* Indiquez l'id de l'Engagement dans le paramètre engagement

Dans ce scénario, un nouveau Test sera créé dans l'Engagement.

**Par nom :**

* Créez un Produit (ou utilisez un produit existant)
* Créez un Engagement dans le produit
* Indiquez product-name
* Indiquez engagement-name
* Indiquez éventuellement product-type-name

Dans ce scénario, DefectDojo recherchera l'Engagement à partir des informations fournies.

Lorsque vous utilisez des noms, vous pouvez laisser l'importateur créer automatiquement les Engagements, les Produits et les Product-types en utilisant `auto-create-context=true`.
Vous pouvez utiliser `deduplication-on-engagement` pour restreindre la déduplication des Constatations importées au nouvel Engagement créé.


**Syntaxe de base de l'import :**
```
defectdojo-cli import [options]
```

#### **Exemple d'import :**
```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Commandes
`example, x`
* Affiche un exemple d'indicateurs requis et facultatifs pour l'opération d'import

#### Options

`--active, -a` 
* Détermine si les Constatations doivent être forcées à Actif ou Inactif lors de l'import.  Une valeur True force les Constatations à Actif, tandis qu'une valeur False force toutes les Constatations à Inactif.  Si aucune valeur n'est définie, le statut Actif dépendra du fichier de rapport entrant. (par défaut : non défini) `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* L'ID de l'objet API Scan Configuration à utiliser lors de l'import ou de la réimportation. (par défaut : 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux points de terminaison (par défaut : false) 
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux constatations (par défaut : false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Si défini sur true, l'importateur crée automatiquement les Engagements, les Produits et les Product_Types (par défaut : false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si True, les anciennes Constatations qui ne sont plus présentes dans le rapport seront fermées avec le statut Atténué lors de l'import. Si un Service a été défini, seules les Constatations de ce Service seront fermées. [$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Indique si --close-old-findings s'applique à **toutes** les Constatations du même type dans le Produit. Par défaut, cette valeur est false, ce qui signifie que seules les anciennes Constatations du même type dans l'Engagement sont dans le périmètre (et seront fermées par Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Si défini sur true, l'importateur restreint la déduplication des constatations importées au nouvel Engagement créé. (par défaut : false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* L'ID de l'Engagement dans lequel importer les constatations. (par défaut : 0) `[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* Le nom de l'Engagement dans lequel importer les constatations. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Détermine le niveau de sévérité le plus bas devant être importé. Les valeurs valides sont : Critical, High, Medium, Low, Info. (par défaut : "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* Le nom du Produit dans lequel importer les constatations. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* Le nom du Type de produit dans lequel importer les constatations. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* Le chemin vers le rapport à importer. (obligatoire). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* Le type de scan de l'outil (obligatoire). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Toute étiquette à appliquer à l'objet Test `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* Le nom du Test dans lequel importer les constatations - Par défaut, il s'agit du nom du type de scan. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* La version du test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* Détermine si les Constatations doivent être définies sur Vérifié lors de l'import. Une valeur True force les Constatations à Vérifié. Si aucune valeur n'est définie, le statut Vérifié dépendra du fichier de rapport entrant. `[$DD_CLI_VERIFIED]`

**Paramètres :**

`--config value, -c value`          
* Le chemin vers le fichier de configuration TOML est utilisé pour définir les valeurs des options. Si l'option est définie à la fois dans le fichier de configuration et dans la CLI, la CLI aura la priorité. `[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* L'URL de l'instance DefectDojo dans laquelle importer les constatations. (obligatoire). `[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignore les erreurs de validation TLS lors de la connexion à l'instance DefectDojo fournie. La plupart des utilisateurs ne devraient pas activer cet indicateur. (par défaut : false) `[$DD_CLI_INSECURE_TLS]`

### Reimport

Utilisez la commande `reimport` pour étendre un Test existant avec des Constatations issues d'un nouveau rapport, de l'une des deux façons suivantes :

Par ID :
- Créez un Produit (ou utilisez un produit existant)
- Créez un Engagement dans le produit
- Importez un rapport de scan et trouvez l'id du Test
- Indiquez cet id dans le paramètre test-id

Par noms :
- Créez un Produit (ou utilisez un produit existant)
- Créez un Engagement dans le produit
- Importez un rapport qui créera un Test
- Indiquez product-name
- Indiquez engagement-name
- Facultatif : indiquez test-name

Dans ce scénario, DefectDojo recherchera le Test à partir des informations fournies. Si aucun test-name n'est indiqué, le test le plus récent dans l'engagement sera choisi en fonction du scan-type.

Lorsque vous utilisez des noms, vous pouvez laisser l'importateur créer automatiquement les Engagements, les Produits et les Product-types en utilisant `auto-create-context=true`.
Vous pouvez utiliser `deduplication-on-engagement` pour restreindre la déduplication des Constatations importées au nouvel Engagement créé.

#### Utilisation

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **Exemple de réimport :**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Commandes

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Options

`--active, -a`                                    
* Détermine si les Constatations doivent être forcées à Actif ou Inactif lors de l'import.  Une valeur True force les Constatations à Actif, tandis qu'une valeur False force toutes les Constatations à Inactif.  Si aucune valeur n'est définie, le statut Actif dépendra du fichier de rapport entrant. `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* L'ID de l'objet API Scan Configuration à utiliser lors de l'import ou de la réimportation. (par défaut : 0) `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux points de terminaison (par défaut : false) `[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux constatations (par défaut : false) `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Si défini sur true, l'importateur crée automatiquement les Engagements, les Produits et les Product_Types (par défaut : false) `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si True, les anciennes Constatations qui ne sont plus présentes dans le rapport seront fermées avec le statut Atténué lors de l'import. Si un Service a été défini, seules les constatations de ce Service seront fermées.[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Indique si --close-old-findings s'applique à **toutes** les Constatations du même type dans le Produit. Par défaut, cette valeur est false, ce qui signifie que seules les anciennes Constatations du même type dans l'Engagement sont dans le périmètre (et seront fermées par Close Old Findings). [$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Si défini sur true, l'importateur restreint la déduplication des constatations importées au nouvel Engagement créé. (par défaut : false) `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* Le nom de l'Engagement dans lequel importer les constatations. `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Détermine le niveau de sévérité le plus bas devant être importé. Les valeurs valides sont : Critical, High, Medium, Low, Info. (par défaut : "Info") `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* Le nom du Produit dans lequel importer les constatations. `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* Le nom du Type de produit dans lequel importer les constatations. `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* Le chemin vers le rapport à importer. (obligatoire). `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`                      
* Le type de scan de l'outil (obligatoire). `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Toute étiquette à appliquer à l'objet Test `[$DD_CLI_TAGS]`

`--test-id value, --ti value`                      
* L'ID du Test dans lequel réimporter les constatations. (par défaut : 0) `[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`                    
* Le nom du Test dans lequel importer les constatations - Par défaut, il s'agit du nom du type de scan. `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`                   
* La version du test. `[$DD_CLI_TEST_VERSION]`

`--verified, -v`                                   
* Détermine si les Constatations doivent être définies sur Vérifié lors de l'import. Une valeur True force les Constatations à Vérifié.  Si aucune valeur n'est définie, le statut Vérifié dépendra du fichier de rapport entrant. `[$DD_CLI_VERIFIED]`

**Paramètres :**

`--config value, -c value`
* Le chemin vers le fichier de configuration TOML est utilisé pour définir les valeurs des options. Si l'option est définie à la fois dans le fichier de configuration et dans la CLI, la CLI aura la priorité. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* L'URL de l'instance DefectDojo dans laquelle importer les constatations. (obligatoire). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignore les erreurs de validation TLS lors de la connexion à l'instance DefectDojo fournie. La plupart des utilisateurs ne devraient pas activer cet indicateur. (par défaut : false) `[$DD_CLI_INSECURE_TLS]`

### Export

#### Utilisation

```
defectdojo-cli export <required options> [optional options]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --config ./config-file-path
	or: defectdojo-cli [global options] export --config ./config-file-path --json ./output_file_path.json
	or: defectdojo-cli [global options] export --config ./config-file-path --csv ./output_file_path.csv
	or: defectdojo-cli export [-h | --help]
	or: defectdojo-cli export example [subcommand options]
	or: defectdojo-cli export example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

Pour exporter des Constatations depuis DefectDojo-CLI, vous devez fournir un fichier de configuration contenant les détails expliquant quelles Constatations vous souhaitez exporter.  Cela est similaire à la méthode GET Findings via l'API.

Pour obtenir de l'aide, utilisez `defectdojo-cli export --help`.

#### **Exemple d'export**

Cet exemple précise l'URL, le format d'export et quelques paramètres de filtre pour créer une liste de Constatations.

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### Commandes

`example, x`
* Affiche un exemple d'indicateurs requis et facultatifs pour l'opération d'export

`help, h`
* Affiche une liste de commandes ou l'aide pour une commande

#### Options

**Filtres de constatations :**

`--active true|false, -a true|false`
* Constatations par statut actif. `[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* Constatations par date de création. Valeurs prises en charge : None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* Constatations par score CVSS v3. (par défaut : ignoré) `[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value` 
* Constatations par ID CWE. (par défaut : ignoré) `[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* Constatations par date. Valeurs prises en charge : None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* Constatations découvertes après la date spécifiée. Format : YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* Constatations découvertes avant la date spécifiée. Format : YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* Constatations par date de découverte. Format : YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* Constatations par statut de doublon. `[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* Constatations par ID d'engagement. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. `[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* Constatations par percentile EPSS. (par défaut : ignoré) `[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* Constatations par score EPSS. (par défaut : ignoré) `[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* Constatations par statut de faux positif. `[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* Constatations par statut d'atténuation. `[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* Constatations par plage de dates à laquelle elles ont été marquées comme atténuées. Valeurs prises en charge : None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* Constatations atténuées après la date spécifiée. Format : YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* Constatations atténuées avant la date spécifiée. Format : YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* Constatations par ID utilisateur mitigated_by. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. Peut être combiné avec --mitigated-by-names. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* Constatations par nom d'utilisateur mitigated_by. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. Peut être combiné avec --mitigated-by-ids. `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* Constatations par date d'atténuation. Format : YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* Constatations par étiquettes qui ne doivent pas être présentes. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. `[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* Constatations par statut Hors périmètre ou dans le périmètre. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* Constatations par statut à l'intérieur ou à l'extérieur du SLA. `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* Constatations par nom de produit. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* Constatations dont le nom de produit contient la chaîne indiquée. `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* Constatations par ID de type de produit. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. Peut être combiné avec --product-type-names `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* Constatations par nom de type de produit. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. Peut être combiné avec --product-type-ids `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* Constatations par statut Risque accepté. `[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* Constatations par sévérité. Les valeurs valides sont : Critical, High, Medium, Low, Info. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. `[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* Constatations par étiquettes devant être présentes. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. `[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* Constatations par ID de test. (par défaut : ignoré) `[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* Constatations dont le titre contient la chaîne indiquée. `[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* Constatations par statut en cours de révision. `[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* Constatations par statut Vérifié. (par défaut : ignoré) `[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* Constatations par ID de vulnérabilité. Cet indicateur peut être utilisé plusieurs fois ou sous forme de liste séparée par des virgules. `[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**Sortie des constatations**

`--csv value`
* Chemin du fichier dans lequel le fichier CSV des constatations sera écrit. `[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  Chemin du fichier dans lequel le fichier JSON des constatations sera écrit. `[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**Paramètres**

`--config value, -c value`
Le chemin vers le fichier de configuration TOML est utilisé pour définir les valeurs des options. Si l'option est définie à la fois dans le fichier de configuration et dans la CLI, la CLI aura la priorité. `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
L'URL de l'instance DefectDojo dans laquelle importer les constatations. (obligatoire). `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
ignore les erreurs de validation TLS lors de la connexion à l'instance DefectDojo fournie. La plupart des utilisateurs ne devraient pas activer cet indicateur. (par défaut : false) `[$DD_CLI_INSECURE_TLS]`

#### Exemple d'export :

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### Interactive

Le mode interactif vous permet de configurer le processus d'import et de réimport, étape par étape.

#### Utilisation

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### Options

`--skip-intro `    
* Ignore l'écran d'introduction (par défaut : false)

`--no-full-screen`
* Désactive le mode plein écran (par défaut : false)

`--log-path value`
* Chemin vers le fichier journal

`--help, -h`
* afficher l'aide

## Universal Importer

`universal-importer` intègre de façon transparente les résultats de scan à DefectDojo, en simplifiant les processus d'importation et de réimportation des constatations et des objets associés. Conçu pour être facile à utiliser, l'outil prend en charge divers points de terminaison, adaptés aussi bien aux importations initiales qu'aux réimportations ultérieures — idéal pour les utilisateurs ayant besoin d'une interaction robuste et flexible avec l'API DefectDojo.

Bien que similaire à DefectDojo-CLI, Universal Importer ne dispose pas de la fonctionnalité d'export, et les variables d'environnement sont codées différemment.

### Commandes

- [`import`](./#import-1)       Importe les constatations dans DefectDojo.
- [`reimport`](./#reimport-1)     Réimporte les constatations dans DefectDojo.
- [`interactive`](./#interactive-1)   Démarre un mode interactif permettant de configurer le processus d'importation et de réimportation, étape par 

### Options globales

`--help, -h`     
* afficher l'aide

`--version, -v`
* afficher la version

#### Formatage de la CLI

`--no-color`
* Désactive la sortie en couleur. (par défaut : false) `[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* Désactive les emojis dans la sortie. (par défaut : false) `[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* Active la sortie détaillée. (par défaut : false) `[$DD_IMPORTER_VERBOSE]`

### Import

Utilisez la commande import pour importer de nouvelles constatations dans DefectDojo.

#### Utilisation

```
universal-importer [global options] import <required flags> [optional flags]
	or: universal-importer [global options] import  --config ./config-file-path
	or: universal-importer import [-h | --help]
	or: universal-importer import example [subcommand options]
	or: universal-importer import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import` peut importer des Constatations de deux façons :

**Par ID :**
* Créez un Produit (ou utilisez un produit existant)
* Créez un Engagement dans le produit
* Indiquez l'id de l'Engagement dans le paramètre engagement

Dans ce scénario, un nouveau Test sera créé dans l'Engagement.

**Par nom :**
* Créez un Produit (ou utilisez un produit existant)
* Créez un Engagement dans le produit
* Indiquez product-name
* Indiquez engagement-name
* Indiquez éventuellement product-type-name

Dans ce scénario, DefectDojo recherchera l'Engagement à partir des informations fournies.

Lorsque vous utilisez des noms, vous pouvez laisser l'importateur créer automatiquement les Engagements, les Produits et les Product-types en utilisant `auto-create-context=true`.
Vous pouvez utiliser `deduplication-on-engagement` pour restreindre la déduplication des Constatations importées au nouvel Engagement créé.


**Syntaxe de base de l'import :**

```
universal-importer import [options]
```

#### **Exemple d'import :**

```
universal-importer import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### Commandes

`example, x`
* Affiche un exemple d'indicateurs requis et facultatifs pour l'opération d'import

#### Options

`--active, -a` 
* Détermine si les Constatations doivent être forcées à Actif ou Inactif lors de l'import.  Une valeur True force les Constatations à Actif, tandis qu'une valeur False force toutes les Constatations à Inactif.  Si aucune valeur n'est définie, le statut Actif dépendra du fichier de rapport entrant. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* L'ID de l'objet API Scan Configuration à utiliser lors de l'import ou de la réimportation. (par défaut : 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux points de terminaison (par défaut : false) 
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux constatations (par défaut : false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* Si défini sur true, l'importateur crée automatiquement les Engagements, les Produits et les Product_Types (par défaut : false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si True, les anciennes Constatations qui ne sont plus présentes dans le rapport seront fermées avec le statut Atténué lors de l'import. Si un Service a été défini, seules les constatations de ce Service seront fermées. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Indique si --close-old-findings s'applique à **toutes** les Constatations du même type dans le Produit. Par défaut, cette valeur est false, ce qui signifie que seules les anciennes Constatations du même type dans l'Engagement sont dans le périmètre (et seront fermées par Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* Si défini sur true, l'importateur restreint la déduplication des constatations importées au nouvel Engagement créé. (par défaut : false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* L'ID de l'Engagement dans lequel importer les constatations. (par défaut : 0) `[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* Le nom de l'Engagement dans lequel importer les constatations. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* Détermine le niveau de sévérité le plus bas devant être importé. Les valeurs valides sont : Critical, High, Medium, Low, Info. (par défaut : "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* Le nom du Produit dans lequel importer les constatations. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* Le nom du Type de produit dans lequel importer les constatations. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* Le chemin vers le rapport à importer. (obligatoire). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* Le type de scan de l'outil (obligatoire). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* Toute étiquette à appliquer à l'objet Test `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* Le nom du Test dans lequel importer les constatations - Par défaut, il s'agit du nom du type de scan. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* La version du test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* Détermine si les Constatations doivent être définies sur Vérifié lors de l'import. Une valeur True force les Constatations à Vérifié.  Si aucune valeur n'est définie, le statut Vérifié dépendra du fichier de rapport entrant. `[$DD_IMPORTER_VERIFIED]`

**Paramètres :**

`--config value, -c value`          
* Le chemin vers le fichier de configuration TOML est utilisé pour définir les valeurs des options. Si l'option est définie à la fois dans le fichier de configuration et dans la CLI, la CLI aura la priorité. `[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* L'URL de l'instance DefectDojo dans laquelle importer les constatations. (obligatoire). `[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          ignore les erreurs de validation TLS lors de la connexion à l'instance DefectDojo fournie. La plupart des utilisateurs ne devraient pas activer cet indicateur. (par défaut : false) `[$DD_IMPORTER_INSECURE_TLS]`

### Reimport

Utilisez la commande `reimport` pour étendre un Test existant avec des Constatations issues d'un nouveau rapport, de l'une des deux façons suivantes :

Par ID :
- Créez un Produit (ou utilisez un produit existant)
- Créez un Engagement dans le produit
- Importez un rapport de scan et trouvez l'id du Test
- Indiquez cet id dans le paramètre test-id

Par noms :
- Créez un Produit (ou utilisez un produit existant)
- Créez un Engagement dans le produit
- Importez un rapport qui créera un Test
- Indiquez product-name
- Indiquez engagement-name
- Facultatif : indiquez test-name

Dans ce scénario, DefectDojo recherchera le Test à partir des informations fournies. Si aucun test-name n'est indiqué, le test le plus récent dans l'engagement sera choisi en fonction du scan-type.

Lorsque vous utilisez des noms, vous pouvez laisser l'importateur créer automatiquement les Engagements, les Produits et les Product-types en utilisant `auto-create-context=true`.
Vous pouvez utiliser `deduplication-on-engagement` pour restreindre la déduplication des Constatations importées au nouvel Engagement créé.

#### Utilisation

```
universal-importer [global options] reimport <required flags> [optional flags]
   or: universal-importer [global options] reimport  --config ./config-file-path
   or: universal-importer reimport [-h | --help]
   or: universal-importer reimport example [subcommand options]
   or: universal-importer reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **Exemple de réimport :**

```
universal-importer reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### Commandes

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### Options

`--active, -a`                                    
* Détermine si les Constatations doivent être forcées à Actif ou Inactif lors de l'import.  Une valeur True force les Constatations à Actif, tandis qu'une valeur False force toutes les Constatations à Inactif.  Si aucune valeur n'est définie, le statut Actif dépendra du fichier de rapport entrant. `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* L'ID de l'objet API Scan Configuration à utiliser lors de l'import ou de la réimportation. (par défaut : 0) `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`                     
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux points de terminaison (par défaut : false) `[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`                      
* Si défini sur true, les étiquettes (issues de l'option --tag) seront appliquées aux constatations (par défaut : false) `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`                 
* Si défini sur true, l'importateur crée automatiquement les Engagements, les Produits et les Product_Types (par défaut : false) `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* Si True, les anciennes Constatations qui ne sont plus présentes dans le rapport seront fermées avec le statut Atténué lors de l'import. Si un Service a été défini, seules les Constatations de ce Service seront fermées. [$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* Indique si --close-old-findings s'applique à **toutes** les Constatations du même type dans le Produit. Par défaut, cette valeur est false, ce qui signifie que seules les anciennes Constatations du même type dans l'Engagement sont dans le périmètre (et seront fermées par Close Old Findings). [$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`          
* Si défini sur true, l'importateur restreint la déduplication des constatations importées au nouvel Engagement créé. (par défaut : false) `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`               
* Le nom de l'Engagement dans lequel importer les constatations. `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`          
* Détermine le niveau de sévérité le plus bas devant être importé. Les valeurs valides sont : Critical, High, Medium, Low, Info. (par défaut : "Info") `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`                   
* Le nom du Produit dans lequel importer les constatations. `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`         
* Le nom du Type de produit dans lequel importer les constatations. `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`                    
* Le chemin vers le rapport à importer. (obligatoire). `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`                      
* Le type de scan de l'outil (obligatoire). `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`  
* Toute étiquette à appliquer à l'objet Test `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`                      
* L'ID du Test dans lequel réimporter les constatations. (par défaut : 0) `[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`                    
* Le nom du Test dans lequel importer les constatations - Par défaut, il s'agit du nom du type de scan. `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`                   
* La version du test. `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`                                   
* Détermine si les Constatations doivent être définies sur Vérifié lors de l'import. Une valeur True force les Constatations à Vérifié. Si aucune valeur n'est définie, le statut Vérifié dépendra du fichier de rapport entrant. (par défaut : non défini) `[$DD_IMPORTER_VERIFIED]`

**Paramètres :**

`--config value, -c value`
* Le chemin vers le fichier de configuration TOML est utilisé pour définir les valeurs des options. Si l'option est définie à la fois dans le fichier de configuration et dans la CLI, la CLI aura la priorité. `[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`  
* L'URL de l'instance DefectDojo dans laquelle importer les constatations. (obligatoire). `[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* ignore les erreurs de validation TLS lors de la connexion à l'instance DefectDojo fournie. La plupart des utilisateurs ne devraient pas activer cet indicateur. (par défaut : false) `[$DD_IMPORTER_INSECURE_TLS]`

### Interactive
Le mode interactif vous permet de configurer le processus d'import et de réimport, étape par étape.

#### Utilisation

```
universal-importer interactive
	or: universal-importer interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: universal-importer interactive [-h | --help]
```

#### Options

`--skip-intro `    
* Ignore l'écran d'introduction (par défaut : false)

`--no-full-screen`
* Désactive le mode plein écran (par défaut : false)
`--log-path value`
* Chemin vers le fichier journal
`--help, -h`
* afficher l'aide


## Dépannage

Si vous rencontrez des problèmes avec ces outils, veuillez vérifier les points suivants :
- Assurez-vous d'utiliser le binaire correct pour votre système d'exploitation et votre architecture de processeur.
- Vérifiez que la clé API est correctement définie dans vos variables d'environnement.
- Vérifiez que l'URL de DefectDojo est correcte et accessible.
- Lors de l'import, confirmez que le fichier de rapport existe et qu'il est dans le format pris en charge pour le type de scan spécifié.  Vous pouvez consulter la liste des scanners pris en charge par DefectDojo dans notre [liste des outils pris en charge](/supported_tools). 
