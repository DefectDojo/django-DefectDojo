---
title: 🌐 Universal Parser
description: ''
draft: 'false'
weight: 1
audience: pro
aliases:
- /fr/en/connecting_your_tools/universal_parser
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : Universal Parser n'est disponible que dans DefectDojo Pro.</span>

Universal Parser est activé pour chaque instance DefectDojo Pro ; il n'y a rien à activer. Consultez notre [présentation d'annonce](https://community.defectdojo.com/universalparser) pour plus d'informations.

## À propos d'Universal Parser
DefectDojo dispose d'une vaste bibliothèque de parseurs, régulièrement mise à jour, pour aider les équipes de sécurité à ingérer des données. Cependant, il arrive que les utilisateurs disposent d'un outil non pris en charge par les parseurs existants, ou qu'ils souhaitent importer des données dans le modèle DefectDojo différemment de la façon dont le parseur le fait.

Universal Parser de DefectDojo est conçu pour offrir aux utilisateurs disposant de types de rapports non pris en charge une solution permettant d'importer et de mapper **n'importe quel fichier JSON, CSV ou XML**.

**Universal Parser, c'est :**

* Un moyen rapide de prendre en charge des formats de fichiers pour lesquels nous ne disposons pas de parseurs Community, comme les rapports produits par des outils internes
* Un outil pour vous aider à ingérer des données, même si un parseur Community est obsolète ou ne structure pas les constatations comme vous le souhaiteriez
* Une alternative à l'écriture de scripts personnalisés pour transformer les rapports d'outils dans le format CSV/JSON attendu par le type d'analyse « Generic Findings Import »
* Conçu pour être facile à utiliser par tous, sans code et avec une configuration minimale

**Universal Parser, ce n'est pas :**

* Un remplacement complet des parseurs open source, des Connectors, ou des rapports « Generic Findings Import » soigneusement retravaillés
* Capable de gérer une logique nuancée et conditionnelle pour structurer les constatations

La configuration d'Universal Parser n'est disponible que dans l'interface Pro, mais vous pouvez toujours importer des analyses à l'aide d'un Universal Parser via l'ancienne interface ou l'API.

## Étape 1 : Créer un nouvel Universal Parser

Vous pouvez créer un nouvel Universal Parser en cliquant sur le bouton « New Universal Parser » dans la barre de navigation, sous la section « Import », ou depuis le lien présent sur la page « Add Findings ».

![image](images/universal_parser.png)

Le premier écran vous demandera un fichier d'analyse et un nom de parseur.

![image](images/universal_parser_2.png)

Le fichier doit :

* Avoir une extension reconnue (voir les extensions de fichiers prises en charge ci-dessous)
* Contenir suffisamment d'objets de type constatation pour être représentatif de rapports réels, c'est-à-dire un fichier qui inclut des valeurs dans tous les champs facultatifs
* Ne pas dépasser environ 1 à 2 Mo — au-delà, l'analyse du fichier prendra généralement plus de temps, sans aucun bénéfice

Le nom du parseur sera utilisé lors de la création du Test_Type pour ce nouveau parseur. Vous retrouverez votre Universal Parser nouvellement créé dans la liste déroulante des types d'analyse de la page « Add Findings », sous un nom du type « Universal Parser - MyCustomParser ». Les noms de parseurs doivent être uniques afin d'éviter toute confusion lors du choix d'un type d'analyse pour les imports.

## Étape 2 : Mapper vos champs de Constatation

![image](images/universal_parser_3.png)

Après avoir téléversé un exemple de fichier d'analyse, sélectionné un nom de parseur et cliqué sur « Next », la page suivante vous permet de configurer la façon dont cet Universal Parser remplira les champs de constatation lors des imports effectués avec cette configuration. À droite, vous trouverez une sélection de champs de constatation DefectDojo (champs de sortie). Des menus déroulants à gauche de chaque champ de sortie vous permettent de sélectionner le ou les éléments (champs d'entrée) de la structure de votre fichier d'analyse à utiliser pour les remplir.

Exemple :

Si vous avez téléversé un fichier d'analyse au format JSON qui ressemble à ceci :

```
{
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345",
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "LOW",
            "CVE": "CVE-2025-54321",
            ...
        },
        ...

    ]
}
```

Vous verrez une représentation hiérarchique des champs uniques détectés à partir de la structure du fichier d'entrée, avec des icônes indiquant le type de chaque champ (si nous pouvons le déterminer). Vous pouvez alors sélectionner le champ d'entrée « title » dans le menu déroulant qui alimente le champ de sortie « Title », le champ d'entrée « description » peut être associé au champ de sortie « Description », et ainsi de suite.

Les noms des champs d'entrée n'ont pas besoin de correspondre aux noms des champs de sortie, et votre fichier d'analyse peut ne pas avoir d'équivalent pour tous les champs de sortie DefectDojo.

### Champs de constatation mappables

Le tableau ci-dessous répertorie tous les champs de constatation DefectDojo (champs de sortie) auxquels vous pouvez mapper un champ d'entrée. Votre fichier d'analyse n'aura pas nécessairement un équivalent pour chacun d'eux — ne mappez que ce qui est présent.

* **Requis** — ce champ de sortie doit avoir au moins un champ d'entrée mappé avant de pouvoir enregistrer le parseur.
* **Accepte plusieurs entrées** — ce champ de sortie peut être alimenté par plusieurs champs d'entrée. Lorsque vous en mappez plusieurs, chaque valeur est présentée sous un en-tête portant le nom de son champ d'entrée (voir [Champs à sélection multiple](#multi-select-fields)).

| Champ de sortie | Requis | Accepte plusieurs entrées | Description |
|---|:---:|:---:|---|
| Title | ✅ | | Brève description de la faille. |
| Severity | ✅ | | Le niveau de sévérité de cette faille (Critical, High, Medium, Low, Info). Par défaut, « Info » si inconnu. |
| Description | ✅ | ✅ | Informations plus longues et plus descriptives sur la faille. |
| Date | | | La date à laquelle la faille a été découverte. |
| CWE | | | Le numéro CWE associé à cette faille. |
| CVSS v3 Vector | | | Le vecteur Common Vulnerability Scoring System version 3 (CVSSv3) associé à cette faille. |
| CVSS v4 Vector | | | Le vecteur Common Vulnerability Scoring System version 4 (CVSSv4) associé à cette faille. |
| Mitigation | | ✅ | Texte décrivant la meilleure façon de corriger la faille. |
| Impact | | ✅ | Texte décrivant l'impact de cette faille sur les systèmes, produits, l'entreprise, etc. |
| References | | ✅ | La documentation externe disponible pour cette faille. |
| Severity Justification | | ✅ | Texte expliquant pourquoi une certaine sévérité a été associée à cette faille. |
| Steps to Reproduce | | ✅ | Texte décrivant les étapes à suivre pour reproduire la faille / le bug. |
| Component Name | | | Nom du composant affecté (nom de bibliothèque, partie d'un système, ...). |
| Component Version | | | Version du composant affecté. |
| File Path | | | Fichier(s) identifié(s) contenant la faille. |
| Line Number | | | Numéro de ligne source du vecteur d'attaque. |
| Active | | | Indique si cette faille est active ou non. Par défaut : true. |
| Verified | | | Indique si cette faille a été vérifiée manuellement par le testeur. Par défaut : false. |
| False Positive | | | Indique si cette faille a été jugée faux positif par le testeur. Par défaut : false. |
| Duplicate | | | Indique si cette faille est un doublon d'autres failles signalées. Par défaut : false. |
| EPSS Score | | | Score EPSS pour le CVE — la probabilité que la vulnérabilité soit exploitée dans les 30 prochains jours. La valeur doit être comprise entre 0,0 et 1,0. |
| EPSS Percentile | | | Percentile EPSS pour le CVE — combien de CVE sont notés au même niveau ou en dessous de celui-ci. La valeur doit être comprise entre 0,0 et 1,0. |
| Unique ID From Tool | | | ID technique de la vulnérabilité issu de l'outil source. Permet le suivi des vulnérabilités uniques. |
| Vuln ID from Tool | | | ID technique non unique issu de l'outil source, associé au type de vulnérabilité. |
| Tags | | | Étiquettes textuelles décrivant cette constatation. |
| Endpoints | | | Les hôtes/URL du produit exposés à cette faille. |
| Vulnerability IDs | | | Un ou plusieurs identifiants d'avis de vulnérabilité associés à cette constatation (le plus souvent, des CVE). |

> **Remarque :** dans l'exemple ci-dessus, un champ d'entrée `CVE` serait mappé au champ de sortie **Vulnerability IDs** — DefectDojo ne possède pas de champ de constatation littéralement nommé « CVE ».

### Champs requis
Les champs de sortie suivants nécessitent un mappage de champ d'entrée :

* Title
* Severity
* Description

### À propos des sévérités
Un Universal Parser accepte toute variation de casse des sévérités DefectDojo - « CRITICAL », « Critical », « cRiTiCaL », etc. - et l'applique à vos constatations. Toute valeur qui ne correspond à aucune sévérité DefectDojo sera remplacée par « Info ». Cela reflète le fonctionnement actuel des parseurs et des Connectors : les valeurs inconnues sont généralement mappées sur « Info ».

### Champs à sélection multiple
Certains champs de sortie acceptent plusieurs champs d'entrée. Si vous choisissez de sélectionner plusieurs champs d'entrée, nous fournirons la valeur de ce champ sous un en-tête portant le nom de ce champ d'entrée.

Exemple

`description`

Ceci a été extrait d'un champ appelé « description » dans le fichier d'entrée

`detailed_description`

Ceci a été extrait d'un champ appelé « detailed_description » dans le fichier d'entrée

## Étape 3 : Prévisualiser vos Constatations

Une fois que vous avez sélectionné vos mappages entre champs d'entrée et champs de sortie, vous pouvez cliquer sur le bouton « Next » pour voir un aperçu de ce à quoi ressembleront les Constatations de votre fichier d'entrée une fois importées dans DefectDojo avec la configuration choisie. Certains champs disposent d'un bouton « expand » à côté d'eux, qui permet de voir le rendu complet en MarkDown de ce à quoi ce champ ressemblera. Nous n'affichons un aperçu que des 25 premières Constatations de votre fichier d'entrée, mais vous pouvez également voir combien de constatations ont été détectées dans l'ensemble du fichier d'analyse.

Si les aperçus ne correspondent pas à ce que vous attendiez, vous pouvez cliquer sur le bouton « Back » pour ajuster les mappages. Une fois satisfait de votre configuration, cliquez sur le bouton « Submit » pour créer votre nouvel Universal Parser. Cette action n'effectue pas d'import automatiquement.

Une fois votre Universal Parser créé, vous serez redirigé vers la page « Add Findings », où vous pourrez téléverser et importer un fichier d'analyse correspondant à la structure du fichier d'exemple fourni à l'étape 1.

## Remarques supplémentaires sur la configuration d'Universal Parser

### Choisir les bons champs d'entrée

Chaque éditeur peut produire des formats de rapport d'analyse très différents, dont certains se rapprochent davantage du modèle de constatation de DefectDojo que d'autres. Nous offrons une flexibilité importante quant à ce que nous acceptons, mais nous devons imposer une certaine structure pour garantir que les constatations ne soient pas altérées lors de la conversion de l'entrée vers la sortie. Bien que nous puissions prendre en charge des champs d'entrée facultatifs, nous n'acceptons pas les champs « globaux », ni les champs qui apparaissent un nombre de fois différent du nombre d'objets de constatation.

#### Exemple

```
{
    "scan_type": "MyToolScan", // <- There is only one instance of this field, which doesn't match the number of findings
    "findings": [
        {
            "title": "Finding 1 Title",
            "description": "Finding 1 Description",
            "severity": "CRITICAL",
            "CVE": "CVE-2025-12345", // <- This optional field only appears in Finding 1 - that's okay!
            ...
        },
        {
            "title": "Finding 2 Title",
            "description": "Finding 2 Description",
            "severity": "CRITICAL",
            ...  // <- While there is no "CVE" field here, we can still query for it and simply default to a null value
        },
        ... 5 more findings ...
    ],
    "global_details": [
        {
            "nested_detail": "Global detail 1"
        },
        {
            "nested_detail": "Global detail 2" // <- The number of "global_details" objects (2) does not match the number of individual finding objects (7)
        }

    ]
}
```

## Après avoir enregistré un Universal Parser

Vous pouvez modifier le Test_Type associé à votre Universal Parser afin de modifier :
* S'il est « actif » ou non. S'il ne l'est pas, il n'apparaîtra pas comme option dans la liste déroulante « Scan Type » de la page « Add Findings »
* Si ses constatations doivent être marquées « static » ou « dynamic »
* Vous pouvez ajuster les codes de hachage de déduplication même outil et inter-outils, ainsi que les codes de hachage de réimport, pour votre Universal Parser dans « Enterprise Settings ». Par défaut, seuls les codes de hachage de déduplication même outil et de réimport sont renseignés, avec les valeurs requises Title, Severity et Description.

## Cycle de vie : création, désactivation, réactivation

Le cycle de vie d'un Universal Parser est **création uniquement**, sans modification ni suppression possible depuis l'interface. Une fois un parseur créé, la configuration de mappage des champs ne peut plus être modifiée, et le parseur lui-même ne peut pas être supprimé depuis l'interface — il s'agit d'un choix de conception, car les configurations d'Universal Parser sont liées à des enregistrements Test_Type susceptibles d'être référencés par des Constatations, des Tests et un historique d'import existants.

Ce que vous **pouvez** faire depuis l'interface :

* **Désactiver** un parseur pour le masquer de la liste déroulante « Scan Type » lors de l'import. Ouvrez **Import → Universal Parser** dans la barre latérale pour voir tous vos Universal Parsers, puis désactivez « Active ». (Vous pouvez également modifier le Test_Type sous-jacent et décocher « active ».) Les parseurs désactivés n'apparaissent plus comme option de type d'analyse sur la page **Add Findings**, mais les Tests déjà importés avec ce parseur ne sont pas affectés et continuent de fonctionner.
* **Réactiver** un parseur depuis le même écran en réactivant « Active ».
* **Modifier les champs du Test_Type** décrits dans la section ci-dessus (actif/inactif, static/dynamic, codes de hachage de déduplication).

### Flux de travail recommandé lorsque le format de rapport d'un scanner change

Étant donné que la configuration de mappage des champs est verrouillée une fois le parseur créé, le flux de travail standard pour gérer un changement de format dans le scanner sous-jacent consiste à **passer à un nouveau parseur** plutôt que d'essayer de modifier l'ancien :

1. **Créez un nouvel Universal Parser** à l'aide d'un échantillon du nouveau format de rapport (voir l'étape 1). Donnez-lui un nom distinct — par exemple en ajoutant `v2` ou une date au nom d'origine.
2. **Basculez les nouveaux imports** de votre pipeline CI/CD ou de votre flux de travail dans l'interface pour utiliser le type d'analyse du nouveau parseur.
3. **Désactivez l'ancien parseur** une fois que vous avez confirmé que le nouveau produit les constatations attendues. Les Tests déjà importés avec l'ancien parseur restent dans DefectDojo et peuvent toujours être triés ; seuls les nouveaux imports sont dirigés vers le nouveau parseur.

Si vous avez besoin qu'une configuration de parseur soit définitivement supprimée (par exemple parce qu'elle contient des noms de champs sensibles), contactez le [support DefectDojo](mailto:support@defectdojo.com).

## Remarque sur le mappage des sévérités

Universal Parser ne dispose **pas** d'un champ de mappage de sévérité configurable. La sévérité est mappée automatiquement selon les règles suivantes :

* Toute variation de casse d'une sévérité DefectDojo est acceptée — `CRITICAL`, `Critical`, `cRiTiCaL`, `critical` sont toutes mappées sur **Critical**. Il en va de même pour `High`, `Medium`, `Low` et `Info`.
* Toute valeur qui ne correspond à aucune des cinq sévérités de DefectDojo est mappée sur **Info**.

Ce comportement est identique pour tous les parseurs de DefectDojo (parseurs intégrés, Connectors et Universal Parsers).

Si un scanner que vous essayez d'ingérer utilise des libellés de sévérité qui ne correspondent pas à ceux de DefectDojo (par exemple « warning », « note », ou des scores CVSS numériques), Universal Parser mappera toutes ces valeurs non correspondantes sur Info. Si vous avez besoin d'un mappage différent, la meilleure solution de contournement actuelle consiste à **transformer les valeurs de sévérité en amont** — par exemple dans votre pipeline CI, avant le téléversement — afin que les valeurs reçues par DefectDojo correspondent déjà à l'un des cinq noms de sévérité DefectDojo.
