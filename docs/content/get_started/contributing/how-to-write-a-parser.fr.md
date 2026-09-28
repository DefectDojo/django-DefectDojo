---
title: Contribuer aux parsers
description: Comment contribuer aux parsers
draft: false
weight: 1
audience: opensource
aliases:
- /fr/en/open_source/contributing/how-to-write-a-parser
---

Toutes les commandes supposent que vous vous trouvez à la racine du dépôt cloné django-DefectDojo.

## Prérequis

- Vous avez forké https://github.com/DefectDojo/django-DefectDojo et cloné le dépôt en local.
- Basculez sur `dev` et assurez-vous d'être à jour avec les derniers changements.
- Il est conseillé de créer une branche dédiée à votre développement, telle que `git checkout -b parser-name`.

Le plus simple est d'utiliser le déploiement docker compose, car il offre une capacité de rechargement à chaud pour uWSGI.
Configurez votre environnement pour utiliser l'environnement dev :

`$ docker/setEnv.sh dev`

Consultez [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) pour plus de détails.

### Images Docker

Vous voudrez construire vos images docker en local, et éventuellement transmettre l'`uid` de votre utilisateur local afin de pouvoir écrire dans l'image (pratique pour les fichiers de migration de base de données). En supposant que l'`uid` de votre utilisateur soit `1000` :

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## Quels fichiers devez-vous modifier ?

| Fichier                                          | Objet
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | Fichier vide pour l'initialisation de la classe
|`dojo/tools/<parser_dir>/parser.py`            | Le cœur du sujet. C'est ici que vous écrivez votre parser proprement dit. Le nom de la classe doit être le nom du module Python sans underscores, suivi de `Parser`. **Exemple :** quand le nom du module Python est `dependency_check`, le nom de la classe doit être `DependencyCheckParser`
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | Fichiers d'exemple contenant des données significatives pour les tests unitaires. L'ensemble minimal.
|`unittests/tools/test_<parser_name>_parser.py` | Tests unitaires du parser.
|`dojo/settings/settings.dist.py`               | Si vous souhaitez utiliser un algorithme de déduplication moderne basé sur un hashcode
|`docs/content/supported_tools/<file/api>/<parser_file>.md` | Documentation : quel format de fichier est requis et comment l'obtenir


## Contrat de la factory

Les parsers sont chargés dynamiquement selon un patron de conception factory. Pour que votre parser soit chargé et fonctionne correctement, vous devez respecter ce contrat.

1. votre parser **DOIT** se trouver dans un sous-module du module `dojo.tools`
   - ex : module `dojo.tools.my_tool.parser`
2. votre parser **DOIT** être une classe de ce sous-module.
   - ex : `dojo.tools.my_tool.parser.MyToolParser`
3. Le nom de cette classe **DOIT** être le nom du module Python sans underscores et avec le suffixe `Parser`.
   - ex : `dojo.tools.my_tool.parser.MyToolParser`
4. Cette classe **DOIT** avoir un constructeur vide ou aucun constructeur
5. Cette classe **DOIT** implémenter 4 méthodes :
   1. `def get_scan_types(self)` Cette fonction retourne une liste de tous les *scan_type* pris en charge par votre parser. Ces identifiants sont utilisés en interne. Votre parser peut prendre en charge plusieurs *scan_type*. Par exemple, certains parsers utilisent des identifiants différents pour modifier le comportement du parser (agrégation, filtrage, etc.)
   2. `def get_label_for_scan_types(self, scan_type):` Cette fonction retourne une chaîne utilisée pour fournir du texte dans l'UI (libellé court)
   3. `def get_description_for_scan_types(self, scan_type):` Cette fonction retourne une chaîne utilisée pour fournir du texte dans l'UI (description longue)
   4. `def get_findings(self, file, test)` Cette fonction retourne une liste de findings
6. Si votre parser a plus d'un scan_type (pour le mode détaillé) vous **DEVEZ** implémenter la méthode `def set_mode(self, mode)`
7. L'instance du parser est réutilisée pour tous les imports effectués pour ce scan_type ; ne stockez donc aucune donnée au niveau de la classe

Exemple :

```Python

class MyToolParser(object):
    def get_scan_types(self):
        return ["My Tool Scan", "My Tool Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        if scan_type == "My Tool Scan":
            return "My Tool XML Scan aggregated by ..."
        else:
            return "My Tool XML Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_findings(self, file, test):
        <...>

```

## Parsers API

DefectDojo dispose d'un nombre limité de parsers API. Bien que nous ne supprimions pas ces connecteurs, l'ajout de connecteurs API s'est avéré problématique, et nous ne pouvons donc pas accepter de nouveaux parsers / connecteurs API de la part de la communauté pour le moment, pour des raisons de supportabilité. Pour maintenir un connecteur API de haute qualité, il est nécessaire de disposer d'une licence pour l'outil. Obtenir cette licence nécessite un partenariat avec l'auteur ou l'éditeur. Nous sommes proches d'annoncer un nouveau programme visant à répondre à ce besoin et à apporter des connecteurs API à DefectDojo.

## Générateur de template

Utilisez le parser [template](https://github.com/DefectDojo/cookiecutter-scanner-parser) pour générer rapidement les fichiers requis. Pour commencer, vous devrez installer [cookiecutter](https://github.com/cookiecutter/cookiecutter).

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

Générez ensuite votre parser de scanner depuis la racine de django-DefectDojo :

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

Lisez [plus d'informations](https://github.com/DefectDojo/cookiecutter-scanner-parser) sur les variables de configuration du template.

## Points d'attention

Voici une liste de points à considérer pour rendre le parser robuste, aussi bien dans les cas courants que dans les cas limites.

### Ne parsez pas les URL à la main

Nous utilisons 2 modules pour gérer les endpoints :
 - `hyperlink`
 - `dojo.models`, avec une classe spécifique pour gérer le traitement des URL en vue de créer des endpoints, `Endpoint`.

Tous les parsers existants utilisent le même code pour parser les URL et créer des endpoints.
Utiliser `Endpoint.from_uri()` est le meilleur moyen de créer des endpoints.
Si vous avez vraiment besoin de parser une URL, utilisez le module `hyperlink`.

Bon exemple :

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

Très mauvais exemple :

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### Utilisez les bonnes bibliothèques pour parser l'information
Différents formats de fichiers sont traités via des bibliothèques. Afin de garder DefectDojo léger et de ne pas étendre la surface d'attaque, limitez au minimum le nombre de bibliothèques utilisées et prenez exemple sur d'autres parsers.

#### defusedXML plutôt que lxml
Comme XML est par défaut un format non sécurisé, les informations extraites des diverses sorties xml doivent être analysées de manière sécurisée. Lors d'une évaluation, nous avons déterminé que defusedXML est la bibliothèque que nous utiliserons à l'avenir pour parser les fichiers xml dans les parsers, car elle est jugée plus sûre. Nous n'accepterons donc que les PR utilisant la bibliothèque defusedxml.

### Tous les attributs ne sont pas obligatoires

Les parsers peuvent avoir de nombreux champs, dont beaucoup peuvent être optionnels.
Il est préférable de ne pas définir un attribut si vous n'avez pas de donnée, plutôt que de le remplir avec des valeurs comme `NA`, `No data`, etc.

Consultez la classe `dojo.models.Finding`

### Des données peuvent manquer dans le rapport source

Assurez-vous toujours d'inclure des vérifications pour éviter d'éventuelles erreurs `KeyError` (par exemple, un champ qui n'existe pas), pour les champs dont vous n'êtes pas absolument certain qu'ils seront toujours présents dans le fichier importé. Ces erreurs se traduisent par des erreurs 500, ce qui n'est pas idéal.

Bon exemple :

```python
   if "mykey" in data:
       finding.cwe = data["mykey"]
```

```python
   finding.cwe = data.get("mykey", 123)
```

```python
   some_list = data.get("key_of_the_list") or []
```

Ce dernier exemple protège contre les cas où `key_of_the_list` est présent, mais vaut `null`.


### Parsing des vecteurs CVSS

Les données peuvent contenir des vecteurs ou des scores `CVSS`. Defect Dojo utilise le module `cvss` fourni par RedHat Security.
Il existe également une méthode utilitaire pour valider le vecteur et en extraire le score de base et la sévérité.

```python
    from dojo.utils import parse_cvss_data

    cvss_vector = <get CVSS3 or CVSS4 vector from the report>
    cvss_data = parse_cvss_data(cvss_vector)
    if cvss_data:
        finding.severity = cvss_data["severity"]
        finding.cvssv3 = cvss_data["cvssv3"]
        finding.cvssv4 = cvss_data["cvssv4"]
        # we don't set any score fields as those will be overwritten by Defect Dojo
```
Toutes les valeurs n'ont pas besoin d'être utilisées, car les rapports de scan fournissent généralement leur propre valeur pour `severity`.
Et parfois aussi pour `cvss_score`. Defect Dojo n'écrasera jamais `cvss3_score` ni `cvss4_score`.
Si aucun score n'est défini, Defect Dojo utilisera la bibliothèque `cvss` pour calculer le score.
La réponse contient également la version majeure détectée du vecteur CVSS dans `cvss_data["major_version"]`.


Si vous avez besoin d'un traitement plus manuel, vous pouvez parser directement le vecteur `CVSS`.

Exemple d'utilisation :

```python
    import cvss.parser
    from cvss import CVSS2, CVSS3, CVSS4

    # TEMPORARY: Use Defect Dojo implementation of `parse_cvss_from_text` white waiting for https://github.com/RedHatProductSecurity/cvss/pull/75 to be released
    vectors = cvss.parser.parse_cvss_from_text("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
        if len(vectors) > 0 and type(vectors[0]) is CVSS3:
            print(vectors[0].severities())  # this is the 3 severities

            cvssv3 = vectors[0].clean_vector()
            severity = vectors[0].severities()[0]
            vectors[0].compute_base_score()
            cvssv3_score = vectors[0].scores()[0]
            finding.severity = severity
            finding.cvssv3_score = cvssv3_score
```

Ne faites pas quelque chose comme ceci :

```
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss < 9:
                return "High"
            elif cvss >= 9:
                return "Critical"
            else:
                return "Informational"
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"
```

## Algorithme de déduplication

Par défaut, un nouveau parser utilise l'algorithme de déduplication « legacy », documenté dans [À propos de la déduplication](/triage_findings/finding_deduplication/about_deduplication/)

Merci d'utiliser un algorithme de déduplication prédéfini lorsque cela est applicable. Lorsque vous utilisez les champs `unique_id_from_tool` ou `vuln_id_from_tool` dans la configuration du hash code, il est important que ceux-ci soient uniques pour le finding et constants dans le temps d'un scan à l'autre. Si ce n'est pas le cas, ces valeurs peuvent tout de même être utiles à définir sur le modèle de finding sans les utiliser pour la déduplication.
Les valeurs doivent provenir directement du rapport et ne doivent pas être calculées en interne par le parser.

## Tests unitaires

Chaque parser doit avoir des tests unitaires, au minimum pour tester 0 vuln, 1 vuln et plusieurs vulns. Vous pouvez regarder comment d'autres parsers les ont mis en place pour vous en inspirer. Plus les tests sont de qualité, mieux c'est.

Il est important d'ajouter des vérifications sur les attributs des findings.
Par ex. :

```python
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("test title", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(False, finding.duplicate)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("CVE-2020-36234", finding.vulnerability_ids[0])
            self.assertEqual(261, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
            self.assertIn("security", finding.tags)
            self.assertIn("network", finding.tags)
            self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
            self.assertEqual("TEST1", finding.vuln_id_from_tool)
```

### Utilisez with pour ouvrir les fichiers d'exemple

Afin de garantir que les descripteurs de fichiers sont correctement fermés, veuillez utiliser le motif with pour ouvrir les fichiers.
Au lieu de :
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

utilisez :
```python
    with open("path_to_file.json") as testfile:
        ...
```

Cela garantit que le fichier est fermé à la fin du bloc with, même si une exception survient à un moment donné dans le bloc.

### Base de données de test

Django utilise une base de données de test séparée pour l'exécution des tests unitaires, appelée `test_defectdojo`. Elle est automatiquement créée et initialisée avec un jeu de données de test de base.

### Exécuter vos tests

Cette commande locale lancera le test unitaire de votre nouveau parser

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

ou comme ceci :

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

Exemple pour le parser aqua :

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_aqua_parser.TestAquaParser -v2'
{{< /highlight >}}

ou comme ceci :

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_aqua_parser.TestAquaParser
{{< /highlight >}}

Si vous souhaitez exécuter tous les tests unitaires des parsers, il suffit d'exécuter `$ docker-compose exec uwsgi bash -c 'python manage.py test -p "test_*_parser.py" -v2'`

### Validation des endpoints

Certains types de parsers créent une liste d'endpoints vulnérables (ils sont stockés dans `finding.unsaved_endpoints`). DefectDojo exige de stocker les endpoints dans un format spécifique (conforme aux RFC). Les endpoints qui ne respectent pas ce format peuvent être stockés, mais ils seront marqués comme cassés (drapeau rouge 🚩dans l'UI). Pour vous assurer que votre parser stocke les endpoints dans le bon format, exécutez la fonction `.clean()` pour tous les endpoints dans les tests unitaires

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### Tests des parsers API

Il ne faut pas tester uniquement le parser, mais aussi l'importer.
La méthode `patch` de `unittest.mock` est généralement utile pour simuler des réponses API.
Il est fortement recommandé de l'utiliser.

## Autres fichiers pouvant être concernés

### Modification du modèle

Dans le cas où vous devriez modifier le modèle, par exemple pour augmenter la taille d'une colonne de base de données afin d'accueillir une chaîne de données plus longue à enregistrer
* Modifiez ce dont vous avez besoin dans `dojo/models.py`
* Créez un nouveau fichier de migration dans dojo/db_migrations en exécutant la commande suivante, et incluez-le dans votre PR

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### Accepter un type de fichier différent à téléverser

Si vous souhaitez pouvoir accepter un nouveau type de fichier pour votre parser, regardez dans `dojo/forms.py` aux alentours de la ligne 436 (au moment de la rédaction) ou repérez les 2 endroits (pour l'import et le ré-import) où vous trouvez la chaîne `attrs={"accept":`.

Formats actuellement acceptés : .xml, .csv, .nessus, .json, .html, .js, .zip.

### Un besoin d'aller au-delà du seul parser.py

Bien sûr, rien ne vous empêche d'avoir plus de fichiers que le seul fichier `parser.py`. C'est du python :-)

## Exemples de pull requests

Si vous souhaitez consulter d'anciens parsers qui font désormais partie de DefectDojo, jetez un œil à https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed

## Mettre à jour la documentation de la page d'import

Merci d'ajouter un nouveau fichier .md dans [`docs/content/en/connecting_your_tools/parsers`] avec les détails de votre nouveau parser.  Incluez les rubriques de contenu suivantes :

* Type(s) de fichier acceptable(s) - merci d'inclure comment générer ce type de fichier à partir de l'outil concerné, car certains outils ont plusieurs méthodes ou nécessitent des commandes spécifiques.
* Un exemple de bloc de test unitaire, le cas échéant.
* Un lien vers le dossier des tests unitaires correspondant, afin que les utilisateurs puissent y accéder rapidement depuis la documentation.
* Un lien vers le scanner lui-même - (par exemple un lien GitHub ou éditeur)

Voici un exemple de page de documentation de parser complète : [https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md)
