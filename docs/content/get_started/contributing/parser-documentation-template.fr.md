---
title: Modèle de documentation de parser
toc_hide: true
weight: 2
audience: opensource
aliases:
- /fr/en/open_source/contributing/parser-documentation-template
---

Ce modèle est conçu pour documenter un parser nouveau ou existant. N'hésitez pas à l'améliorer avec toute information supplémentaire susceptible d'aider vos collègues professionnels de la sécurité.

* Copiez ce fichier .md et ajoutez-le dans `/docs/content/supported_tools/file` du dépôt GitHub.
* Mettez à jour le titre pour qu'il corresponde au nom de votre parser nouveau ou existant.
* Remplissez toutes les sections listées ci-dessous. Merci de supprimer les instructions ou exemples présents dans chaque section.

### Types de fichiers
_Précisez tous les types de fichiers acceptés par votre parser (par ex., CSV, JSON, XML)._
_Incluez les instructions pour créer ou exporter le format de fichier accepté depuis l'outil de sécurité concerné._

### Total des champs dans [File Format]
Nombre total de champs :  _Nombre total de champs contenus dans le fichier d'export de l'outil de sécurité._
Nombre total de champs parsés :  _Nombre total de champs parsés dans le finding DefectDojo._
Nombre total de champs NON parsés : _Nombre total de champs NON parsés dans le finding DefectDojo._

_En utilisant le format ci-dessous, fournissez une brève description de chaque champ et de la façon dont il correspond au modèle de données de DefectDojo._
_Incluez tous les champs trouvés dans le fichier d'export de l'outil de sécurité, dans leur ordre d'apparition, en indiquant les champs qui ne sont pas parsés._

Champs dans l'ordre d'apparition :
1. **Champ 1** - _Description de la façon dont ce champ est mappé (par ex., mappé vers le titre du finding, l'hôte de l'endpoint.)_
2. **Champ 2** - _Description de la façon dont ce champ est mappé / non mappé._
3. **Champ 3** - _Description de la façon dont ce champ est mappé / non mappé._
4. **Champ 4** - _Description de la façon dont ce champ est mappé / non mappé._
_(continuez pour chaque champ du fichier.)_

### Détails du mappage des champs
_Pour chaque finding créé, incluez des détails sur la façon dont le parser analyse les données spécifiques. Par exemple :_
- Comment les endpoints sont créés (par ex., en combinant les champs IP, Domain, Port et Protocol).
- Comment les occurrences sont gérées (par ex., `nb_occurences` par défaut fixé à 1, incrémenté pour les doublons).
- Comment la déduplication est gérée (par ex., à l'aide d'un hash de severity + title + description).
- Décrit la sévérité par défaut si aucun mappage ne correspond.

### Données de scan d'exemple ou tests unitaires
_Ajoutez un lien vers le dossier des tests unitaires ou des données de scan d'exemple dans le dépôt GitHub. Par exemple :_
- [Dossier de données de scan d'exemple](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/[parser-name])

### Lien vers l'outil
_Fournissez un lien vers le scanner ou l'outil lui-même (par ex., dépôt GitHub, site de l'éditeur ou documentation). Par exemple :_
- [Nom de l'outil](https://www.example.com/)
