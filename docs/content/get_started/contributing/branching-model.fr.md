---
title: Branches et versions Open Source
description: Comment nous créons les versions
draft: false
weight: 3
audience: opensource
aliases:
- /fr/en/open_source/contributing/branching-model
---

## Versions régulières

L'équipe DefectDojo vise à maintenir la cadence suivante :

- Versions mineures : au moins une fois par mois, le premier lundi du mois.
- Correctifs/Bugfix : versions chaque semaine, le lundi.
- Versions de sécurité : réalisées en dehors de notre cadence habituelle, selon la gravité.

Les GitHub Actions font foi. Les versions sont semi-automatisées. Les étapes d'une version régulière sont les suivantes :
1. Créer la branche de version à partir de `dev` ou `bugfix` et préparer une PR vers `master` ([détails](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> Un mainteneur vérifie et fusionne manuellement la PR
1. Créer le tag, publier la version brouillon (draft release) et effectuer le build+push Docker ([détails](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> Un mainteneur retravaille les notes du release-drafter et publie la version
1. Une PR pour fusionner `master` vers `dev` et `bugfix` est créée afin de réaligner les branches ([détails](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## Versions de sécurité
Les PR liées à des problèmes de sécurité sont traitées via des [avis de sécurité](https://github.com/DefectDojo/django-DefectDojo/security/advisories) qui permettent de travailler en privé sur le code sans divulguer prématurément les vulnérabilités.

## Modèle de version et de correctif d'urgence

Les diagrammes sont créés avec [plantUML](https://plantuml.com). Vous trouverez un éditeur web pour PlantUML à l'adresse https://www.planttext.com.



<!-- PlantUML Schema -->
<div hidden>
```
@startuml

participant "Dev Branch" as dev #LightBlue
participant "BugFix Branch" as bugfix #LightGreen
participant "Release Branch" as release #LightGoldenRodYellow
participant "Master Branch" as master #LightSalmon

== Minor Release (Monthly) ==

dev -> release: Create branch "release/2.x.0"
release -> master: Merge
note right: Official Release\n - Tag 2.x.0\n - Push 2.x.0 to DockerHub
master --> bugfix: Merge master into bugfix to realign
master --> dev: Merge master back into dev

== Patch/BugFix Release (Weekly) ==

bugfix -> release: Create branch "release/2.x.y"
release -> master: Merge
note right: Official Release\n - Tag 2.x.y\n - Push 2.x.y to DockerHub
master -> bugfix: Merge master back into bugfix to realign
master --> dev: Merge master into dev to realign

== Security Release (As Needed) ==

master -> release: Create branch "release/2.x.y"
release -> master: Merge
note right: Official Release\n - Tag 2.x.y\n - Push 2.x.y to DockerHub
master --> bugfix: Merge master into bugfix to realign
master --> dev: Merge master into dev to realign

@enduml
```
</div>
