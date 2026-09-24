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

Toutes les versions sont issues de la branche `dev`. L'équipe DefectDojo vise à maintenir la cadence suivante :

- Versions mineures : au moins une fois par mois, le premier lundi du mois.
- Correctifs : versions chaque semaine, le lundi.
- Versions de sécurité : peuvent être réalisées en dehors de notre cadence habituelle, selon la gravité. Elles sont aussi issues de `dev`.

Il n'y a pas de branche séparée pour les corrections de bugs, ni de branche de correctif d'urgence à partir de `master`. Toute PR, correction ou fonctionnalité, cible `dev`.

Les GitHub Actions font foi. Les versions sont semi-automatisées. Les étapes de chaque version sont les suivantes :
1. Créer la branche de version à partir de `dev` et préparer une PR vers `master` ([détails](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-1-create-pr.yml))
--> Un mainteneur vérifie et fusionne manuellement la PR
1. Créer le tag, publier la version brouillon (draft release) et effectuer le build+push Docker ([détails](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-2-tag-docker-push.yml))
--> Un mainteneur retravaille les notes du release-drafter et publie la version
1. Une PR pour fusionner `master` vers `dev` est créée afin de réaligner les branches ([détails](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-3-master-into-dev.yml))

## Versions de sécurité
Les PR liées à des problèmes de sécurité sont traitées via des [avis de sécurité](https://github.com/DefectDojo/django-DefectDojo/security/advisories) qui permettent de travailler en privé sur le code sans divulguer prématurément les vulnérabilités.

## Modèle de version

Les diagrammes sont créés avec [plantUML](https://plantuml.com). Vous trouverez un éditeur web pour PlantUML à l'adresse https://www.planttext.com.



<!-- PlantUML Schema -->
<div hidden>
```
@startuml

participant "Dev Branch" as dev #LightBlue
participant "Release Branch" as release #LightGoldenRodYellow
participant "Master Branch" as master #LightSalmon

== Minor Release (Monthly) ==

dev -> release: Create branch "release/2.x.0"
release -> master: Merge
note right: Official Release\n - Tag 2.x.0\n - Push 2.x.0 to DockerHub
master --> dev: Merge master back into dev

== Patch Release (Weekly) ==

dev -> release: Create branch "release/2.x.y"
release -> master: Merge
note right: Official Release\n - Tag 2.x.y\n - Push 2.x.y to DockerHub
master --> dev: Merge master back into dev

@enduml
```
</div>
