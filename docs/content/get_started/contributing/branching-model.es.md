---
title: Ramas y versiones de código abierto
description: Cómo creamos las versiones
draft: false
weight: 3
audience: opensource
aliases:
- /es/en/open_source/contributing/branching-model
---

## Versiones regulares

El equipo de DefectDojo se propone mantener la siguiente cadencia:

- Versiones menores: al menos una vez al mes, el primer lunes del mes.
- Parche/Corrección de errores: versiones cada semana, los lunes.
- Versiones de seguridad: se realizarán fuera de nuestra cadencia habitual según la gravedad.

Las GitHub Actions son la fuente de verdad. Las versiones están semiautomatizadas. Los pasos para una versión regular son:
1. Crear la rama de versión a partir de `dev` o `bugfix` y preparar un PR contra `master` ([detalles](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> Un mantenedor verifica y fusiona manualmente el PR
1. Etiquetar, emitir un borrador de versión y compilar+publicar la imagen docker ([detalles](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> Un mantenedor pule las notas de release-drafter y publica la versión
1. Se crea un PR para fusionar `master` de nuevo en `dev` y `bugfix` con el fin de realinear las ramas ([detalles](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## Versiones de seguridad
Los PR relacionados con problemas de seguridad se gestionan mediante [avisos de seguridad](https://github.com/DefectDojo/django-DefectDojo/security/advisories) que ofrecen una forma de trabajar en el código de forma privada sin divulgar prematuramente las vulnerabilidades.

## Modelo de versión y hotfix

Diagramas creados con [plantUML](https://plantuml.com). Encuentre un editor web para PlantUML en https://www.planttext.com.



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
