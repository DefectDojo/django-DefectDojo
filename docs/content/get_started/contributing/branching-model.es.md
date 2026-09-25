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

Todas las versiones salen de la rama `dev`. El equipo de DefectDojo se propone mantener la siguiente cadencia:

- Versiones menores: al menos una vez al mes, el primer lunes del mes.
- Parches: versiones cada semana, los lunes.
- Versiones de seguridad: pueden realizarse fuera de nuestra cadencia habitual según la gravedad. También salen de `dev`.

No hay una rama separada para correcciones de errores ni una rama de hotfix a partir de `master`. Todo pull request, sea una corrección o una funcionalidad, se dirige a `dev`.

Las GitHub Actions son la fuente de verdad. Las versiones están semiautomatizadas. Los pasos para cada versión son:
1. Crear la rama de versión a partir de `dev` y preparar un PR contra `master` ([detalles](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-1-create-pr.yml))
--> Un mantenedor verifica y fusiona manualmente el PR
1. Etiquetar, emitir un borrador de versión y compilar+publicar la imagen docker ([detalles](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-2-tag-docker-push.yml))
--> Un mantenedor pule las notas de release-drafter y publica la versión
1. Se crea un PR para fusionar `master` de nuevo en `dev` con el fin de realinear las ramas ([detalles](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-3-master-into-dev.yml))

## Versiones de seguridad
Los PR relacionados con problemas de seguridad se gestionan mediante [avisos de seguridad](https://github.com/DefectDojo/django-DefectDojo/security/advisories) que ofrecen una forma de trabajar en el código de forma privada sin divulgar prematuramente las vulnerabilidades.

## Modelo de versiones

Diagramas creados con [plantUML](https://plantuml.com). Encuentre un editor web para PlantUML en https://www.planttext.com.



<!-- PlantUML Schema -->
<div hidden>
```
@startuml

participant "Dev Branch" as dev #LightBlue
participant "Release Branch" as release #LightGoldenRodYellow
participant "Master Branch" as master #LightSalmon

== Minor Release (Monthly) ==

dev -> release: Create branch "release/merge-dev-into-master-2.x.0"
release -> master: Merge
note right: Official Release\n - Tag 2.x.0\n - Push 2.x.0 to DockerHub
master --> dev: Merge master back into dev

== Patch Release (Weekly) ==

dev -> release: Create branch "release/merge-dev-into-master-2.x.y"
release -> master: Merge
note right: Official Release\n - Tag 2.x.y\n - Push 2.x.y to DockerHub
master --> dev: Merge master back into dev

@enduml
```
</div>
