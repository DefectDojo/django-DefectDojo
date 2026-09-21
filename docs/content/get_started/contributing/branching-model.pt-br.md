---
title: Branching e Releases do Open-Source
description: Como criamos releases
draft: false
weight: 3
audience: opensource
aliases:
- /pt-br/en/open_source/contributing/branching-model
---

## Releases regulares

A equipe do DefectDojo busca manter a seguinte cadência:

- Releases menores (minor): pelo menos uma vez por mês, na primeira segunda-feira do mês.
- Patch/Bugfix: releases toda semana, às segundas-feiras.
- Releases de segurança: serão realizadas fora da nossa cadência regular, dependendo da severidade.

As GitHub Actions são a fonte da verdade. Os releases são semiautomatizados. As etapas de um release regular são:
1. Criar o branch de release a partir de `dev` ou `bugfix` e preparar um PR contra `master` ([detalhes](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> Um mantenedor verifica e faz o merge manual do PR
1. Criar a tag, emitir o draft release e fazer o build+push do docker ([detalhes](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> Um mantenedor ajusta as notas do release-drafter e publica o release
1. É criado um PR para fazer o merge de `master` de volta para `dev` e `bugfix`, realinhando os branches ([detalhes](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## Releases de segurança
PRs relacionados a questões de segurança são feitos por meio de [security advisories](https://github.com/DefectDojo/django-DefectDojo/security/advisories), que oferecem uma forma de trabalhar de modo privado no código sem divulgar prematuramente as vulnerabilidades.

## Modelo de release e hotfix

Diagramas criados com [plantUML](https://plantuml.com). Encontre um editor web para PlantUML em https://www.planttext.com.



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
