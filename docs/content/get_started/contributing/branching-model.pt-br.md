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

Todos os releases saem do branch `dev`. A equipe do DefectDojo busca manter a seguinte cadência:

- Releases menores (minor): pelo menos uma vez por mês, na primeira segunda-feira do mês.
- Patch: releases toda semana, às segundas-feiras.
- Releases de segurança: podem ser realizadas fora da nossa cadência regular, dependendo da severidade. Elas também saem de `dev`.

Não existe um branch separado para correções de bugs nem um branch de hotfix a partir de `master`. Todo pull request, seja correção ou funcionalidade, é direcionado a `dev`.

As GitHub Actions são a fonte da verdade. Os releases são semiautomatizados. As etapas de cada release são:
1. Criar o branch de release a partir de `dev` e preparar um PR contra `master` ([detalhes](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-1-create-pr.yml))
--> Um mantenedor verifica e faz o merge manual do PR
1. Criar a tag, emitir o draft release e fazer o build+push do docker ([detalhes](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-2-tag-docker-push.yml))
--> Um mantenedor ajusta as notas do release-drafter e publica o release
1. É criado um PR para fazer o merge de `master` de volta para `dev`, realinhando os branches ([detalhes](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-3-master-into-dev.yml))

## Releases de segurança
PRs relacionados a questões de segurança são feitos por meio de [security advisories](https://github.com/DefectDojo/django-DefectDojo/security/advisories), que oferecem uma forma de trabalhar de modo privado no código sem divulgar prematuramente as vulnerabilidades.

## Modelo de release

Diagramas criados com [plantUML](https://plantuml.com). Encontre um editor web para PlantUML em https://www.planttext.com.



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
