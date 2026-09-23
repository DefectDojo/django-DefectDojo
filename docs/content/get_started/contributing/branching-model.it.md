---
title: Branching e Release Open-Source
description: Come creiamo le release
draft: false
weight: 3
audience: opensource
aliases:
- /it/en/open_source/contributing/branching-model
---

## Release regolari

Il team di DefectDojo punta a mantenere il seguente ritmo:

- Release minori: almeno una volta al mese, il primo lunedì del mese.
- Patch/Bugfix: release ogni settimana di lunedì.
- Release di sicurezza: verranno eseguite al di fuori del nostro ritmo regolare, a seconda della gravità.

GitHub Actions è la fonte autorevole. Le release sono semi-automatizzate. I passaggi per una release regolare sono:
1. Crea il branch di release da `dev` o `bugfix` e prepara una PR verso `master` ([dettagli](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> Un maintainer verifica e unisce manualmente la PR
1. Tag, creazione della release in bozza e build+push Docker ([dettagli](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> Un maintainer rifinisce le note del release-drafter e pubblica la release
1. Viene creata una PR per unire `master` di nuovo in `dev` e `bugfix`, per riallineare i branch ([dettagli](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## Release di sicurezza
Le PR relative a problemi di sicurezza vengono gestite tramite [security advisory](https://github.com/DefectDojo/django-DefectDojo/security/advisories), che offrono un modo per lavorare privatamente sul codice senza divulgare prematuramente le vulnerabilità.

## Modello di release e hotfix

Diagrammi creati con [plantUML](https://plantuml.com). Trovi un editor web per PlantUML su https://www.planttext.com.



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
