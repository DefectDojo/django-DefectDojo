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

Tutte le release partono dal branch `dev`. Il team di DefectDojo punta a mantenere il seguente ritmo:

- Release minori: almeno una volta al mese, il primo lunedì del mese.
- Patch: release ogni settimana di lunedì.
- Release di sicurezza: possono essere eseguite al di fuori del nostro ritmo regolare, a seconda della gravità. Anche queste partono da `dev`.

Non esiste un branch separato per le correzioni di bug né un branch di hotfix da `master`. Ogni pull request, correzione o funzionalità, punta a `dev`.

GitHub Actions è la fonte autorevole. Le release sono semi-automatizzate. I passaggi per ogni release sono:
1. Crea il branch di release da `dev` e prepara una PR verso `master` ([dettagli](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-1-create-pr.yml))
--> Un maintainer verifica e unisce manualmente la PR
1. Tag, creazione della release in bozza e build+push Docker ([dettagli](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-2-tag-docker-push.yml))
--> Un maintainer rifinisce le note del release-drafter e pubblica la release
1. Viene creata una PR per unire `master` di nuovo in `dev`, per riallineare i branch ([dettagli](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-3-master-into-dev.yml))

## Release di sicurezza
Le PR relative a problemi di sicurezza vengono gestite tramite [security advisory](https://github.com/DefectDojo/django-DefectDojo/security/advisories), che offrono un modo per lavorare privatamente sul codice senza divulgare prematuramente le vulnerabilità.

## Modello di release

Diagrammi creati con [plantUML](https://plantuml.com). Trovi un editor web per PlantUML su https://www.planttext.com.



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
