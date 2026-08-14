---
title: Open-Source-Branching und Releases
description: Wie wir Releases erstellen
draft: false
weight: 3
audience: opensource
aliases:
- /de/en/open_source/contributing/branching-model
---

## Reguläre Releases

Das DefectDojo-Team strebt folgenden Rhythmus an:

- Minor-Releases: mindestens einmal pro Monat, am ersten Montag des Monats.
- Patch/Bugfix: Releases jede Woche am Montag.
- Security-Releases: erfolgen je nach Schweregrad außerhalb unseres regulären Rhythmus.

GitHub Actions sind die maßgebliche Quelle. Die Releases sind teilautomatisiert. Die Schritte für ein reguläres Release sind:
1. Den Release-Branch aus `dev` oder `bugfix` erstellen und einen PR gegen `master` vorbereiten ([Details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> Ein Maintainer prüft den PR und merged ihn manuell
1. Tag setzen, Draft-Release anlegen und Docker-Image bauen und pushen ([Details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> Ein Maintainer überarbeitet die Notizen des Release-Drafters und veröffentlicht das Release
1. Es wird ein PR erstellt, der `master` zurück in `dev` und `bugfix` merged, um die Branches wieder abzugleichen ([Details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## Security-Releases
PRs zu Sicherheitsproblemen werden über [Security Advisories](https://github.com/DefectDojo/django-DefectDojo/security/advisories) abgewickelt. Diese bieten die Möglichkeit, nicht öffentlich am Code zu arbeiten, ohne Schwachstellen vorzeitig offenzulegen.

## Release- und Hotfix-Modell

Die Diagramme wurden mit [plantUML](https://plantuml.com) erstellt. Einen webbasierten Editor für PlantUML finden Sie unter https://www.planttext.com.



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
