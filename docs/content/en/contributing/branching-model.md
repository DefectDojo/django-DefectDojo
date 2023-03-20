---
title: "Branching model"
description: "How we create releases"
draft: false
weight: 3
---

## Regular releases

The DefectDojo team aims to maintain the following cadence: 

- Minor releases: at least once a month on the first Monday of the month.
- Patch/Bugfix: releases every week on Monday.
- Security releases: will be performed outside of our regular cadence depending on severity.

GitHub Actions are the source of truth. The releases are semi-automated. The steps for a regular release are:
1. Create the release branch from `dev` or `bugfix` and prepare a PR against `master` ([details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> A maintainer verifies and manually merges the PR
1. Tag, issue draft release and docker build+push ([details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> A maintainer massages the release-drafter notes and publishes the release
1. A PR to merge `master` back to `dev` and `bugfix` is created to re-align the branches ([details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## Security releases
PRs that relate to security issues are done through [security advisories](https://github.com/DefectDojo/django-DefectDojo/security/advisories) which provide a way to work privately on code without prematurely disclosing vulnerabilities.

## Release and hotfix model
![Schemas](../../images/branching_model_v2.png)

Diagrams created with [plantUML](https://plantuml.com). Find a web-based editor for PlantUML at https://www.planttext.com.

## Documentation
A `dev` version of the documentation built from the `dev` branch is available at [DefectDojo Documentation - dev branch](https://documentation.defectdojo.com/dev/).


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
