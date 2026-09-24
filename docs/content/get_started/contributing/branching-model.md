---
title: "Open-Source Branching & Releases"
description: "How we create releases"
draft: false
weight: 3
audience: opensource
aliases:
  - "/open_source/contributing/branching-model/"
  - /en/open_source/contributing/branching-model
---
## Regular releases

All releases come from the `dev` branch. The DefectDojo team aims to maintain the following cadence:

- Minor releases: at least once a month on the first Monday of the month.
- Patch releases: every week on Monday.
- Security releases: may be cut outside of our regular cadence depending on severity. They also come from `dev`.

There is no separate branch for bug fixes and no hotfix branch off `master`. Every pull request, bug fix or feature, targets `dev`.

GitHub Actions are the source of truth. The releases are semi-automated. The steps for every release are:
1. Create the release branch from `dev` and prepare a PR against `master` ([details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-1-create-pr.yml))
--> A maintainer verifies and manually merges the PR
1. Tag, issue draft release and docker build+push ([details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-2-tag-docker-push.yml))
--> A maintainer massages the release-drafter notes and publishes the release
1. A PR to merge `master` back to `dev` is created to re-align the branches ([details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-3-master-into-dev.yml))

## Security releases
PRs that relate to security issues are done through [security advisories](https://github.com/DefectDojo/django-DefectDojo/security/advisories) which provide a way to work privately on code without prematurely disclosing vulnerabilities.

## Release model

Diagrams created with [plantUML](https://plantuml.com). Find a web-based editor for PlantUML at https://www.planttext.com.



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
