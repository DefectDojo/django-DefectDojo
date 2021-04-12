---
title: "Branching Model"
date: 2021-02-17T20:46:28+01:00
draft: false
---

The DefectDojo team aims to release at least once a month, on the last Tuesday.
Bugfix or security releases can come at any time.

In doubt, GitHub Actions are the source of truth. The releases are semi-automated right now, with a DefectDojo maintainer proceeding with each major step in the release. The steps for a regular release are:
1. Create the release branch from `dev` and prepare a PR against `master` ([Details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> A maintainer verifies and manually merges the PR
2. Tag, issue draft release and docker build+push ([Details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> A maintainer massages the release-drafter notes and publishes the release
3. A PR to merge `master` back to `dev` is created to re-align the branches ([details](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## Security releases
PRs that relate to security issues are done through [Security advisories](https://github.com/DefectDojo/django-DefectDojo/security/advisories) which provide a way to work privately on code without prematurely disclosing vulnerabilities.

## Release and hotfix model
![Schemas](../../images/branching_model.png)

Diagrams created with [plantUML](https://plantuml.com). Find a web-based editor for PlantUML at https://www.planttext.com.
