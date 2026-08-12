---
title: Installation
description: DefectDojo unterstützt verschiedene Installationsoptionen.
draft: false
weight: 1
audience: opensource
aliases:
- /de/en/open_source/installation/installation
---

## **Empfohlene Optionen**
---

### Docker Compose

Anleitung siehe [DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>)

### SaaS (mit Support und zur Unterstützung des Projekts)

[SaaS-Link](https://defectdojo.com/platform)

---
## **Varianten der Docker-Images**
---

DefectDojo veröffentlicht Docker-Images in mehreren Varianten:

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ Unterstützt | ⚠️ Unit-getestet |
| **Alpine** | ⚠️ Community | ⚠️ Community |

**Debian auf AMD64** ist die offiziell unterstützte und getestete Konfiguration. Alle CI-Tests (Unit-, Integrations- und Performance-Tests) laufen gegen diese Kombination.

**Debian auf ARM64** wird gebaut und in der CI durch Unit-Tests abgedeckt, Integrations- und Performance-Tests laufen dafür jedoch nicht.

Die **Alpine**-Varianten werden gebaut und veröffentlicht, sind aber durch keine automatisierten Tests abgedeckt. Die Nutzung erfolgt auf eigenes Risiko.

---
## **Optionen für Mutige (nicht offiziell unterstützt)**
---
### Kubernetes

Anleitung siehe [KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>)

### Lokale Installation mit godojo

Anleitung siehe [README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)
im godojo-Repository

---

## Anpassen der Einstellungen

Siehe [Konfiguration](../configuration)
