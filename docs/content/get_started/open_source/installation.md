---
title: "Installation"
description: "DefectDojo supports various installation options."
draft: false
weight: 1
audience: opensource
aliases:
  - /en/open_source/installation/installation
---
## **Recommended Options**
---

### Docker Compose

See instructions in [DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>)

### SaaS (Includes Support & Supports the Project)

[SaaS link](https://defectdojo.com/platform)

---
## **Docker Image Variants**
---

DefectDojo publishes Docker images in multiple variants:

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | Supported | Community |
| **Alpine** | Community | Community |

**Debian on AMD64** is the officially supported and tested configuration. All CI tests (unit, integration, and performance) run exclusively against this combination.

The other variants (Alpine, ARM64) are built and published but are not covered by automated testing. Use them at your own risk.

---
## **Options for the brave (not officially supported)**
---
### Kubernetes

See instructions in [KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>)

### Local install with godojo

See instructions in [README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)
in the godojo repository

---

## Customizing of settings

See [Configuration](../configuration)
