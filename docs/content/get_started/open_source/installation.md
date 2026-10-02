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

The Compose file pulls DefectDojo's images through `registry.defectdojo.com` (run by DefectDojo, Inc.), which keeps them off your Docker Hub rate limits and logs each pull: the IP address is used to identify the organization and deleted within three days, and DefectDojo may reach out about its products or to ask for feedback. See [section 1.4 of the privacy policy](https://defectdojo.com/privacy-policy) for details and how to object, or set `DD_IMAGE_REGISTRY=docker.io` to pull straight from Docker Hub.

### SaaS (Includes Support & Supports the Project)

[SaaS link](https://defectdojo.com/platform)

---
## **Docker Image Variants**
---

DefectDojo publishes Docker images in multiple variants:

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ Supported | ⚠️ Unit tested |
| **Alpine** | ⚠️ Community | ⚠️ Community |

**Debian on AMD64** is the officially supported and tested configuration. All CI tests (unit, integration, and performance) run against this combination.

**Debian on ARM64** is built and covered by unit tests in CI, but integration and performance tests are not run against it.

The **Alpine** variants are built and published but are not covered by any automated testing. Use them at your own risk.

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
