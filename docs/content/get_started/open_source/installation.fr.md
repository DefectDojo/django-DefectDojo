---
title: Installation
description: DefectDojo prend en charge diverses options d'installation.
draft: false
weight: 1
audience: opensource
aliases:
- /fr/en/open_source/installation/installation
---

## **Options recommandées**
---

### Docker Compose

Consultez les instructions dans [DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>)

### SaaS (inclut le support et soutient le projet)

[Lien SaaS](https://defectdojo.com/platform)

---
## **Variantes d'image Docker**
---

DefectDojo publie des images Docker en plusieurs variantes :

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ Pris en charge | ⚠️ Testé unitairement |
| **Alpine** | ⚠️ Communauté | ⚠️ Communauté |

**Debian sur AMD64** est la configuration officiellement prise en charge et testée. Tous les tests CI (unitaires, d'intégration et de performance) sont exécutés sur cette combinaison.

**Debian sur ARM64** est construit et couvert par des tests unitaires en CI, mais les tests d'intégration et de performance ne sont pas exécutés sur cette combinaison.

Les variantes **Alpine** sont construites et publiées, mais ne sont couvertes par aucun test automatisé. Utilisez-les à vos propres risques.

---
## **Options pour les plus audacieux (non officiellement prises en charge)**
---
### Kubernetes

Consultez les instructions dans [KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>)

### Installation locale avec godojo

Consultez les instructions dans [README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)
dans le dépôt godojo

---

## Personnalisation des paramètres

Consultez [Configuration](../configuration)
