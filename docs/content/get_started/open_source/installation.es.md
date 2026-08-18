---
title: Instalación
description: DefectDojo admite varias opciones de instalación.
draft: false
weight: 1
audience: opensource
aliases:
- /es/en/open_source/installation/installation
---

## **Opciones recomendadas**
---

### Docker Compose

Consulte las instrucciones en [DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>)

### SaaS (incluye soporte y contribuye al proyecto)

[Enlace SaaS](https://defectdojo.com/platform)

---
## **Variantes de imagen Docker**
---

DefectDojo publica imágenes Docker en múltiples variantes:

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ Compatible | ⚠️ Con pruebas unitarias |
| **Alpine** | ⚠️ Comunidad | ⚠️ Comunidad |

**Debian en AMD64** es la configuración oficialmente compatible y probada. Todas las pruebas de CI (unitarias, de integración y de rendimiento) se ejecutan contra esta combinación.

**Debian en ARM64** se compila y se cubre con pruebas unitarias en CI, pero no se ejecutan pruebas de integración ni de rendimiento contra ella.

Las variantes de **Alpine** se compilan y publican, pero no están cubiertas por ninguna prueba automatizada. Úselas bajo su propio riesgo.

---
## **Opciones para los valientes (no compatibles oficialmente)**
---
### Kubernetes

Consulte las instrucciones en [KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>)

### Instalación local con godojo

Consulte las instrucciones en [README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)
en el repositorio godojo

---

## Personalización de la configuración

Consulte [Configuración](../configuration)
