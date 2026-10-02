---
title: Instalação
description: O DefectDojo suporta várias opções de instalação.
draft: false
weight: 1
audience: opensource
aliases:
- /pt-br/en/open_source/installation/installation
---

## **Opções recomendadas**
---

### Docker Compose

Veja as instruções em [DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>)

### SaaS (inclui suporte e apoia o projeto)

[Link do SaaS](https://defectdojo.com/platform)

---
## **Variantes de imagem Docker**
---

O DefectDojo publica imagens Docker em múltiplas variantes:

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ Suportado | ⚠️ Testado por unit tests |
| **Alpine** | ⚠️ Comunidade | ⚠️ Comunidade |

O **Debian no AMD64** é a configuração oficialmente suportada e testada. Todos os testes de CI (unitários, de integração e de performance) são executados nessa combinação.

O **Debian no ARM64** é compilado e coberto por testes unitários no CI, mas os testes de integração e performance não são executados nele.

As variantes **Alpine** são compiladas e publicadas, mas não são cobertas por nenhum teste automatizado. Use-as por sua conta e risco.

---
## **Opções para os corajosos (não suportadas oficialmente)**
---
### Kubernetes

Veja as instruções em [KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>)

### Instalação local com godojo

Veja as instruções em [README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)
no repositório godojo

---

## Personalização de configurações

Veja [Configuração](../configuration)
