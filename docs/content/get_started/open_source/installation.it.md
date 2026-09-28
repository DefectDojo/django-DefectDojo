---
title: Installazione
description: DefectDojo supporta diverse opzioni di installazione.
draft: false
weight: 1
audience: opensource
aliases:
- /it/en/open_source/installation/installation
---

## **Opzioni consigliate**
---

### Docker Compose

Consulta le istruzioni in [DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>)

### SaaS (include il supporto e sostiene il progetto)

[Link SaaS](https://defectdojo.com/platform)

---
## **Varianti dell'immagine Docker**
---

DefectDojo pubblica immagini Docker in diverse varianti:

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ Supportato | ⚠️ Testato con unit test |
| **Alpine** | ⚠️ Community | ⚠️ Community |

**Debian su AMD64** è la configurazione ufficialmente supportata e testata. Tutti i test CI (unit, integrazione e prestazioni) vengono eseguiti su questa combinazione.

**Debian su ARM64** viene compilato ed è coperto da unit test in CI, ma i test di integrazione e prestazioni non vengono eseguiti su di esso.

Le varianti **Alpine** vengono compilate e pubblicate, ma non sono coperte da alcun test automatizzato. Usale a tuo rischio.

---
## **Opzioni per i coraggiosi (non ufficialmente supportate)**
---
### Kubernetes

Consulta le istruzioni in [KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>)

### Installazione locale con godojo

Consulta le istruzioni in [README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)
nel repository godojo

---

## Personalizzazione delle impostazioni

Consulta [Configurazione](../configuration)
