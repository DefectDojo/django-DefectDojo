---
title: "Rapid7 InsightAppSec"
description: "Cómo configurar el Conector Upstream de Rapid7 InsightAppSec para DefectDojo"
weight: 112
audience: pro
---
El conector de Rapid7 InsightAppSec importa **hallazgos de vulnerabilidades DAST** desde la plataforma en la nube InsightAppSec, enriquecidos con metadatos del módulo de ataque (por ejemplo, *SQL Injection*), puntuaciones CVSS y la evidencia recopilada por el escaneo. DefectDojo crea un Record para cada **app** de InsightAppSec.

**Tenga en cuenta:** este conector es distinto del conector **Rapid7 InsightVM** que se describe más abajo: InsightAppSec es el producto DAST en la nube de Rapid7 dentro de la plataforma Insight, mientras que los hallazgos de InsightVM provienen de su propia Security Console.

#### Requisitos previos

Una cuenta de la plataforma Insight con InsightAppSec, y una **API key** de la plataforma: en [Rapid7 Insight platform](https://insight.rapid7.com), abra el menú de configuración (el ícono de engranaje) > **API Keys** y genere una **User Key** (cualquier rol) o una **Organization Key** (administradores de la plataforma). Copie la clave cuando se muestre: solo se muestra una vez.

También necesitará la **región** de su plataforma, visible en su URL de Insight (por ejemplo, `us`, `us2`, `us3`, `eu`, `ca`, `au` o `ap`).

#### Asignaciones del conector

1. Ingrese el endpoint de API de su región en el campo **Location**, por ejemplo `https://us.api.insight.rapid7.com` (reemplace `us` por su región).
2. Ingrese la API key de la plataforma Insight en el campo **API Key**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada app de InsightAppSec se convierte en un Record. Solo se importan las vulnerabilidades **abiertas** (Unreviewed o Verified): los hallazgos que Rapid7 ha marcado como Remediated, Falso positivo, Ignored o Duplicado se excluyen, por lo que reimportar los cierra en DefectDojo. Las severidades se asignan directamente (`SAFE` e `INFORMATIONAL` se importan como Informativa).
