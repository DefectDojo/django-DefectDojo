---
title: "Rapid7 InsightVM - Cloud Instance"
description: "Cómo configurar el Conector Upstream de Rapid7 InsightVM - Cloud Instance para DefectDojo"
weight: 113
audience: pro
---
El conector de Rapid7 InsightVM - Cloud Instance importa hallazgos de vulnerabilidades de activos desde InsightVM alojado en la **plataforma Rapid7 Insight** (Cloud Integrations API v4), enriquecidos con el catálogo de vulnerabilidades de la plataforma. DefectDojo crea un Record para cada **site** de InsightVM.

**Tenga en cuenta:** este conector es para InsightVM que se ejecuta en la plataforma en la nube Rapid7 Insight. Si sus hallazgos provienen de su propia **Security Console** on\-premises, use en su lugar el conector [Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/), que se autentica con credenciales de la consola en lugar de una API key de la plataforma.

#### Requisitos previos

Una cuenta de la plataforma Insight con InsightVM, y una **API key** de la plataforma: en [Rapid7 Insight platform](https://insight.rapid7.com), abra el menú de configuración (el ícono de engranaje) > **API Keys** y genere una **User Key** (cualquier rol) o una **Organization Key** (administradores de la plataforma). Copie la clave cuando se muestre: solo se muestra una vez.

También necesitará la **región** de su plataforma, visible en su URL de Insight (por ejemplo, `us`, `us2`, `us3`, `eu`, `ca`, `au` o `ap`).

#### Asignaciones del conector

1. Ingrese el endpoint de API de su región en el campo **Location**, por ejemplo `https://us.api.insight.rapid7.com` (reemplace `us` por su región). Este campo viene pre\-rellenado con el endpoint de EE. UU.
2. Ingrese la API key de la plataforma Insight en el campo **API Key**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada site de InsightVM se convierte en un Record; el conector lee los activos de integración de la plataforma e importa sus hallazgos de vulnerabilidades, enriquecidos con el catálogo de vulnerabilidades. Los hallazgos se importan bajo el mismo tipo **Rapid7 InsightVM - Connectors Import** que el conector on\-premises, por lo que los resultados de ambos conectores se deduplican juntos.
