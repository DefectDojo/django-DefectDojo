---
title: "Cloudflare"
description: "Cómo configurar el Conector Upstream de Cloudflare para DefectDojo"
weight: 36
audience: pro
---
El conector de Cloudflare importa **Security Center insights** — problemas de postura de seguridad que Cloudflare identifica sobre su cuenta y sus zonas, como un registro DMARC faltante, DNSSEC no habilitado o un problema de certificado. DefectDojo crea un Registro para cada zona (dominio) que tenga insights abiertos, además de un Registro a nivel de cuenta para los insights que no están asociados a una zona específica.

#### Prerrequisitos

Necesitará un **API token** de Cloudflare (no la Global API Key heredada). Cree uno en **My Profile > API Tokens > Create Token** dentro del panel de Cloudflare. La opción más rápida es la plantilla **"Read all resources"**; para un token con privilegios mínimos, otorgue **Zone > Zone > Read** (todas las zonas) más acceso de lectura a nivel de cuenta para Security Center.

#### Asignaciones del conector

1. Ingrese `https://api.cloudflare.com/client/v4` en el campo **Location**.
2. Ingrese el API token en el campo **Secret**.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo autodescubre las cuentas y zonas a las que el token tiene acceso — no se requiere un ID de cuenta. Solo se importan los insights abiertos (activos, no descartados), por lo que los insights que resuelva o descarte en Cloudflare se marcan automáticamente como Mitigado en DefectDojo en la siguiente sincronización.
